import { posixTest } from '../fixtures/native-scope.mjs';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { JobJournal } from '../../packages/runtime-manager/src/job-journal.js';
import { producePodmanProbe, runPodmanValidation } from '../../packages/runtime-manager/src/podman-runner.js';
import { PODMAN_PROBE_SCRIPT } from '../../packages/runtime-manager/src/podman-probe-script.js';
import type { PodmanProbeEvidence } from '../../packages/runtime-manager/src/podman-runner.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const hash = (value: Buffer | string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

async function fixture<T>(run: (fixture: any) => Promise<T>): Promise<T> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-podman-'));
  const root = await realpath(base);
  let snapshot: Awaited<ReturnType<typeof captureValidationSnapshot>> | undefined;
  try {
    for (const name of ['workspace', 'state', 'graph', 'hooks']) await mkdir(path.join(root, name), { mode: 0o700 });
    await writeFile(path.join(root, 'workspace', 'file.conllu'), '# sent_id = 1\n1\tword\t_\tX\t_\t_\t0\troot\t_\t_\n\n');
    snapshot = await captureValidationSnapshot(guard, path.join(root, 'workspace'), [path.join(root, 'workspace')]);
    const engine = path.join(root, 'podman'); await writeFile(engine, 'trusted podman binary');
    const profile = { defaultAction: 'SCMP_ACT_ERRNO', syscalls: [] };
    const profileBytes = Buffer.from(JSON.stringify(profile)); const seccompProfile = path.join(root, 'seccomp.json'); await writeFile(seccompProfile, profileBytes);
    const digest = `sha256:${'a'.repeat(64)}`;
    const image = { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: `sha256:${'b'.repeat(64)}` };
    const graph = path.join(root, 'graph'); const configPath = path.join(graph, 'config.json');
    const expectedEnvironment = ['PATH=/usr/bin', 'LANG=C'];
    const containersConf = path.join(root, 'containers.conf'); const configBytes = Buffer.from('[containers]\nmounts = []\n[engine]\nhooks_dir = []\n'); await writeFile(containersConf, configBytes, { mode: 0o600 });
    const defaultMountsFile = path.join(root, 'mounts.conf'); await writeFile(defaultMountsFile, '', { mode: 0o600 });
    const spec = { root: { readonly: true }, process: { terminal: false, noNewPrivileges: true, cwd: '/work', user: { uid: 10001, gid: 10001 }, args: ['python', '-m', 'ud_agent.worker'], env: expectedEnvironment,
      capabilities: { bounding: [], effective: [], inheritable: [], permitted: [], ambient: [] }, rlimits: [{ type: 'RLIMIT_NOFILE', soft: 1024, hard: 1024 }] },
      mounts: [{ type: 'bind', source: await realpath(snapshot.directory), destination: '/work', options: ['rbind', 'ro'] }, { type: 'tmpfs', destination: '/tmp', options: ['nosuid', 'nodev', 'noexec', 'size=67108864'] }],
      linux: { namespaces: [{ type: 'pid' }, { type: 'ipc' }, { type: 'network' }, { type: 'user' }, { type: 'cgroup' }], seccomp: profile, devices: [], resources: { memory: { limit: 2_147_483_648 }, cpu: { quota: 200_000, period: 100_000 }, pids: { limit: 128 }, devices: [] } } };
    await writeFile(configPath, JSON.stringify(spec));
    const liveProbe: PodmanProbeEvidence = { engineSha256: hash('trusted podman binary'), imageDigest: digest, contextSha256: image.contextSha256, seccompSha256: hash(profileBytes), containersConfSha256: hash(configBytes), defaultMountsSha256: hash(''), graphRoot: graph, architecture: 'arm64', verifiedAtMs: Date.now(), workerUid: 10001, workerGid: 10001, noNetwork: true, noPull: true, readOnlyRuntime: true, readOnlySnapshot: true, capabilitiesDropped: true, seccompEnforced: true, limitsEnforced: true, isolatedConfig: true, cleanupVerified: true };
    const journal = await JobJournal.open(path.join(root, 'state'));
    const input = { engine, engineSha256: liveProbe.engineSha256, guard, guardSha256: hash(await readFile(guard)), snapshot, hooksDirectory: path.join(root, 'hooks'), defaultMountsFile, containersConf, containersConfSha256: liveProbe.containersConfSha256, seccompProfile, seccompSha256: liveProbe.seccompSha256, image, expectedEnvironment, journal, files: ['file.conllu'], validationOptions: { language_code: 'en', level: 5 }, host: { platform: 'linux', arch: 'arm64' as const }, liveProbe };
    return await run({ root, input, spec, configPath, journal, digest, image });
  } finally { if (snapshot) await snapshot.cleanup(); await rm(base, { recursive: true, force: true }); }
}

function fakeRunner(f: any, behavior: 'normal' | 'cancel' | 'cleanup-fails' | 'create-uncertain' | 'rootful' = 'normal') {
  let name = ''; let exists = false; const id = 'c'.repeat(64); const commands: string[][] = [];
  const result = (code: number, value: unknown = '') => ({ code, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });
  const runner: typeof runCommand = async (_exe, args, options) => {
    commands.push([...args]);
    if (args.includes('info')) return result(0, { host: { arch: 'arm64', security: { rootless: behavior !== 'rootful' } }, store: { graphRoot: path.join(f.root, 'graph') } });
    if (args.includes('image') && args.includes('inspect')) return result(0, [{ Digest: f.digest, RepoDigests: [f.image.reference] }]);
    if (args.includes('create')) {
      if (behavior === 'create-uncertain') throw new Error('COMMAND_TIMEOUT');
      name = args[args.indexOf('--name') + 1] ?? ''; exists = true; return result(0, `${id}\n`);
    }
    if (args.includes('inspect')) return result(0, [{ Id: id, Name: name, ImageDigest: f.digest, OCIConfigPath: f.configPath, EffectiveCaps: [], BoundingCaps: [], State: { Status: 'created' }, Config: { Labels: { 'io.ud-agent.job': name }, User: '10001:10001', Tty: false, OpenStdin: true }, HostConfig: { Privileged: false, ReadonlyRootfs: true, NetworkMode: 'none', Devices: [], PublishAllPorts: false } }]);
    if (args.includes('start')) {
      if (behavior === 'cancel') throw new Error('COMMAND_CANCELLED');
      const request = JSON.parse(options.input?.toString() ?? 'null');
      expect(request).toMatchObject({ operation: 'validation_report', arguments: { working_tree_path: '/work', file_paths: ['file.conllu'], ud_context_path: '/opt/ud-agent/context/context.json' } });
      return result(0, '{"ok":true,"result":{"passed":false}}\n');
    }
    if (args.includes('exists')) return result(exists ? 0 : 1);
    if (args.includes('stop')) return result(0);
    if (args.includes('rm')) { if (behavior === 'cleanup-fails') return result(125); exists = false; return result(0); }
    throw new Error(`unexpected command ${args.join(' ')}`);
  };
  return { runner, commands };
}

if (process.platform !== 'win32') describe('Podman validation transport orchestration', () => {
  posixTest('does not silently elevate or accept a forged rootful local context', async () => fixture(async f => {
    const fake = fakeRunner(f, 'rootful');
    await expect(runPodmanValidation({ ...f.input, allowRootful: true, runner: fake.runner })).rejects.toThrow(process.getuid?.() === 0 ? 'mode changed since the runtime probe' : 'already-authorized root context');
    expect(fake.commands.some(command => command.includes('create'))).toBe(false);
    expect(await f.journal.pending()).toEqual([]);
  }));
  posixTest('requires fresh bound independent probes before any engine command', async () => fixture(async f => {
    const fake = fakeRunner(f);
    await expect(runPodmanValidation({ ...f.input, liveProbe: undefined, runner: fake.runner })).rejects.toThrow('PODMAN_LIVE_PROBE_REQUIRED');
    expect(fake.commands).toEqual([]);
  }));

  posixTest('runs only after both inspections and verifies exact owned cleanup', async () => fixture(async f => {
    const fake = fakeRunner(f);
    expect(await runPodmanValidation({ ...f.input, runner: fake.runner })).toEqual({ ok: true, result: { passed: false } });
    const create = fake.commands.find(command => command.includes('create'));
    expect(create).toContain('--pull=never'); expect(create).toContain('--network=none');
    expect(fake.commands.findIndex(command => command.includes('inspect') && command.includes('container'))).toBeLessThan(fake.commands.findIndex(command => command.includes('start')));
    expect(fake.commands.some(command => command.includes('rm') && command.includes('--force'))).toBe(true);
    expect(await f.journal.pending()).toEqual([]);
  }));

  posixTest('rejects injected OCI network namespace before start and cleans the owned job', async () => fixture(async f => {
    f.spec.linux.namespaces[2].path = '/host/network';
    await writeFile(f.configPath, JSON.stringify(f.spec));
    const fake = fakeRunner(f);
    await expect(runPodmanValidation({ ...f.input, runner: fake.runner })).rejects.toThrow('namespace_network');
    expect(fake.commands.some(command => command.includes('start'))).toBe(false);
    expect(await f.journal.pending()).toEqual([]);
  }));

  posixTest('does not return a worker result when cancellation or cleanup failure occurs', async () => fixture(async f => {
    const cancelled = fakeRunner(f, 'cancel');
    await expect(runPodmanValidation({ ...f.input, runner: cancelled.runner })).rejects.toThrow('COMMAND_CANCELLED');
    expect(await f.journal.pending()).toEqual([]);
    const failed = fakeRunner(f, 'cleanup-fails');
    await expect(runPodmanValidation({ ...f.input, runner: failed.runner })).rejects.toThrow('PODMAN_CLEANUP_UNVERIFIED');
    expect(await f.journal.pending()).toMatchObject([{ phase: 'cleanup_pending', container_id: 'c'.repeat(64) }]);
  }));

  posixTest('keeps a planned journal if create outcome is unknown', async () => fixture(async f => {
    const fake = fakeRunner(f, 'create-uncertain');
    await expect(runPodmanValidation({ ...f.input, runner: fake.runner })).rejects.toThrow('PODMAN_CREATE_OUTCOME_UNKNOWN');
    expect(await f.journal.pending()).toMatchObject([{ phase: 'planned' }]);
  }));
});


if (process.platform !== 'win32') describe('live Podman probe production', () => {
  const output = { schema_version: 1, uid: 10001, gid: 10001, euid: 10001, egid: 10001, interfaces: ['lo'], default_route: false, root_readonly: true, snapshot_readonly: true, no_new_privileges: true, capabilities_dropped: true, seccomp_enforced: true, memory_max: 2147483648, pids_max: 128, cpu_quota: 200000, cpu_period: 100000, nofile_soft: 1024, nofile_hard: 1024 };
  async function probeFixture(f: any, modifiedOutput: unknown) {
    const tracer = path.join(f.root, 'strace'); await writeFile(tracer, 'tracer');
    const fake = fakeRunner(f);
    const runner: typeof runCommand = async (exe, args, options) => {
      if (exe === tracer) {
        const trace = args[args.indexOf('-o') + 1]; if (!trace) throw new Error('missing trace');
        await writeFile(trace, `execve(${JSON.stringify(f.input.engine)}, [], 0x0) = 0\n`);
        return { code: 125, stdout: Buffer.alloc(0), stderr: Buffer.from('image not known locally') };
      }
      if (args.includes('image') && args.includes('exists')) return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      if (args.includes('create')) {
        const mount = args.find(argument => argument.startsWith('--mount=type=bind,source='));
        if (!mount) throw new Error('missing fixture mount');
        const source = mount.slice('--mount=type=bind,source='.length).split(',')[0];
        f.spec.mounts[0].source = source;
        f.spec.process.args = ['/usr/local/bin/python', '-c', PODMAN_PROBE_SCRIPT];
        await writeFile(f.configPath, JSON.stringify(f.spec));
      }
      if (args.includes('start')) return { code: 0, stdout: Buffer.from(`${JSON.stringify(modifiedOutput)}\n`), stderr: Buffer.alloc(0) };
      return fake.runner(exe, args, options);
    };
    return { tracer, tracerSha256: hash('tracer'), runner };
  }
  posixTest('does not run a probe on an unsupported host', async () => fixture(async f => {
    const extra = await probeFixture(f, output);
    const commands: string[][] = [];
    const runner: typeof runCommand = async (_exe, args) => { commands.push([...args]); throw new Error('unexpected command'); };
    await expect(producePodmanProbe({ ...f.input, ...extra, host: { platform: 'darwin', arch: 'arm64' }, runner })).rejects.toThrow('native supported Linux');
    expect(commands).toEqual([]);
  }));
  posixTest('returns evidence only after no-pull, actual process observation, OCI inspection and cleanup', async () => fixture(async f => {
    const extra = await probeFixture(f, output);
    const evidence = await producePodmanProbe({ ...f.input, ...extra });
    expect(evidence).toMatchObject({ engineSha256: f.input.engineSha256, imageDigest: f.digest, graphRoot: path.join(f.root, 'graph'), noPull: true, cleanupVerified: true, workerUid: 10001 });
    expect(await f.journal.pending()).toEqual([]);
  }));
  posixTest('rejects failed process confinement after cleaning the owned container', async () => fixture(async f => {
    const extra = await probeFixture(f, { ...output, snapshot_readonly: false });
    await expect(producePodmanProbe({ ...f.input, ...extra })).rejects.toThrow('read_only_mounts');
    expect(await f.journal.pending()).toEqual([]);
  }));
});

if (process.platform === 'win32') it('legacy Podman journal refuses Windows state without manufacturing POSIX authority', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-podman-journal-refusal-')));
  try {
    await expect(JobJournal.open(root)).rejects.toThrow('WINDOWS_STATE_GUARD_REQUIRED');
    expect(await readdir(root)).toEqual([]);
  } finally { await rm(root, { recursive: true, force: true }); }
});
