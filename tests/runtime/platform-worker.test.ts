import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { admitLimaRuntime } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import { runPlatformWorker, recoverPlatformJobs, platformAuthorityIdentity } from '../../packages/coordinator/src/platform-worker.js';
import { PlatformJournal } from '../../packages/coordinator/src/platform-journal.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const sha = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const success = (value: unknown = '') => ({ code: 0, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });
async function fixture<T>(run: (context: Awaited<ReturnType<typeof prepare>>) => Promise<T>): Promise<T> { const root = await mkdtemp(path.join(os.tmpdir(), 'ud-platform-worker-')); try { return await run(await prepare(root)); } finally { await rm(root, { recursive: true, force: true }); } }
async function prepare(base: string) {
  const executable = path.join(base, 'limactl'); const stateRoot = path.join(base, 'state'); const workspace = path.join(base, 'workspace');
  await writeFile(executable, 'lima'); await mkdir(stateRoot, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const sentence = '# sent_id = 1\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n'; await writeFile(path.join(workspace, 'a.conllu'), sentence);
  const workingTree = await realpath(workspace);
  const receipt = { schema_version: 1 as const, executable, binarySha256: sha('lima'), instance: 'ud-agent', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: sha('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: sha('containerd'), ctr: '/usr/local/bin/ctr', ctrSha256: sha('ctr'), address: '/run/user/1000/containerd/containerd.sock', guestUid: 1000, guestHome: '/home/test', architecture: 'arm64' as const };
  const image = { reference: `ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-core@${sha('image')}`, digest: sha('image'), contextSha256: sha('context'), configDigest: sha('config'), diffIds: [sha('layer')] };
  const createInputs: Buffer[] = []; let changedPolicy = false;
  const containers = new Map<string, Record<string, unknown>>(); const commands: string[][] = []; let volume = ''; let job = ''; let failed: false | 'before' | 'after' = false; let foreign = false; let pidStat = 'regular file|1000|666|4|12345|1'; let pid = '4321'; let preexistingPid = false; let parentStat = 'directory|1000|700|54321';
  const runner: typeof runCommand = async (_exe, args, options) => {
    commands.push([...args]); if (args[0] === '--version') return success('limactl version 2.0.0\n'); if (args[0] === 'list') return success([{ name: 'ud-agent', status: 'Running', arch: 'aarch64', vmType: 'vz' }]);
    if (args.includes('/usr/bin/test')) return args.some(value => value.endsWith('/ud-agent-stdin.pid')) && preexistingPid ? { ...success(), code: 1 } : success();
    if (args.includes('/usr/bin/stat')) return success(args.at(-1)?.endsWith('/ud-agent-stdin.pid') ? pidStat : parentStat);
    if (args.includes('/usr/bin/cat') && args.at(-1)?.endsWith('/ud-agent-stdin.pid')) return success(pid);
    if (args.includes('/usr/bin/id')) return success('1000\n');
    if (args.includes('/proc/sys/kernel/random/boot_id')) return success('11111111-1111-4111-8111-111111111111\n');
    if (args.includes('/usr/bin/sha256sum')) return success(`${receipt.nerdctlSha256.slice(7)}  ${receipt.nerdctl}\n${receipt.containerdSha256.slice(7)}  ${receipt.containerd}\n${receipt.ctrSha256.slice(7)}  ${receipt.ctr}\n`);
    const actual = args.slice(args.indexOf('--cgroup-manager') + 2);
    if (actual[0] === 'info') return success({ Rootless: true, Namespace: 'ud-agent', Snapshotter: 'overlayfs', CgroupManager: 'systemd', Daemon: {} });
    if (actual[0] === 'image') return success([{ Image: { name: image.reference, target: { digest: image.digest } }, ManifestDesc: { digest: image.digest }, ImageConfigDesc: { digest: image.configDigest }, ImageConfig: { os: 'linux', architecture: 'arm64', rootfs: { type: 'layers', diff_ids: image.diffIds } } }]);
    if (actual[0] === 'volume' && actual[1] === 'create') { volume = actual.at(-1)!; job = actual[actual.indexOf('--label') + 1]!.split('=')[1]!; return success(`${volume}\n`); }
    if (actual[0] === 'volume' && actual[1] === 'inspect') return volume ? success([{ Name: volume, Mountpoint: '/home/test/ud-agent-volume', Labels: { 'io.ud-agent.job': job } }]) : { ...success(), code: 1 };
    if (actual[0] === 'volume' && actual[1] === 'rm') { volume = ''; return success(); }
    if (actual[0] === 'volume' && actual[1] === 'ls') return success(volume ? [{ Name: volume, Driver: 'local', Mountpoint: '/home/test/ud-agent-volume', Labels: `io.ud-agent.job=${job}` }] : []);
    if (actual[0] === 'create') {
      if (failed === 'before') throw new Error('lost create response');
      const name = actual[actual.indexOf('--name') + 1]!; const id = createHash('sha256').update(name).digest('hex'); const args = actual.slice(actual.indexOf(image.reference) + 1);
      const inputReadOnly = actual.some(value => value.startsWith('type=volume,') && value.endsWith(',readonly'));
      const record = { ID: id, Image: image.reference, Labels: { 'io.ud-agent.job': foreign ? 'unrelated' : job, 'nerdctl/namespace': 'ud-agent', 'nerdctl/name': name, 'nerdctl/state-dir': `/home/test/.local/share/nerdctl/12345678/containers/ud-agent/${id}` }, Spec: { root: { readonly: true }, process: { user: { uid: 10001, gid: 10001 }, noNewPrivileges: true, terminal: false, cwd: '/work', args: ['/usr/local/bin/python', ...args], capabilities: { bounding: [], effective: [], inheritable: [], permitted: [], ambient: [] } }, linux: { namespaces: ['pid', 'ipc', 'network', 'user', 'cgroup'].map(type => ({ type })), seccomp: { defaultAction: 'SCMP_ACT_ERRNO' }, resources: { memory: { limit: 2147483648 }, pids: { limit: 128 }, cpu: { quota: 200000, period: 100000 } } }, mounts: [{ destination: '/input', source: '/home/test/ud-agent-volume', options: [inputReadOnly ? 'ro' : 'rw'] }, { destination: '/tmp', type: 'tmpfs', options: ['nosuid', 'nodev', 'noexec'] }] } };
      if (actual.includes('seccomp=/dev/stdin')) {
        expect(Buffer.isBuffer(options.input)).toBe(true); createInputs.push(Buffer.from(options.input!));
        record.Spec.linux.seccomp = JSON.parse(options.input!.toString('utf8'));
        if (changedPolicy) record.Spec.linux.seccomp = { defaultAction: 'SCMP_ACT_ERRNO' };
      } else expect(options.input).toBeUndefined();
      containers.set(name, record); containers.set(id, record); if (failed === 'after') throw new Error('lost create response'); return success(`${id}\n`);
    }
    if (actual.includes('inspect')) { const found = containers.get(actual.at(-1)!); return found ? success([found]) : { ...success(), code: 1 }; }
    if (actual[0] === 'stop') return success();
    if (actual[0] === 'rm') { const found = containers.get(actual.at(-1)!); for (const [key, value] of containers) if (value === found) containers.delete(key); return success(); }
    // A short-lived completed ctr task is deleted while its container remains
    // Created. Handoff must not depend on catching a transient Up status.
    if (actual[0] === 'container' && actual[1] === 'ls') return success([...new Set(containers.values())].map(record => ({ ID: record.ID, Status: 'Created' })));
    throw new Error(`unexpected command ${JSON.stringify(actual)}`);
  };
  const runtime = await admitLimaRuntime(receipt, runner);
  return { runtime, stateRoot, workingTree, image, sentence, commands, containers, runner, createInputs, changePolicy: () => { changedPolicy = true; }, failCreate: (mode: 'before' | 'after' = 'before') => { failed = mode; }, foreignLabel: () => { foreign = true; }, pidMarker: (stat: string, value = '4321', preexisting = false, parent = 'directory|1000|700|54321') => { pidStat = stat; pid = value; preexistingPid = preexisting; parentStat = parent; } };
}

describe('generic platform worker broker', () => {
  it('uses verified snapshot framing, independent worker response, and read-only handoff with owned cleanup', async () => fixture(async context => {
    let transfers = 0;
    const result = await runPlatformWorker(context.runtime, context.image, guard, context.stateRoot, { operation: 'validation_report', arguments: { working_tree_path: context.workingTree, file_paths: ['a.conllu'], language_code: 'en' }, workingTree: context.workingTree, allowedRoots: [context.workingTree], filePaths: ['a.conllu'], options: { language_code: 'en' } }, context.runner, async (_exe, args, input) => {
      expect(args).toContain('--pid-file'); const marker = args[args.indexOf('--pid-file') + 1]!; expect(marker).toBe(`/home/test/.local/share/nerdctl/12345678/containers/ud-agent/${args.at(-1)}/ud-agent-stdin.pid`);
      const chunks = []; for await (const bytes of input) chunks.push(bytes); const data = Buffer.concat(chunks); transfers++;
      const container = context.containers.get(args.at(-1)!)!; const process = (container.Spec as any).process;
      if (transfers === 1) { const frames = data.toString('utf8').trimEnd().split('\n').map(line => JSON.parse(line)); const bytes = Buffer.concat(frames.filter(frame => frame.type === 'chunk').map(frame => Buffer.from(frame.bytes_base64, 'base64'))); expect(bytes.toString('utf8')).toBe(context.sentence); expect(frames[0].type).toBe('begin'); expect(frames.at(-1).type).toBe('end'); return Buffer.from(`${JSON.stringify({ status: 'loaded', snapshot_sha256: process.args.at(-1) })}\n`); }
      const request = JSON.parse(data.toString()); expect(request.operation).toBe('validation_report'); expect(request.arguments.file_paths).toEqual(['a.conllu']); expect(request.files).toEqual([{ path: 'a.conllu', size: Buffer.byteLength(context.sentence), sha256: sha(context.sentence).slice(7) }]);
      return Buffer.from('{"ok":true,"result":{"passed":true,"incidents":[],"fixture_evidence":"independent"}}\n');
    });
    expect(result.result).toEqual({ passed: true, incidents: [], fixture_evidence: 'independent' }); expect(transfers).toBe(2); expect(context.containers.size).toBe(0); expect(await readFile(path.join(context.workingTree, 'a.conllu'), 'utf8')).toBe(context.sentence);
    expect(await (await PlatformJournal.open(context.stateRoot, guard)).pending()).toEqual([]);
    const creates = context.commands.filter(args => args.includes('create') && args.includes('--pull=never')); expect(creates).toHaveLength(2); expect(creates[1]!.some(value => value.startsWith('type=volume,') && value.endsWith(',readonly'))).toBe(true);
  }));

  it('binds render-only stdin seccomp bytes to receipt identity and complete native inspection before snapshot transfer', async () => fixture(async context => {
    const policy = { defaultAction: 'SCMP_ACT_ERRNO', defaultErrnoRet: 1, archMap: [{ architecture: 'SCMP_ARCH_AARCH64', subArchitectures: ['SCMP_ARCH_ARM'] }], syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }, { names: ['clone'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 235012096, valueTwo: 0, op: 'SCMP_CMP_MASKED_EQ' }] }] };
    const text = JSON.stringify(policy), file = path.join(context.stateRoot, 'render-policy.json'); await writeFile(file, text);
    const image = { ...context.image, seccompProfile: { path: file, sha256: sha(text), sizeBytes: Buffer.byteLength(text) } };
    const request = { operation: 'validation_report', arguments: { file_paths: ['a.conllu'] }, workingTree: context.workingTree, allowedRoots: [context.workingTree], filePaths: ['a.conllu'], options: {} };
    let transfers = 0;
    await runPlatformWorker(context.runtime, image, guard, context.stateRoot, request, context.runner, async (_exe, args, input) => {
      for await (const _bytes of input) { /* Consume the actual broker transfer. */ }
      const command = ((context.containers.get(args.at(-1)!)!.Spec as any).process.args as string[]);
      return Buffer.from(++transfers === 1 ? JSON.stringify({ status: 'loaded', snapshot_sha256: command.at(-1) }) + '\n' : '{"ok":true,"result":{"passed":true}}\n');
    });
    const expected = { defaultAction: 'SCMP_ACT_ERRNO', defaultErrnoRet: 1, architectures: ['SCMP_ARCH_AARCH64', 'SCMP_ARCH_ARM'], syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }, { names: ['clone'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 235012096, op: 'SCMP_CMP_MASKED_EQ' }] }] };
    expect(context.createInputs.map(bytes => JSON.parse(bytes.toString()))).toEqual([expected, expected]);expect(transfers).toBe(2);
    context.changePolicy(); let transferred = false;
    await expect(runPlatformWorker(context.runtime, image, guard, context.stateRoot, request, context.runner, async () => { transferred = true; return Buffer.alloc(0); })).rejects.toThrow('seccomp');
    expect(transferred).toBe(false);
    const pending = await (await PlatformJournal.open(context.stateRoot, guard)).pending();expect(pending).toHaveLength(1);expect(pending[0]?.pending_create).toBe('loader');
    expect((await recoverPlatformJobs(context.runtime, image, guard, context.stateRoot, context.runner)).recovered).toEqual([pending[0]!.id]);expect(context.containers.size).toBe(0);
    const before = context.commands.length;await writeFile(file, text + ' ');
    await expect(runPlatformWorker(context.runtime, image, guard, context.stateRoot, request, context.runner)).rejects.toThrow('LIMA_SECCOMP_PROFILE_CHANGED');
    expect(context.commands).toHaveLength(before);
  }));

  it('rejects stale, foreign, linked, executable, malformed and non-private stdin handoff markers before transferring snapshot bytes', async () => {
    for (const [stat, pid, stale, parent] of [
      ['regular file|1000|666|4|12345|1', '4321', true, 'directory|1000|700|54321'],
      ['symbolic link|1000|644|4|12345|1', '4321', false, 'directory|1000|700|54321'],
      ['regular file|1001|644|4|12345|1', '4321', false, 'directory|1000|700|54321'],
      ['regular file|1000|777|4|12345|1', '4321', false, 'directory|1000|700|54321'],
      ['regular file|1000|644|11|12345|1', '4321', false, 'directory|1000|700|54321'],
      ['regular file|1000|644|4|12345|2', '4321', false, 'directory|1000|700|54321'],
      ['regular file|1000|644|4|12345|1', '4321\n', false, 'directory|1000|700|54321'],
      ['regular file|1000|666|4|12345|1', '4321', false, 'directory|1000|755|54321'],
      ['regular file|1000|666|4|12345|1', '4321', false, 'directory|1001|700|54321'],
      ['regular file|1000|666|4|12345|1', '4321', false, 'symbolic link|1000|700|54321'],
    ] as const) await fixture(async context => {
      context.pidMarker(stat, pid, stale, parent); let delivered = false;
      await expect(runPlatformWorker(context.runtime, context.image, guard, context.stateRoot, { operation: 'validation_report', arguments: { file_paths: ['a.conllu'] }, workingTree: context.workingTree, allowedRoots: [context.workingTree], options: {} }, context.runner, async (_exe, _args, input) => { for await (const _chunk of input) delivered = true; return Buffer.alloc(0); })).rejects.toThrow('LIMA_TASK_STDIN_HANDOFF_FAILED');
      expect(delivered).toBe(false); expect(context.containers.size).toBe(0); expect(await (await PlatformJournal.open(context.stateRoot, guard)).pending()).toEqual([]);
    });
  }, process.platform === 'win32' ? 180_000 : 30_000);

  it('cleans exact owned resources after cancellation and retains ambiguous-create evidence', async () => fixture(async context => {
    const request = { operation: 'validation_report', arguments: { working_tree_path: context.workingTree, file_paths: ['a.conllu'], language_code: 'en' }, workingTree: context.workingTree, allowedRoots: [context.workingTree], filePaths: ['a.conllu'], options: {} };
    await expect(runPlatformWorker(context.runtime, context.image, guard, context.stateRoot, request, context.runner, async () => { throw new Error('WORKER_CANCELLED'); })).rejects.toThrow('WORKER_CANCELLED');
    expect(context.containers.size).toBe(0); expect(await (await PlatformJournal.open(context.stateRoot, guard)).pending()).toEqual([]);
    context.failCreate(); await expect(runPlatformWorker(context.runtime, context.image, guard, context.stateRoot, request, context.runner)).rejects.toThrow('CREATE_OUTCOME_UNKNOWN');
    const pending = await (await PlatformJournal.open(context.stateRoot, guard)).pending(); expect(pending).toHaveLength(1); expect(pending[0]).toMatchObject({ phase: 'initialized', lifecycle_revision: 2, pending_create: 'loader' });
    await expect(recoverPlatformJobs(context.runtime, context.image, guard, context.stateRoot, context.runner)).rejects.toThrow('PLATFORM_CREATE_OUTCOME_UNKNOWN');
  }));

  it('recovers a lost create response and distinguishes stable gaps from pending requests', async () => fixture(async context => {
    context.failCreate('after');
    await expect(runPlatformWorker(context.runtime, context.image, guard, context.stateRoot, { operation: 'validation_report', arguments: { working_tree_path: context.workingTree, file_paths: ['a.conllu'] }, workingTree: context.workingTree, allowedRoots: [context.workingTree], filePaths: ['a.conllu'], options: {} }, context.runner)).rejects.toThrow('PLATFORM_CREATE_OUTCOME_UNKNOWN');
    const journal = await PlatformJournal.open(context.stateRoot, guard); const pending = await journal.pending(); expect(pending).toHaveLength(1);
    expect((await recoverPlatformJobs(context.runtime, context.image, guard, context.stateRoot, context.runner)).recovered).toEqual([pending[0]!.id]); expect(context.containers.size).toBe(0); expect(await journal.pending()).toEqual([]);
    const id = '11111111-1111-4111-8111-111111111111';
    await journal.create({ schema_version: 1, lifecycle_revision: 2, id, provider: 'lima-nerdctl', authority: platformAuthorityIdentity(context.runtime), image: context.image.digest, phase: 'planned' });
    await journal.transition(id, 'volume'); await journal.transition(id, 'initialized');
    expect((await recoverPlatformJobs(context.runtime, context.image, guard, context.stateRoot, context.runner)).recovered).toEqual([id]); expect(await journal.pending()).toEqual([]);
  }));
});
