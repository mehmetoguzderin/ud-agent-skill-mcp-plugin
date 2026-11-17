import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { guardedIdentity, guardedRead } from '../../workspace/src/guard.js';
import type { Snapshot } from '../../workspace/src/snapshot.js';
import { captureValidationSnapshot, verifySnapshotIntegrity } from '../../workspace/src/snapshot.js';
import { runCommand } from './command.js';
import { JobJournal } from './job-journal.js';
import { inspectPodmanJob, podmanCreateArgs, podmanLocalMode, validatePodmanOciSpec } from './podman.js';
import type { PodmanJob } from './podman.js';
import { readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import type { ImageReceipt } from './receipt.js';
import { verifyEmptyPodmanMounts, verifyIsolatedPodmanConfig } from './podman-config.js';
import { validateLiveProbeOutput } from './podman-probe-script.js';
import { probePodmanNoPull } from './podman-no-pull.js';
import { cleanupRootfulSnapshot, stageRootfulSnapshot } from './podman-rootful-staging.js';

type Runner = typeof runCommand;
export type PodmanProbeEvidence = {
  engineSha256: string; imageDigest: string; contextSha256: string; seccompSha256: string;
  graphRoot: string; architecture: 'amd64' | 'arm64'; verifiedAtMs: number;
  containersConfSha256: string; defaultMountsSha256: string;
  workerUid: number; workerGid: number; noNetwork: boolean; noPull: boolean;
  readOnlyRuntime: boolean; readOnlySnapshot: boolean; capabilitiesDropped: boolean;
  seccompEnforced: boolean; limitsEnforced: boolean; isolatedConfig: boolean; cleanupVerified: boolean;
  /** Absent in older rootless evidence; rootful evidence must explicitly set false. */
  rootless?: boolean;
};
type PodmanValidation = {
  engine: string; engineSha256: string; guard: string; guardSha256: string;
  snapshot: Snapshot; hooksDirectory: string; defaultMountsFile: string; containersConf: string; containersConfSha256: string; seccompProfile: string; seccompSha256: string;
  image: ImageReceipt; expectedEnvironment: string[]; journal: JobJournal;
  files: string[]; validationOptions: Record<string, unknown>; host: { platform: string; arch: 'amd64' | 'arm64' };
  liveProbe?: PodmanProbeEvidence;
  /** Product policy may admit a rootful local engine; no privilege escalation is performed. */
  allowRootful?: boolean;
  signal?: AbortSignal; runner?: Runner;
};

function checkLiveProbe(input: PodmanValidation): PodmanProbeEvidence {
  const probe = input.liveProbe;
  const emptySha = `sha256:${createHash('sha256').update('').digest('hex')}`;
  if (!probe || probe.engineSha256 !== input.engineSha256 || probe.imageDigest !== input.image.digest || probe.contextSha256 !== input.image.contextSha256 || probe.seccompSha256 !== input.seccompSha256 || probe.containersConfSha256 !== input.containersConfSha256 || probe.defaultMountsSha256 !== emptySha || probe.architecture !== input.host.arch || !path.isAbsolute(probe.graphRoot) || !Number.isSafeInteger(probe.verifiedAtMs) || probe.verifiedAtMs > Date.now() || Date.now() - probe.verifiedAtMs > 300_000 || probe.workerUid !== 10001 || probe.workerGid !== 10001 || probe.noNetwork !== true || probe.noPull !== true || probe.readOnlyRuntime !== true || probe.readOnlySnapshot !== true || probe.capabilitiesDropped !== true || probe.seccompEnforced !== true || probe.limitsEnforced !== true || probe.isolatedConfig !== true || probe.cleanupVerified !== true) throw new Error('PODMAN_LIVE_PROBE_REQUIRED: fresh independent runtime and confinement evidence is unavailable.');
  return probe;
}

function decodeJson(data: Buffer, label: string): unknown {
  try { return JSON.parse(data.toString('utf8')); } catch { throw new Error(`${label} returned malformed JSON.`); }
}
function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function ownedContainer(raw: unknown, name: string, expectedDigest: string): string | undefined {
  const item = Array.isArray(raw) && raw.length === 1 ? record(raw[0]) : undefined;
  const config = record(item?.Config); const labels = record(config?.Labels);
  return item && typeof item.Id === 'string' && /^[0-9a-f]{64}$/.test(item.Id) && item.Name === name && item.ImageDigest === expectedDigest && labels?.['io.ud-agent.job'] === name ? item.Id : undefined;
}
function successful(result: { code: number }, description: string): void { if (result.code !== 0) throw new Error(`${description} failed.`); }

async function cleanupOwnedPodmanJob(journal: JobJournal, job: PodmanJob, engine: string, configFile: string, runner: Runner, knownId?: string): Promise<void> {
  const current = await journal.load(job.name);
  if ((current.engine_mode ?? 'rootless') !== (job.engineMode ?? 'rootless')) throw new Error('PODMAN_CLEANUP_UNVERIFIED: engine mode differs from the journal.');
  if (current.phase === 'cleaned') return;
  const pending = current.phase === 'cleanup_pending' ? current : await journal.transition(job.name, 'cleanup_pending', knownId);
  const short = { timeoutMs: 10_000, maxOutputBytes: 1024 * 1024, containersConf: configFile };
  const exists = await runner(engine, ['--remote=false', 'container', 'exists', job.name], short);
  if (exists.code === 1) {
    if (job.engineMode === 'rootful') await cleanupRootfulSnapshot(journal, job.name);
    await journal.transition(job.name, 'cleaned'); return;
  }
  if (exists.code !== 0) throw new Error('PODMAN_CLEANUP_UNVERIFIED: could not determine whether the owned job exists.');
  const inspect = await runner(engine, ['--remote=false', 'container', 'inspect', job.name], short);
  successful(inspect, 'Podman ownership inspection');
  const id = ownedContainer(decodeJson(inspect.stdout, 'Podman inspection'), job.name, job.image.digest);
  if (!id || (pending.container_id !== undefined && id !== pending.container_id)) throw new Error('PODMAN_CLEANUP_UNVERIFIED: job identity does not match.');
  await runner(engine, ['--remote=false', 'container', 'stop', '--time=2', id], short);
  const remove = await runner(engine, ['--remote=false', 'container', 'rm', '--force', id], short);
  successful(remove, 'Podman owned container removal');
  const after = await runner(engine, ['--remote=false', 'container', 'exists', id], short);
  if (after.code !== 1) throw new Error('PODMAN_CLEANUP_UNVERIFIED: container removal is not confirmed.');
  if (job.engineMode === 'rootful') await cleanupRootfulSnapshot(journal, job.name);
  await journal.transition(job.name, 'cleaned', id);
}

/** Retry exact owned-container cleanup; an interrupted create without an ID remains unresolved. */
export async function recoverPodmanJob(journal: JobJournal, job: PodmanJob, engine: string, engineSha256: string, configFile: string, configSha256: string, runner: Runner = runCommand): Promise<void> {
  const existing = await journal.load(job.name);
  if (existing.engine_sha256 !== engineSha256 || existing.image_digest !== job.image.digest) throw new Error('Recovery engine or image identity differs from the journal.');
  if (existing.phase === 'cleaned') return;
  if (existing.phase === 'planned' && !existing.container_id) throw new Error('PODMAN_CREATE_OUTCOME_UNKNOWN: manual reconciliation is required.');
  await verifyArchive(engine, engineSha256);
  await verifyIsolatedPodmanConfig(configFile, configSha256);
  await cleanupOwnedPodmanJob(journal, job, engine, configFile, runner, existing.container_id);
}

/**
 * Low-level Linux validation transport. Callers must first establish product
 * receipt and host-profile acceptance. This method is not wired to MCP until
 * genuine cross-platform image, isolation, and recovery acceptance exists.
 */
async function executePodman(input: PodmanValidation, purpose: 'validation' | 'probe'): Promise<{ result: Record<string, unknown>; graphRoot: string; rootless: boolean }> {
  if (input.host.platform !== 'linux' || (input.host.arch !== 'arm64' && input.host.arch !== 'amd64')) throw new Error('Podman validation transport requires a native supported Linux host.');
  if (typeof process.getuid !== 'function' || (process.getuid() === 0 && input.allowRootful !== true)) throw new Error('The coordinator must run as a nonroot user unless an explicit rootful policy is selected.');
  if (!path.isAbsolute(input.engine) || !path.isAbsolute(input.guard) || !/^sha256:[0-9a-f]{64}$/.test(input.seccompSha256)) throw new Error('Invalid trusted runtime identity.');
  const liveProbe = purpose === 'validation' ? checkLiveProbe(input) : undefined;
  const runner = input.runner ?? runCommand;
  await verifyArchive(input.engine, input.engineSha256);
  await verifyArchive(input.guard, input.guardSha256);
  await verifyIsolatedPodmanConfig(input.containersConf, input.containersConfSha256);
  await verifyEmptyPodmanMounts(input.defaultMountsFile);
  const profileBytes = await readBoundedReceiptBytes(input.seccompProfile);
  if (`sha256:${createHash('sha256').update(profileBytes).digest('hex')}` !== input.seccompSha256) throw new Error('Seccomp profile differs from the frozen product policy.');
  const seccomp = decodeJson(profileBytes, 'Seccomp profile');
  const hooks = await lstat(input.hooksDirectory);
  if (!hooks.isDirectory() || hooks.isSymbolicLink() || (hooks.mode & 0o077) !== 0 || hooks.uid !== process.getuid() || (await readdir(input.hooksDirectory)).length !== 0) throw new Error('Podman hook directory is not a private empty product directory.');
  const snapshot = await lstat(input.snapshot.directory);
  if (!snapshot.isDirectory() || snapshot.isSymbolicLink() || (snapshot.mode & 0o077) !== 0 || snapshot.uid !== process.getuid()) throw new Error('Snapshot directory is not private and user-owned.');
  const verifiedSnapshot = await verifySnapshotIntegrity(input.guard, input.snapshot);
  const available = new Set(input.snapshot.files.filter(file => file.path.endsWith('.conllu')).map(file => file.path));
  if (input.files.length === 0 || input.files.length > 10_000 || new Set(input.files).size !== input.files.length || input.files.some(file => !available.has(file))) throw new Error('Selected CoNLL-U files do not match the authorized snapshot.');
  if (typeof input.validationOptions.language_code !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/i.test(input.validationOptions.language_code)) throw new Error('An explicit validation language code is required.');
  const permitted = new Set(['language_code', 'level', 'coref', 'test_filters', 'exclude_filters']);
  if (Object.keys(input.validationOptions).some(key => !permitted.has(key))) throw new Error('Unsupported validation option.');
  const timeout = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024, containersConf: input.containersConf, ...(input.signal ? { signal: input.signal } : {}) };
  const infoResult = await runner(input.engine, ['--remote=false', 'info', '--format', 'json'], timeout);
  successful(infoResult, 'Podman information');
  const info = decodeJson(infoResult.stdout, 'Podman info');
  const engineMode = podmanLocalMode(info, input.host.arch);
  if (!engineMode) throw new Error('Podman engine mode or native worker architecture is not verified.');
  if (engineMode === 'rootful' && (input.allowRootful !== true || process.getuid() !== 0)) throw new Error('A rootful local Podman engine requires the explicitly selected rootful profile and an already-authorized root context.');
  if (engineMode === 'rootless' && process.getuid() === 0) throw new Error('A rootless Podman engine must run under a nonroot coordinator.');
  if (liveProbe && (liveProbe.rootless ?? true) !== (engineMode === 'rootless')) throw new Error('Podman engine mode changed since the runtime probe.');
  const graphRoot = record(record(info)?.store)?.graphRoot;
  if (typeof graphRoot !== 'string' || !path.isAbsolute(graphRoot)) throw new Error('Podman graph root is not available.');
  const graph = await realpath(graphRoot);
  if (liveProbe && graph !== liveProbe.graphRoot) throw new Error('Podman graph root changed since the runtime probe.');
  const graphStat = await lstat(graph, { bigint: true });
  if (!graphStat.isDirectory() || graphStat.isSymbolicLink() || graphStat.uid !== BigInt(process.getuid())) throw new Error('Podman graph root ownership is not verified.');
  const graphIdentity = await guardedIdentity(input.guard, graph);
  if (graphIdentity.device !== graphStat.dev.toString() || graphIdentity.inode !== graphStat.ino.toString()) throw new Error('Podman graph root changed.');
  const imageResult = await runner(input.engine, ['--remote=false', 'image', 'inspect', input.image.reference], timeout);
  successful(imageResult, 'Podman local image inspection');
  const image = decodeJson(imageResult.stdout, 'Podman image inspection');
  const inspectedImage = Array.isArray(image) && image.length === 1 ? record(image[0]) : undefined;
  if (inspectedImage?.Digest !== input.image.digest || !Array.isArray(inspectedImage.RepoDigests) || !inspectedImage.RepoDigests.includes(input.image.reference)) throw new Error('Local Podman image does not match the immutable receipt.');
  const name = `ud-agent-${randomUUID()}`;
  const job: PodmanJob = { name, snapshotDirectory: engineMode === 'rootful' ? path.join(input.journal.directory, name, 'input') : verifiedSnapshot, hooksDirectory: input.hooksDirectory, defaultMountsFile: input.defaultMountsFile, seccompProfile: input.seccompProfile, image: input.image, expectedEnvironment: input.expectedEnvironment, purpose, engineMode };
  await input.journal.create({ version: 1, name, engine: 'podman', engine_sha256: input.engineSha256, image_digest: input.image.digest, phase: 'planned', engine_mode: engineMode });
  let id: string | undefined; let createReturned = true; let result: Record<string, unknown> | undefined; let failure: unknown;
  try {
    if (engineMode === 'rootful') {
      const staged = await stageRootfulSnapshot(input.journal, name, input.guard, input.snapshot, verifiedSnapshot);
      if (staged !== job.snapshotDirectory) throw new Error('Rootful snapshot staging identity changed.');
    }
    const createArgs = podmanCreateArgs(job);
    // Once creation starts, interruption leaves an unknown container outcome.
    createReturned = false;
    const created = await runner(input.engine, createArgs, timeout);
    createReturned = true;
    successful(created, 'Podman job creation');
    id = created.stdout.toString('utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(id)) { id = undefined; throw new Error('Podman returned an invalid job identity.'); }
    await input.journal.transition(name, 'created', id);
    const inspection = await runner(input.engine, ['--remote=false', 'container', 'inspect', id], timeout);
    successful(inspection, 'Podman job inspection');
    const details = inspectPodmanJob(decodeJson(inspection.stdout, 'Podman inspection'), job, id, graph);
    if (details.failures.length || !details.configPath) throw new Error(`Podman isolation inspection failed: ${details.failures.join(', ')}`);
    const relativeConfig = path.relative(graph, details.configPath);
    const oci = decodeJson(await guardedRead(input.guard, graph, relativeConfig, 1024 * 1024, graphIdentity), 'Podman OCI configuration');
    const violations = validatePodmanOciSpec(oci, job, seccomp);
    if (violations.length) throw new Error(`Podman effective OCI policy failed: ${violations.join(', ')}`);
    await input.journal.transition(name, 'running');
    const request = { operation: 'validation_report', arguments: { working_tree_path: '/work', file_paths: input.files, ud_context_path: '/opt/ud-agent/context/context.json', options: input.validationOptions } };
    const payload = purpose === 'probe' ? Buffer.alloc(0) : Buffer.from(`${JSON.stringify(request)}\n`);
    const started = await runner(input.engine, ['--remote=false', `--hooks-dir=${job.hooksDirectory}`, `--default-mounts-file=${job.defaultMountsFile}`, 'start', '--attach', '--interactive', id], { timeoutMs: 300_000, maxOutputBytes: 16 * 1024 * 1024, input: payload, containersConf: input.containersConf, ...(input.signal ? { signal: input.signal } : {}) });
    successful(started, 'Podman worker');
    const lines = started.stdout.toString('utf8').split('\n').filter(Boolean);
    if (lines.length !== 1) throw new Error('Worker returned an invalid response stream.');
    const decoded = record(decodeJson(Buffer.from(lines[0] ?? ''), 'Worker'));
    if (!decoded || (purpose === 'validation' && typeof decoded.ok !== 'boolean')) throw new Error('Worker returned an invalid response envelope.');
    if (purpose === 'probe') {
      const violations = validateLiveProbeOutput(decoded);
      if (violations.length) throw new Error(`PODMAN_LIVE_PROBE_FAILED: ${violations.join(', ')}`);
    }
    result = decoded;
  } catch (error: unknown) { failure = error; }
  try {
    // If the CLI died while create was in flight, existence alone cannot prove
    // a detached helper will not finish later. Retain the planned journal.
    if (!createReturned) throw new Error('PODMAN_CREATE_OUTCOME_UNKNOWN: manual reconciliation is required.');
    await cleanupOwnedPodmanJob(input.journal, job, input.engine, input.containersConf, runner, id);
  } catch (error: unknown) {
    const reason = error instanceof Error ? error.message : 'unknown cleanup failure';
    throw new Error(`PODMAN_CLEANUP_UNVERIFIED: ${reason}`);
  }
  if (failure) throw failure;
  if (!result) throw new Error('Worker did not return a result.');
  return { result, graphRoot: graph, rootless: engineMode === 'rootless' };
}

/** Validation cannot run without fresh matching evidence; this transport is not exposed to MCP. */
export async function runPodmanValidation(input: PodmanValidation): Promise<Record<string, unknown>> {
  return (await executePodman(input, 'validation')).result;
}

type ProbeInput = Omit<PodmanValidation, 'snapshot' | 'files' | 'validationOptions' | 'liveProbe'> & { tracer: string; tracerSha256: string };

/**
 * Produce preliminary confinement evidence from a private, product-authored
 * fixture. This does not establish release readiness or expose domain execution.
 */
export async function producePodmanProbe(input: ProbeInput): Promise<PodmanProbeEvidence> {
  if (input.host.platform !== 'linux' || (input.host.arch !== 'arm64' && input.host.arch !== 'amd64')) throw new Error('Podman confinement probing requires a native supported Linux host.');
  if (typeof process.getuid !== 'function' || (process.getuid() === 0 && input.allowRootful !== true)) throw new Error('The coordinator must run as a nonroot user unless an explicit rootful policy is selected.');
  await probePodmanNoPull(input);
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-probe-fixture-'));
  let snapshot: Snapshot | undefined;
  try {
    const root = await realpath(fixture);
    await writeFile(path.join(root, 'probe.conllu'), '# sent_id = 1\n# text = word\n1\tword\t_\tX\t_\t_\t0\troot\t_\t_\n\n', { flag: 'wx', mode: 0o600 });
    snapshot = await captureValidationSnapshot(input.guard, root, [root]);
    const { graphRoot, rootless } = await executePodman({ ...input, snapshot, files: ['probe.conllu'], validationOptions: { language_code: 'en' } }, 'probe');
    return { engineSha256: input.engineSha256, imageDigest: input.image.digest, contextSha256: input.image.contextSha256, seccompSha256: input.seccompSha256, graphRoot, rootless, architecture: input.host.arch, verifiedAtMs: Date.now(), containersConfSha256: input.containersConfSha256, defaultMountsSha256: `sha256:${createHash('sha256').update('').digest('hex')}`, workerUid: 10001, workerGid: 10001, noNetwork: true, noPull: true, readOnlyRuntime: true, readOnlySnapshot: true, capabilitiesDropped: true, seccompEnforced: true, limitsEnforced: true, isolatedConfig: true, cleanupVerified: true };
  } finally {
    if (snapshot) await snapshot.cleanup();
    await rm(fixture, { recursive: true, force: true });
  }
}

