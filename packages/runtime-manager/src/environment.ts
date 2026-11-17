import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { ENGINES, candidateEngines, findExecutable, isEngineSupported, platformPreferred } from './profiles.js';
import type { ConcreteEngine, Engine, Host } from './profiles.js';
import { inspectLocalDocker } from './docker-inspection.js';
import { authorizeWorkspace } from '../../workspace/src/authorization.js';
import { USERSPACE_READ_ONLY_OPERATIONS } from '../../workspace/src/userspace-operations.js';
import { readBoundedReceipt } from './receipt.js';
import { prepareUserspace, repairUserspace, prepareUserspaceRender, resolveUserspaceExecution, userspaceStateRoot, verifyUserspacePack } from './userspace.js';
import type { runCommand } from './command.js';
import type { UserspaceExecution } from './userspace.js';
import { runtimeCatalog } from './runtime-demand.js';
import type { OperationDemand } from './runtime-demand.js';
const userspaceEvidence = new WeakMap<object, UserspaceExecution>();
/** Internal capability; it never appears in the serializable environment result. */
export function verifiedUserspaceExecution(result: object): UserspaceExecution | undefined { return userspaceEvidence.get(result); }

export type CatalogEntry = { id: string; name: string; runtime_pack: string };
export type CheckInput = { working_tree_path?: string; required_tools?: string[]; engine?: Engine; offline?: boolean };
export type SetupInput = CheckInput & { mode?: 'ensure' | 'repair' | 'update' | 'resume'; network?: 'bootstrap_only' | 'offline'; dry_run?: boolean; continuation_token?: string; target_release?: string };
export type OciEngine = Exclude<ConcreteEngine, 'userspace'>;
export type OciInspection = { availability: 'available' | 'unavailable'; rootless: boolean | null; reason: string };
export type OciReadiness = { engine: OciEngine; executable: string; rootless: boolean | null; image_digest: string; context_sha256: string; verification: 'verified'; available_operations: readonly string[]; isolation_model?: string; guest_rootless?: boolean; virtual_machine?: { name: string; fingerprint: string; boot_id: string } };
type OciReadinessCallback = (engine: OciEngine, executable: string, host: Host, requestedTools: readonly string[], control?: { mode: NonNullable<SetupInput['mode']> }) => Promise<OciReadiness | null>;
type OciSetupCallback = (engine: OciEngine, executable: string, host: Host, requestedTools: readonly string[], control?: { mode: NonNullable<SetupInput['mode']> }) => Promise<OciReadiness | null>;
export type RuntimeOptions = { setupMode?: SetupInput['mode']; operationDemand?: OperationDemand; signal?: AbortSignal; autoSetup?: boolean; host?: Host; searchPath?: string; allowedRoots?: readonly string[]; sourceRoot: string; savedEngine?: ConcreteEngine; setupNetwork?: 'bootstrap_only' | 'offline'; appleRunner?: typeof runCommand; dockerRunner?: typeof runCommand; userspaceStateRoot?: string; ociInspection?: (engine: OciEngine, executable: string, host: Host) => Promise<OciInspection>; ociAdmission?: (engine: Exclude<ConcreteEngine, 'userspace'>, executable: string, host: Host) => Promise<boolean>; ociReadiness?: OciReadinessCallback; ociSetup?: OciSetupCallback };

function verifiedOciRecord(value: OciReadiness | null, engine: OciEngine, executable: string, catalog: CatalogEntry[]): OciReadiness | null {
  if (value === null) return null;
  if (!value || value.engine !== engine || value.executable !== executable || value.verification !== 'verified' || (value.rootless !== true && value.rootless !== false && value.rootless !== null) || (engine === 'docker-rootless' && value.rootless !== true) || !/^sha256:[0-9a-f]{64}$/.test(value.image_digest) || !/^sha256:[0-9a-f]{64}$/.test(value.context_sha256) || !Array.isArray(value.available_operations) || value.available_operations.length === 0 || new Set(value.available_operations).size !== value.available_operations.length || value.available_operations.some(name => !catalog.some(item => item.name === name))) throw new Error('INVALID_OCI_READINESS_EVIDENCE');
  if ((value.isolation_model !== undefined && (typeof value.isolation_model !== 'string' || value.isolation_model.length === 0 || value.isolation_model.length > 128)) || (value.guest_rootless !== undefined && typeof value.guest_rootless !== 'boolean') || (value.virtual_machine !== undefined && (!value.virtual_machine || typeof value.virtual_machine !== 'object' || Array.isArray(value.virtual_machine) || ['name', 'fingerprint', 'boot_id'].some(key => typeof (value.virtual_machine as Record<string, unknown>)[key] !== 'string' || !(value.virtual_machine as Record<string, string>)[key] || (value.virtual_machine as Record<string, string>)[key]!.length > 4096)))) throw new Error('INVALID_OCI_READINESS_EVIDENCE');
  return value;
}

function isolationEvidence(value: OciReadiness): Record<string, unknown> {
  return { rootless_verified: value.rootless, worker_uid_verified: true, verification: value.verification, available_operations: value.available_operations, image_digest: value.image_digest, context_sha256: value.context_sha256, ...(value.isolation_model === undefined ? {} : { isolation_model: value.isolation_model }), ...(value.guest_rootless === undefined ? {} : { guest_rootless: value.guest_rootless }), ...(value.virtual_machine === undefined ? {} : { virtual_machine: value.virtual_machine }) };
}

function normalizeTools(input: string[] | undefined, catalog: CatalogEntry[]): string[] {
  const requested = input ?? ['validation_report'];
  if (requested.length === 1 && requested[0] === '*') return catalog.map(tool => tool.name);
  if (requested.length === 0 || requested.includes('*')) throw new Error('required_tools must be nonempty and wildcard must stand alone.');
  const known = new Set(catalog.map(tool => tool.name));
  for (const name of requested) if (!known.has(name)) throw new Error(`Unknown domain tool: ${name}`);
  return [...new Set(requested)];
}

async function regularFileExists(name: string): Promise<boolean> {
  try { return (await lstat(name)).isFile(); }
  catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

async function userspacePackUnavailable(error: unknown, sourceRoot: string): Promise<boolean> {
  const value = error as { code?: unknown; message?: unknown };
  if (value.message === 'USERSPACE_RECEIPT_NOT_FROZEN') return true;
  if (value.code !== 'ENOENT') return false;
  let lock: Record<string, unknown> | undefined;
  try { lock = await readBoundedReceipt(path.join(sourceRoot, 'runtime', 'runtime.lock.json')); }
  catch (lockError: unknown) { if ((lockError as NodeJS.ErrnoException).code !== 'ENOENT') throw lockError; }
  return lock?.state !== 'frozen';
}

export async function checkEnvironment(input: CheckInput, catalog: CatalogEntry[], options: RuntimeOptions): Promise<Record<string, unknown>> {
  catalog = runtimeCatalog(catalog, options.operationDemand);
  const host = options.host ?? { platform: process.platform, arch: process.arch };
  const requested = normalizeTools(input.required_tools, catalog);
  const selection = input.engine ?? 'auto';
  if (!ENGINES.includes(selection)) throw new Error(`Unknown engine: ${selection}`);
  if (input.working_tree_path !== undefined) await authorizeWorkspace(input.working_tree_path, options.allowedRoots ?? []);
  const platformName = host.platform === 'darwin' ? 'macos' : host.platform === 'win32' ? 'windows' : host.platform;
  const base = { requested_tools: requested, platform: { os: platformName, arch: host.arch }, working_tree_changes: [] as string[] };
  if (!platformPreferred(host)) return { ...base, status: 'unsupported_platform', ready: false, missing: ['supported_host_platform'] };
  if (selection !== 'auto' && !isEngineSupported(selection, host)) return { ...base, status: 'unsupported_platform', ready: false, missing: ['selected_engine_unsupported'], runtime: { engine: selection } };
  const searchPath = options.searchPath ?? process.env.PATH ?? '';
  type Candidate = { engine: ConcreteEngine; executable?: string; availability: 'available' | 'unverified' | 'unavailable'; rootless: boolean | null; reason: string };
  const candidates: Candidate[] = [];
  const toCheck = selection === 'auto' ? candidateEngines(host, options.savedEngine) : [selection];
  for (const candidate of toCheck) {
    if (candidate === 'userspace') { candidates.push({ engine: candidate, availability: 'available', rootless: null, reason: 'Uses a product-owned host environment when prepared.' }); continue; }
    const executable = await findExecutable(candidate, host, searchPath);
    if (!executable) { candidates.push({ engine: candidate, availability: 'unavailable', rootless: null, reason: 'Runtime executable is not installed.' }); continue; }
    if (candidate === 'docker' || candidate === 'docker-rootless') {
      const inspection = await inspectLocalDocker(executable, host, options.dockerRunner);
      const available = inspection.status === 'available' && (candidate !== 'docker-rootless' || inspection.rootless === true);
      candidates.push({ engine: candidate, executable, availability: available ? 'available' : 'unavailable', rootless: inspection.rootless, reason: candidate === 'docker-rootless' && inspection.status === 'available' && !inspection.rootless ? 'The selected Docker daemon is not rootless.' : inspection.reason });
    } else if (options.ociInspection) {
      const inspected = await options.ociInspection(candidate, executable, host);
      if (!['available', 'unavailable'].includes(inspected.availability) || ![true, false, null].includes(inspected.rootless) || typeof inspected.reason !== 'string') throw new Error('INVALID_OCI_INSPECTION');
      candidates.push({ engine: candidate, executable, ...inspected });
    } else candidates.push({ engine: candidate, executable, availability: 'unverified', rootless: null, reason: 'Executable exists; runtime availability has not been verified without starting services.' });
  }
  // Explicit choices never silently switch engines. A saved profile is reused
  // when it has not been shown unavailable; otherwise an already responding
  // OCI daemon outranks executable-only hints and the userspace fallback.
  let selected: Candidate | undefined;
  let selectedUserspace: UserspaceExecution | undefined;
  if (selection !== 'auto') selected = candidates[0];
  else {
    let saved = candidates.find(item => item.engine === options.savedEngine && item.availability === 'available');
    // Userspace is always discoverable, but that alone does not mean a saved
    // selection is still usable. Keep it only when its frozen environment is
    // actually ready for all requested operations.
    if (saved?.engine === 'userspace') {
      if (!requested.every(name => USERSPACE_READ_ONLY_OPERATIONS.includes(name))) saved = undefined;
      else {
        // Validate the pack separately: a missing prepared environment permits
        // reselection, while a missing asset under a frozen receipt is damage.
        try { await verifyUserspacePack(options.sourceRoot, host, options.userspaceStateRoot ?? userspaceStateRoot(host)); }
        catch (error: unknown) {
          if (await userspacePackUnavailable(error, options.sourceRoot)) saved = undefined;
          else throw error;
        }
      }
      if (saved) {
        try {
          const prepared = await resolveUserspaceExecution(options.sourceRoot, options.userspaceStateRoot ?? userspaceStateRoot(host), host);
          if (!prepared.packs.includes('core')) throw new Error('Userspace core pack is missing.');
          selectedUserspace = prepared;
        } catch (error: unknown) {
          const value = error as { code?: unknown; message?: unknown };
          if (value.code === 'ENOENT' || value.message === 'USERSPACE_RECEIPT_NOT_FROZEN') saved = undefined;
          else throw error;
        }
      }
    }
    selected = saved ?? candidates.find(item => item.engine !== 'userspace' && item.availability === 'available')
      ?? candidates.find(item => item.engine !== 'userspace' && item.availability === 'unverified')
      ?? candidates.find(item => item.engine === 'userspace');
  }
  if (!selected) return { ...base, status: 'unsupported_platform', ready: false, missing: ['selected_engine_unsupported'], runtime: { engine: selection } };
  let ociReady: OciReadiness | null = null;
  const admittedCandidate = async (candidate: Candidate): Promise<OciReadiness | null> => {
    if (candidate.engine === 'userspace' || !candidate.executable || candidate.availability !== 'available' || !options.ociReadiness) return null;
    const admitted = options.setupMode ? await options.ociReadiness(candidate.engine, candidate.executable, host, requested, { mode: options.setupMode }) : await options.ociReadiness(candidate.engine, candidate.executable, host, requested);
    const ready = verifiedOciRecord(admitted, candidate.engine, candidate.executable, catalog);
    if (ready && (!requested.every(name => ready.available_operations.includes(name)) || ready.rootless !== candidate.rootless)) throw new Error('INVALID_OCI_READINESS_EVIDENCE');
    return ready;
  };
  ociReady = await admittedCandidate(selected);
  if (selection === 'auto' && selected.engine !== 'userspace' && selected.engine !== options.savedEngine && !ociReady) {
    // Reuse a completely admitted available engine before preparing another
    // profile. Explicit choices and usable saved selections retain priority.
    for (const candidate of candidates) {
      if (candidate === selected || candidate.engine === 'userspace') continue;
      const ready = await admittedCandidate(candidate);
      if (ready) { selected = candidate; ociReady = ready; break; }
    }
  }
  // A responding daemon is not an admitted worker adapter. If an already
  // verified userspace environment can execute the request, use it until the
  // selected OCI adapter has its own product/containment evidence. Explicit
  // requests never change engine. Damaged receipts are failures, not a reason
  // to silently use a different runtime.
  if (selection === 'auto' && selected.engine !== 'userspace' && (selected.availability !== 'available' || !options.ociSetup) && requested.every(name => USERSPACE_READ_ONLY_OPERATIONS.includes(name))) {
    const admitted = ociReady !== null || (selected.executable && options.ociAdmission ? await options.ociAdmission(selected.engine, selected.executable, host) : false);
    if (!admitted) {
      try {
        const pack = await verifyUserspacePack(options.sourceRoot, host, options.userspaceStateRoot ?? userspaceStateRoot(host));
        if (pack.packs.includes('core')) selected = { engine: 'userspace', availability: 'available', rootless: null, reason: 'The OCI adapter is not admitted; a verified userspace pack can be prepared or reused.' };
      } catch (error: unknown) {
        if (!(await userspacePackUnavailable(error, options.sourceRoot))) throw error;
      }
    }
  }
  const { engine, executable } = selected;
  const packs = [...new Set(catalog.filter(item => requested.includes(item.name)).map(item => item.runtime_pack))];
  const releaseLock = path.join(options.sourceRoot, 'runtime', 'runtime.lock.json');
  const lockExists = await regularFileExists(releaseLock);
  const missing: string[] = [];
  if (!executable && engine !== 'userspace') missing.push('engine_executable');
  if (selected.availability === 'unavailable' && executable) missing.push('running_local_engine');
  if (!lockExists) missing.push('trusted_runtime_lock');
  else {
    try {
      const lock: unknown = JSON.parse(await readFile(releaseLock, 'utf8'));
      if (!lock || typeof lock !== 'object') missing.push('valid_runtime_lock');
      else missing.push(...packs.map(pack => `${pack}_image_and_verified_context`));
    } catch { missing.push('valid_runtime_lock'); }
  }
  missing.push(...(engine === 'userspace' ? ['verified_private_userspace_environment'] : ['containment_and_worker_uid_probe']));
  const runtime = {
    engine, executable: executable ?? null,
    isolation_model: engine === 'apple-container' ? 'per-container-vm' : engine === 'wslc' ? 'managed-wsl-vm' : engine === 'lima-nerdctl' ? 'lima-vm' : engine === 'userspace' ? 'host-userspace' : 'container-engine',
    rootless_verified: selected.rootless, worker_uid_verified: false, verification: 'not_probed',
    selection_reason: selection !== 'auto' ? 'explicit' : options.savedEngine === engine ? 'saved' : engine === 'userspace' ? (selected.reason.startsWith('The OCI adapter') ? 'no_admitted_oci_engine' : 'no_available_oci_engine') : 'existing_oci_engine',
    availability: selected.availability, availability_reason: selected.reason,
    preferred_engine: platformPreferred(host),
    detected_oci: candidates.filter(item => item.engine !== 'userspace' && item.executable).map(item => ({ engine: item.engine, availability: item.availability, rootless_verified: item.rootless })),
    project_code_allowed: engine !== 'userspace',
  };
  if (ociReady && ociReady.engine === engine) return { ...base, status: 'ready', ready: true, runtime: { ...runtime, ...isolationEvidence(ociReady) }, missing: [], host_prerequisites: [], working_tree_changes: [] };
  if (engine === 'userspace') {
    const supported = [...USERSPACE_READ_ONLY_OPERATIONS];
    const unsupported = requested.filter(name => !supported.includes(name));
    if (unsupported.length) return { ...base, status: 'blocked_by_policy', ready: false, runtime: { ...runtime, available_operations: supported }, missing: ['userspace_operation_not_available'], unsupported_operations: unsupported, host_prerequisites: [], working_tree_changes: [] };
    try {
      const state = options.userspaceStateRoot ?? userspaceStateRoot(host);
      const capability = selectedUserspace ?? await resolveUserspaceExecution(options.sourceRoot, state, host);
      if (!capability.packs.includes('core')) throw new Error('Userspace core pack is missing.');
      if (packs.some(pack => !capability.packs.includes(pack as 'core' | 'render')) || packs.includes('render') && capability.renderReady !== true) throw new Error('USERSPACE_RENDER_PACK_REQUIRED');
      const result = { ...base, status: 'ready', ready: true, runtime: { ...runtime, verification: 'verified_product_pack_and_private_environment', available_operations: supported.filter(name => { const pack = catalog.find(tool => tool.name === name)?.runtime_pack as 'core' | 'render'; return capability.packs.includes(pack) && (pack !== 'render' || capability.renderReady === true); }), runtime_manifest_sha256: capability.manifestSha256 }, missing: [], host_prerequisites: [], working_tree_changes: [] };
      userspaceEvidence.set(result, capability); return result;
    } catch (error: unknown) {
      // A check is observational: missing, damaged, or absent assets are never
      // repaired here. Setup reports the precise failure when requested.
      const value = error as { code?: unknown; message?: unknown };
      if (value.code !== 'ENOENT' && value.message !== 'USERSPACE_RECEIPT_NOT_FROZEN' && value.message !== 'USERSPACE_RENDER_PACK_REQUIRED') return { ...base, status: 'failed', ready: false, runtime, missing: ['valid_userspace_environment'], reason: typeof value.message === 'string' ? value.message : 'Userspace integrity verification failed.', host_prerequisites: [], working_tree_changes: [] };
    }
  }
  return {
    ...base, status: engine === 'userspace' || (executable && selected.availability !== 'unavailable') ? 'setup_needed' : 'needs_host_prerequisite', ready: false, runtime, missing,
    host_prerequisites: engine === 'userspace' || (executable && selected.availability !== 'unavailable') ? [] : [`Make the selected ${engine} runtime available using its provider's documented method.`],
    next_call: { name: 'setup_ud_environment', arguments: {
      ...(input.working_tree_path === undefined ? {} : { working_tree_path: input.working_tree_path }),
      required_tools: requested, engine,
      ...(input.offline ? { network: 'offline' } : {}),
    } },
    footprint_estimate: { available: false, reason: 'No verified size receipt.' },
  };
}

export async function setupEnvironment(input: SetupInput, catalog: CatalogEntry[], options: RuntimeOptions): Promise<Record<string, unknown>> {
  catalog = runtimeCatalog(catalog, options.operationDemand);
  if (options.signal?.aborted) throw new Error('WORKER_CANCELLED');
  const mode = input.mode ?? 'ensure';
  options = { ...options, setupMode: mode };
  if (mode === 'resume' && !input.continuation_token) throw new Error('continuation_token is required for resume.');
  if (mode !== 'resume' && input.continuation_token) throw new Error('continuation_token is only accepted for resume.');
  if (mode === 'update' && !input.target_release) throw new Error('target_release is required for update.');
  if (mode !== 'update' && input.target_release) throw new Error('target_release is only accepted for update.');
  // Select the runtime before inspecting its dependencies. An OCI installation
  // needs its native helper and images; private userspace is verified only when
  // selected. A failed selected-pack verification still propagates unchanged.
  const check = await checkEnvironment(input, catalog, options);
  const actions = [
    'Inspect the selected local engine and verify its isolation profile.',
    'Verify the installed release receipt and required platform-specific worker images.',
    'Verify the immutable context and run UID, isolation, transfer, and validation probes.',
  ];
  if (input.dry_run) return { ...check, dry_run: true, mode, network: input.network ?? 'bootstrap_only', actions, working_tree_changes: [] };
  const runtime = check.runtime as { engine?: unknown; executable?: unknown; rootless_verified?: unknown } | undefined;
  // Only an explicit Lima choice may provision the receipt-bound product-owned
  // VM. Detection remains read-only, and auto selection reuses running OCI.
  const ownedLimaSetup = input.engine === 'lima-nerdctl' && runtime?.engine === 'lima-nerdctl' && typeof runtime.executable === 'string' && options.ociSetup !== undefined;
  if (check.status === 'unsupported_platform' || (check.status === 'needs_host_prerequisite' && !ownedLimaSetup)) return { ...check, mode, actions };
  if (mode === 'resume') return { ...check, status: 'failed', mode, actions, reason: 'No matching authenticated setup continuation is available.' };
  if (mode === 'update' && input.target_release !== '0.1.0-beta.1') return { ...check, status: 'coordinator_upgrade_required', mode, actions, reason: 'Target release is not the installed compatible product release.' };
  const host = options.host ?? { platform: process.platform, arch: process.arch };
  // Try responding OCI providers in the same order as detection. Availability
  // failures may advance to another provider; integrity and containment errors
  // propagate and can never authorize a weaker fallback.
  if ((input.engine ?? 'auto') === 'auto' && options.ociSetup && check.status !== 'failed'
      && !(check.ready === true && (runtime?.engine !== 'userspace' || options.savedEngine === 'userspace'))) {
    const requested = normalizeTools(input.required_tools, catalog);
    for (const engine of candidateEngines(host, options.savedEngine).filter((engine): engine is OciEngine => engine !== 'userspace')) {
      if (options.signal?.aborted) throw new Error('WORKER_CANCELLED');
      const providerCheck = await checkEnvironment({ ...input, engine }, catalog, options);
      const selected = providerCheck.runtime as { executable?: unknown; availability?: unknown; rootless_verified?: unknown } | undefined;
      if (typeof selected?.executable !== 'string' || selected.availability !== 'available') continue;
      const selection_reason = options.savedEngine === engine ? 'saved' : 'existing_oci_engine';
      if (providerCheck.ready === true) return { ...providerCheck, runtime: { ...(providerCheck.runtime as Record<string, unknown>), selection_reason }, mode, actions, reused: true };
      const ready = verifiedOciRecord(await options.ociSetup(engine, selected.executable, host, requested, { mode }), engine, selected.executable, catalog);
      if (!ready) continue;
      if (ready.rootless !== selected.rootless_verified || !requested.every(name => ready.available_operations.includes(name))) throw new Error('INVALID_OCI_READINESS_EVIDENCE');
      return { ...providerCheck, status: 'ready', ready: true, runtime: { ...(providerCheck.runtime as Record<string, unknown>), selection_reason, ...isolationEvidence(ready) }, missing: [], host_prerequisites: [], working_tree_changes: [], mode, actions, reused: false };
    }
    if (runtime?.engine !== 'userspace') {
      const fallback = await setupEnvironment({ ...input, engine: 'userspace' }, catalog, options);
      const selected = fallback.runtime;
      return selected && typeof selected === 'object' && !Array.isArray(selected)
        ? { ...fallback, runtime: { ...selected as Record<string, unknown>, selection_reason: 'no_admitted_oci_engine' } }
        : fallback;
    }
  }
  if (typeof runtime?.engine === 'string' && runtime.engine !== 'userspace' && isEngineSupported(runtime.engine as ConcreteEngine, host) && typeof runtime.executable === 'string' && (check.status !== 'needs_host_prerequisite' || ownedLimaSetup) && options.ociSetup) {
    if (check.ready === true) return { ...check, mode, actions, reused: true };
    const requested = normalizeTools(input.required_tools, catalog);
    if (!options.ociSetup) return { ...check, status: 'blocked_by_policy', ready: false, mode, actions, reason: 'No admitted OCI setup route is available for the requested operations.' };
    const ready = verifiedOciRecord(await options.ociSetup(runtime.engine as OciEngine, runtime.executable, host, requested, { mode }), runtime.engine as OciEngine, runtime.executable, catalog);
    if (!ready) return { ...check, status: 'blocked_by_policy', ready: false, mode, actions, reason: 'Selected runtime and confinement evidence is not available.' };
    if (ready.rootless !== runtime.rootless_verified || !requested.every(name => ready.available_operations.includes(name))) throw new Error('INVALID_OCI_READINESS_EVIDENCE');
    return { ...check, status: 'ready', ready: true, runtime: { ...(check.runtime as Record<string, unknown>), ...isolationEvidence(ready) }, missing: [], host_prerequisites: [], working_tree_changes: [], mode, actions, reused: false };
  }
  if (runtime?.engine === 'userspace') {
    if (check.status === 'blocked_by_policy') return { ...check, mode, actions, reason: 'The requested operation is not available in userspace; project-authored code requires OCI.' };
    try {
      const state = options.userspaceStateRoot ?? userspaceStateRoot(host);
      const prepared = await (mode === 'repair' ? repairUserspace : prepareUserspace)(options.sourceRoot, state, options.searchPath ?? process.env.PATH ?? '', host, input.network ?? 'bootstrap_only', options.signal);
      if (normalizeTools(input.required_tools, catalog).some(name => catalog.find(item => item.name === name)?.runtime_pack === 'render')) await prepareUserspaceRender(prepared.capability, input.network ?? 'bootstrap_only', options.signal);
      const ready = await checkEnvironment({ ...input, engine: 'userspace' }, catalog, options);
      return { ...ready, mode, actions, installer: prepared.installer, reused: prepared.reused, network: input.network ?? 'bootstrap_only' };
    } catch (error: unknown) {
      const value = error as { code?: unknown; message?: unknown };
      const message = typeof value?.message === 'string' ? value.message : 'Userspace preparation failed.';
      const absent = value?.code === 'ENOENT' || message === 'USERSPACE_RECEIPT_NOT_FROZEN' || message === 'USERSPACE_COMPATIBLE_PYTHON_REQUIRED';
      return { ...check, status: absent ? 'needs_host_prerequisite' : 'failed', ready: false, mode, actions, reason: message, network: input.network ?? 'bootstrap_only' };
    }
  }
  // Only an accepted immutable release receipt is authority to acquire/run assets.
  // No unconstrained URLs, user images, or unverified container calls are attempted.
  return { ...check, status: 'blocked_by_policy', mode, actions, reason: 'No verified worker/context acceptance receipt is available for this installation.' };
}
