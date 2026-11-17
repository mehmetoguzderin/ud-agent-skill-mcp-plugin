import { checkEnvironment, setupEnvironment, verifiedUserspaceExecution } from '../../runtime-manager/src/environment.js';
import type { CheckInput, RuntimeOptions, SetupInput } from '../../runtime-manager/src/environment.js';
import type { Contract } from './catalog.js';
import { acquireUserspaceLease, resolveUserspaceExecution, userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { runUserspaceValidation } from './userspace-worker.js';
import { USERSPACE_READ_ONLY_OPERATIONS } from '../../workspace/src/userspace-operations.js';
import { dockerStateRoot } from './docker-readiness.js';
import { providerInspection, providerReadiness, resolveAdmittedProvider, setupProvider } from './provider-runtime.js';
import type { OciEngine } from '../../runtime-manager/src/environment.js';
import { loadSavedSelection, saveSelection, selectionRoot } from '../../runtime-manager/src/selection.js';
import type { ConcreteEngine } from '../../runtime-manager/src/profiles.js';
import { brokerWorkerResult } from './result-broker.js';
import { ResourceStore } from './resources.js';
import type { ResourceReference } from './resources.js';
import { exportWorkerArtifacts } from './export-broker.js';
import { loadNativeGuardReceipt } from '../../runtime-manager/src/receipt.js';
import { decodeWorkerArtifact } from './worker-artifacts.js';
import path from 'node:path';
import { prepareWorkerContexts, resolveContextResource } from './context-broker.js';
import { setupContinuation } from './setup-continuation.js';
import { loadCompletedPlanBatches, MutationRecovery, verifyDependencyContexts } from './mutation-recovery.js';
import { withCompletedPlanBatches } from '../../workspace/src/plan-completions.js';
import { operationCoverage, operationResourceKind, operationScope } from './operation-evidence.js';
import { resolveProductGuard } from './docker-authority.js';
import { openEvaluationOperation } from './eval-observer.js';
import { summarizeOperationResult } from './result-summary.js';
import { rejectionGuidance } from './skill-routes.js'; import { absoluteFileArguments, quotedEmptyContextArguments, relativeWorkspaceArguments, workspaceFileArguments } from '../../workspace/src/authorization.js';

const VERSION = '0.1.0-beta.1';

type Evidence = { scope?: Record<string, unknown>; inputs?: Record<string, unknown>; provenance?: Record<string, unknown>; diagnostics?: unknown[]; artifacts?: ResourceReference[]; coverage?: Record<string, unknown>; limitations?: string[] };

function candidateValidationOptions(args: Record<string, unknown>): Record<string, unknown> | undefined {
  const edit = args.edit_options && typeof args.edit_options === 'object' ? args.edit_options as Record<string, unknown> : {};
  const options = args.options && typeof args.options === 'object' && !Array.isArray(args.options) ? args.options as Record<string, unknown> : {};
  const configured = edit.validation_options ?? options.validation_options ?? args.options;
  if (!configured || typeof configured !== 'object' || Array.isArray(configured)) return undefined;
  const source = configured as Record<string, unknown>;
  if (typeof source.language_code !== 'string' || !source.language_code) return undefined;
  return Object.fromEntries(Object.entries(source).filter(([key]) => ['language_code', 'level', 'coref', 'test_filters', 'exclude_filters', 'check_families', 'repository_name'].includes(key)));
}

function workerArguments(args: Record<string, unknown>): Record<string, unknown> {
  const value = { ...args };
  if (args.options && typeof args.options === 'object' && !Array.isArray(args.options)) {
    const { output_conflict_policy: _conflict, idempotency_key: _key, validation_options: _validation, ud_context_path: context, ...options } = args.options as Record<string, unknown>;
    if (value.ud_context_path === undefined && context !== undefined) value.ud_context_path = context;
    if (Array.isArray(options.check_families) && options.check_families.some(value => value === 'repository' || value === 'documentation') && options.repository_name === undefined && typeof args.working_tree_path === 'string') options.repository_name = args.working_tree_path.split(/[\\/]/).filter(Boolean).at(-1);
    value.options = options;
  }
  return value;
}

function formatResponse(contract: Contract, start: number, result: Record<string, unknown>, failed: boolean, evidence: Evidence = {}) {
  const envelope = {
    schema_version: '1', operation: contract.name, operation_id: contract.id,
    execution: { status: result.status === 'incomplete' ? 'incomplete' : failed ? 'rejected' : 'completed', elapsed_ms: Date.now() - start },
    scope: evidence.scope ?? {}, inputs: evidence.inputs ?? {}, provenance: { product_version: VERSION, ...evidence.provenance }, result,
    diagnostics: evidence.diagnostics ?? [], artifacts: evidence.artifacts ?? [], coverage: evidence.coverage ?? { requested: [], completed: [], skipped: [] }, limitations: evidence.limitations ?? [],
  };
  const summary = summarizeOperationResult(envelope, envelope.execution.status === 'rejected' ? { guidance: rejectionGuidance(contract.name) } : {});
  return { content: [{ type: 'text' as const, text: summary }], structuredContent: envelope, ...(failed ? { isError: true } : {}) };
}

export async function executeOperation(contract: Contract, args: Record<string, unknown>, domain: Contract[], runtimeOptions: RuntimeOptions, signal?: AbortSignal, control?: { selectAllFiles?: boolean; resources?: ResourceStore; progress?: (completed: number, total: number, message: string) => Promise<void>; observe?: (event: { type: 'tool_call'; name: string } | { type: 'tool_result'; name: string; execution: unknown; provenance: unknown }) => void }) {
  const quoted = quotedEmptyContextArguments(args); if (quoted) args = quoted.args;
  const relative = await relativeWorkspaceArguments(args, runtimeOptions.allowedRoots ?? []); if (relative) args = relative.args;
  const start = Date.now(), located = await workspaceFileArguments(args, runtimeOptions.allowedRoots ?? []); if (located) args = located.args;
  // Once a file working_tree_path became its folder, ud_context_path naming that folder repeats the workspace too.
  const requoted = located || relative ? quotedEmptyContextArguments(args) : undefined; if (requoted) args = requoted.args;
  const files = await absoluteFileArguments(args); if (files) args = files.args;
  const notes = [quoted?.note, relative?.note, located?.note, requoted?.note, files?.note].filter((note): note is string => typeof note === 'string');
  const evaluation = await openEvaluationOperation(contract.name, args);
  control?.observe?.({ type: 'tool_call', name: contract.name });
  const response = (item: Contract, began: number, result: Record<string, unknown>, failed: boolean, evidence: Evidence = {}) => formatResponse(item, began, result, failed, notes.length ? { ...evidence, limitations: [...notes, ...(evidence.limitations ?? [])] } : evidence);
  // These are completed coordinator phases, not inferred worker percentages.
  // A revoked request must never publish a successful terminal notification.
  // Delivery is advisory: failure or backpressure cannot replace an actual
  // result or keep a runtime lease indefinitely. An issued SDK send itself is
  // not revocable; its eventual settlement has no effect on the operation.
  let progressDeliveryAvailable = true;
  const progress = async (completed: number, message: string) => {
    if (signal?.aborted) { if (completed < 4) throw new Error('WORKER_CANCELLED'); return; }
    if (!progressDeliveryAvailable || !control?.progress) return;
    let delivery: Promise<void>;
    try { delivery = control.progress(completed, 4, message); }
    catch { progressDeliveryAvailable = false; return; }
    let timer: ReturnType<typeof setTimeout> | undefined, abort: (() => void) | undefined;
    try {
      const delivered = await Promise.race([
        Promise.resolve(delivery).then(() => 'delivered' as const, () => 'unavailable' as const),
        new Promise<'unavailable'>(resolve => { timer = setTimeout(() => resolve('unavailable'), 250); }),
        new Promise<'cancelled'>(resolve => { abort = () => resolve('cancelled'); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort(); }),
      ]);
      if (delivered === 'unavailable') progressDeliveryAvailable = false;
      if (signal?.aborted && completed < 4) throw new Error('WORKER_CANCELLED');
    } finally { if (timer) clearTimeout(timer); if (abort) signal?.removeEventListener('abort', abort); }
  };
  const reject = (error: unknown) => {
    const value = error as { code?: unknown; message?: unknown };
    const code = signal?.aborted ? 'WORKER_CANCELLED' : typeof value?.code === 'string' ? value.code : typeof value?.message === 'string' && /^WORKER_CANCELLED\b/.test(value.message) ? 'WORKER_CANCELLED' : 'REQUEST_REJECTED';
    const message = typeof value?.message === 'string' ? value.message : 'Request rejected.';
    return response(contract, start, { status: 'rejected', reason: message, code }, true);
  };
  const execute = async () => {
  try {
    // Runtime callbacks are coordinator-owned; callers cannot supply evidence.
    const { ociAdmission: _admission, ociReadiness: _readiness, ociSetup: _setup, ociInspection: _inspection, ...suppliedOptions } = runtimeOptions;
    const baseOptions: RuntimeOptions = { ...suppliedOptions, operationDemand: { operation: contract.name, arguments: args }, ...(signal ? { signal } : {}) };
    const selectedHost = baseOptions.host ?? { platform: process.platform, arch: process.arch };
    const stateGuard = process.platform === 'win32' ? (await loadNativeGuardReceipt(baseOptions.sourceRoot, selectedHost)).guard : undefined;
    const saved = baseOptions.savedEngine ?? await loadSavedSelection(selectionRoot(selectedHost, baseOptions.userspaceStateRoot), selectedHost, stateGuard);
    const options: RuntimeOptions = { ...baseOptions,
      ...(saved === undefined ? {} : { savedEngine: saved }),
      ociInspection: (engine, executable, host) => providerInspection(engine, executable, host, baseOptions),
      ociReadiness: (engine, executable, host, requested, control) => providerReadiness(control ? { ...baseOptions, setupMode: control.mode } : baseOptions, engine, executable, host, requested),
      ociSetup: (engine, executable, host, requested, control) => setupProvider({ ...baseOptions, setupMode: control?.mode ?? 'ensure', setupNetwork: args.network === 'offline' || args.offline === true ? 'offline' : 'bootstrap_only' }, engine, executable, host, requested),
    };
    let resourceStore = control?.resources;
    const getResources = async () => resourceStore ??= await ResourceStore.open(`${baseOptions.userspaceStateRoot ?? userspaceStateRoot(selectedHost)}-resources`, baseOptions.allowedRoots ?? [], stateGuard ?? (await resolveProductGuard(baseOptions.sourceRoot, selectedHost)).guard, signal);
    const finish = async (result: Record<string, unknown>, failed: boolean, evidence: Evidence) => {
      const resources = await getResources();
      const artifacts: ResourceReference[] = [];
      const project = async (value: unknown, depth = 0): Promise<unknown> => {
        if (depth > 32) throw new Error('Worker result nesting exceeds its limit.');
        if (Array.isArray(value)) { const output: unknown[] = []; for (const item of value) output.push(await project(item, depth + 1)); return output; }
        if (!value || typeof value !== 'object') return value;
        const item = value as Record<string, unknown>;
        if ((typeof item.relative_path === 'string' || typeof item.filename === 'string') && typeof item.mime_type === 'string' && (typeof item.content_base64 === 'string' || typeof item.content === 'string')) {
          const artifact = decodeWorkerArtifact(item);
          const reference = await resources.put('artifacts', artifact.bytes, artifact.mime, undefined, signal);
          artifacts.push(reference); return { relative_path: artifact.relativePath, ...reference };
        }
        const output: Record<string, unknown> = {}; for (const [key, child] of Object.entries(item)) output[key] = await project(child, depth + 1); return output;
      };
      const managed = await project(result) as Record<string, unknown>;
      const report = await resources.put(operationResourceKind(contract.name, result), Buffer.from(JSON.stringify({ operation: contract.name, result: managed, ...evidence })), 'application/json', undefined, signal);
      if (Buffer.byteLength(JSON.stringify({ result: managed, ...evidence, artifacts })) > 256 * 1024) {
        const summary = { original_status: managed.status ?? 'complete', ...(typeof managed.passed === 'boolean' ? { passed: managed.passed } : {}), incident_count: Array.isArray(result.incidents) ? result.incidents.length : 0, artifact_count: artifacts.length };
        return response(contract, start, { status: result.status === 'incomplete' ? 'incomplete' : 'resource', ...(typeof managed.passed === 'boolean' ? { passed: managed.passed } : {}), report_resource: report, summary }, failed, {
          scope: { report_resource: report, working_tree_path: args.working_tree_path },
          inputs: { snapshot_sha256: evidence.inputs?.snapshot_sha256, report_resource: report },
          provenance: evidence.provenance ?? {}, diagnostics: [], artifacts: [report], coverage: evidence.coverage ?? {},
          limitations: [...(evidence.limitations ?? []), 'The complete result, scope, diagnostics and artifact inventory are in the immutable report resource.'],
        });
      }
      return response(contract, start, { ...managed, report_resource: report }, failed, { ...evidence, artifacts });
    };
    if (contract.name === 'check_ud_environment') {
      await progress(0, 'Checking local runtime readiness');
      const result = await checkEnvironment(args as CheckInput, domain, options);
      return response(contract, start, result, false);
    }
    if (contract.name === 'setup_ud_environment') {
      if (args.mode !== 'resume' && args.continuation_token !== undefined) throw new Error('SETUP_CONTINUATION_REQUIRES_RESUME');
      if (args.mode === 'resume' && args.dry_run === true) throw new Error('SETUP_CONTINUATION_DRY_RUN_INVALID');
      await progress(0, 'Checking runtime setup prerequisites');
      await progress(1, args.dry_run === true ? 'Assessing local runtime setup' : 'Preparing the verified local runtime');
      const result = args.dry_run === true ? await setupEnvironment(args as SetupInput, domain, options) : await setupContinuation(args as SetupInput, baseOptions.sourceRoot, await getResources(), request => setupEnvironment(request, domain, options), signal);
      const selected = result.runtime as { engine?: ConcreteEngine } | undefined;
      if (result.ready === true) await progress(2, 'Local runtime readiness verified');
      if (result.ready === true && selected?.engine && args.dry_run !== true) {
        await progress(3, 'Saving the verified runtime selection');
        await saveSelection(selectionRoot(selectedHost, baseOptions.userspaceStateRoot), selectedHost, selected.engine, stateGuard);
      }
      const failed = result.status === 'blocked_by_policy' || result.status === 'failed';
      return response(contract, start, result, failed);
    }
    await progress(0, 'Checking local runtime readiness');
    await evaluation?.step('check_ud_environment', true);
    let check = await checkEnvironment({
      working_tree_path: args.working_tree_path as string,
      required_tools: [contract.name],
    }, domain, options);
    await evaluation?.observation('runtime_readiness', { stage: 'initial', result: check });
    if (baseOptions.autoSetup === true && check.ready !== true && ['setup_needed', 'needs_host_prerequisite'].includes(check.status as string)) {
      await progress(1, 'Preparing the verified local runtime');
      await evaluation?.step('setup_ud_environment', true);
      const prepared = await setupEnvironment({ working_tree_path: args.working_tree_path as string, required_tools: [contract.name], network: baseOptions.setupNetwork ?? 'bootstrap_only' }, domain, options);
      await evaluation?.observation('runtime_readiness', { stage: 'prepared', result: prepared });
      const selected = prepared.runtime as { engine?: ConcreteEngine } | undefined;
      if (prepared.ready === true && selected?.engine) {
        await saveSelection(selectionRoot(selectedHost, baseOptions.userspaceStateRoot), selectedHost, selected.engine, stateGuard);
        await evaluation?.step('check_ud_environment', true);
        check = await checkEnvironment({ working_tree_path: args.working_tree_path as string, required_tools: [contract.name], engine: selected.engine }, domain, options);
      } else check = prepared;
    }
    await evaluation?.observation('runtime_readiness', { stage: 'final', result: check });
    if (check.ready === true) await progress(2, 'Local runtime readiness verified');
    const contextValue = args.ud_context_path ?? (args.options && typeof args.options === 'object' ? (args.options as Record<string, unknown>).ud_context_path : undefined);
    const contextBundle = check.ready === true && typeof contextValue === 'string' && contextValue.startsWith('ud://') ? await resolveContextResource(args, await getResources()) : undefined;
    const runtime = check.runtime as { engine?: unknown; executable?: unknown } | undefined;
    if (check.ready === true && typeof runtime?.engine === 'string' && runtime.engine !== 'userspace' && typeof runtime.executable === 'string') {
      if (typeof args.working_tree_path !== 'string') throw new Error('A granted absolute working tree is required.');
      if (typeof contextValue === 'string' && contextValue !== '' && !contextValue.startsWith('ud://')) {
        const context = path.resolve(args.working_tree_path, contextValue);
        if (!(baseOptions.allowedRoots ?? []).some(root => { const relative = path.relative(root, context); return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); })) throw new Error('DOCKER_CONTEXT_UNAVAILABLE: the context is outside the authorized grants; retry with ud_context_path empty (no value) for the default context.');
      }
      const host = baseOptions.host ?? { platform: process.platform, arch: process.arch };
      const admitted = await resolveAdmittedProvider(baseOptions, runtime.engine as OciEngine, runtime.executable, host, [contract.name]);
      if (!admitted) throw new Error('DOCKER_READINESS_CHANGED');
      const authority = admitted;
      const provenance = { runtime: runtime.engine, ...(authority.platform ? { runtime_platform: authority.platform } : {}), image_digest: authority.image.digest, context_sha256: authority.image.contextSha256 };
      const mutation = contract.access?.writes_workspace ? await MutationRecovery.open({ operation: contract.name, args, guard: authority.guard, grants: baseOptions.allowedRoots ?? [], stateRoot: `${admitted.stateRoot}-transactions`, provenance, ...(contract.name === 'plan_apply' ? { resources: await getResources() } : {}) }) : undefined;
      try {
      await progress(3, 'Executing the requested operation');
      const replay = await mutation?.replay();
      if (replay && !replay.snapshot) return await finish(replay.result, true, { provenance: replay.provenance });
      const batches = !replay && contract.name === 'plan_apply' ? await loadCompletedPlanBatches({ args, guard: authority.guard, grants: baseOptions.allowedRoots ?? [], stateRoot: `${admitted.stateRoot}-transactions`, resources: await getResources(), ...(signal ? { signal } : {}) }) : [];
      return await withCompletedPlanBatches(batches, async () => {
      const run = (operation: string, selectAll = false) => admitted.run({ workingTree: args.working_tree_path as string, allowedRoots: baseOptions.allowedRoots ?? [], filePaths: (args.file_paths ?? []) as string[], options: (args.options ?? {}) as Record<string, unknown>, operation, arguments: workerArguments(args), ...(contextBundle ? { contextBundle } : {}), ...(signal ? { signal } : {}), ...(control?.selectAllFiles || selectAll ? { selectAllFiles: true } : {}) });
      const executed = replay?.snapshot ? { result: replay.result, snapshot: replay.snapshot } : await run(contract.name === 'project_consistency_report' ? 'validation_report' : contract.name, contract.name === 'project_consistency_report');
      let result = executed.result;
      if (!replay && contract.name === 'project_consistency_report') {
        try {
          await evaluation?.step('project_rules_validation', true);
          const project = await run('_project_rules', true);
          if (project.snapshot.sha256 !== executed.snapshot.sha256) throw new Error('WORKTREE_CHANGED_BETWEEN_VALIDATORS');
          const modulePath = path.resolve(args.working_tree_path as string, args.validator_module_path as string);
          const source = project.snapshot.source_map?.find(item => item.original_path === modulePath)?.snapshot_path ?? args.validator_module_path;
          const fingerprint = project.snapshot.files.find(item => item.path === source);
          if (!fingerprint) throw new Error('PROJECT_CODE_IDENTITY_UNVERIFIED');
          result = { status: 'complete', passed: result.passed === true && project.result.passed === true, official: result, project: project.result, scope: result.scope, incidents: [...(Array.isArray(result.incidents) ? result.incidents : []), ...(Array.isArray(project.result.incidents) ? project.result.incidents : [])], coverage: { ...(result.coverage && typeof result.coverage === 'object' && !Array.isArray(result.coverage) ? result.coverage : {}), official_validation: 'completed', project_rules: 'completed' }, provenance: { validator_module_path: source, validator_class_name: args.validator_class_name, source_sha256: fingerprint.sha256, project_code: { file_path: source, sha256: fingerprint.sha256, size_bytes: fingerprint.size, validator_class_name: args.validator_class_name } }, limitations: ['Official and project-authored validation ran in independent fresh OCI jobs.'] };
        } catch (error: unknown) {
          result = { status: 'incomplete', passed: false, official: result, coverage: { official_validation: 'completed', project_rules: 'incomplete' }, reason: error instanceof Error ? error.message : 'Project validation failed.' };
        }
      }
      if (!replay) {
      result = await prepareWorkerContexts({ operation: contract.name, args, result, guard: authority.guard, grants: baseOptions.allowedRoots ?? [], contextSha256: authority.image.contextSha256, resources: await getResources(), ...(contextBundle ? { contextBundle } : {}) });
      result = await brokerWorkerResult({ operation: contract.name, args, result, snapshot: executed.snapshot, guard: authority.guard, allowedRoots: baseOptions.allowedRoots ?? [], stateRoot: `${admitted.stateRoot}-transactions`, verifyDependencies: async values => verifyDependencyContexts(values, await getResources()), ...(mutation ? { remember: (result, snapshot, dependencies) => mutation.remember(result, snapshot, dependencies), recordValidation: validation => mutation.validated(validation), completePlan: (batch, result) => mutation.completePlan(batch, result) } : {}), ...(contextBundle ? { contextBundle } : {}), ...(signal ? { signal } : {}), validate: async (workingTree, files, stagedContext) => {
        const validationOptions = candidateValidationOptions(args);
        if (!validationOptions) return { completed: false, passed: false, details: { code: 'VALIDATION_LANGUAGE_REQUIRED' } };
        await evaluation?.step('candidate_validation', true);
        const checked = await admitted.run({ operation: 'validation_report', workingTree, allowedRoots: [workingTree, ...(baseOptions.allowedRoots ?? [])], filePaths: files, options: validationOptions, arguments: { working_tree_path: workingTree, file_paths: files, options: validationOptions, ud_context_path: stagedContext ?? contextValue ?? '' }, ...(contextBundle ? { contextBundle } : {}), ...(signal ? { signal } : {}) });
        return { completed: checked.result.status !== 'incomplete' && typeof checked.result.passed === 'boolean', passed: checked.result.passed === true, details: checked.result };
      } });
      }
      result = await exportWorkerArtifacts({ args, result, guard: authority.guard, allowedRoots: baseOptions.allowedRoots ?? [], stateRoot: `${admitted.stateRoot}-exports`, ...(signal ? { signal } : {}) });
      return await finish(result, result.status === 'incomplete', {
        scope: operationScope(result, args, executed.snapshot.files),
        inputs: { working_tree_path: args.working_tree_path, snapshot_sha256: executed.snapshot.sha256, files: executed.snapshot.files, source_mapping: executed.snapshot.source_map ?? [] },
        provenance: replay?.provenance ?? provenance,
        diagnostics: Array.isArray(result.incidents) ? result.incidents : [],
        coverage: operationCoverage(result),
        limitations: Array.isArray(result.limitations) ? result.limitations.filter((value): value is string => typeof value === 'string') : [],
      });
      });
      } finally { await mutation?.release(); }
    }
    if (USERSPACE_READ_ONLY_OPERATIONS.includes(contract.name) && check.ready === true && runtime?.engine === 'userspace') {
      const capability = verifiedUserspaceExecution(check) ?? await resolveUserspaceExecution(runtimeOptions.sourceRoot, runtimeOptions.userspaceStateRoot, runtimeOptions.host);
      const release = await acquireUserspaceLease(capability);
      let mutation: MutationRecovery | undefined;
      try {
        await progress(3, 'Executing the requested operation');
        const provenance = { runtime: 'userspace', runtime_manifest_sha256: capability.manifestSha256, memory_limit_enforced: process.platform === 'linux' || process.platform === 'win32' };
        mutation = contract.access?.writes_workspace ? await MutationRecovery.open({ operation: contract.name, args, guard: capability.guard, grants: baseOptions.allowedRoots ?? [], stateRoot: `${runtimeOptions.userspaceStateRoot ?? dockerStateRoot(baseOptions, selectedHost)}-transactions`, provenance, ...(contract.name === 'plan_apply' ? { resources: await getResources() } : {}) }) : undefined;
        const replay = await mutation?.replay();
        if (replay && !replay.snapshot) return await finish(replay.result, true, { provenance: replay.provenance });
        const batches = !replay && contract.name === 'plan_apply' ? await loadCompletedPlanBatches({ args, guard: capability.guard, grants: baseOptions.allowedRoots ?? [], stateRoot: `${runtimeOptions.userspaceStateRoot ?? dockerStateRoot(baseOptions, selectedHost)}-transactions`, resources: await getResources(), ...(signal ? { signal } : {}) }) : [];
        return await withCompletedPlanBatches(batches, async () => {
        const executed = replay?.snapshot ? { result: replay.result, snapshot: replay.snapshot, memoryLimitEnforced: replay.provenance.memory_limit_enforced === true } : await runUserspaceValidation(capability, { operation: contract.name, arguments: workerArguments(args), ...(contextBundle ? { contextBundle } : {}), allowedRoots: runtimeOptions.allowedRoots ?? [], ...(signal ? { signal } : {}), ...(control?.selectAllFiles ? { selectAllFiles: true } : {}) });
        const preparedResult = replay ? replay.result : await prepareWorkerContexts({ operation: contract.name, args, result: executed.result, guard: capability.guard, grants: baseOptions.allowedRoots ?? [], contextSha256: '', installedContext: capability.contextPath, resources: await getResources(), ...(contextBundle ? { contextBundle } : {}) });
        let result = replay ? replay.result : await brokerWorkerResult({ operation: contract.name, args, result: preparedResult, snapshot: executed.snapshot, guard: capability.guard, installedContext: capability.contextPath, ...(contextBundle ? { contextBundle } : {}), allowedRoots: baseOptions.allowedRoots ?? [], stateRoot: `${runtimeOptions.userspaceStateRoot ?? dockerStateRoot(baseOptions, selectedHost)}-transactions`, verifyDependencies: async values => verifyDependencyContexts(values, await getResources()), ...(mutation ? { remember: (result, snapshot, dependencies) => mutation!.remember(result, snapshot, dependencies), recordValidation: validation => mutation!.validated(validation), completePlan: (batch, result) => mutation!.completePlan(batch, result) } : {}), ...(signal ? { signal } : {}), validate: async (workingTree, files, stagedContext) => {
          const validationOptions = candidateValidationOptions(args);
          if (!validationOptions) return { completed: false, passed: false, details: { code: 'VALIDATION_LANGUAGE_REQUIRED' } };
          await evaluation?.step('candidate_validation', true);
          const checked = await runUserspaceValidation(capability, { operation: 'validation_report', arguments: { working_tree_path: workingTree, file_paths: files, ud_context_path: stagedContext ?? contextValue ?? '', options: validationOptions }, ...(contextBundle ? { contextBundle } : {}), allowedRoots: [workingTree, ...(baseOptions.allowedRoots ?? [])], ...(signal ? { signal } : {}) });
          return { completed: checked.result.status !== 'incomplete' && typeof checked.result.passed === 'boolean', passed: checked.result.passed === true, details: checked.result };
        } });
        result = await exportWorkerArtifacts({ args, result, guard: capability.guard, allowedRoots: baseOptions.allowedRoots ?? [], stateRoot: `${runtimeOptions.userspaceStateRoot ?? dockerStateRoot(baseOptions, selectedHost)}-exports`, ...(signal ? { signal } : {}) });
        const limitations = Array.isArray(result.limitations) ? result.limitations.filter((value): value is string => typeof value === 'string') : [];
        limitations.push('Userspace execution runs as the current user without container isolation.');
        if (!executed.memoryLimitEnforced) limitations.push('A per-process memory limit is not enforced on this host.');
        return await finish(result, result.status === 'incomplete', {
          scope: operationScope(result, args, executed.snapshot.files), inputs: { working_tree_path: args.working_tree_path, snapshot_sha256: executed.snapshot.sha256, files: executed.snapshot.files, source_mapping: executed.snapshot.source_map ?? [] },
          provenance: replay?.provenance ?? provenance,
          diagnostics: Array.isArray(result.incidents) ? result.incidents : [],
          coverage: operationCoverage(result),
          limitations,
        });
        });
      } finally { await mutation?.release(); await release(); }
    }
    return response(contract, start, {
      status: 'incomplete', code: 'ENVIRONMENT_NOT_READY',
      reason: 'A verified isolated worker environment is required.', environment: check,
    }, true);
  } catch (error: unknown) {
    return reject(error);
  }
  };
  const value = await execute();
  // A worker result is terminal only after its finally blocks have released
  // owned leases/journals. Cleanup failure must not be preceded by 100% progress.
  if (!value.isError && value.structuredContent.execution.status === 'completed') {
    const message = contract.name === 'check_ud_environment' ? 'Readiness inquiry completed'
      : contract.name === 'setup_ud_environment' ? value.structuredContent.result.ready === true ? 'Runtime preparation completed' : 'Setup assessment completed'
      : 'Operation completed';
    await progress(4, message);
  }
  control?.observe?.({ type: 'tool_result', name: contract.name, execution: value.structuredContent.execution, provenance: value.structuredContent.provenance });
  await evaluation?.result(value, contract.access?.writes_workspace === true);
  return value;
}
