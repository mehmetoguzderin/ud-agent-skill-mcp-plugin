/** Read only the owned server entry produced by the actual installed connector. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { fileReceipt, safeRelative } from '../release/candidate.mjs';
import assert from 'node:assert/strict';

export function workflowProfile(home, platform = process.platform) {
  const api = platform === 'win32' ? path.win32 : path.posix;
  if (!['darwin', 'linux', 'win32'].includes(platform) || !api.isAbsolute(home)) throw new Error('Workflow profile needs an absolute native home.');
  const env = { HOME: home, USERPROFILE: home, XDG_DATA_HOME: api.join(home, 'data'), XDG_CACHE_HOME: api.join(home, 'cache'), XDG_CONFIG_HOME: api.join(home, 'config'), APPDATA: api.join(home, 'appdata'), LOCALAPPDATA: api.join(home, 'localappdata') };
  const state = platform === 'darwin' ? api.join(home, 'Library', 'Application Support', 'ud-agent', 'userspace') : platform === 'win32' ? api.join(env.LOCALAPPDATA, 'ud-agent', 'data', 'userspace') : api.join(env.XDG_DATA_HOME, 'ud-agent', 'userspace');
  return { env, state };
}

export function verifyWorkflowCleanup(value, engine) {
  if (!value || value.action !== 'owned-runtime' || value.dry_run !== false || !Array.isArray(value.paths) || !Array.isArray(value.providers) || value.providers.some(item => item.status !== 'complete' || !Array.isArray(item.protected_paths) || item.protected_paths.length > 0) || (engine !== 'userspace' && value.providers.length !== 1)) throw new Error('Workflow owned cleanup is incomplete or protected.');
  return value;
}

export function verifyWorkflowQualification(installation, requested = 'candidate') {
  if (!['candidate', 'diagnostic', 'available-target'].includes(requested)) throw new Error('Workflow qualification must be candidate or diagnostic, or explicit available-target.');
  const build = JSON.parse(readFileSync(path.join(installation, 'BUILD-RECEIPT.json'), 'utf8'));
  if (build.qualification !== (requested === 'diagnostic' ? 'local_candidate' : 'preacceptance_candidate')) throw new Error('Workflow payload qualification differs from the explicitly requested evidence scope.');
  if (requested === 'available-target') return { qualification: 'available-target-scripted-replay', acceptance_eligible: false, target_execution_eligible: true };
  return { qualification: requested === 'diagnostic' ? 'diagnostic-scripted-replay-not-final-acceptance' : 'candidate-scripted-replay', acceptance_eligible: requested === 'candidate' };
}

/** Flags only: actual bytes are always verified by the existing runtime reader. */
export function workflowRuntimeInputOptions(requested) {
  if (!['candidate', 'diagnostic', 'available-target'].includes(requested)) throw new Error('Unknown workflow runtime input scope.');
  return { allowDiagnostic: requested === 'diagnostic', allowAvailable: requested === 'available-target' };
}

/** Reconcile an already verified runtime row with the actual installed payload. */
export function verifyWorkflowRuntimeSubject(selected, payload, requested) {
  const expected = { candidate: 'preacceptance-runtime-inputs', diagnostic: 'diagnostic-runtime-inputs', 'available-target': 'available-target-runtime-inputs' }[requested];
  assert.ok(expected, 'Unknown workflow runtime input scope.');
  assert.equal(selected.candidate.qualification, expected, 'Workflow runtime inputs differ from the explicit evidence scope');
  assert.equal(selected.candidate.source_sha256, payload.source_tree_sha256, 'Workflow source differs from its actual installation');
  assert.equal(selected.candidate.runtime_lock_sha256, payload.runtime_lock_sha256, 'Workflow runtime differs from its actual installation');
  assert.ok(Object.values(selected.formats).some(item => item.inventory_sha256 === payload.inventory_sha256), 'Offline inputs must bind this exact original assembled installation.');
  if (requested !== 'available-target') return { offline_inputs: selected.candidate_receipt };
  const binding = selected.available_bindings;
  assert.ok(binding?.verified === true && binding.candidate_bindings_verified === true && binding.material_bindings_verified === true && binding.target_execution_eligible === true && binding.source_replay_performed === false && binding.source_replay_required === true && typeof binding.source_coverage_receipt?.path === 'string' && /^[a-f0-9]{64}$/.test(binding.source_coverage_receipt.sha256 ?? '') && Number.isSafeInteger(binding.source_coverage_receipt.size) && binding.source_coverage_receipt.size > 0, 'Available-target workflow candidate/material byte bindings are missing or have a different replay role.');
  return { offline_inputs: selected.candidate_receipt, available_bindings: binding, source_replay_performed: false, source_replay_required: true, source_coverage_receipt: binding.source_coverage_receipt };
}

export function loadWorkflowHost(root, host) {
  if (!['codex', 'claude', 'gemini'].includes(host)) throw new Error('Workflow host must be codex, claude or gemini.');
  const adapter = JSON.parse(readFileSync(path.join(root, 'evals/adapters', host + '.json'), 'utf8'));
  if (adapter.schema_version !== 1 || adapter.host !== host || !['json', 'toml'].includes(adapter.format) || adapter.model_execution !== 'external-not-run' || typeof adapter.server_key !== 'string' || typeof adapter.connect_host !== 'string') throw new Error('Workflow host adapter is invalid.');
  safeRelative(adapter.configuration); safeRelative(adapter.skills);
  return adapter;
}

export function workflowHostEntry(adapter, workspace, installation, node) {
  const receipt = fileReceipt(workspace, adapter.configuration);
  if (receipt.size > 4 * 1024 * 1024) throw new Error('Workflow host configuration is too large.');
  const text = readFileSync(path.join(workspace, adapter.configuration), 'utf8');
  const document = adapter.format === 'toml' ? parseToml(text) : JSON.parse(text);
  const entry = document?.[adapter.server_key]?.ud;
  if (!entry || typeof entry.command !== 'string' || !path.isAbsolute(entry.command) || !Array.isArray(entry.args) || entry.args.some(item => typeof item !== 'string') || entry.env !== undefined) throw new Error('Generated host entry is not a confined stdio invocation.');
  const suffix = process.platform === 'win32' ? '.exe' : '';
  const native = path.join(installation, 'bin/ud-agent' + suffix), coordinator = path.join(installation, 'lib/coordinator.mjs');
  const expected = entry.command === native ? ['mcp', '--allow-root', workspace] : entry.command === node ? [coordinator, 'mcp', '--allow-root', workspace] : null;
  if (!expected || JSON.stringify(entry.args) !== JSON.stringify(expected)) throw new Error('Generated host entry does not point at the verified candidate and exact workspace.');
  fileReceipt(installation, entry.command === native ? 'bin/ud-agent' + suffix : 'lib/coordinator.mjs');
  return { command: entry.command, args: [...entry.args] };
}
