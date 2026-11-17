/** Deterministic grading of broker-observed workflow results and side effects. */
import { lstatSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, safeRelative, sha256 } from '../release/candidate.mjs';

const DIGEST = /^[0-9a-f]{64}$/;
const MAX_FILES = 100_000;
const MAX_BYTES = 2 * 1024 * 1024 * 1024;

function canonicalFiles(files) {
  return [...files].map(({ path: name, sha256: digest, size, mode }) => ({ path: name, sha256: digest, size, mode }))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
function canonicalDirs(directories) {
  return [...directories].map(({ path: name, mode }) => ({ path: name, mode }))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
function snapshotDigest(files, directories, rootMode) {
  return sha256(Buffer.from(JSON.stringify({ files: canonicalFiles(files), directories: canonicalDirs(directories), root_mode: rootMode })));
}

function captureOnce(root) {
  const rootInfo = lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('WORKSPACE_ROOT_UNSAFE');
  const files = [];
  const directories = [];
  let bytes = 0;
  function walk(relative) {
    if (relative.split('/').length > 128) throw new Error('WORKSPACE_SNAPSHOT_LIMIT');
    const directory = relative ? path.join(root, ...relative.split('/')) : root;
    for (const name of readdirSync(directory).sort()) {
      if (!name || name.includes('/') || name.includes('\\') || name === '.' || name === '..') throw new Error('WORKSPACE_NAME_UNSAFE');
      const next = relative ? `${relative}/${name}` : name;
      safeRelative(next);
      const item = path.join(directory, name);
      const info = lstatSync(item);
      if (info.isSymbolicLink()) throw new Error('WORKSPACE_SYMLINK_UNSUPPORTED');
      if (info.isDirectory()) {
        if (directories.length >= MAX_FILES) throw new Error('WORKSPACE_SNAPSHOT_LIMIT');
        directories.push({ path: next, mode: info.mode & 0o777 });
        walk(next);
      }
      else if (info.isFile()) {
        if (files.length >= MAX_FILES || bytes + info.size > MAX_BYTES) throw new Error('WORKSPACE_SNAPSHOT_LIMIT');
        const receipt = fileReceipt(root, next);
        const confirmed = lstatSync(item);
        if (!confirmed.isFile() || confirmed.isSymbolicLink() || confirmed.dev !== info.dev || confirmed.ino !== info.ino || confirmed.mode !== info.mode || confirmed.size !== info.size || confirmed.mtimeMs !== info.mtimeMs || confirmed.ctimeMs !== info.ctimeMs) throw new Error('WORKSPACE_CHANGED_DURING_CAPTURE');
        bytes += receipt.size;
        if (bytes > MAX_BYTES) throw new Error('WORKSPACE_SNAPSHOT_LIMIT');
        files.push({ path: next, sha256: receipt.sha256, size: receipt.size, mode: info.mode & 0o777 });
      } else throw new Error('WORKSPACE_SPECIAL_FILE_UNSUPPORTED');
    }
  }
  walk('');
  const sorted = canonicalFiles(files);
  const sortedDirs = canonicalDirs(directories);
  const rootMode = rootInfo.mode & 0o777;
  return { schema_version: 1, files: sorted, directories: sortedDirs, root_mode: rootMode,
    sha256: snapshotDigest(sorted, sortedDirs, rootMode) };
}

/** Called by an authorized test harness before/after the workflow. */
export function captureWorkspace(root) {
  const first = captureOnce(root);
  const second = captureOnce(root);
  if (first.sha256 !== second.sha256) throw new Error('WORKSPACE_CHANGED_DURING_CAPTURE');
  return second;
}

function validSnapshot(snapshot) {
  if (!snapshot || snapshot.schema_version !== 1 || !Array.isArray(snapshot.files) || !Array.isArray(snapshot.directories) || !Number.isInteger(snapshot.root_mode) || snapshot.root_mode < 0 || snapshot.root_mode > 0o777 || !DIGEST.test(snapshot.sha256 ?? '')) return false;
  const names = new Set();
  try {
    for (const item of snapshot.files) {
      if (!item || typeof item !== 'object' || !DIGEST.test(item.sha256 ?? '') || !Number.isSafeInteger(item.size) || item.size < 0 || !Number.isInteger(item.mode) || item.mode < 0 || item.mode > 0o777 || names.has(item.path)) return false;
      safeRelative(item.path);
      names.add(item.path);
    }
    for (const item of snapshot.directories) {
      if (!item || typeof item !== 'object' || !Number.isInteger(item.mode) || item.mode < 0 || item.mode > 0o777 || names.has(item.path)) return false;
      safeRelative(item.path);
      names.add(item.path);
    }
  } catch { return false; }
  return snapshotDigest(snapshot.files, snapshot.directories, snapshot.root_mode) === snapshot.sha256;
}

function jsonPointer(value, pointer) {
  if (typeof pointer !== 'string' || (pointer && !pointer.startsWith('/'))) throw new Error('INVALID_JSON_POINTER');
  if (!pointer) return value;
  let current = value;
  for (const token of pointer.slice(1).split('/')) {
    if (/~(?![01])/.test(token)) throw new Error('INVALID_JSON_POINTER');
    const key = token.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, key)) throw new Error('JSON_POINTER_MISSING');
    current = current[key];
  }
  return current;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalJson(value[key])]));
  return value;
}

/**
 * Compare independent expected values with actual files and broker observations.
 * The instrumentation's completeness must be established by the calling harness;
 * this grader never turns a missing or incomplete observation into a pass.
 */
export function gradeWorkflow({ workspaceRoot, artifactRoot, before, observation, outcome, expected }) {
  const diagnostics = [];
  const fail = code => diagnostics.push(code);
  if (!validSnapshot(before)) fail('BASELINE_INVALID');
  const observationSource = observation?.source === 'broker' || observation?.source === 'mcp-client';
  if (!observationSource || observation.complete !== true || !Array.isArray(observation.events)) fail('OBSERVATION_INCOMPLETE');
  if (!expected || typeof expected !== 'object' || !outcome || typeof outcome !== 'object') return { passed: false, diagnostics: [...diagnostics, 'INVALID_GRADE_INPUT'] };
  if (typeof expected.execution_status !== 'string' || outcome.execution?.status !== expected.execution_status) fail('EXECUTION_STATUS_MISMATCH');
  if (Object.hasOwn(expected, 'passed') && (typeof expected.passed !== 'boolean' || outcome.result?.passed !== expected.passed)) fail('DOMAIN_OUTCOME_MISMATCH');
  const assertions = expected.assertions;
  if (!Array.isArray(assertions)) fail('ASSERTIONS_MISSING');
  else if (!assertions.length && !Object.hasOwn(expected, 'passed')) fail('DOMAIN_EXPECTATION_MISSING');
  else for (const assertion of assertions) {
    try {
      if (!assertion || typeof assertion.pointer !== 'string' || !Object.hasOwn(assertion, 'value') || JSON.stringify(canonicalJson(jsonPointer(outcome, assertion.pointer))) !== JSON.stringify(canonicalJson(assertion.value))) fail(`ASSERTION_MISMATCH:${assertion?.pointer ?? '<invalid>'}`);
    } catch { fail(`ASSERTION_MISMATCH:${assertion?.pointer ?? '<invalid>'}`); }
  }
  const allowedWrites = new Set();
  if (!Array.isArray(expected.allowed_writes)) fail('WRITE_POLICY_MISSING');
  else for (const value of expected.allowed_writes) {
    try { safeRelative(value); if (allowedWrites.has(value)) fail(`DUPLICATE_WRITE_POLICY:${value}`); allowedWrites.add(value); }
    catch { fail('WRITE_POLICY_INVALID'); }
  }
  let after;
  try { after = captureWorkspace(workspaceRoot); } catch { fail('WORKSPACE_CAPTURE_FAILED'); }
  if (after && validSnapshot(before)) {
    if (before.root_mode !== after.root_mode) fail('UNEXPECTED_WORKSPACE_ROOT_MODE');
    const old = new Map([...before.files, ...before.directories].map(item => [item.path, item]));
    const now = new Map([...after.files, ...after.directories].map(item => [item.path, item]));
    for (const name of new Set([...old.keys(), ...now.keys()])) {
      if ((old.has(name) !== now.has(name) || old.get(name)?.sha256 !== now.get(name)?.sha256 || old.get(name)?.size !== now.get(name)?.size || old.get(name)?.mode !== now.get(name)?.mode) && !allowedWrites.has(name)) fail(`UNEXPECTED_WORKSPACE_CHANGE:${name}`);
    }
  }
  const policyArrays = [expected.required_tools, expected.allowed_tools, expected.allowed_processes];
  if (policyArrays.some(items => !Array.isArray(items) || items.some(item => typeof item !== 'string' || !item) || new Set(items).size !== items.length) || typeof expected.allow_network !== 'boolean' || (Array.isArray(expected.required_tools) && Array.isArray(expected.allowed_tools) && expected.required_tools.some(name => !expected.allowed_tools.includes(name)))) fail('ACTION_POLICY_MISSING');
  else if (observation?.complete === true && observationSource && Array.isArray(observation.events)) {
    const seen = new Set();
    for (const event of observation.events) {
      if (!event || typeof event !== 'object' || typeof event.type !== 'string') { fail('INVALID_ACTION_EVENT'); continue; }
      if (event.type === 'tool_call') {
        if (typeof event.name !== 'string' || !expected.allowed_tools.includes(event.name)) fail(`UNEXPECTED_TOOL:${event.name ?? '<invalid>'}`);
        else seen.add(event.name);
      } else if (event.type === 'network') {
        if (!expected.allow_network) fail('UNEXPECTED_NETWORK');
      } else if (event.type === 'process') {
        if (typeof event.name !== 'string' || !expected.allowed_processes.includes(event.name)) fail(`UNEXPECTED_PROCESS:${event.name ?? '<invalid>'}`);
      } else if (event.type === 'file_write') {
        try { safeRelative(event.path); if (!allowedWrites.has(event.path)) fail(`UNEXPECTED_WRITE_EVENT:${event.path}`); }
        catch { fail('INVALID_WRITE_EVENT'); }
      } else fail(`UNKNOWN_ACTION_EVENT:${event.type}`);
    }
    for (const name of expected.required_tools) if (typeof name !== 'string' || !seen.has(name)) fail(`REQUIRED_TOOL_MISSING:${name}`);
  }
  if (!Array.isArray(expected.artifacts) || !Array.isArray(outcome.artifacts)) fail('ARTIFACT_INVENTORY_MISSING');
  else {
    let artifactRootSafe = expected.artifacts.length === 0;
    if (!artifactRootSafe) {
      try { const info = lstatSync(artifactRoot); artifactRootSafe = info.isDirectory() && !info.isSymbolicLink(); }
      catch { artifactRootSafe = false; }
      if (!artifactRootSafe) fail('ARTIFACT_ROOT_UNSAFE');
    }
    const reported = new Map();
    for (const item of outcome.artifacts) {
      if (!item || typeof item.path !== 'string' || reported.has(item.path)) { fail('ARTIFACT_INVENTORY_INVALID'); continue; }
      reported.set(item.path, item);
    }
    const expectedNames = new Set();
    for (const item of expected.artifacts) {
      if (!item || typeof item.path !== 'string' || expectedNames.has(item.path) || !DIGEST.test(item.sha256 ?? '') || !Number.isSafeInteger(item.size) || item.size < 0) { fail('EXPECTED_ARTIFACT_INVALID'); continue; }
      expectedNames.add(item.path);
      const report = reported.get(item.path);
      if (!report || report.sha256 !== item.sha256 || report.size !== item.size) fail(`ARTIFACT_REPORT_MISMATCH:${item.path}`);
      try {
        if (!artifactRootSafe) throw new Error('ARTIFACT_ROOT_UNSAFE');
        const actual = fileReceipt(artifactRoot, item.path);
        if (actual.sha256 !== item.sha256) fail(`ARTIFACT_HASH_MISMATCH:${item.path}`);
        if (actual.size !== item.size) fail(`ARTIFACT_SIZE_MISMATCH:${item.path}`);
      } catch { fail(`ARTIFACT_UNREADABLE:${item.path}`); }
    }
    for (const name of reported.keys()) if (!expectedNames.has(name)) fail(`UNEXPECTED_ARTIFACT:${name}`);
  }
  return { passed: diagnostics.length === 0, diagnostics, coverage: { workspace_files: after?.files.length ?? 0,
    events: Array.isArray(observation?.events) ? observation.events.length : null,
    artifacts: Array.isArray(expected.artifacts) ? expected.artifacts.length : null },
    limitations: ['Side-effect coverage depends on the calling harness providing complete broker instrumentation.',
      'Workspace capture is sequential and cannot guarantee an atomic snapshot against uncooperative writers.'] };
}
