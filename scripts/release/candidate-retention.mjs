/** Bounded retention of registered local candidates; never adopts legacy trees. */
import { randomUUID } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, safeRelative, sha256, sourceReceipt, verifyRecordedFile } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';

const marker = '.ud-candidate-owner.json';
const need = (value, message) => { if (!value) throw new Error(message); };
const json = file => JSON.parse(readFileSync(file, 'utf8'));
function paths(root, output) {
  root = path.resolve(root);
  need(realpathSync(root) === root && lstatSync(root).isDirectory(), 'Candidate owner root must be an ordinary real directory.');
  const artifacts = path.join(root, '.artifacts');
  if (!existsSync(artifacts)) mkdirSync(artifacts, { mode: 0o700 });
  need(!lstatSync(artifacts).isSymbolicLink() && lstatSync(artifacts).isDirectory(), 'Candidate artifact root must be an ordinary directory.');
  const storage = path.join(artifacts, 'storage');
  if (!existsSync(storage)) mkdirSync(storage, { mode: 0o700 });
  need(!lstatSync(storage).isSymbolicLink() && lstatSync(storage).isDirectory(), 'Candidate storage registry must be an ordinary directory.');
  if (output !== undefined) {
    output = path.resolve(output);
    const relative = path.relative(artifacts, output), parts = relative.split(path.sep);
    need(relative && !path.isAbsolute(relative) && parts.every(part => part && part !== '..' && part !== '.') && !['storage', '.storage-reservation'].includes(parts[0]), 'Candidate output must be an owned artifact directory outside storage controls.');
    let parent = artifacts;
    for (const part of parts.slice(0, -1)) {
      parent = path.join(parent, part);
      need(!lstatSync(parent).isSymbolicLink() && lstatSync(parent).isDirectory() && realpathSync(parent) === parent, 'Candidate output ancestors must be ordinary real directories.');
      need(!existsSync(path.join(parent, marker)) && !existsSync(path.join(parent, '.ud-storage-owner.json')), 'Candidate output must not be nested inside another owned candidate or scratch tree.');
    }
  }
  return { root, storage, output, registry: path.join(storage, 'candidates.json') };
}
function save(location, state) {
  const temporary = path.join(location.storage, '.candidates-' + randomUUID());
  try {
    const fd = openSync(temporary, 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify(state, null, 2) + '\n'); fsyncSync(fd); }
    finally { closeSync(fd); }
    renameSync(temporary, location.registry);
  } finally { if (existsSync(temporary)) rmSync(temporary); }
}
function owned(location, record) {
  const output = paths(location.root, record.output).output;
  const info = lstatSync(output);
  need(info.isDirectory() && !info.isSymbolicLink() && info.dev === record.device && info.ino === record.inode && info.uid === record.uid, 'Registered candidate directory ownership changed.');
  const file = path.join(output, marker);
  need(!lstatSync(file).isSymbolicLink() && lstatSync(file).isFile() && canonicalJson(json(file)) === canonicalJson(record.owner), 'Registered candidate ownership marker changed.');
  if (record.manifest) need(fileReceipt(output, record.manifest.path).sha256 === record.manifest.sha256, 'Registered candidate manifest changed; refusing cleanup.');
  return output;
}
function compact(record, action) {
  return { output: record.output, id: record.owner.id, action, ...(record.manifest ? { manifest: record.manifest, source_tree_sha256: record.source_tree_sha256, runtime_lock_sha256: record.runtime_lock_sha256, artifact_count: record.artifacts.length, artifacts_sha256: sha256(Buffer.from(canonicalJson(record.artifacts))) } : {}) };
}
function cleanup(location, state) {
  if (!state.cleanup) return;
  const record = state.cleanup;
  need(record.output !== state.current?.output, 'Current candidate cannot be removed.');
  // Save the exact receipt before removing only its reproducible payload.
  state.history = [...state.history, compact(record, 'payload-cleanup-requested')].slice(-16); save(location, state);
  if (lstatSync(record.output, { throwIfNoEntry: false })) rmSync(owned(location, record), { recursive: true });
  state.history[state.history.length - 1].action = 'payload-removed'; state.cleanup = null; save(location, state);
}
function retainCurrent(location, state, receipt, manifest) {
  const previous = state.current;
  state.current = { ...state.active, manifest: receipt, source_tree_sha256: manifest.source_tree_sha256, runtime_lock_sha256: manifest.runtime_lock_sha256, artifacts: manifest.artifacts.map(({ id, path, sha256, size }) => ({ id, path, sha256, size })) };
  state.active = null;
  if (previous) {
    if (previous.output === state.last_passed?.output) {
      // A passing result remains meaningful as compact evidence, but its old
      // payload must not occupy space alongside the new candidate.
      state.last_passed = { ...compact(previous, 'historical-passed'), acceptance_report_sha256: state.last_passed.acceptance_report_sha256 };
    }
    state.cleanup = previous;
  }
  save(location, state); cleanup(location, state); return state.current;
}
function acquireLock(location, lock) {
  try { mkdirSync(lock, { mode: 0o700 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const before = lstatSync(lock), file = path.join(lock, 'owner.json');
    need(before.isDirectory() && !before.isSymbolicLink() && existsSync(file) && !lstatSync(file).isSymbolicLink() && lstatSync(file).size <= 4096, 'Candidate retention lock ownership is ambiguous.');
    const owner = json(file);
    need(owner.root === location.root && Number.isSafeInteger(owner.pid) && owner.pid > 0, 'Candidate retention lock has another owner.');
    let stopped = false;
    try { process.kill(owner.pid, 0); } catch (probe) { if (probe.code === 'ESRCH') stopped = true; else throw probe; }
    need(stopped, 'Candidate retention is already active.');
    const after = lstatSync(lock);
    need(before.dev === after.dev && before.ino === after.ino, 'Candidate retention lock changed during recovery.');
    rmSync(lock, { recursive: true }); mkdirSync(lock, { mode: 0o700 });
  }
  writeFileSync(path.join(lock, 'owner.json'), JSON.stringify({ root: location.root, pid: process.pid }) + '\n', { flag: 'wx', mode: 0o600 });
}
function transaction(root, output, action) {
  const location = paths(root, output), lock = path.join(location.storage, 'candidates.lock');
  acquireLock(location, lock);
  try {
    let state = { schema_version: 1, owner_root: location.root, active: null, current: null, last_passed: null, cleanup: null, history: [] };
    if (existsSync(location.registry)) {
      need(!lstatSync(location.registry).isSymbolicLink() && lstatSync(location.registry).size <= 4 * 1024 ** 2, 'Candidate retention registry is not bounded ordinary data.');
      state = json(location.registry);
      need(state.schema_version === 1 && state.owner_root === location.root && Array.isArray(state.history) && state.history.length <= 16, 'Candidate retention registry has another owner or version.');
    }
    cleanup(location, state);
    // Older registries retained both current and last-passed payloads. Under
    // the bounded policy only the current payload survives; preserve the
    // passing identity and report hash before reclaiming the old owned tree.
    const legacyPassed = state.last_passed;
    if (legacyPassed?.owner && legacyPassed.output !== state.current?.output) {
      state.last_passed = { ...compact(legacyPassed, 'historical-passed'), acceptance_report_sha256: legacyPassed.acceptance_report_sha256 };
      state.cleanup = legacyPassed;
      save(location, state); cleanup(location, state);
    }
    return action(location, state);
  } finally { rmSync(lock, { recursive: true }); }
}

/** Creates one owned output. An incomplete run must be resumed/aborted first. */
export function beginCandidate(root, output) {
  return transaction(root, output, (location, state) => {
    need(state.active === null, 'An owned candidate assembly is incomplete; clean or finish it before starting another.');
    for (const retained of [state.current].filter(Boolean)) need(location.output !== retained.output && !location.output.startsWith(retained.output + path.sep) && !retained.output.startsWith(location.output + path.sep), 'Candidate output overlaps a retained candidate.');
    need(!existsSync(location.output), 'Candidate retention requires a new output; existing trees are never adopted.');
    mkdirSync(location.output, { mode: 0o700 });
    const info = lstatSync(location.output), owner = { schema_version: 1, owner_root: location.root, output: location.output, id: randomUUID() };
    writeFileSync(path.join(location.output, marker), JSON.stringify(owner) + '\n', { flag: 'wx', mode: 0o600 });
    state.active = { output: location.output, device: info.dev, inode: info.ino, uid: info.uid, owner, pid: process.pid };
    try { save(location, state); }
    catch (error) { rmSync(owned(location, state.active), { recursive: true }); throw error; }
    return state.active;
  });
}

/** Call after the existing artifact verifier; assembly is never acceptance. */
export function completeCandidate(root, output, manifest) {
  return transaction(root, output, (location, state) => {
    need(state.active?.output === location.output, 'Candidate completion has no matching owned assembly.');
    owned(location, state.active);
    need(!existsSync(path.join(location.output, 'INCOMPLETE')), 'Incomplete candidate cannot enter retained current state.');
    const receipt = fileReceipt(location.output, 'available-candidate.json');
    need(receipt.size <= 1024 ** 2 && canonicalJson(json(path.join(location.output, receipt.path))) === canonicalJson(manifest), 'Candidate completion manifest differs from its exact stored bytes.');
    need(manifest.qualification === 'available-target-preacceptance' && manifest.status === 'preacceptance_candidate' && manifest.production_ready === false && /^[a-f0-9]{64}$/.test(manifest.source_tree_sha256) && /^[a-f0-9]{64}$/.test(manifest.runtime_lock_sha256), 'Explicit preacceptance candidate identities are required.');
    verifyRecordedFile(location.output, manifest.source_snapshot.receipt);
    need(json(path.join(location.output, manifest.source_snapshot.receipt.path)).sha256 === manifest.source_tree_sha256, 'Candidate source receipt has another source identity.');
    need(fileReceipt(location.output, safeRelative(manifest.runtime_root) + '/runtime/runtime.lock.json').sha256 === manifest.runtime_lock_sha256, 'Candidate runtime lock identity differs.');
    need(Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0 && manifest.artifacts.length <= 1024, 'Candidate artifact inventory is empty or unbounded.');
    for (const artifact of manifest.artifacts) need(safeRelative(artifact.path).startsWith('artifacts/') && /^[a-f0-9]{64}$/.test(artifact.sha256) && Number.isSafeInteger(artifact.size) && artifact.size >= 0, 'Candidate artifact receipt is invalid.');
    return retainCurrent(location, state, receipt, manifest);
  });
}

/** Retain a full development package without promoting it to acceptance. */
export function completeLocalCandidate(root, output, manifest) {
  return transaction(root, output, (location, state) => {
    need(state.active?.output === location.output, 'Candidate completion has no matching owned assembly.');
    owned(location, state.active);
    need(!existsSync(path.join(location.output, 'INCOMPLETE')), 'Incomplete candidate cannot enter retained current state.');
    const receipt = fileReceipt(location.output, 'local-candidate.json');
    need(receipt.size <= 1024 ** 2 && canonicalJson(json(path.join(location.output, receipt.path))) === canonicalJson(manifest), 'Candidate completion manifest differs from its exact stored bytes.');
    need(manifest.schema_version === 1 && manifest.status === 'local_candidate' && manifest.production_ready === false && /^[a-f0-9]{64}$/.test(manifest.source_tree_sha256) && /^[a-f0-9]{64}$/.test(manifest.runtime_lock_sha256), 'Explicit local candidate identities are required.');
    need(sourceReceipt(location.root).sha256 === manifest.source_tree_sha256, 'Local candidate source changed after preparation.');
    need(fileReceipt(location.root, 'runtime/runtime.lock.json').sha256 === manifest.runtime_lock_sha256, 'Local candidate runtime lock identity differs.');
    need(Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0 && manifest.artifacts.length <= 1024, 'Candidate artifact inventory is empty or unbounded.');
    const prefix = path.relative(location.root, location.output).split(path.sep).join('/') + '/', ids = new Set(), files = new Set();
    for (const artifact of manifest.artifacts) {
      need(typeof artifact.id === 'string' && /^[a-z0-9][a-z0-9._-]*$/.test(artifact.id) && !ids.has(artifact.id) && safeRelative(artifact.path).startsWith(prefix) && !files.has(artifact.path), 'Local candidate artifact is duplicated or outside its owned output.');
      verifyRecordedFile(location.root, artifact); ids.add(artifact.id); files.add(artifact.path);
    }
    return retainCurrent(location, state, receipt, manifest);
  });
}

/** Failed/cancelled assembly cleanup; does not delete a completed candidate. */
export function abortCandidate(root, output) {
  return transaction(root, output, (location, state) => {
    need(state.active?.output === location.output, 'Candidate abort has no matching owned assembly.');
    owned(location, state.active); state.cleanup = state.active; state.active = null;
    save(location, state); cleanup(location, state);
  });
}

/** Clean only an exact incomplete candidate; a completed or foreign path is untouched. */
export function abortCandidateIfActive(root, output) {
  return transaction(root, output, (location, state) => {
    if (state.active?.output !== location.output) return false;
    need(Number.isSafeInteger(state.active.pid) && state.active.pid > 0, 'Interrupted candidate has no recorded process identity.');
    let alive = true;
    try { process.kill(state.active.pid, 0); } catch (error) { if (error.code === 'ESRCH') alive = false; else throw error; }
    need(!alive, 'Candidate assembly is still active.');
    if (process.platform !== 'win32') {
      let group = false;
      try { process.kill(-state.active.pid, 0); group = true; } catch (error) { if (error.code !== 'ESRCH') throw error; }
      need(!group, 'Candidate assembly process group is still active.');
    }
    owned(location, state.active); state.cleanup = state.active; state.active = null;
    save(location, state); cleanup(location, state); return true;
  });
}

/** After storage-owner recovery, reclaim an interrupted registered assembly. */
export function recoverAbandonedCandidate(root) {
  const registry = path.join(path.resolve(root), '.artifacts/storage/candidates.json');
  if (!existsSync(registry)) return false;
  return transaction(root, undefined, (location, state) => {
    if (!state.active) return false;
    need(Number.isSafeInteger(state.active.pid) && state.active.pid > 0, 'Interrupted candidate has no recorded process identity.');
    let alive = true;
    try { process.kill(state.active.pid, 0); } catch (error) { if (error.code === 'ESRCH') alive = false; else throw error; }
    need(!alive, 'Candidate assembly is still active.');
    if (process.platform !== 'win32') {
      let group = false;
      try { process.kill(-state.active.pid, 0); group = true; } catch (error) { if (error.code !== 'ESRCH') throw error; }
      need(!group, 'Candidate assembly process group is still active.');
    }
    owned(location, state.active); state.cleanup = state.active; state.active = null;
    save(location, state); cleanup(location, state); return true;
  });
}

/** Only a caller's complete candidate-bound acceptance verifier can set this. */
export function markCandidatePassed(root, output, reportFile, verifyAcceptance) {
  need(typeof verifyAcceptance === 'function', 'A complete candidate acceptance verifier is required.');
  return transaction(root, output, (location, state) => {
    need(state.current?.output === location.output, 'Only the current complete candidate can become last passed.');
    owned(location, state.current);
    const report = fileReceipt(path.dirname(reportFile), path.basename(reportFile));
    need(report.size <= 32 * 1024 ** 2, 'Candidate acceptance report exceeds its bound.');
    const result = verifyAcceptance(json(reportFile), json(path.join(location.output, state.current.manifest.path)), location.output);
    need(result?.verified === true && result.locally_complete === true && result.source_tree_sha256 === state.current.source_tree_sha256 && result.candidate_manifest_sha256 === state.current.manifest.sha256, 'Complete candidate-bound acceptance was not verified.');
    need(fileReceipt(path.dirname(reportFile), path.basename(reportFile)).sha256 === report.sha256, 'Candidate acceptance report changed during verification.');
    const previous = state.last_passed;
    state.last_passed = { ...state.current, acceptance_report_sha256: report.sha256 };
    // Earlier passed candidates retain only their compact identity after a new
    // candidate is assembled; do not treat that receipt as an owned tree.
    if (previous && previous.output !== state.current.output && previous.owner && existsSync(previous.output)) state.cleanup = previous;
    save(location, state); cleanup(location, state); return state.last_passed;
  });
}
