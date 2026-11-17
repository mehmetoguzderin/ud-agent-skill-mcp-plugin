/** Durable immutable publication reconciliation; fixtures exercise real HTTP transports. */
import { closeSync, constants, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readRecordedBytes, sha256, verifyRecordedFile } from './candidate.mjs';
import { verifyProductionCandidate } from './verify.mjs';
import { assertObjectIdentity, canonicalJson, HttpTransport } from './http-transports.mjs';

const HASH = /^[0-9a-f]{64}$/;
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
function insist(value, message) { if (!value) throw new Error(message); }

class VerifiedPublication {
  #identity;

  constructor(root, bytes, signature) {
    verifyProductionCandidate(root, bytes, signature);
    this.#identity = [root, sha256(bytes), canonicalJson(signature)];
  }

  static assert(verification, root, bytes, signature) {
    const identity = verification instanceof VerifiedPublication ? verification.#identity : undefined;
    insist(identity && identity[0] === root && identity[1] === sha256(bytes) && identity[2] === canonicalJson(signature), 'Publication verification belongs to a different command or candidate.');
  }

  close() { this.#identity = undefined; }
}

/** Share expensive verification only within one invocation of the publisher. */
export async function withVerifiedPublication(root, bytes, signature, operation) {
  const verification = new VerifiedPublication(root, bytes, signature);
  try { return await operation(verification); }
  finally { verification.close(); }
}

export function requireVerifiedPublication(root, bytes, signature, verification) {
  if (verification === undefined) verifyProductionCandidate(root, bytes, signature);
  else VerifiedPublication.assert(verification, root, bytes, signature);
}

function writeAtomic(directory, name, value) {
  const target = path.join(directory, name); const temporary = path.join(directory, `.${name}-${randomUUID()}`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, target); const parent = openSync(directory, constants.O_RDONLY); try { fsyncSync(parent); } finally { closeSync(parent); } }
  finally { rmSync(temporary, { force: true }); }
}

export class PublicationJournal {
  constructor(directory, manifestSha256) {
    insist(path.isAbsolute(directory) && HASH.test(manifestSha256), 'Invalid publication journal identity.');
    let cursor = path.parse(directory).root;
    for (const part of directory.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try { const info = lstatSync(cursor); insist(info.isDirectory() && !info.isSymbolicLink(), 'Publication journal path is unsafe.'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; mkdirSync(cursor, { mode: 0o700 }); }
    }
    const info = lstatSync(directory);
    insist((info.mode & 0o077) === 0 && (typeof process.getuid !== 'function' || info.uid === process.getuid()), 'Publication journal must be private and owned.');
    this.directory = directory; this.manifest = manifestSha256;
  }
  async withLock(operation) {
    // The locked developer interpreter is a release-tooling prerequisite only;
    // installed coordinators never use this helper or discover ambient Python.
    const python = process.env.UD_RELEASE_PYTHON ?? path.join(projectRoot, process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python');
    insist(path.isAbsolute(python), 'Release lock interpreter must be absolute.');
    const lockEnvironment = { PATH: path.dirname(python), LC_ALL: 'C', ...(process.platform === 'win32' && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
    const child = spawn(python, ['-I', '-B', path.join(projectRoot, 'scripts/release/lock_holder.py'), path.join(this.directory, '.lock'), '--timeout', '30'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: lockEnvironment });
    child.stdin.on('error', () => { /* helper failure is reported by completion */ });
    let output = '', errors = '', ready = false, closed = false;
    const completion = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => { closed = true; resolve({ code, signal }); });
    });
    child.stderr.on('data', bytes => { errors += bytes.toString('utf8'); if (errors.length > 8192) child.kill(); });
    const timer = setTimeout(() => child.kill(), 35_000);
    try {
      await new Promise((resolve, reject) => {
        child.stdout.on('data', bytes => {
          output += bytes.toString('utf8');
          if (output.length > 4096) { child.kill(); reject(new Error('Release lock helper output exceeded its bound.')); return; }
          if (!output.endsWith('\n')) return;
          try { const value = JSON.parse(output); insist(value.schema_version === 1 && value.locked === true && value.pid === child.pid, 'Invalid release lock helper response.'); ready = true; resolve(); }
          catch (error) { reject(error); }
        });
        completion.then(result => { if (!ready) reject(new Error(`Release lock failed: ${result.code ?? result.signal}: ${errors}`)); }, reject);
      });
      clearTimeout(timer);
      const result = await operation();
      insist(!closed, 'Release lock holder exited during publication.');
      return result;
    } finally {
      clearTimeout(timer); child.stdin.end();
      const shutdown = setTimeout(() => child.kill(), 5000);
      try { const result = await completion; insist(result.code === 0 && !result.signal, `Release lock holder failed: ${errors}`); }
      finally { clearTimeout(shutdown); }
    }
  }
  load() {
    const filename = path.join(this.directory, 'publication-state.json');
    let data;
    try { const info = lstatSync(filename); insist(info.isFile() && !info.isSymbolicLink() && info.size <= 8 * 1024 * 1024, 'Invalid publication journal file.'); data = JSON.parse(readFileSync(filename, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; return { schema_version: 1, manifest_sha256: this.manifest, revision: 0, targets: {}, channels: {} }; }
    insist(data.schema_version === 1 && data.manifest_sha256 === this.manifest && Number.isSafeInteger(data.revision) && data.revision >= 0 && data.targets && typeof data.targets === 'object' && data.channels && typeof data.channels === 'object', 'Publication journal belongs to a different candidate or format.');
    return data;
  }
  save(data) { insist(data.manifest_sha256 === this.manifest, 'Publication journal identity changed.'); data.revision++; writeAtomic(this.directory, 'publication-state.json', data); }
}

function localAdapter(adapter) {
  return adapter?.http instanceof HttpTransport && ['localhost', '127.0.0.1', '[::1]'].includes(adapter.http.base.hostname);
}
function matching(actual, item) { return actual && actual.sha256 === item.sha256 && actual.size === item.size; }

/**
 * Every nonlocal transport requires genuine production acceptance first. Local
 * HTTP fixtures are explicitly qualified as fixtures and cannot certify a release.
 */
export async function reconcilePublication(root, manifestBytes, signature, targets, adapters, journalDirectory, { attempts = 3, verification = undefined } = {}) {
  insist(Buffer.isBuffer(manifestBytes) && Number.isSafeInteger(attempts) && attempts >= 1 && attempts <= 5, 'Invalid publication request.');
  insist(Array.isArray(targets) && targets.length > 0 && adapters && typeof adapters === 'object', 'Publication targets are required.');
  const fixture = targets.every(item => localAdapter(adapters[item.target]));
  if (!fixture) requireVerifiedPublication(root, manifestBytes, signature, verification);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  insist(Array.isArray(manifest.artifacts), 'Candidate artifact inventory is missing.');
  const artifactMap = new Map(manifest.artifacts.map(item => [item.id, item]));
  insist(artifactMap.size === manifest.artifacts.length, 'Candidate artifact inventory contains duplicates.');
  const seen = new Set();
  for (const item of targets) {
    insist(item && typeof item.target === 'string' && typeof item.coordinate === 'string' && item.coordinate.length > 0 && item.coordinate.length <= 2048 && !/[\0\r\n]/.test(item.coordinate) && typeof item.artifact_id === 'string', 'Invalid immutable publication target.');
    const key = `${item.target}:${item.coordinate}`;
    insist(!seen.has(key) && adapters[item.target] && typeof adapters[item.target].inspect === 'function' && typeof adapters[item.target].publish === 'function' && artifactMap.has(item.artifact_id), 'Duplicate or unsupported immutable publication target.'); seen.add(key);
  }
  const journal = new PublicationJournal(journalDirectory, sha256(manifestBytes));
  return journal.withLock(async () => {
    const ledger = journal.load(); ledger.qualification = fixture ? 'local_http_fixture_only' : 'production';
    for (const item of targets) {
      const key = `${item.target}:${item.coordinate}`, artifact = artifactMap.get(item.artifact_id), adapter = adapters[item.target];
      const streamsArchive = typeof adapter.publishArtifact === 'function';
      const bytes = streamsArchive ? null : readRecordedBytes(root, artifact, 512 * 1024 * 1024);
      if (streamsArchive) { verifyRecordedFile(root, artifact); adapter.verifyArtifact(artifact, root); }
      else assertObjectIdentity(artifact, bytes);
      const previous = ledger.targets[key];
      insist(!previous || (previous.sha256 === artifact.sha256 && previous.size === artifact.size && previous.artifact_id === artifact.id), 'Immutable publication journal conflicts with candidate.');
      ledger.targets[key] = { artifact_id: artifact.id, sha256: artifact.sha256, size: artifact.size, state: previous?.state ?? 'planned' }; journal.save(ledger);
      let verified = false;
      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          let actual = await adapter.inspect(item, artifact.size);
          if (actual) { insist(matching(actual, artifact), `Immutable target conflict: ${key}`); verified = true; break; }
          ledger.targets[key].state = 'publishing'; journal.save(ledger);
          try { if (streamsArchive) await adapter.publishArtifact(item, artifact, root); else await adapter.publish(item, bytes); }
          catch (error) {
            // A disconnected response can follow a successful immutable write.
            // Always read back before deciding whether another write is safe.
            if (!error.transient && error.status !== 409 && error.status !== 422) throw error;
            actual = await adapter.inspect(item, artifact.size);
            if (actual) { insist(matching(actual, artifact), `Immutable target conflict after response loss: ${key}`); verified = true; break; }
            if (!error.transient || attempt + 1 === attempts) throw error;
            continue;
          }
          actual = await adapter.inspect(item, artifact.size);
          if (actual) { insist(matching(actual, artifact), `Published target differs: ${key}`); verified = true; break; }
          if (attempt + 1 === attempts) throw new Error(`Published target did not become visible: ${key}`);
        } catch (error) { if (!error.transient || attempt + 1 === attempts) throw error; }
      }
      insist(verified, `Publication could not verify: ${key}`);
      ledger.targets[key].state = 'verified'; journal.save(ledger);
    }
    return ledger;
  });
}

export async function promotePublication(root, manifestBytes, signature, targets, adapters, journalDirectory, promotions, { attempts = 3, verification = undefined } = {}) {
  insist(Number.isSafeInteger(attempts) && attempts >= 1 && attempts <= 5, 'Invalid promotion retry bound.');
  if (!targets.every(item => localAdapter(adapters[item.target]))) requireVerifiedPublication(root, manifestBytes, signature, verification);
  const journal = new PublicationJournal(journalDirectory, sha256(manifestBytes));
  return journal.withLock(async () => {
    const ledger = journal.load();
    const artifacts = new Map(JSON.parse(manifestBytes.toString('utf8')).artifacts.map(item => [item.id, item]));
    for (const item of targets) {
      const recorded = ledger.targets[`${item.target}:${item.coordinate}`], artifact = artifacts.get(item.artifact_id);
      insist(recorded?.state === 'verified' && artifact && matching(recorded, artifact) && recorded.artifact_id === artifact.id, 'Promotion requires every immutable target to verify.');
    }
    for (const item of promotions) {
      insist(targets.some(target => target.target === item.target && target.coordinate === item.coordinate) && adapters[item.target] && typeof adapters[item.target].promote === 'function' && typeof adapters[item.target].verifyPromotion === 'function', 'Promotion target is not in the accepted immutable set.');
      const key = `${item.target}:${item.channel ?? 'release'}`;
      ledger.channels[key] = { coordinate: item.coordinate, state: 'promoting' }; journal.save(ledger);
      let verified = false;
      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          if (await adapters[item.target].verifyPromotion(item.channel, item.bytes, item.mediaType)) { verified = true; break; }
          try { await adapters[item.target].promote(item.channel, item.bytes, item.mediaType); }
          catch (error) { if (!error.transient) throw error; }
          if (await adapters[item.target].verifyPromotion(item.channel, item.bytes, item.mediaType)) { verified = true; break; }
        } catch (error) { if (!error.transient || attempt + 1 === attempts) throw error; }
      }
      insist(verified, 'Promotion did not verify after its bounded retries.');
      ledger.channels[key] = { coordinate: item.coordinate, state: 'promoted' }; journal.save(ledger);
    }
    return ledger;
  });
}
