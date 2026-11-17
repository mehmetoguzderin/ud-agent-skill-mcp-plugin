/** Local fixture-only immutable release reconciliation. No remote transport. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { sha256, verifyRecordedFile } from './candidate.mjs';

const HASH = /^[0-9a-f]{64}$/;
const NAME = /^[A-Za-z0-9@][A-Za-z0-9@/._:+-]*$/;
const TARGETS = new Set(['github', 'ghcr', 'npm', 'mcp-registry']);

/** In-memory fixture registry only. This adapter performs no I/O or network. */
export class FixtureRegistry {
  #objects = new Map();
  #channels = new Map();
  #failures = new Map();
  #key(target, coordinate) { return `${target}\0${coordinate}`; }
  seed(target, coordinate, bytes) { this.#objects.set(this.#key(target, coordinate), Buffer.from(bytes)); }
  transientFailures(target, count) { this.#failures.set(target, count); }
  #maybeFail(target) {
    const count = this.#failures.get(target) ?? 0;
    if (count > 0) { this.#failures.set(target, count - 1); const error = new Error('Fixture transient failure.'); error.transient = true; throw error; }
  }
  inspect(target, coordinate) {
    this.#maybeFail(target);
    const bytes = this.#objects.get(this.#key(target, coordinate));
    return bytes ? { sha256: sha256(bytes), size: bytes.length } : null;
  }
  publish(target, coordinate, bytes) {
    this.#maybeFail(target);
    const key = this.#key(target, coordinate);
    if (this.#objects.has(key)) throw new Error('Fixture immutable coordinate already exists.');
    this.#objects.set(key, Buffer.from(bytes));
  }
  setChannel(name, target, coordinate) { this.#channels.set(name, { target, coordinate }); }
  getChannel(name) { return this.#channels.get(name) ?? null; }
}
function attempt(fn, attempts) {
  for (let i = 0; i < attempts; i++) {
    try { return fn(); }
    catch (error) { if (!error?.transient || i + 1 === attempts) throw error; }
  }
  throw new Error('Unreachable retry state.');
}

export function reconcileFixture(root, candidate, previous, registry, attempts = 3) {
  if (!(registry instanceof FixtureRegistry)) throw new Error('Only the in-memory fixture adapter is available.');
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 5) throw new Error('Invalid retry bound.');
  if (!candidate || !HASH.test(candidate.manifest_sha256 ?? '') || !Array.isArray(candidate.targets) || !candidate.targets.length) throw new Error('Invalid immutable candidate.');
  if (previous && (previous.schema_version !== 1 || previous.manifest_sha256 !== candidate.manifest_sha256 || !previous.targets || typeof previous.targets !== 'object')) throw new Error('Ledger belongs to a different candidate.');
  const ledger = previous ? structuredClone(previous) : { schema_version: 1, manifest_sha256: candidate.manifest_sha256, targets: {} };
  const seen = new Set();
  try {
    for (const item of candidate.targets) {
      if (!TARGETS.has(item.target) || typeof item.coordinate !== 'string' || !NAME.test(item.coordinate) || !HASH.test(item.sha256 ?? '')) throw new Error('Invalid immutable target.');
      const key = `${item.target}:${item.coordinate}`;
      if (seen.has(key)) throw new Error('Duplicate immutable target.');
      seen.add(key);
      const recorded = ledger.targets[key];
      if (recorded && (recorded.sha256 !== item.sha256 || recorded.state !== 'verified')) throw new Error('Ledger target conflicts with candidate.');
      const verifiedFile = verifyRecordedFile(root, item);
      const bytes = readFileSync(path.join(root, ...verifiedFile.path.split('/')));
      if (bytes.length !== item.size || sha256(bytes) !== item.sha256) throw new Error('Artifact changed during publication preparation.');
      let current = attempt(() => registry.inspect(item.target, item.coordinate), attempts);
      if (current && (current.sha256 !== item.sha256 || current.size !== item.size)) throw new Error(`Immutable target conflict: ${key}`);
      if (!current) {
        for (let i = 0; i < attempts; i++) {
          try {
            registry.publish(item.target, item.coordinate, bytes);
            break;
          } catch (error) {
            if (!error?.transient) throw error;
            // The write may have succeeded despite a lost response. Inspect
            // before retrying an immutable coordinate.
            current = attempt(() => registry.inspect(item.target, item.coordinate), attempts);
            if (current) break;
            if (i + 1 === attempts) throw error;
          }
        }
        for (let i = 0; i < attempts && !current; i++) current = attempt(() => registry.inspect(item.target, item.coordinate), attempts);
        if (!current || current.sha256 !== item.sha256 || current.size !== item.size) throw new Error(`Published fixture did not verify: ${key}`);
      }
      ledger.targets[key] = { state: 'verified', sha256: item.sha256, size: item.size };
    }
    return ledger;
  } catch (error) { error.ledger = ledger; throw error; }
}

export function promoteFixture(candidate, ledger, registry, channel, target, coordinate) {
  if (!(registry instanceof FixtureRegistry) || !NAME.test(channel) || !TARGETS.has(target) || !NAME.test(coordinate)) throw new Error('Invalid fixture promotion.');
  if (!ledger || ledger.manifest_sha256 !== candidate?.manifest_sha256 || !Array.isArray(candidate.targets) || !candidate.targets.length) throw new Error('Promotion requires the matching candidate ledger.');
  for (const item of candidate.targets) {
    const state = ledger.targets[`${item.target}:${item.coordinate}`];
    if (!state || state.state !== 'verified' || state.sha256 !== item.sha256) throw new Error('Cannot promote before every immutable target is verified.');
  }
  if (!candidate.targets.some(item => item.target === target && item.coordinate === coordinate)) throw new Error('Channel target is not in the accepted candidate.');
  registry.setChannel(channel, target, coordinate);
}
