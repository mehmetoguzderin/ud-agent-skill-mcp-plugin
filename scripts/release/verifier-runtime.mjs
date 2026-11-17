/** Source-bound, privately staged Python for production release verification. */
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readlinkSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readRecordedBytes, safeRelative } from './candidate.mjs';
const sessions = new WeakMap();
const policyPath = 'release/verifier-runtimes.lock.json';
function insist(value, message) { if (!value) throw new Error(message); }
function sourceFile(root, source, name, maximum = 16 * 1024 ** 2) {
  const row = source.files.find(item => item.path === name); insist(row, `Required verifier runtime source file missing: ${name}`);
  return readRecordedBytes(root, row, maximum);
}
function approved(root, source, requested) {
  insist(typeof requested === 'string' && path.isAbsolute(requested) && existsSync(requested), 'Release verifier interpreter must be an existing absolute approved executable.');
  const selected = realpathSync(requested), policy = JSON.parse(sourceFile(root, source, policyPath).toString('utf8'));
  insist(policy.schema_version === 1 && policy.purpose === 'release-verifier-python' && Array.isArray(policy.profiles), 'Release verifier interpreter policy is invalid.');
  const platform = `${process.platform}-${process.arch}`;
  for (const profile of policy.profiles) {
    if (profile.platform !== platform || profile.status !== 'approved') continue;
    insist(profile.inventory && profile.approval, 'Approved verifier interpreter requires an inventory and independent origin review.');
    const bytes = sourceFile(root, source, profile.inventory.path), inventory = JSON.parse(bytes.toString('utf8'));
    insist(source.files.some(row => row.path === profile.inventory.path && row.sha256 === profile.inventory.sha256 && row.size === profile.inventory.size), 'Verifier runtime inventory identity differs from protected source.');
    const review = JSON.parse(sourceFile(root, source, profile.approval.path).toString('utf8'));
    insist(source.files.some(row => row.path === profile.approval.path && row.sha256 === profile.approval.sha256 && row.size === profile.approval.size) && review.qualification === 'independent-verifier-runtime-origin-and-byte-closure-review' && review.decision === 'approved-for-release-verification' && review.inventory?.sha256 === profile.inventory.sha256 && review.inventory?.size === profile.inventory.size && review.origin_archive_sha256 === inventory.origin?.archive?.sha256 && review.generator_sha256 === inventory.generator?.sha256, 'Verifier runtime origin/closure review is missing or stale.');
    insist(inventory.schema_version === 1 && inventory.qualification === 'publisher-archive-verifier-prefix-inventory-not-approval' && inventory.platform === platform && inventory.site_initialization === 'disabled-with-S' && inventory.pycache_policy === 'private-empty-prefix-with-B' && inventory.unresolved_dependencies?.length === 0 && Array.isArray(inventory.files) && inventory.files.length > 0 && inventory.files.length <= 100000 && Array.isArray(inventory.links), 'Verifier runtime closure is invalid or unresolved.');
    const origin = inventory.origin?.release_receipt;
    insist(source.files.some(row => row.path === inventory.generator?.path && row.sha256 === inventory.generator?.sha256), 'Verifier runtime producer source differs from its reviewed inventory.');
    for (const helper of inventory.helpers ?? []) insist(source.files.some(row => row.path === helper.path && row.sha256 === helper.sha256), 'Verifier runtime inspection helper differs from its reviewed inventory.');
    insist(origin && source.files.some(row => row.path === origin.path && row.sha256 === origin.sha256 && row.size === origin.size), 'Verifier runtime publisher origin is outside protected source.');
    const release = JSON.parse(sourceFile(root, source, origin.path).toString('utf8'));
    const assets = release.assets?.filter(row => row.name === inventory.origin.archive.name && row.digest === 'sha256:' + inventory.origin.archive.sha256 && row.size === inventory.origin.archive.size && row.browser_download_url === inventory.origin.archive.url);
    insist(assets?.length === 1, 'Verifier runtime publisher asset differs from frozen release.');
    const entry = safeRelative(inventory.entrypoint), suffix = path.sep + entry.split('/').join(path.sep);
    insist(inventory.native_files?.some(row => row.path === entry && row.architectures?.includes(platform)), 'Verifier runtime entrypoint has no matching approved native CPU.');
    if (!selected.endsWith(suffix)) continue;
    const prefix = selected.slice(0, -suffix.length), row = inventory.files.find(item => item.path === entry);
    insist(row?.executable === true, 'Verifier runtime executable is not in the approved closure.');
    readRecordedBytes(prefix, row, 512 * 1024 ** 2);
    return { prefix, inventory, profile };
  }
  throw new Error('No approved release-verifier interpreter matches this host and executable; unprovisioned or unreviewed runtimes cannot authorize release verification.');
}

/** Cheap data-only rejection; never executes an override before ancestry. */
export function preflightReleaseInterpreter(root, source, requested = process.env.UD_RELEASE_PYTHON) {
  if (requested !== undefined) approved(root, source, requested);
}

/** Copy exact approved runtime bytes, omitting all host caches, into owned files. */
export function stageVerifierPrefix(prefix, inventory, destination) {
  prefix = realpathSync(prefix);
  insist(!existsSync(destination), 'Verifier runtime staging must be new.');
  const files = new Map(), links = new Map(); let total = 0;
  for (const row of inventory.files) { safeRelative(row.path); insist(!files.has(row.path) && typeof row.executable === 'boolean' && Number.isSafeInteger(row.size) && row.size >= 0 && row.size <= 512 * 1024 ** 2, 'Verifier runtime file inventory is invalid.'); files.set(row.path, row); total += row.size; }
  insist(total <= 2 * 1024 ** 3, 'Verifier runtime closure exceeds its bound.');
  for (const row of inventory.links) { safeRelative(row.path); safeRelative(row.resolved_target); insist(!links.has(row.path) && !files.has(row.path) && files.has(row.resolved_target), 'Verifier runtime alias is invalid.'); links.set(row.path, row); }
  const omitted = new Set();
  for (const row of inventory.excluded_optional_payloads ?? []) {
    const original = files.get(safeRelative(row.path));
    insist(original && original.sha256 === row.sha256 && original.size === row.size && typeof row.reason === 'string' && row.reason.length > 0 && !omitted.has(row.path) && row.path !== inventory.entrypoint, 'Verifier runtime optional exclusion is invalid.');
    omitted.add(row.path);
  }
  insist([...links.values()].every(row => !omitted.has(row.resolved_target)), 'Verifier runtime alias references an excluded optional file.');
  const seen = new Set();
  function visit(name) {
    if (name.split('/').includes('__pycache__') || name.endsWith('.pyc')) return;
    const filename = path.join(prefix, name), info = lstatSync(filename);
    if (info.isSymbolicLink()) { const row = links.get(name); insist(row && readlinkSync(filename) === row.linkname && realpathSync(filename) === path.join(prefix, row.resolved_target), 'Verifier runtime has an unapproved alias.'); seen.add(name); }
    else if (info.isDirectory()) for (const item of readdirSync(filename).sort()) visit(name ? name + '/' + item : item);
    else { insist(info.isFile() && files.has(name), 'Verifier runtime contains an unapproved file or special entry.'); seen.add(name); }
  }
  visit(''); insist(seen.size === files.size + links.size, 'Verifier runtime omits required files.');
  mkdirSync(destination, { mode: 0o700 });
  try {
    for (const row of files.values()) { const bytes = readRecordedBytes(prefix, row, 512 * 1024 ** 2); if (omitted.has(row.path)) continue; const target = path.join(destination, row.path); mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 }); writeFileSync(target, bytes, { flag: 'wx', mode: row.executable ? 0o500 : 0o400 }); }
    for (const row of links.values()) { const original = files.get(row.resolved_target), bytes = readRecordedBytes(destination, original, 512 * 1024 ** 2), target = path.join(destination, row.path); mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 }); writeFileSync(target, bytes, { flag: 'wx', mode: original.executable ? 0o500 : 0o400 }); }
    const expected = new Set([...files.keys(), ...links.keys()].filter(name => !omitted.has(name))), actual = new Set();
    function staged(name) {
      const target = path.join(destination, name), info = lstatSync(target);
      if (info.isDirectory()) for (const child of readdirSync(target)) staged(name ? name + '/' + child : child);
      else { insist(info.isFile() && !info.isSymbolicLink() && expected.has(name), 'Private verifier prefix contains an untracked file or cache.'); actual.add(name); }
    }
    staged(''); insist(actual.size === expected.size, 'Private verifier prefix omits expected files.');
    return { files: files.size - omitted.size, aliases: links.size, ...(omitted.size ? { excluded_optional_files: omitted.size } : {}) };
  } catch (error) { rmSync(destination, { recursive: true, force: true }); throw error; }
}

/** Called only after the production protected-source gate has succeeded. */
/** @param {{python?: string, scratchParent?: string, beforeStage?: (bytes: number) => unknown}} [options] */
export function verifyReleaseInterpreter(root, source, options = {}) {
  const { python } = options;
  const requested = python ?? process.env.UD_RELEASE_PYTHON ?? path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const { prefix, inventory, profile } = approved(root, source, requested);
  // Charge the complete inventoried prefix before creating any staging files.
  // Optional omitted files are intentionally included in this conservative plan.
  options.beforeStage?.(inventory.files.reduce((total, row) => total + row.size, 0));
  const parent = options.scratchParent === undefined ? os.tmpdir() : realpathSync(options.scratchParent);
  const owned = mkdtempSync(path.join(parent, 'ud-release-verifier-runtime-')), runtime = path.join(owned, 'python'), cache = path.join(owned, 'empty-pycache');
  try {
    stageVerifierPrefix(prefix, inventory, runtime); mkdirSync(cache, { mode: 0o700 });
    const session = Object.freeze({}); sessions.set(session, { owned, executable: path.join(runtime, inventory.entrypoint), cache, receipt: { qualification: 'source-bound-privately-staged-verifier-runtime', profile: profile.id, platform: inventory.platform, version: inventory.version, inventory: profile.inventory, approval: profile.approval, producer: inventory.generator, origin_archive_sha256: inventory.origin.archive.sha256, site_initialization: false, bytecode_cache: 'private-empty' } }); return session;
  } catch (error) { rmSync(owned, { recursive: true, force: true }); throw error; }
}

export function releasePythonCommand(session, args) {
  const runtime = sessions.get(session); insist(runtime, 'An authenticated privately staged verifier interpreter session is required.');
  // -S blocks venv/site .pth processing. The private cache prefix plus -B
  // prevents both reading substituted host pyc files and creating new caches.
  return { executable: runtime.executable, args: ['-I', '-S', '-B', '-X', `pycache_prefix=${runtime.cache}`, ...args], env: { PATH: process.env.PATH ?? '', LC_ALL: 'C', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) } };
}
export function releaseVerifierReceipt(session) { const runtime = sessions.get(session); insist(runtime, 'An authenticated verifier runtime session is required.'); return structuredClone(runtime.receipt); }
/** The private interpreter is counted by the supervising storage reservation. */
export function releaseVerifierOwnedRoot(session) { const runtime = sessions.get(session); insist(runtime, 'An authenticated verifier runtime session is required.'); return runtime.owned; }
export function closeReleaseInterpreter(session) { const runtime = sessions.get(session); if (runtime) { sessions.delete(session); rmSync(runtime.owned, { recursive: true, force: true }); } }
