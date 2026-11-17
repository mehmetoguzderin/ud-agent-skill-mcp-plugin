/** Local source and artifact receipts. No Git commits, remote calls, or publication. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync, readdirSync } from 'node:fs';
import path from 'node:path';

export const SOURCE_ROOTS = Object.freeze([
  'LICENSE', 'NOTICE', 'README.md', 'AGENTS.md', 'CHANGELOG.md', 'CONTRIBUTING.md',
  'SECURITY.md', 'SUPPORT.md', 'REUSE.toml', '.editorconfig', '.gitattributes', '.gitignore', '.node-version',
  'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'pyproject.toml', 'uv.lock', 'package.json', 'package-lock.json',
  'tsconfig.json', 'stryker.config.mjs', 'vitest.config.mts', 'vitest.config.ts', 'vitest.config.mjs',
  'plugin.json', 'mcp.json', '.mcp.json', 'gemini-extension.json', '.github', '.agents',
  '.claude-plugin', '.grok-plugin', 'kimi.plugin.json', 'contracts', 'packages', 'packaging', 'runtime', 'quality', 'release', 'scripts', 'skills',
  'tests', 'workers', 'licenses', 'registry', 'evals',
]);
const EXCLUDED_DIRS = new Set(['.artifacts', '.stryker-tmp', '__pycache__', 'node_modules', 'target', '.venv', '.pytest_cache', 'coverage', '.cache']);
const HASH = /^[0-9a-f]{64}$/;

export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
export function safeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') || value.includes(':') || value.startsWith('/') || value.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Unsafe relative artifact path.');
  }
  return value;
}

export function fileReceipt(root, relative) {
  safeRelative(relative);
  const resolvedRoot = path.resolve(root);
  let current = resolvedRoot;
  for (const component of relative.split('/')) {
    current = path.join(current, component);
    const info = lstatSync(current);
    if (info.isSymbolicLink()) throw new Error(`Symbolic link in input: ${relative}`);
  }
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(current, flags);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile()) throw new Error(`Input is not a regular file: ${relative}`);
    const digest = createHash('sha256');
    const bytes = Buffer.allocUnsafe(1024 * 1024);
    let size = 0;
    for (;;) {
      const count = readSync(fd, bytes, 0, bytes.length, null);
      if (!count) break;
      size += count;
      if (!Number.isSafeInteger(size)) throw new Error('Input too large.');
      digest.update(bytes.subarray(0, count));
    }
    const after = fstatSync(fd, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || BigInt(size) !== before.size) {
      throw new Error(`Input changed while being read: ${relative}`);
    }
    return { path: relative, sha256: digest.digest('hex'), size, executable: (before.mode & 0o111n) !== 0n };
  } finally { closeSync(fd); }
}

export function sourceReceipt(root) {
  const records = [];
  function visit(relative) {
    const item = path.join(root, ...relative.split('/'));
    let info;
    try { info = lstatSync(item); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (info.isSymbolicLink()) throw new Error(`Symbolic link in source inventory: ${relative}`);
    if (info.isDirectory()) {
      for (const entry of readdirSync(item).sort()) {
        if (!EXCLUDED_DIRS.has(entry) && !entry.endsWith('.pyc')) visit(`${relative}/${entry}`);
      }
    } else if (info.isFile()) records.push(fileReceipt(root, relative));
    else throw new Error(`Unsupported source entry: ${relative}`);
  }
  for (const name of SOURCE_ROOTS) visit(name);
  records.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (!records.length) throw new Error('Source inventory cannot be empty.');
  return { algorithm: 'sha256-json-file-inventory-v1', sha256: sha256(Buffer.from(JSON.stringify(records))), files: records };
}

export function verifyRecordedFile(root, record) {
  if (!record || typeof record !== 'object' || !HASH.test(record.sha256 ?? '') || !Number.isSafeInteger(record.size) || record.size < 0) throw new Error('Invalid artifact receipt.');
  const actual = fileReceipt(root, record.path);
  if (actual.sha256 !== record.sha256 || actual.size !== record.size) throw new Error(`Artifact receipt mismatch: ${record.path}`);
  return actual;
}

/** Read, hash and parse-bound the same opened file; reject swaps and symlinks. */
export function readRecordedBytes(root, record, maximum = 16 * 1024 * 1024) {
  if (!record || typeof record !== 'object' || !HASH.test(record.sha256 ?? '') || !Number.isSafeInteger(record.size) || record.size < 0 || !Number.isSafeInteger(maximum) || maximum < 0 || record.size > maximum) throw new Error('Invalid bounded artifact receipt.');
  safeRelative(record.path);
  let current = path.resolve(root);
  for (const component of record.path.split('/')) {
    current = path.join(current, component);
    if (lstatSync(current).isSymbolicLink()) throw new Error(`Symbolic link in input: ${record.path}`);
  }
  const fd = openSync(current, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size !== BigInt(record.size)) throw new Error(`Artifact receipt mismatch: ${record.path}`);
    const storage = Buffer.alloc(record.size + 1); let used = 0;
    while (used < storage.length) {
      const count = readSync(fd, storage, used, storage.length - used, null);
      if (!count) break;
      used += count;
    }
    const bytes = storage.subarray(0, used);
    const after = fstatSync(fd, { bigint: true });
    if (bytes.length !== record.size || sha256(bytes) !== record.sha256 || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error(`Artifact receipt mismatch: ${record.path}`);
    return bytes;
  } finally { closeSync(fd); }
}

export function readJsonFile(root, relative) {
  fileReceipt(root, relative);
  return JSON.parse(readFileSync(path.join(root, ...relative.split('/')), 'utf8'));
}
