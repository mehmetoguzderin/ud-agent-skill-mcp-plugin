import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { guardedGrant, guardedIdentity, guardedList, guardedPrivateDirectory, guardedRead } from './guard.js';
import type { GuardIdentity } from './guard.js';
import { portablePathKey, validPortablePath } from './portable-path.js';

export type SnapshotFile = { path: string; size: number; sha256: string };
export type Snapshot = { directory: string; files: SnapshotFile[]; sha256: string; root_identity: GuardIdentity; snapshot_identity: GuardIdentity; consistency: 'verified-per-file'; cleanup: () => Promise<void> };
const MAX_FILES = 10_000;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const INCLUDED_ROOTS = new Set(['README.md', 'LICENSE.txt', 'LICENSE', 'CONTRIBUTING.md', 'stats.xml', 'not-to-release']);

async function inventory(guard: string, root: string, identity: GuardIdentity, signal?: AbortSignal, inputPaths: readonly string[] = [], includeDefaults = true): Promise<{ path: string; size: number }[]> {
  const queue = ['.'];
  const result: { path: string; size: number }[] = [];
  let entries = 0;
  while (queue.length) {
    const dir = queue.shift();
    if (dir === undefined) break;
    const listing = await guardedList(guard, root, dir, identity, signal);
    const normalizedNames = new Set<string>();
    for (const item of listing) {
      if (++entries > MAX_FILES * 10) throw new Error('Workspace inventory exceeds its entry budget.');
      const relative = dir === '.' ? item.name : `${dir}/${item.name}`;
      if (item.name === '.git') continue;
      if (!validPortablePath(relative)) throw new Error(`Workspace contains an unsafe portable path: ${relative}`);
      const portableName = portablePathKey(item.name);
      if (normalizedNames.has(portableName)) throw new Error(`Workspace has a case or Unicode filename collision: ${relative}`);
      normalizedNames.add(portableName);
      if (item.kind === 'symlink' || item.kind === 'other') throw new Error(`Workspace contains an unsupported link or special file: ${relative}`);
      if (item.kind === 'directory') { queue.push(relative); continue; }
      const included = (includeDefaults && (relative.endsWith('.conllu') || (dir === '.' && INCLUDED_ROOTS.has(item.name)))) || inputPaths.some(selected => selected === '.' || relative === selected || relative.startsWith(`${selected}/`));
      if (!included) continue;
      if (item.kind !== 'file') throw new Error(`Selected input is not a regular file: ${relative}`);
      if (item.size > MAX_FILE_BYTES) throw new Error(`Input exceeds per-file limit: ${relative}`);
      result.push({ path: relative, size: item.size });
      if (result.length > MAX_FILES) throw new Error('Workspace exceeds its selected file budget.');
    }
  }
  result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (result.reduce((sum, file) => sum + file.size, 0) > MAX_TOTAL_BYTES) throw new Error('Workspace exceeds its input byte budget.');
  return result;
}

/** Capture through the native guard; each selected file is re-read to detect changes. */
export async function captureValidationSnapshot(guard: string, requestedRoot: string, grantedRoots: readonly string[], signal?: AbortSignal, inputPaths: readonly string[] = [], includeDefaults = true): Promise<Snapshot> {
  if (!path.isAbsolute(guard) || !path.isAbsolute(requestedRoot)) throw new Error('Guard and workspace paths must be absolute.');
  if (inputPaths.length > MAX_FILES || inputPaths.some(value => typeof value !== 'string' || (value !== '.' && !validPortablePath(value)))) throw new Error('Operation input paths must be bounded portable workspace paths.');
  const authorizedRoot = path.resolve(requestedRoot);
  const identity = await guardedGrant(guard, requestedRoot, grantedRoots, signal);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-snapshot-'));
  const cleanup = async () => { await rm(directory, { recursive: true, force: true }); };
  try {
    const snapshotRoot = await realpath(directory);
    const snapshotInfo = await lstat(snapshotRoot, { bigint: true });
    const snapshotIdentity = await guardedIdentity(guard, snapshotRoot, signal);
    if (snapshotIdentity.device !== snapshotInfo.dev.toString() || snapshotIdentity.inode !== snapshotInfo.ino.toString()) throw new Error('SNAPSHOT_ROOT_CHANGED');
    if (process.platform === 'win32') await guardedPrivateDirectory(guard, snapshotRoot, '.', snapshotIdentity, true);
    const before = await inventory(guard, authorizedRoot, identity, signal, inputPaths, includeDefaults);
    const files: SnapshotFile[] = [];
    for (const file of before) {
      const first = await guardedRead(guard, authorizedRoot, file.path, MAX_FILE_BYTES, identity, signal);
      const second = await guardedRead(guard, authorizedRoot, file.path, MAX_FILE_BYTES, identity, signal);
      if (first.length !== file.size || !first.equals(second)) throw new Error('WORKTREE_CHANGED_DURING_SNAPSHOT');
      const target = path.join(directory, ...file.path.split('/'));
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, first, { flag: 'wx', mode: 0o600 });
      files.push({ path: file.path, size: first.length, sha256: createHash('sha256').update(first).digest('hex') });
    }
    const after = await inventory(guard, authorizedRoot, identity, signal, inputPaths, includeDefaults);
    if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('WORKTREE_CHANGED_DURING_SNAPSHOT');
    await chmod(directory, 0o700);
    return { directory: snapshotRoot, files, sha256: createHash('sha256').update(JSON.stringify(files)).digest('hex'), root_identity: identity, snapshot_identity: snapshotIdentity, consistency: 'verified-per-file', cleanup };
  } catch (error: unknown) { await cleanup(); throw error; }
}

/** Select only explicitly named non-corpus inputs in addition to corpus files. */
export function operationInputPaths(args: Record<string, unknown>): string[] {
  const selected = new Set<string>();
  const walk = (value: unknown, depth: number, key = '') => {
    if (depth > 16) throw new Error('Operation input nesting exceeds its limit.');
    if (/^(?:output|destination|working_tree|ud_context)(?:_|$)/.test(key)) return;
    if (typeof value === 'string' && /(?:^|_)paths?$/.test(key)) {
      if (value !== '.' && !validPortablePath(value)) throw new Error(`Operation input must be a portable workspace path: ${key}`);
      selected.add(value);
    } else if (Array.isArray(value)) {
      if (value.length > MAX_FILES) throw new Error('Operation input selection exceeds its limit.');
      for (const item of value) walk(item, depth + 1, key.endsWith('s') ? key.slice(0, -1) : key);
    } else if (value && typeof value === 'object') for (const [name, item] of Object.entries(value)) walk(item, depth + 1, name);
  };
  walk(args, 0);
  return [...selected].sort();
}

/** Verify every staged byte and reject extra files immediately before execution. */
export async function verifySnapshotIntegrity(guard: string, snapshot: Snapshot, signal?: AbortSignal): Promise<string> {
  if ((await lstat(snapshot.directory)).isSymbolicLink()) throw new Error('Snapshot root cannot be a symbolic link.');
  const root = await realpath(snapshot.directory);
  const info = await lstat(root, { bigint: true });
  if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077n) !== 0n) || (typeof process.getuid === 'function' && info.uid !== BigInt(process.getuid()))) throw new Error('Snapshot root is not private and user-owned.');
  const identity = await guardedIdentity(guard, root, signal);
  if (identity.device !== info.dev.toString() || identity.inode !== info.ino.toString() || identity.device !== snapshot.snapshot_identity.device || identity.inode !== snapshot.snapshot_identity.inode) throw new Error('SNAPSHOT_ROOT_CHANGED');
  if (process.platform === 'win32') await guardedPrivateDirectory(guard, root, '.', identity, false);
  if (snapshot.files.length > MAX_FILES || createHash('sha256').update(JSON.stringify(snapshot.files)).digest('hex') !== snapshot.sha256) throw new Error('Snapshot manifest fingerprint does not match.');
  const expected = new Map(snapshot.files.map(file => [file.path, file]));
  if (expected.size !== snapshot.files.length) throw new Error('Snapshot manifest contains duplicate paths.');
  if (snapshot.files.some(file => !Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES || !/^[0-9a-f]{64}$/.test(file.sha256)) || snapshot.files.reduce((sum, file) => sum + file.size, 0) > MAX_TOTAL_BYTES) throw new Error('Snapshot manifest has invalid file bounds.');
  const allowedDirs = new Set<string>(['.']);
  for (const filename of expected.keys()) {
    if (!validPortablePath(filename)) throw new Error('Snapshot manifest contains an unsafe path.');
    const parts = filename.split('/');
    parts.pop();
    for (let index = 1; index <= parts.length; index++) allowedDirs.add(parts.slice(0, index).join('/'));
  }
  const queue = ['.']; const found = new Set<string>();
  while (queue.length) {
    const directory = queue.shift(); if (directory === undefined) break;
    for (const entry of await guardedList(guard, root, directory, identity, signal)) {
      const relative = directory === '.' ? entry.name : `${directory}/${entry.name}`;
      if (entry.kind === 'directory' && allowedDirs.has(relative)) { queue.push(relative); continue; }
      const declared = expected.get(relative);
      if (entry.kind !== 'file' || !declared || found.has(relative) || entry.size !== declared.size) throw new Error(`Unexpected or changed snapshot entry: ${relative}`);
      const bytes = await guardedRead(guard, root, relative, MAX_FILE_BYTES, identity, signal);
      if (bytes.length !== declared.size || createHash('sha256').update(bytes).digest('hex') !== declared.sha256) throw new Error(`Snapshot bytes changed: ${relative}`);
      found.add(relative);
    }
  }
  if (found.size !== expected.size) throw new Error('A declared snapshot file is missing.');
  return root;
}
