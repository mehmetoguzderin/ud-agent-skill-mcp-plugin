import { lstat, opendir, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/** Bounded launch-time discovery, never a recursive scan of a user's home. */
export async function discoverWorkspace(cwd = process.cwd(), home = os.homedir()): Promise<string | undefined> {
  const root = await realpath(cwd);
  if (root === path.parse(root).root || root === await realpath(home).catch(() => path.resolve(home))) return undefined;
  const info = await lstat(cwd);
  if (!info.isDirectory() || info.isSymbolicLink()) return undefined;
  const banks: string[] = []; let count = 0;
  for await (const entry of await opendir(root)) {
    if (++count > 512) break;
    if (entry.isFile() && entry.name.endsWith('.conllu')) return root;
    if (entry.name === '.git' && (entry.isDirectory() || entry.isFile())) return root;
    if (entry.isFile() && ['package.json', 'Cargo.toml', 'pyproject.toml'].includes(entry.name)) return root;
    if (banks.length < 32 && entry.isDirectory() && /^UD_[A-Za-z][A-Za-z0-9_-]+$/.test(entry.name)) banks.push(entry.name);
  }
  for (const bank of banks) {
    let count = 0;
    for await (const entry of await opendir(path.join(root, bank))) {
      if (++count > 256) break;
      if (entry.isFile() && entry.name.endsWith('.conllu')) return root;
    }
  }
  return undefined;
}
