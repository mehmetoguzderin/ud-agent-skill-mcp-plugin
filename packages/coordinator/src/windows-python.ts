import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

type FileIdentity = { path: string; sha256: string; bytes?: Buffer };
export type WindowsPythonLaunch = {
  executable: string; executableSha256: string;
  venv?: { executable: string; executableSha256: string; config: string; configSha256: string };
};
const invalid = () => new Error('WORKER_PYTHON_ENVIRONMENT_INVALID');
const changed = () => new Error('WORKER_RUNTIME_IDENTITY_CHANGED');
function same(a: BigIntStats, b: BigIntStats): boolean {
  return a.isFile() && b.isFile() && !a.isSymbolicLink() && !b.isSymbolicLink()
    && a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mode === b.mode
    && a.nlink === b.nlink && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

async function ordinary(filename: string, maximum: number, retain = false): Promise<FileIdentity> {
  if (!path.isAbsolute(filename) || filename.includes('\0')) throw invalid();
  const named = await lstat(filename, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink() || named.size < 1n || named.size > BigInt(maximum)) throw invalid();
  const canonical = await realpath(filename);
  const handle = await open(canonical, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (!same(named, before) || !same(before, await lstat(canonical, { bigint: true }))) throw changed();
    const hash = createHash('sha256'), buffer = Buffer.alloc(Math.min(maximum, 1024 * 1024)), chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, total);
      if (!bytesRead) break;
      total += bytesRead;
      if (BigInt(total) > before.size) throw changed();
      const chunk = buffer.subarray(0, bytesRead); hash.update(chunk);
      if (retain) chunks.push(Buffer.from(chunk));
    }
    if (BigInt(total) !== before.size || !same(before, await handle.stat({ bigint: true }))
      || !same(before, await lstat(filename, { bigint: true })) || !same(before, await lstat(canonical, { bigint: true }))
      || await realpath(filename) !== canonical) throw changed();
    return { path: canonical, sha256: hash.digest('hex'), ...(retain ? { bytes: Buffer.concat(chunks) } : {}) };
  } finally { await handle.close(); }
}

/** CPython's Windows venv redirector installs a nested Job without the worker
 * limits. Launch its exact base directly instead, using CPython's own explicit
 * launcher override to preserve venv prefix/site packages under -I. Both pinned
 * CPython lines implement this in Modules/getpath.py (3.14.10 and 3.15.2).
 * Only the verified runtime's ordinary pyvenv.cfg selects the base; no ambient
 * Python environment or executable search participates in this resolution.
 */
export async function resolveWindowsPython(python: string): Promise<WindowsPythonLaunch> {
  const launcher = await ordinary(python, 256 * 1024 * 1024);
  const directory = path.dirname(launcher.path);
  const candidates = [...new Set([path.join(directory, 'pyvenv.cfg'), path.join(path.dirname(directory), 'pyvenv.cfg')])];
  const configs: FileIdentity[] = [];
  for (const filename of candidates) {
    // CPython's getpath.c rejects files at or above its 32 KiB read bound.
    try { configs.push(await ordinary(filename, 32 * 1024 - 1, true)); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  if (!configs.length) {
    if (path.basename(directory).toLowerCase() === 'scripts') throw invalid();
    return { executable: launcher.path, executableSha256: launcher.sha256 };
  }
  if (configs.length !== 1 || path.basename(launcher.path).toLowerCase() !== 'python.exe') throw invalid();
  const config = configs[0]!;
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(config.bytes); } catch { throw invalid(); }
  // getpath.c scans NUL-terminated lines, and Python's strip() recognizes
  // controls that JavaScript trim() does not. Preserve BOM for rejection too:
  // neither decoding nor trimming may hide a different home key from CPython.
  // Ordinary tabs, LF and CRLF remain valid configuration whitespace.
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufeff]/.test(text)) throw invalid();
  const homes = text.split(/\r?\n/).flatMap(line => {
    const equal = line.indexOf('=');
    return equal >= 0 && line.slice(0, equal).trim().toLowerCase() === 'home' ? [line.slice(equal + 1).trim()] : [];
  });
  if (homes.length !== 1 || !path.isAbsolute(homes[0]!) || /[\x00-\x1f]/.test(homes[0]!)) throw invalid();
  const base = await ordinary(path.join(homes[0]!, 'python.exe'), 256 * 1024 * 1024);
  if (base.path === launcher.path) throw invalid();
  // The native supervisor reopens and pins all three exact byte identities
  // without write/delete sharing for the complete worker lifetime.
  return { executable: base.path, executableSha256: base.sha256,
    venv: { executable: launcher.path, executableSha256: launcher.sha256, config: config.path, configSha256: config.sha256 } };
}
