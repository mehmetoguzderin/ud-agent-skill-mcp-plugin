import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, durableWrite } from '../../workspace/src/journal.js';
import { runCommand } from './command.js';

const RECEIPT = 'lima-cli.json';
const SHA = /^sha256:[0-9a-f]{64}$/;
type Identity = { executable: string; sha256: string; device: string; inode: string; size: string; modified_ns: string; changed_ns: string; mode: number; uid: number };
type Saved = Identity & { schema_version: 1; engine: 'lima-nerdctl'; version: string };
export type LimaCliSelection = { binarySha256: string; version?: string; source: 'official' | 'external'; identity?: Saved; previousReceiptSha256?: string };
export type LimaCliOptions = { executable: string; officialSha256: string; sourceRoot: string; stateRoot: string; prepare?: boolean; repair?: boolean; signal?: AbortSignal };
function sha(bytes: Buffer): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function within(root: string, file: string): boolean { const relative = path.relative(root, file); return relative === '' || relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); }
function stableVersion(value: string): boolean { const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value); return !!match && match.slice(1).every(item => Number.isSafeInteger(Number(item))) && (Number(match[1]) > 2 || Number(match[1]) === 2 && Number(match[2]) >= 3); }
function cancelled(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('PLATFORM_SETUP_CANCELLED'); }

async function executableIdentity(executable: string, signal?: AbortSignal): Promise<Identity> {
  if (!path.isAbsolute(executable) || executable.includes('\0') || await realpath(executable) !== executable) throw new Error('LIMA_CLI_UNSAFE');
  const file = await open(executable, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > 512n * 1024n * 1024n || (Number(before.mode) & 0o022) !== 0 || (Number(before.mode) & 0o111) === 0 || typeof process.getuid === 'function' && before.uid !== 0n && before.uid !== BigInt(process.getuid())) throw new Error('LIMA_CLI_UNSAFE');
    const hash = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let position = 0;
    for (;;) { cancelled(signal); const { bytesRead } = await file.read(buffer, 0, buffer.length, position); if (!bytesRead) break; position += bytesRead; if (BigInt(position) > before.size) throw new Error('LIMA_CLI_CHANGED_DURING_ADMISSION'); hash.update(buffer.subarray(0, bytesRead)); }
    const after = await file.stat({ bigint: true }); const current = await lstat(executable, { bigint: true });
    if (BigInt(position) !== before.size || ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid'].some(key => before[key as keyof typeof before] !== after[key as keyof typeof after] || before[key as keyof typeof before] !== current[key as keyof typeof current])) throw new Error('LIMA_CLI_CHANGED_DURING_ADMISSION');
    return { executable, sha256: `sha256:${hash.digest('hex')}`, device: before.dev.toString(), inode: before.ino.toString(), size: before.size.toString(), modified_ns: before.mtimeNs.toString(), changed_ns: before.ctimeNs.toString(), mode: Number(before.mode), uid: Number(before.uid) };
  } finally { await file.close(); }
}
async function savedReceipt(root: string): Promise<{ value: Saved; sha256: string } | undefined> {
  const filename = path.join(root, RECEIPT);
  let info; try { info = await lstat(filename); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  const directory = await lstat(root);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 || typeof process.getuid === 'function' && directory.uid !== process.getuid() || !info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('LIMA_CLI_RECEIPT_UNSAFE');
  const bytes = await boundedRead(filename, 16384); let raw: unknown;
  try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('LIMA_CLI_RECEIPT_INVALID'); }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('LIMA_CLI_RECEIPT_INVALID'); const value = raw as Saved;
  if (Object.keys(value).sort().join(',') !== 'changed_ns,device,engine,executable,inode,mode,modified_ns,schema_version,sha256,size,uid,version' || value.schema_version !== 1 || value.engine !== 'lima-nerdctl' || typeof value.executable !== 'string' || !path.isAbsolute(value.executable) || typeof value.sha256 !== 'string' || !SHA.test(value.sha256) || typeof value.version !== 'string' || !stableVersion(value.version) || ['device', 'inode', 'size', 'modified_ns', 'changed_ns'].some(key => typeof value[key as keyof Saved] !== 'string' || !/^\d{1,40}$/.test(value[key as keyof Saved] as string)) || !Number.isSafeInteger(value.mode) || value.mode < 0 || !Number.isSafeInteger(value.uid) || value.uid < 0) throw new Error('LIMA_CLI_RECEIPT_INVALID');
  return { value, sha256: sha(bytes) };
}
function matches(saved: Saved, actual: Identity): boolean { return Object.entries(actual).every(([key, value]) => saved[key as keyof Saved] === value); }

/** Unknown external installations are availability hints, never damaged product assets. */
export async function selectLimaCli(options: LimaCliOptions, runner: typeof runCommand = runCommand): Promise<LimaCliSelection | null> {
  cancelled(options.signal);
  if (!path.isAbsolute(options.sourceRoot) || !path.isAbsolute(options.stateRoot) || !SHA.test(options.officialSha256)) throw new Error('LIMA_CLI_ADMISSION_INVALID');
  const saved = await savedReceipt(options.stateRoot);
  const owned = within(path.resolve(options.sourceRoot), options.executable) || within(path.resolve(options.stateRoot), options.executable);
  let actual: Identity;
  try { actual = await executableIdentity(options.executable, options.signal); }
  catch (error) { if (!saved && !owned && ((error as Error).message === 'LIMA_CLI_UNSAFE' || (error as NodeJS.ErrnoException).code === 'ENOENT')) return null; throw error; }
  if (owned && actual.sha256 !== options.officialSha256) throw new Error('LIMA_OWNED_CLI_INTEGRITY_FAILED');
  if (saved && matches(saved.value, actual)) return { binarySha256: actual.sha256, version: saved.value.version, source: 'external', identity: saved.value, previousReceiptSha256: saved.sha256 };
  if (saved && !options.repair) throw new Error('LIMA_CLI_IDENTITY_CHANGED_REPAIR_REQUIRED');
  if (!saved && actual.sha256 === options.officialSha256) return { binarySha256: actual.sha256, source: 'official' };
  if (!options.prepare) return null;
  let version: string | undefined;
  try {
    const result = await runner(options.executable, ['--version'], { timeoutMs: 5000, maxOutputBytes: 65536, ...(options.signal ? { signal: options.signal } : {}) });
    const text = new TextDecoder('utf-8', { fatal: true }).decode(result.stdout).trim(); const match = /^limactl version ([0-9]+\.[0-9]+\.[0-9]+)$/.exec(text);
    if (result.code === 0 && match && stableVersion(match[1]!)) version = match[1]!;
  } catch (error) { cancelled(options.signal); if ((error as Error).message === 'COMMAND_CANCELLED') throw error; }
  const after = await executableIdentity(options.executable, options.signal);
  if (JSON.stringify(actual) !== JSON.stringify(after)) throw new Error('LIMA_CLI_CHANGED_DURING_ADMISSION');
  if (!version) return null;
  return { binarySha256: actual.sha256, version, source: 'external', identity: { ...actual, schema_version: 1, engine: 'lima-nerdctl', version }, ...(saved ? { previousReceiptSha256: saved.sha256 } : {}) };
}

/** Caller holds the provider setup kernel lease through containment and this commit. */
export async function commitLimaCli(selection: LimaCliSelection, stateRoot: string, signal?: AbortSignal): Promise<void> {
  if (!selection.identity) return; cancelled(signal);
  const actual = await executableIdentity(selection.identity.executable, signal);
  if (!matches(selection.identity, actual)) throw new Error('LIMA_CLI_CHANGED_DURING_ADMISSION');
  const previous = await savedReceipt(stateRoot);
  if (previous?.sha256 !== selection.previousReceiptSha256) throw new Error('LIMA_CLI_ADMISSION_CONFLICT');
  const info = await lstat(stateRoot);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('LIMA_CLI_RECEIPT_UNSAFE');
  if (previous && matches(previous.value, actual)) return;
  await durableWrite(path.join(stateRoot, RECEIPT), Buffer.from(`${JSON.stringify(selection.identity)}\n`));
}
