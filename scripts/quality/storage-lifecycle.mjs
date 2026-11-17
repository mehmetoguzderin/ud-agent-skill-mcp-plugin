/** Bounded, owned scratch for local quality and release work. MIT. */
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, rmSync, statfsSync, writeFileSync, writeSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { batchWindowsStorage, createWindowsStorage, verifyWindowsStorage, windowsStorageLeaseEnvironment } from './windows-storage.mjs';

export const STORAGE_LIMITS = Object.freeze({ totalBytes: 72_000_000_000, ordinaryBytes: 2_000_000_000, releaseBytes: 4_000_000_000, freeReserveBytes: 10_000_000_000 });
export const PROTECTED_MUTATION_SCRATCH_BYTES = 8_000_000_000;
const RECORD = 'reservation.json', MARKER = '.ud-storage-owner.json', ENV = 'UD_STORAGE_LEASE';
const need = (condition, message) => { if (!condition) throw new Error(`Storage admission: ${message}`); };
const bytes = value => Number.isSafeInteger(value) && value >= 0;
const inside = (root, file) => file === root || file.startsWith(root + path.sep);
const json = file => JSON.parse(readFileSync(file, 'utf8'));
const writeJson = (file, value) => {
  const body = JSON.stringify(value) + '\n';
  if (process.platform === 'win32') createWindowsStorage(file, 'file', body);
  else writeFileSync(file, body, { flag: 'wx', mode: 0o600 });
};
const privateDirectory = directory => {
  if (process.platform === 'win32') createWindowsStorage(directory, 'directory');
  else mkdirSync(directory, { mode: 0o700 });
};
// Keep the same 128-bit UUID while leaving room for native Unix socket paths.
const scratchName = id => 'ud-' + Buffer.from(id.replaceAll('-', ''), 'hex').toString('base64url');
/** Two Docker source copies (input and work), per-file filesystem overhead,
 * native compiler/staged executable state and compact reports, charged as scratch. */
export function mutationStoragePlan(sourceBytes, fileCount) {
  need(bytes(sourceBytes) && bytes(fileCount) && fileCount > 0, 'mutation source inventory has no finite byte plan');
  const inputBytes = sourceBytes + fileCount * 8192 + 16 * 1024 ** 2;
  // Protected Rust discovery retains its build and immutable test executables
  // together. The former 128 MiB allowance killed successful native builds.
  const stateBytes = inputBytes + 1024 * 1024 ** 2;
  const reportBytes = 128 * 1024 ** 2;
  const plannedBytes = inputBytes + stateBytes + reportBytes;
  need([inputBytes, stateBytes, plannedBytes].every(bytes) && plannedBytes <= PROTECTED_MUTATION_SCRATCH_BYTES, 'mutation source and state cannot fit protected scratch');
  const profile = plannedBytes > STORAGE_LIMITS.ordinaryBytes ? 'release' : 'ordinary';
  return { inputBytes, stateBytes, reportBytes, plannedBytes, profile,
    ...(plannedBytes > STORAGE_LIMITS.releaseBytes ? { transientAllowance: PROTECTED_MUTATION_SCRATCH_BYTES } : {}) };
}
function limitsFor(overrides = {}, transientAllowance) {
  const ceilings = { ...STORAGE_LIMITS };
  if (transientAllowance !== undefined) {
    need(bytes(transientAllowance) && transientAllowance >= STORAGE_LIMITS.releaseBytes && transientAllowance <= 48_000_000_000, 'local transient allowance must be between 4 and 48 GB');
    ceilings.releaseBytes = transientAllowance;
  }
  need(Object.keys(overrides).every(key => key in STORAGE_LIMITS), 'unknown budget field');
  const limits = { ...ceilings, ...overrides };
  for (const [key, value] of Object.entries(limits)) need(bytes(value) && (key === 'freeReserveBytes' ? value >= ceilings[key] : value <= ceilings[key]), 'budgets may only be tightened');
  return limits;
}
function ordinaryDirectory(directory) {
  const full = path.resolve(directory), actual = realpathSync(full), info = lstatSync(full);
  need(actual === full && info.isDirectory() && !info.isSymbolicLink(), `directory is linked or special: ${full}`);
  return full;
}
function ownedControlDirectory(directory, privateMode = false) {
  ordinaryDirectory(directory); const info = lstatSync(directory);
  if (process.platform === 'win32') verifyWindowsStorage(directory, 'directory', privateMode);
  else need((process.getuid === undefined || info.uid === process.getuid()) && !(info.mode & (privateMode ? 0o077 : 0o022)), 'control directory is not owned or is writable by others');
}
function privateFile(file, limit = 16384) {
  const info = lstatSync(file);
  need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size <= limit && (process.getuid === undefined || info.uid === process.getuid() && !(info.mode & 0o077)), 'ownership record is not a private ordinary file');
  if (process.platform === 'win32') verifyWindowsStorage(file, 'file', true);
  return json(file);
}
/** Create only a new control root; existing artifacts are never re-permissioned. */
export function prepareStorageControl(root) {
  const artifacts = path.join(ordinaryDirectory(root), '.artifacts');
  if (existsSync(artifacts)) ownedControlDirectory(artifacts); else privateDirectory(artifacts);
  return artifacts;
}
function running(pid) {
  need(Number.isSafeInteger(pid) && pid > 0, 'invalid owner PID');
  try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}
function storageInspection() {
  // A Windows directory pending deletion can reject inspection before the
  // next lookup reports ENOENT. Share one finite retry budget across the
  // entire scan; inaccessible entries never become a zero-byte observation.
  let retries = 10, deadline;
  const waiting = new Int32Array(new SharedArrayBuffer(4));
  return operation => {
    for (;;) {
      try { return operation(); }
      catch (error) {
        if (process.platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(error.code) || retries === 0) throw error;
        const now = performance.now(); deadline ??= now + 100;
        const delay = Math.min(10, deadline - now);
        if (delay <= 0) throw error;
        retries--; Atomics.wait(waiting, 0, 0, delay);
      }
    }
  };
}
function scanTreeBytes(root, limit, seen, inspect) {
  let size = 0; const pending = [path.resolve(root)];
  while (pending.length) {
    // A child process may remove its own temporary entry between listing and
    // inspection; a vanished entry occupies no storage and is not an error.
    const file = pending.pop(), info = inspect(() => lstatSync(file, { bigint: true, throwIfNoEntry: false }));
    if (!info) continue;
    if (info.isDirectory() && !info.isSymbolicLink()) { let names; try { names = inspect(() => readdirSync(file)); } catch (error) { if (error.code === 'ENOENT') continue; throw error; } for (const name of names) pending.push(path.join(file, name)); }
    else {
      // Identical device/inode means an actual hard link, not an assumed clone.
      // Do not follow symbolic links, including links outside owned storage.
      if (info.isFile() && info.nlink > 1n) { const key = `${info.dev}:${info.ino}`; if (seen.has(key)) continue; seen.add(key); }
      // Large sparse holes occupy no storage: charge such a file's allocated blocks.
      const allocated = (info.blocks ?? 0n) * 512n;
      size += Number(process.platform !== 'win32' && info.size - allocated > 1048576n ? allocated : info.size); need(bytes(size) && size <= limit, `owned storage exceeds its byte budget (observed_bytes=${size}, limit_bytes=${limit})`);
    }
  }
  return size;
}
export function storageTreeBytes(root, limit = Number.MAX_SAFE_INTEGER, seen = new Set()) {
  return scanTreeBytes(root, limit, seen, storageInspection());
}
/** Count an explicit set of owned paths once, without following symlinks. */
export function ownedStorageBytes(roots, limit = Number.MAX_SAFE_INTEGER) {
  need(Array.isArray(roots) && roots.length > 0 && bytes(limit), 'owned storage roots and a finite byte limit are required');
  const inspect = storageInspection();
  const canonical = [...new Set(roots.map(file => {
    need(typeof file === 'string' && path.isAbsolute(file), 'owned storage root must be absolute');
    const resolved = path.resolve(file);
    const info = inspect(() => lstatSync(resolved, { throwIfNoEntry: false }));
    if (info) need(!info.isSymbolicLink() && realpathSync(resolved) === resolved, 'owned storage root must not be linked');
    return resolved;
  }))].sort((a, b) => a.length - b.length || a.localeCompare(b));
  const distinct = [];
  for (const root of canonical) if (!distinct.some(parent => inside(parent, root))) distinct.push(root);
  let total = 0; const seen = new Set();
  for (const root of distinct) { total += scanTreeBytes(root, limit - total, seen, inspect); need(bytes(total) && total <= limit, 'owned storage exceeds its byte budget'); }
  return total;
}
/** Credit only already-owned exact inodes that have moved into the output. */
export function transferredOutputBytes(root, outputPath, transferJournal, identities = undefined) {
  if (transferJournal === undefined || !existsSync(transferJournal)) return 0;
  const journal = privateFile(transferJournal, 1024 * 1024);
  need(transferJournal === path.join(path.resolve(root), '.artifacts/storage/source-transfer.json') && journal.schema_version === 1 && journal.owner_root === path.resolve(root) && journal.output === outputPath && Array.isArray(journal.entries) && journal.entries.length <= 1000, 'output transfer journal differs');
  let credit = 0; const seen = new Set();
  for (const row of journal.entries) {
    need(typeof row.source === 'string' && inside(path.join(path.resolve(root), '.artifacts'), row.source) && typeof row.destination === 'string' && path.dirname(row.destination) === path.join(outputPath, 'artifacts') && !seen.has(row.destination) && bytes(row.size) && bytes(row.device) && bytes(row.inode), 'output transfer identity is invalid');
    seen.add(row.destination);
    const moved = lstatSync(row.destination, { throwIfNoEntry: false });
    if (!moved) continue;
    need(!existsSync(row.source) && moved.isFile() && !moved.isSymbolicLink() && moved.dev === row.device && moved.ino === row.inode && moved.size === row.size, 'transferred output inode differs');
    identities?.push(`m:${row.destination}:${row.device}:${row.inode}`);
    credit += row.size; need(bytes(credit), 'transferred output budget exceeds numeric bounds');
  }
  return credit;
}
/** Count staged links only when they still name the exact admitted input inode. */
export function linkedOutputBytes(root, outputPath, ownedRoots, links, identities = undefined) {
  let credit=0; const seen=new Set();
  for(const row of links??[]){
    need(typeof row.source==='string' && [root,...ownedRoots].some(parent=>inside(path.resolve(parent),row.source)) && typeof row.destination==='string' && inside(outputPath,row.destination) && bytes(row.size) && bytes(row.device) && bytes(row.inode),'shared output identity is invalid');
    const destination=lstatSync(row.destination,{throwIfNoEntry:false});if(!destination)continue;
    const source=lstatSync(row.source);const key=`${row.device}:${row.inode}`;
    need(!seen.has(key)&&source.isFile()&&!source.isSymbolicLink()&&destination.isFile()&&!destination.isSymbolicLink()&&source.dev===row.device&&source.ino===row.inode&&destination.dev===row.device&&destination.ino===row.inode&&source.size===row.size&&destination.size===row.size,'shared output inode differs');
    seen.add(key);identities?.push(`l:${row.destination}:${key}`);credit+=row.size;need(bytes(credit),'shared output budget exceeds numeric bounds');
  }
  return credit;
}
/** Retry if an admitted rename/link crosses the output inventory scan. */
export function stableOutputBytes(measure, credits) {
  for(let attempt=0;attempt<10;attempt++) {
    let before,total,after;
    try{before=credits();total=measure();after=credits();}
    catch(error){if(error.code==='ENOENT'||/transferred output inode differs|shared output inode differs/.test(error.message))continue;throw error;}
    if(before.identity===after.identity&&before.bytes===after.bytes){need(bytes(total)&&total>=after.bytes,'output inventory differs from its credited inodes');return total-after.bytes;}
  }
  throw new Error('Storage admission: output transfers did not settle during measurement');
}
function freeBytes(directory) { const info = statfsSync(directory, { bigint: true }); return Number(info.bavail * info.bsize); }
export function assertStorageAdmission({ plannedBytes, plannedOutputBytes = 0, profile = 'ordinary', ownedBytes, freeBytes: available, limits: overrides, transientAllowance }) {
  need(transientAllowance === undefined || profile === 'release', 'local transient allowance requires an explicit release profile');
  const limits = limitsFor(overrides, transientAllowance);
  need(['ordinary', 'release'].includes(profile) && bytes(plannedBytes) && plannedBytes > 0 && bytes(plannedOutputBytes) && bytes(ownedBytes) && bytes(available), 'an explicit finite planned byte count is required');
  need(plannedBytes <= limits[profile === 'release' ? 'releaseBytes' : 'ordinaryBytes'], `${profile} scratch exceeds its fixed budget`);
  need(ownedBytes + plannedBytes + plannedOutputBytes <= limits.totalBytes, 'owned working total would exceed its fixed budget');
  need(available - plannedBytes - plannedOutputBytes >= limits.freeReserveBytes, 'planned writes would consume the 10 GB free reserve');
  return { plannedBytes, plannedOutputBytes, profile, ownedBytes, freeBytes: available, limits };
}
function verifyRecord(lock, expected) {
  return batchWindowsStorage(() => {
  ownedControlDirectory(path.dirname(lock)); ownedControlDirectory(lock, true);
  const record = privateFile(path.join(lock, RECORD));
  need(record.schema_version === 1 && /^[a-f0-9-]{36}$/.test(record.id) && record.lock === lock && [path.join(record.parent, 'ud-storage-' + record.id), path.join(record.parent, scratchName(record.id))].includes(record.directory), 'reservation identity differs');
  if (expected) need(record.id === expected.id && record.root === expected.root && record.directory === expected.directory && record.pid === expected.pid, 'inherited reservation differs');
  ordinaryDirectory(record.parent);
  if (existsSync(record.directory)) {
    if (process.platform === 'win32') ownedControlDirectory(record.directory, true); else ordinaryDirectory(record.directory);
    const marker = privateFile(path.join(record.directory, MARKER));
    need(marker.id === record.id && marker.lock === lock, 'scratch ownership marker differs');
  }
  return record;
  });
}
/** Return the verified parent scratch for a subprocess in an active lease. */
export function inheritedStorageDirectory(env = process.env) {
  if (!env[ENV]) return undefined;
  let token;
  try { token = JSON.parse(Buffer.from(env[ENV], 'base64url').toString()); }
  catch { throw new Error('Storage admission: invalid inherited reservation'); }
  const record = verifyRecord(token.lock, token);
  need(running(record.pid), 'inherited owner is gone');
  ordinaryDirectory(record.directory);
  return record.directory;
}
/** Borrow only the exact scratch/output budget of a supervising process. */
/** @param {{root:string,output?:string,plannedBytes:number,plannedOutputBytes?:number,env?:NodeJS.ProcessEnv}} options */
function inheritedStorage({ root, output, plannedBytes, plannedOutputBytes = 0, env = process.env }) {
  let token;
  try { token = JSON.parse(Buffer.from(env[ENV] ?? '', 'base64url').toString()); }
  catch { throw new Error('Storage admission: invalid inherited reservation'); }
  const record = verifyRecord(token.lock, token);
  need(running(record.pid) && record.root === path.resolve(root) && (output === undefined ? record.outputPath === undefined : record.outputPath === path.resolve(output)), 'inherited output reservation differs');
  need(record.profile === 'release' && bytes(plannedBytes) && plannedBytes <= record.plannedBytes && bytes(plannedOutputBytes) && plannedOutputBytes <= record.plannedOutputBytes, 'inherited output budget differs');
  ordinaryDirectory(record.directory);
  const markerBytes = storageTreeBytes(path.join(record.directory, MARKER));
  const id = randomUUID(), childFile = path.join(record.lock, 'child-' + id);
  const child = { parent_id: record.id, id, pid: process.pid, plannedBytes: 0, directory: record.directory, process_group: process.platform !== 'win32' ? process.pid : null };
  writeJson(childFile, child);
  let closed = false;
  return {
    directory: record.directory,
    env: { ...windowsStorageLeaseEnvironment(), [ENV]: env[ENV] },
    check(outputBytes = 0) {
      need(!closed && running(record.pid), 'supervising owner is gone');
      verifyRecord(record.lock, token);
      need(bytes(outputBytes) && outputBytes <= record.plannedOutputBytes, 'output exceeds its declared plan');
      need(storageTreeBytes(record.directory, record.plannedBytes + markerBytes) - markerBytes <= record.plannedBytes, 'scratch exceeds its declared plan');
      need(Math.min(freeBytes(record.root), freeBytes(record.directory), record.outputParent === undefined ? Number.MAX_SAFE_INTEGER : freeBytes(record.outputParent)) >= record.limits.freeReserveBytes, 'free-space reserve would be consumed');
    },
    cleanup() {
      if (closed) return;
      const current = privateFile(childFile);
      need(current.id === id && current.parent_id === record.id && current.pid === process.pid, 'borrowed reservation identity changed');
      rmSync(childFile); closed = true;
    },
    supervisorPid: record.pid,
  };
}
export function inheritedOutputStorage(options) { return inheritedStorage(options); }
export function inheritedScratchStorage({ root, plannedBytes, env = process.env }) { return inheritedStorage({ root, plannedBytes, env }); }
/** Stop an owned worker group if its storage supervisor dies unexpectedly. */
export function watchStorageSupervisor(supervisorPid) {
  need(Number.isSafeInteger(supervisorPid) && supervisorPid > 0, 'invalid supervising process');
  const program = `const {spawnSync}=require('node:child_process');const parent=Number(process.argv[1]),worker=Number(process.argv[2]);let stopping=false;const alive=p=>{try{process.kill(p,0);return true}catch(e){return e.code!=='ESRCH'}};process.on('SIGTERM',()=>{});setInterval(()=>{if(!alive(worker))process.exit(0);if(stopping||alive(parent))return;stopping=true;if(process.platform==='win32'){spawnSync('taskkill',['/PID',String(worker),'/T','/F'],{stdio:'ignore'});process.exit(0)}try{process.kill(-worker,'SIGTERM')}catch{}setTimeout(()=>{try{process.kill(-worker,'SIGKILL')}catch{}process.exit(0)},1000)},250);`;
  const watcher = spawn(process.execPath, ['-e', program, String(supervisorPid), String(process.pid)], { stdio: 'ignore', windowsHide: true });
  watcher.unref();
  return watcher;
}
/** Recover only an exact recorded scratch tree whose owner is demonstrably gone. */
export function recoverStorage(root) {
  root = ordinaryDirectory(root);
  const lock = path.join(root, '.artifacts', '.storage-reservation');
  if (!existsSync(lock)) return false;
  const record = verifyRecord(lock);
  need(record.root === root && !running(record.pid), 'another storage owner is active or ambiguous');
  need(readdirSync(lock).every(name => name === RECORD || /^child-[a-f0-9-]{36}$/.test(name)), 'reservation lock contains an unowned entry');
  for (const name of readdirSync(lock).filter(name => name.startsWith('child-'))) {
    const child = privateFile(path.join(lock, name));
    need(child.parent_id === record.id && !running(child.pid), 'a child storage owner remains active');
    if (child.process_group && process.platform !== 'win32') {
      let exists = false;
      try { process.kill(-child.process_group, 0); exists = true; } catch (error) { if (error.code !== 'ESRCH') throw error; }
      need(!exists, 'a child storage process group remains active');
    }
  }
  rmSync(record.directory, { recursive: true, force: true }); rmSync(lock, { recursive: true });
  return true;
}
function safeTarget(directory, relative) {
  need(typeof relative === 'string' && relative.length && !relative.includes('\\') && !relative.includes(':') && !relative.includes('\0') && !path.isAbsolute(relative) && relative.split('/').every(part => part && part !== '.' && part !== '..' && part !== MARKER), 'unsafe scratch path');
  let parent = directory;
  const parts = relative.split('/');
  for (const part of parts.slice(0, -1)) {
    parent = path.join(parent, part);
    if (existsSync(parent)) ordinaryDirectory(parent); else mkdirSync(parent, { mode: 0o700 });
  }
  return path.join(directory, ...parts);
}

/**
 * Reserve once per heavy workflow. Children explicitly inherit lease.env.
 * @param {{root?: string, plannedBytes?: number, plannedOutputBytes?: number, outputParent?: string, outputPath?: string, externalOwnedBytes?: number, ownedRoots?: string[], profile?: string, inputRoots?: string[], scratchParent?: string, label?: string, limits?: Partial<typeof STORAGE_LIMITS>, transientAllowance?: number, env?: NodeJS.ProcessEnv, onCancel?: () => void | Promise<void>}} [options]
 */
export function reserveStorage({ root, plannedBytes, plannedOutputBytes = 0, outputParent, outputPath, externalOwnedBytes = 0, ownedRoots = [], profile = 'ordinary', inputRoots = [], scratchParent = os.tmpdir(), label = 'workflow', limits: overrides, transientAllowance, env = process.env, onCancel } = {}) {
  need(transientAllowance === undefined || profile === 'release', 'local transient allowance requires an explicit release profile');
  const limits = limitsFor(overrides, transientAllowance);
  need(['ordinary', 'release'].includes(profile) && bytes(plannedBytes) && plannedBytes > 0 && plannedBytes <= limits[profile === 'release' ? 'releaseBytes' : 'ordinaryBytes'], 'an explicit bounded scratch plan and profile are required');
  need(bytes(plannedOutputBytes), 'output storage must have a finite byte count');
  need(bytes(externalOwnedBytes), 'external owned storage must have a finite observed byte count');
  need(Array.isArray(ownedRoots) && ownedRoots.every(file => typeof file === 'string' && path.isAbsolute(file)), 'owned storage roots must be absolute paths');
  root = ordinaryDirectory(root); scratchParent = realpathSync(scratchParent); ordinaryDirectory(scratchParent);
  if (outputParent !== undefined) outputParent = ordinaryDirectory(outputParent);
  if (outputPath !== undefined) need(path.isAbsolute(outputPath) && outputParent !== undefined && inside(outputParent, path.resolve(outputPath)) && plannedOutputBytes > 0, 'output path must have an admitted parent and budget');
  need(typeof label === 'string' && label.length <= 120, 'invalid reservation label');
  let record, child, lock, directory, admission;
  if (env[ENV]) {
    let token; try { token = JSON.parse(Buffer.from(env[ENV], 'base64url').toString()); } catch { throw new Error('Storage admission: invalid inherited reservation'); }
    lock = token.lock; record = verifyRecord(lock, token); need(running(record.pid), 'inherited owner is gone');
    need(transientAllowance === undefined || transientAllowance <= (record.transient_allowance?.bytes ?? STORAGE_LIMITS.releaseBytes), 'a child cannot increase the parent transient allowance');
    need(externalOwnedBytes <= (record.externalOwnedBytes ?? 0), 'external owned bytes must be admitted by the parent reservation');
    need(ownedRoots.every(file => (record.ownedRoots ?? []).some(parent => inside(parent, path.resolve(file))) || inside(record.root, path.resolve(file))), 'external owned roots must be admitted by the parent reservation');
    need(plannedOutputBytes === 0, 'a child cannot independently allocate the parent output budget');
    need(outputParent === undefined, 'a child cannot independently choose a parent output filesystem');
    need(outputPath === undefined, 'a child cannot independently choose a parent output path');
    need(bytes(plannedBytes) && plannedBytes > 0 && plannedBytes <= record.plannedBytes, 'child plan exceeds parent reservation');
    const childLock = path.join(lock, 'joining'); privateDirectory(childLock);
    try {
      const reserved = readdirSync(lock).filter(name => name.startsWith('child-')).reduce((sum, name) => sum + privateFile(path.join(lock, name)).plannedBytes, 0);
      need(storageTreeBytes(record.directory, record.plannedBytes) + reserved + plannedBytes <= record.plannedBytes, 'concurrent child plans exceed parent reservation');
      const id = randomUUID(); directory = path.join(record.directory, 'child-' + id);
      child = { parent_id: record.id, id, pid: process.pid, plannedBytes, directory };
      writeJson(path.join(lock, 'child-' + id), child);
    } finally { rmSync(childLock, { recursive: true }); }
  } else {
    const artifacts = path.join(root, '.artifacts');
    if (existsSync(artifacts)) ownedControlDirectory(artifacts);
    lock = path.join(artifacts, '.storage-reservation');
    // A dead owner's exact scratch must be reclaimed before it can prevent its
    // own admission; an active or ambiguous owner still blocks this request.
    if (existsSync(lock)) recoverStorage(root);
    const id = randomUUID(); directory = path.join(scratchParent, scratchName(id));
    record = { schema_version: 1, id, pid: process.pid, root, lock, parent: scratchParent, directory, plannedBytes, plannedOutputBytes, ...(outputParent === undefined ? {} : { outputParent }), ...(outputPath === undefined ? {} : { outputPath: path.resolve(outputPath) }), externalOwnedBytes, ownedRoots: ownedRoots.map(file => path.resolve(file)), profile, limits, label, ...(transientAllowance === undefined ? {} : { transient_allowance: { kind: 'explicit-local-operator-opt-in', bytes: transientAllowance } }) };
    for (const input of inputRoots) need(!inside(realpathSync(input), directory), 'scratch output is nested inside an input tree');
    // No payload or lock is created before a real measurement admits this job.
    admission = assertStorageAdmission({ plannedBytes, plannedOutputBytes, profile, ownedBytes: ownedStorageBytes([root, ...ownedRoots], limits.totalBytes) + externalOwnedBytes, freeBytes: Math.min(freeBytes(root), freeBytes(scratchParent), outputParent === undefined ? Number.MAX_SAFE_INTEGER : freeBytes(outputParent)), limits, transientAllowance });
    if (!existsSync(artifacts)) privateDirectory(artifacts);
    privateDirectory(lock);
    try { writeJson(path.join(lock, RECORD), record); } catch (error) { rmSync(lock, { recursive: true }); throw error; }
  }
  let created = false;
  try {
    for (const input of inputRoots) need(!inside(realpathSync(input), directory), 'scratch output is nested inside an input tree');
    privateDirectory(directory); created = true; writeJson(path.join(directory, MARKER), { id: child?.id ?? record.id, lock, parent_id: child ? record.id : null });
  } catch (error) {
    if (created) rmSync(directory, { recursive: true });
    if (child) rmSync(path.join(lock, 'child-' + child.id)); else rmSync(lock, { recursive: true });
    throw error;
  }
  const ownerFile = path.join(directory, MARKER), baselineBytes = storageTreeBytes(directory);
  let usedBytes = 0, closed = false;
  function verifyOwner() {
    return batchWindowsStorage(() => {
    need(!closed, 'reservation is already closed'); verifyRecord(lock, record);
    if (process.platform === 'win32') ownedControlDirectory(directory, true); else ordinaryDirectory(directory);
    const marker = privateFile(ownerFile); need(marker.id === (child?.id ?? record.id) && marker.lock === lock, 'scratch ownership changed');
    });
  }
  function check(additionalBytes = 0) {
    verifyOwner(); need(bytes(additionalBytes), 'invalid additional byte count');
    usedBytes = storageTreeBytes(directory, plannedBytes + baselineBytes) - baselineBytes;
    const output = child ? 0 : plannedOutputBytes;
    const chargedScratch = output ? 0 : additionalBytes;
    if (output) need(additionalBytes <= output, 'output exceeds its declared plan');
    need(usedBytes + chargedScratch <= plannedBytes, 'scratch exceeds its declared plan');
    need(storageTreeBytes(record.directory, record.plannedBytes + baselineBytes) + chargedScratch <= record.plannedBytes + baselineBytes, 'shared scratch exceeds its declared plan');
    const available = Math.min(freeBytes(record.root), freeBytes(directory), record.outputParent === undefined ? Number.MAX_SAFE_INTEGER : freeBytes(record.outputParent));
    need(available - additionalBytes >= limits.freeReserveBytes, 'free-space reserve would be consumed');
    return { usedBytes, plannedBytes, plannedOutputBytes: output, outputBytes: output ? additionalBytes : 0, freeBytes: available };
  }
  function beforeWrite(size) {
    verifyOwner(); need(bytes(size), 'invalid write size');
    try { check(); need(usedBytes + size <= plannedBytes, 'scratch exceeds its declared plan'); } catch (error) {
      if (/scratch exceeds/.test(error.message)) throw new Error('Storage admission: write exceeds its declared scratch plan');
      throw error;
    }
    if (!child) need(!readdirSync(lock).some(name => name.startsWith('child-')), 'parent writes must wait for child cleanup');
    need(Math.min(freeBytes(record.root), freeBytes(directory), record.outputParent === undefined ? Number.MAX_SAFE_INTEGER : freeBytes(record.outputParent)) - size >= limits.freeReserveBytes, 'write would consume free-space reserve');
  }
  function write(relative, body) {
    const data = Buffer.isBuffer(body) ? body : Buffer.from(body); beforeWrite(data.length);
    const target = safeTarget(directory, relative); writeFileSync(target, data, { flag: 'wx', mode: 0o600 }); usedBytes += data.length; return target;
  }
  function copy(source, relative, expected = {}) {
    const input = openSync(source, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); let output, target;
    try {
      const info = fstatSync(input); need(info.isFile() && (expected.size === undefined || expected.size === info.size), 'copy input size or type differs'); beforeWrite(info.size);
      target = safeTarget(directory, relative); output = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), info.mode & 0o111 ? 0o700 : 0o600);
      const buffer = Buffer.alloc(Math.min(1024 ** 2, info.size + 1)), hash = createHash('sha256'); let copied = 0;
      for (;;) { const count = readSync(input, buffer, 0, buffer.length, null); if (!count) break; need(copied + count <= info.size, 'copy input grew'); let offset = 0; while (offset < count) offset += writeSync(output, buffer, offset, count - offset); copied += count; hash.update(buffer.subarray(0, count)); }
      const after = fstatSync(input), digest = hash.digest('hex');
      need(copied === info.size && after.size === info.size && after.mtimeMs === info.mtimeMs && after.ctimeMs === info.ctimeMs && (expected.sha256 === undefined || expected.sha256 === digest), 'copy input changed or hash differs');
      usedBytes += copied; return target;
    } catch (error) { if (output !== undefined) { closeSync(output); output = undefined; } if (target) rmSync(target, { force: true }); throw error; }
    finally { closeSync(input); if (output !== undefined) closeSync(output); }
  }
  function cleanup() {
    if (closed) return;
    verifyOwner();
    if (!child) for (const name of readdirSync(lock).filter(name => name.startsWith('child-'))) need(!running(privateFile(path.join(lock, name)).pid), 'child must finish before parent cleanup');
    rmSync(directory, { recursive: true });
    if (child) rmSync(path.join(lock, 'child-' + child.id)); else rmSync(lock, { recursive: true });
    closed = true; process.removeListener('exit', exit); process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate);
  }
  function exit() { try { cleanup(); } catch { /* Exact ownership record remains for restart recovery. */ } }
  async function signal(code) { try { await onCancel?.(); cleanup(); } catch (error) { process.stderr.write(`${error.message}\n`); } process.exit(code); }
  const interrupt = () => signal(130), terminate = () => signal(143);
  process.once('exit', exit); process.once('SIGINT', interrupt); process.once('SIGTERM', terminate);
  return { directory, plannedBytes, plannedOutputBytes, admission, env: { ...windowsStorageLeaseEnvironment(), [ENV]: Buffer.from(JSON.stringify({ lock, id: record.id, root: record.root, directory: record.directory, pid: record.pid })).toString('base64url') }, check, write, copy, cleanup };
}
export async function withStorage(options, callback) {
  const lease = reserveStorage(options);
  try { return await callback(lease); } finally { lease.cleanup(); }
}

/** Thin wrapper for existing native/Python drivers; no alternate test framework. */
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const [mode, root, planned, profile, ...rest] = process.argv.slice(2);
  const ownedRoots = []; let externalOwnedBytes = 0, externalSpecified = false, outputPath, plannedOutputBytes, scratchParent, callerPid, transferJournal, sharedInputs, transientAllowance;
  while (rest.length && rest[0] !== '--') {
    const key = rest.shift(), value = rest.shift();
    if (key === '--owned-root' && value && path.isAbsolute(value)) ownedRoots.push(value);
    else if (key === '--external-owned-bytes' && !externalSpecified && /^\d+$/.test(value ?? '')) { externalOwnedBytes = Number(value); externalSpecified = true; }
    else if (key === '--output' && outputPath === undefined && value && path.isAbsolute(value)) outputPath = path.resolve(value);
    else if (key === '--output-bytes' && plannedOutputBytes === undefined && /^\d+$/.test(value ?? '')) plannedOutputBytes = Number(value);
    else if (key === '--scratch-parent' && scratchParent === undefined && value && path.isAbsolute(value)) scratchParent = path.resolve(value);
    else if (key === '--transient-bytes' && transientAllowance === undefined && /^\d+$/.test(value ?? '') && bytes(Number(value)) && Number(value) > 0) transientAllowance = Number(value);
    else if (key === '--caller-pid' && callerPid === undefined && /^\d+$/.test(value ?? '') && Number.isSafeInteger(Number(value)) && Number(value) > 0) callerPid = Number(value);
    else if (key === '--output-transfer-journal' && transferJournal === undefined && value && path.isAbsolute(value)) transferJournal = path.resolve(value);
    else if (key === '--output-shared-inputs' && sharedInputs === undefined && value && value.length<=128*1024) { try { sharedInputs=JSON.parse(Buffer.from(value,'base64url').toString('utf8')); } catch { throw new Error('Storage admission: invalid shared output identities'); } need(Array.isArray(sharedInputs)&&sharedInputs.length<=1000,'invalid shared output identities'); }
    else throw new Error('Storage admission: invalid owned storage option');
  }
  const separator = rest.shift(), command = rest.shift(), args = rest;
  need(mode === '--run' && root && /^\d+$/.test(planned ?? '') && separator === '--' && command, 'usage: storage-lifecycle.mjs --run ROOT PLANNED_BYTES ordinary|release [--transient-bytes N] [--owned-root PATH] [--external-owned-bytes N] [--output PATH --output-bytes N] -- COMMAND [ARGS]; {scratch} expands to owned scratch');
  need(outputPath === undefined && plannedOutputBytes === undefined || outputPath !== undefined && bytes(plannedOutputBytes) && plannedOutputBytes > 0 && !lstatSync(outputPath, { throwIfNoEntry: false }), 'output requires a new path and an explicit positive byte budget');
  if (transferJournal !== undefined) need(outputPath !== undefined && transferJournal === path.join(path.resolve(root), '.artifacts/storage/source-transfer.json'), 'transfer journal has another owner or output');
  if (sharedInputs !== undefined) need(outputPath !== undefined, 'shared output requires an output path');
  let outputParent = outputPath === undefined ? undefined : path.dirname(outputPath);
  while (outputParent !== undefined && !existsSync(outputParent)) {
    const parent = path.dirname(outputParent);
    need(parent !== outputParent, 'output has no existing parent');
    outputParent = parent;
  }
  if (outputParent !== undefined) outputParent = ordinaryDirectory(outputParent);
  let child, completion, forceStop, monitor, monitorError, executionError;
  const group = process.platform !== 'win32';
  function send(signal) {
    if (!child?.pid) return;
    try { if (group) process.kill(-child.pid, signal); else child.kill(signal); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  function stop() {
    send('SIGTERM');
    forceStop ??= setTimeout(() => { try { send('SIGKILL'); } catch (error) { monitorError ??= error; } }, 2000);
    forceStop.unref();
  }
  const lease = reserveStorage({ root, plannedBytes: Number(planned), plannedOutputBytes: plannedOutputBytes ?? 0, outputParent, outputPath, ownedRoots, externalOwnedBytes, profile, scratchParent, transientAllowance, label: path.basename(command), onCancel: async () => {
    if (!child) return;
    stop();
    // The command's leader can exit while descendants still hold the group.
    try { await completion; } finally { send('SIGKILL'); clearTimeout(forceStop); }
  } });
  try {
    const expand = value => value === '{scratch}' || value.startsWith('{scratch}/') ? lease.directory + value.slice('{scratch}'.length) : value;
    child = spawn(command, args.map(expand), { env: { ...process.env, ...lease.env, UD_STORAGE_DIRECTORY: lease.directory }, stdio: 'inherit', detached: group });
    completion = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
    // Admission is checked once. Execution does not repeatedly walk build
    // trees or turn a completed command into a byte-budget failure.
    if (callerPid !== undefined) monitor = setInterval(() => { try {
      need(running(callerPid), 'supervising caller stopped');
    } catch (error) { monitorError ??= error; stop(); } }, 500);
    const result = await completion;
    if (monitorError) { send('SIGKILL'); throw monitorError; }
    if (outputPath !== undefined) need(!lstatSync(outputPath, { throwIfNoEntry: false })?.isSymbolicLink(), 'output path became a symbolic link');
    process.exitCode = result.signal ? 1 : result.code ?? 1;
  } catch (error) { executionError = error; throw error; }
  finally {
    clearInterval(monitor); clearTimeout(forceStop);
    try { lease.cleanup(); }
    catch (cleanupError) {
      // Interrupted original tests can leave sealed fixture directories. Keep
      // the execution failure that stopped them as well as the cleanup error.
      if (executionError) throw new AggregateError([executionError, cleanupError], 'Storage command failed and owned cleanup also failed', { cause: executionError });
      throw cleanupError;
    }
  }
}
