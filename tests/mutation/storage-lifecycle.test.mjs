import { test, expect, vi } from 'vitest';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statfsSync, symlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PROTECTED_MUTATION_SCRATCH_BYTES, STORAGE_LIMITS, assertStorageAdmission, mutationStoragePlan, ownedStorageBytes, recoverStorage, reserveStorage, stableOutputBytes, storageTreeBytes, withStorage } from '../../scripts/quality/storage-lifecycle.mjs';

vi.mock('node:fs', async importOriginal => {
  const original = await importOriginal();
  return { ...original, lstatSync: vi.fn(original.lstatSync), readdirSync: vi.fn(original.readdirSync), statfsSync: vi.fn(original.statfsSync) };
});

const originalFs = await vi.importActual('node:fs');
const helper = new URL('../../scripts/quality/storage-lifecycle.mjs', import.meta.url).href;
function fixture() { return realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-storage-test-'))); }
const remove = root => rmSync(root, { recursive: true, force: true });

// Model only platform selection, transient inspection errors and elapsed time;
// successful observations still read the real fixture files and native inodes.
function inspectionModel(platform, run) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform'); let elapsed = 0;
  Object.defineProperty(process, 'platform', { ...descriptor, value: platform });
  const clock = vi.spyOn(performance, 'now').mockImplementation(() => elapsed);
  const wait = vi.spyOn(Atomics, 'wait').mockImplementation((_array, _index, _value, delay) => { elapsed += delay; return 'timed-out'; });
  try { return run({ wait, advance: amount => { elapsed += amount; } }); }
  finally { clock.mockRestore(); wait.mockRestore(); vi.mocked(lstatSync).mockReset(); vi.mocked(readdirSync).mockReset(); Object.defineProperty(process, 'platform', descriptor); }
}

test('storage policy fixes total, ordinary, release and free-reserve limits', () => {
  expect(STORAGE_LIMITS).toEqual({ totalBytes: 72_000_000_000, ordinaryBytes: 2_000_000_000, releaseBytes: 4_000_000_000, freeReserveBytes: 10_000_000_000 });
  const base = { plannedBytes: 512, ownedBytes: 1024, freeBytes: STORAGE_LIMITS.freeReserveBytes + 512 };
  expect(assertStorageAdmission(base).plannedBytes).toBe(512);
  for (const bad of [{ plannedBytes: undefined }, { plannedBytes: Infinity }, { plannedBytes: 0 }, { plannedBytes: STORAGE_LIMITS.ordinaryBytes + 1 }, { ownedBytes: STORAGE_LIMITS.totalBytes }, { freeBytes: STORAGE_LIMITS.freeReserveBytes + 511 }, { profile: 'unlimited' }, { limits: { ordinaryBytes: STORAGE_LIMITS.ordinaryBytes + 1 } }]) expect(() => assertStorageAdmission({ ...base, ...bad })).toThrow(/Storage admission/);
  expect(assertStorageAdmission({ ...base, profile: 'release', plannedBytes: STORAGE_LIMITS.releaseBytes, freeBytes: STORAGE_LIMITS.releaseBytes + STORAGE_LIMITS.freeReserveBytes }).profile).toBe('release');
});

test('output accounting retries when a transferred inode crosses the scan',()=>{
  const sequence=[{bytes:0,identity:''},{bytes:100,identity:'first'},{bytes:100,identity:'first'},{bytes:100,identity:'first'}];let scans=0;
  expect(stableOutputBytes(()=>{scans++;return 107;},()=>sequence.shift())).toBe(7);expect(scans).toBe(2);
  const sameSize=[{bytes:100,identity:'old'},{bytes:100,identity:'new'},{bytes:100,identity:'new'},{bytes:100,identity:'new'}];
  expect(stableOutputBytes(()=>105,()=>sameSize.shift())).toBe(5);
  let attempts=0;expect(()=>stableOutputBytes(()=>100,()=>({bytes:0,identity:String(attempts++)}))).toThrow(/did not settle/);
});
test('explicit large release allowance preserves the total and free reserves', () => {
  const base = { plannedBytes: 5_000_000_000, profile: 'release', transientAllowance: 48_000_000_000, ownedBytes: 1_000_000_000, freeBytes: 30_000_000_000 };
  expect(assertStorageAdmission(base).limits.releaseBytes).toBe(48_000_000_000);
  expect(STORAGE_LIMITS.releaseBytes).toBe(4_000_000_000);
  for (const bad of [{ transientAllowance: undefined }, { transientAllowance: 48_000_000_001 }, { profile: 'ordinary' }, { ownedBytes: STORAGE_LIMITS.totalBytes - base.plannedBytes + 1 }, { freeBytes: 14_999_999_999 }, { limits: { totalBytes: STORAGE_LIMITS.totalBytes + 1 } }]) expect(() => assertStorageAdmission({ ...base, ...bad })).toThrow(/Storage admission/);
  const root = fixture();
  try {
    // Exercise large admission budgets with explicit free-space observations;
    // the fixture itself writes only small owned records on the real disk.
    vi.mocked(statfsSync).mockReturnValue({ bavail: 14_999_999_999n, bsize: 1n });
    expect(() => reserveStorage({ root, profile: 'release', plannedBytes: 5_000_000_000, transientAllowance: 12_000_000_000 })).toThrow(/free reserve/);
    vi.mocked(statfsSync).mockReturnValue({ bavail: 30_000_000_000n, bsize: 1n });
    const lease = reserveStorage({ root, profile: 'release', plannedBytes: 5_000_000_000, transientAllowance: 12_000_000_000 });
    const token = JSON.parse(Buffer.from(lease.env.UD_STORAGE_LEASE, 'base64url'));
    const record = JSON.parse(readFileSync(path.join(token.lock, 'reservation.json')));
    expect(record.transient_allowance).toEqual({ kind: 'explicit-local-operator-opt-in', bytes: 12_000_000_000 });
    lease.cleanup();
    const parent = reserveStorage({ root, plannedBytes: 4096 });
    try { expect(() => reserveStorage({ root, profile: 'release', plannedBytes: 512, transientAllowance: 12_000_000_000, env: parent.env })).toThrow(/parent transient allowance/); }
    finally { parent.cleanup(); }
  } finally { vi.mocked(statfsSync).mockReset(); remove(root); }
});

test('mutation planning charges immutable input, worker copy and compact evidence', () => {
  const result = mutationStoragePlan(1000, 4);
  expect(result.inputBytes).toBe(1000 + 4 * 8192 + 16 * 1024 ** 2);
  expect(result.stateBytes).toBe(result.inputBytes + 1024 * 1024 ** 2);
  expect(result.plannedBytes).toBe(result.inputBytes + result.stateBytes + result.reportBytes);
  const native = mutationStoragePlan(120_000_000, 2200);
  expect(native.stateBytes).toBeGreaterThan(1_000_000_000);
  expect(native.plannedBytes).toBeLessThanOrEqual(STORAGE_LIMITS.ordinaryBytes);
  expect(native.profile).toBe('ordinary');
  const frozenSourceBytes = 642_000_000;
  const frozen = mutationStoragePlan(frozenSourceBytes, 18107);
  expect(frozen.profile).toBe('release');
  expect(frozen.plannedBytes).toBeGreaterThan(STORAGE_LIMITS.ordinaryBytes);
  expect(frozenSourceBytes + frozen.plannedBytes).toBeLessThan(PROTECTED_MUTATION_SCRATCH_BYTES);
  const larger = mutationStoragePlan(1_500_000_000, 18107);
  expect(larger.transientAllowance).toBe(PROTECTED_MUTATION_SCRATCH_BYTES);
  for (const bad of [[-1, 2], [1, 0], [Infinity, 2], [PROTECTED_MUTATION_SCRATCH_BYTES, 1]]) expect(() => mutationStoragePlan(...bad)).toThrow(/Storage admission/);
});

test('over-budget admission creates neither reservation nor scratch', () => {
  const root = fixture();
  try {
    expect(() => reserveStorage({ root, plannedBytes: STORAGE_LIMITS.ordinaryBytes + 1 })).toThrow(/bounded scratch plan/);
    expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
  } finally { remove(root); }
});

test('observed external owned storage is charged without contacting an engine', () => {
  const root = fixture(); let lease;
  try {
    expect(() => reserveStorage({ root, plannedBytes: 1, externalOwnedBytes: STORAGE_LIMITS.totalBytes })).toThrow(/owned working total/);
    expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
    expect(() => reserveStorage({ root, plannedBytes: 1, externalOwnedBytes: NaN })).toThrow(/finite observed/);
    lease = reserveStorage({ root, plannedBytes: 1024, externalOwnedBytes: 4096 });
    expect(lease.admission.ownedBytes).toBe(4096);
    expect(() => reserveStorage({ root, plannedBytes: 1, externalOwnedBytes: 4097, env: lease.env })).toThrow(/admitted by the parent/);
  } finally { lease?.cleanup(); remove(root); }
});

test('retained output has its own finite budget within total and reserve', () => {
  const root = fixture(); let lease;
  try {
    const base = { plannedBytes: 5, plannedOutputBytes: 8, ownedBytes: 0, freeBytes: STORAGE_LIMITS.freeReserveBytes + 13, limits: { totalBytes: 13 } };
    expect(assertStorageAdmission(base).plannedOutputBytes).toBe(8);
    expect(() => assertStorageAdmission({ ...base, plannedOutputBytes: 9 })).toThrow(/owned working total/);
    expect(() => assertStorageAdmission({ ...base, freeBytes: STORAGE_LIMITS.freeReserveBytes + 12 })).toThrow(/free reserve/);
    expect(() => assertStorageAdmission({ ...base, plannedOutputBytes: Infinity })).toThrow(/finite/);
    lease = reserveStorage({ root, plannedBytes: 5, plannedOutputBytes: 8, limits: { totalBytes: 13 } });
    lease.write('scratch', '12345');
    writeFileSync(path.join(root, 'output'), '12345678');
    expect(lease.check(8)).toMatchObject({ usedBytes: 5, outputBytes: 8 });
    expect(() => lease.check(9)).toThrow(/output exceeds/);
    expect(() => lease.write('overflow', 'x')).toThrow(/write exceeds/);
    expect(() => reserveStorage({ root, plannedBytes: 1, plannedOutputBytes: 1, env: lease.env })).toThrow(/child cannot/);
  } finally { lease?.cleanup(); remove(root); }
});

test('whole project and explicit external roots are counted once, including hard links', () => {
  const root = fixture(), external = fixture(); let lease;
  try {
    mkdirSync(path.join(root, 'node_modules')); mkdirSync(path.join(root, '.venv'));
    writeFileSync(path.join(root, 'node_modules', 'dependency'), 'abcdefghij');
    writeFileSync(path.join(root, '.venv', 'interpreter'), '12345');
    linkSync(path.join(root, 'node_modules', 'dependency'), path.join(external, 'same-bytes'));
    writeFileSync(path.join(external, 'other'), '1234567');
    expect(ownedStorageBytes([root, path.join(root, 'node_modules'), external])).toBe(22);
    expect(() => reserveStorage({ root, ownedRoots: [external], plannedBytes: 100, limits: { totalBytes: 121 } })).toThrow(/owned working total/);
    expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
    lease = reserveStorage({ root, ownedRoots: [external, path.join(root, 'node_modules')], plannedBytes: 100, externalOwnedBytes: 3 });
    expect(lease.admission.ownedBytes).toBe(25);
    expect(() => reserveStorage({ root, ownedRoots: [os.tmpdir()], plannedBytes: 1, env: lease.env })).toThrow(/admitted by the parent/);
  } finally { lease?.cleanup(); remove(root); remove(external); }
});

test('one heavy owner excludes another and bounded writes stop before output', () => {
  const root = fixture(), lease = reserveStorage({ root, plannedBytes: 16 });
  try {
    expect(() => reserveStorage({ root, plannedBytes: 1 })).toThrow(/active or ambiguous/);
    expect(readFileSync(lease.write('nested/example', 'independent'), 'utf8')).toBe('independent');
    expect(() => lease.write('overflow', 'too much')).toThrow(/write exceeds/);
    expect(existsSync(path.join(lease.directory, 'overflow'))).toBe(false);
    expect(lease.check().usedBytes).toBe(11);
  } finally { lease.cleanup(); remove(root); }
});

test('copies verify expected bytes and delete altered input outputs', () => {
  const root = fixture(), lease = reserveStorage({ root, plannedBytes: 20 });
  try {
    const source = path.join(root, 'input'); writeFileSync(source, 'abc');
    expect(readFileSync(lease.copy(source, 'good', { size: 3, sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' }), 'utf8')).toBe('abc');
    expect(() => lease.copy(source, 'changed', { sha256: '0'.repeat(64) })).toThrow(/hash differs/);
    expect(existsSync(path.join(lease.directory, 'changed'))).toBe(false);
    expect(() => lease.copy(source, 'size', { size: 4 })).toThrow(/size or type/);
  } finally { lease.cleanup(); remove(root); }
});

test('path escapes, linked destinations and outputs nested in inputs are refused', () => {
  const root = fixture(), lease = reserveStorage({ root, plannedBytes: 128 });
  try {
    for (const name of ['../escape', '/absolute', 'a/../../escape', 'a\\escape', '.ud-storage-owner.json']) expect(() => lease.write(name, 'x')).toThrow(/unsafe scratch path/);
    symlinkSync(root, path.join(lease.directory, 'foreign'));
    expect(() => lease.write('foreign/escape', 'x')).toThrow(/linked or special/);
    expect(existsSync(path.join(root, 'escape'))).toBe(false);
    expect(() => reserveStorage({ root: fixtureRoot(root), scratchParent: root, inputRoots: [root], plannedBytes: 128 })).toThrow(/nested inside/);
  } finally { lease.cleanup(); remove(root); }
});
function fixtureRoot(root) { const child = path.join(root, 'other-owner'); mkdirSync(child); return child; }

test('storage inventory never follows links into unrelated storage', () => {
  const root = fixture();
  try {
    const owned = path.join(root, 'owned'), foreign = path.join(root, 'foreign'); mkdirSync(owned); mkdirSync(foreign);
    writeFileSync(path.join(foreign, 'large'), Buffer.alloc(4096)); writeFileSync(path.join(owned, 'small'), 'ok'); symlinkSync(foreign, path.join(owned, 'linked'));
    expect(storageTreeBytes(owned)).toBe(2 + Buffer.byteLength(foreign));
    expect(() => storageTreeBytes(foreign, 1024)).toThrow(/byte budget \(observed_bytes=4096, limit_bytes=1024\)/);
  } finally { remove(root); }
});

test.each(['lstat', 'readdir'])('Windows inspection model retries %s denial until actual disappearance is observed', operation => {
  const root = fixture(), temporary = path.join(root, 'temporary'); mkdirSync(temporary);
  writeFileSync(path.join(temporary, 'removed'), 'temporary bytes'); writeFileSync(path.join(root, 'retained'), 'kept');
  try {
    inspectionModel('win32', ({ wait }) => {
      const denied = Object.assign(new Error('pending deletion'), { code: 'EPERM' }); let attempts = 0;
      const original = operation === 'lstat' ? originalFs.lstatSync : originalFs.readdirSync;
      vi.mocked(operation === 'lstat' ? lstatSync : readdirSync).mockImplementation((file, ...options) => {
        if (file === temporary && attempts++ === 0) throw denied;
        return original(file, ...options);
      });
      wait.mockImplementationOnce(() => { remove(temporary); return 'timed-out'; });
      expect(storageTreeBytes(root)).toBe(4);
      expect(attempts).toBe(2); expect(wait).toHaveBeenCalledTimes(1); expect(existsSync(temporary)).toBe(false);
      expect(storageTreeBytes(temporary)).toBe(0);
    });
  } finally { remove(root); }
});

test.each(['EPERM', 'EACCES', 'EBUSY'])('Windows inspection model counts fresh bytes after transient %s and retains hard-link and byte bounds', code => {
  const root = fixture(), file = path.join(root, 'data'); writeFileSync(file, 'old'); linkSync(file, path.join(root, 'same-inode'));
  try {
    inspectionModel('win32', ({ wait }) => {
      let attempts = 0;
      vi.mocked(lstatSync).mockImplementation((name, ...options) => {
        if (name === root && attempts++ === 0) throw Object.assign(new Error('temporarily busy'), { code });
        return originalFs.lstatSync(name, ...options);
      });
      wait.mockImplementationOnce(() => { writeFileSync(file, 'current'); return 'timed-out'; });
      expect(storageTreeBytes(root)).toBe(7); expect(wait).toHaveBeenCalledTimes(1);
      expect(() => storageTreeBytes(root, 6)).toThrow(/byte budget/);
      expect(readFileSync(file, 'utf8')).toBe('current');
    });
  } finally { remove(root); }
});

test.each(['lstat', 'readdir'])('Windows inspection model refuses persistent %s denial after one finite scan budget', operation => {
  const root = fixture(); writeFileSync(path.join(root, 'unread'), 'cannot be omitted');
  try {
    inspectionModel('win32', ({ wait }) => {
      const denied = Object.assign(new Error('persistent denial'), { code: 'EPERM' }); let attempts = 0;
      const original = operation === 'lstat' ? originalFs.lstatSync : originalFs.readdirSync;
      vi.mocked(operation === 'lstat' ? lstatSync : readdirSync).mockImplementation((file, ...options) => {
        if (file === root) { attempts++; throw denied; }
        return original(file, ...options);
      });
      expect(() => storageTreeBytes(root)).toThrow(denied);
      expect(attempts).toBe(11); expect(wait).toHaveBeenCalledTimes(10);
      expect(wait.mock.calls.reduce((sum, call) => sum + call[3], 0)).toBe(100);
    });
    expect(readFileSync(path.join(root, 'unread'), 'utf8')).toBe('cannot be omitted');
  } finally { remove(root); }
});

test('Windows inspection model shares its retry budget across all owned roots', () => {
  const parent = fixture(), roots = Array.from({ length: 12 }, (_, index) => path.join(parent, String(index).padStart(2, '0')));
  for (const root of roots) { mkdirSync(root); writeFileSync(path.join(root, 'data'), 'x'); }
  try {
    inspectionModel('win32', ({ wait }) => {
      const attempted = new Set(), denied = Object.assign(new Error('next root still busy'), { code: 'EBUSY' });
      vi.mocked(readdirSync).mockImplementation((file, ...options) => {
        if (roots.includes(file) && !attempted.has(file)) { attempted.add(file); throw denied; }
        return originalFs.readdirSync(file, ...options);
      });
      expect(() => ownedStorageBytes(roots)).toThrow(denied);
      expect(attempted.size).toBe(11); expect(wait).toHaveBeenCalledTimes(10);
    });
    expect(ownedStorageBytes(roots)).toBe(12);
  } finally { remove(parent); }
});

test('Windows inspection model stops retrying when the scan retry deadline expires', () => {
  const root = fixture();
  try {
    inspectionModel('win32', ({ wait, advance }) => {
      const denied = Object.assign(new Error('still inaccessible'), { code: 'EACCES' }); let attempts = 0;
      vi.mocked(readdirSync).mockImplementation(file => { expect(file).toBe(root); attempts++; throw denied; });
      wait.mockImplementationOnce(() => { advance(101); return 'timed-out'; });
      expect(() => storageTreeBytes(root)).toThrow(denied);
      expect(attempts).toBe(2); expect(wait).toHaveBeenCalledTimes(1);
    });
  } finally { remove(root); }
});

test.each([['win32', 'EIO'], ['linux', 'EPERM'], ['darwin', 'EACCES']])('inspection model immediately refuses %s %s outside the Windows transient policy', (platform, code) => {
  const root = fixture();
  try {
    inspectionModel(platform, ({ wait }) => {
      const denied = Object.assign(new Error('not retryable'), { code }); let attempts = 0;
      vi.mocked(lstatSync).mockImplementation(file => { expect(file).toBe(root); attempts++; throw denied; });
      expect(() => storageTreeBytes(root)).toThrow(denied);
      expect(attempts).toBe(1); expect(wait).not.toHaveBeenCalled();
    });
  } finally { remove(root); }
});

test('success, failure and repeated runs remove scratch while retaining external reports', async () => {
  const root = fixture(), report = path.join(root, 'report.json'); let directory;
  try {
    for (let index = 0; index < 3; index++) await withStorage({ root, plannedBytes: 16 }, lease => { directory = lease.directory; lease.write('data', 'payload'); writeFileSync(report, '{"observed":true}'); });
    expect(existsSync(directory)).toBe(false); expect(readFileSync(report, 'utf8')).toBe('{"observed":true}');
    await expect(withStorage({ root, plannedBytes: 16 }, lease => { directory = lease.directory; lease.write('data', 'payload'); throw new Error('observed failure'); })).rejects.toThrow('observed failure');
    expect(existsSync(directory)).toBe(false); expect(storageTreeBytes(path.join(root, '.artifacts'))).toBe(0);
  } finally { remove(root); }
}, 30_000);

test('external writes are measured and exceeding a declared plan fails', () => {
  const root = fixture(), lease = reserveStorage({ root, plannedBytes: 8 });
  try { writeFileSync(path.join(lease.directory, 'external'), 'ninebytes'); expect(() => lease.check()).toThrow(/budget|plan/); }
  finally { lease.cleanup(); remove(root); }
});

test('explicit child leases share the budget and cannot release the parent', () => {
  const root = fixture(), parent = reserveStorage({ root, plannedBytes: 4096 }); let child;
  try {
    child = reserveStorage({ root, plannedBytes: 512, env: parent.env }); child.write('result', 'child');
    expect(child.directory.startsWith(parent.directory + path.sep)).toBe(true);
    expect(() => parent.cleanup()).toThrow(/child must finish/);
    child.cleanup(); expect(existsSync(parent.directory)).toBe(true);
    parent.write('parent', 'still owns reservation');
    expect(() => reserveStorage({ root, plannedBytes: 4096, env: parent.env })).toThrow(/child plans/);
    expect(() => reserveStorage({ root, plannedBytes: 1, env: { UD_STORAGE_LEASE: 'forged' } })).toThrow(/inherited reservation/);
  } finally { child?.cleanup(); parent.cleanup(); remove(root); }
}, 30_000);

test('owned marker changes block cleanup rather than deleting foreign content', () => {
  const root = fixture(), lease = reserveStorage({ root, plannedBytes: 128 }), marker = path.join(lease.directory, '.ud-storage-owner.json');
  const original = readFileSync(marker);
  try {
    writeFileSync(marker, JSON.stringify({ id: 'foreign', lock: 'foreign' }));
    expect(() => lease.cleanup()).toThrow(/ownership/); expect(existsSync(lease.directory)).toBe(true);
  } finally { writeFileSync(marker, original); lease.cleanup(); remove(root); }
});

test('interrupt cleans exact owned scratch and leaves a nonzero result', () => {
  const root = fixture();
  try {
    const code = `import {reserveStorage} from ${JSON.stringify(helper)};const lease=reserveStorage({root:process.argv[1],plannedBytes:128});lease.write('work','payload');console.log(lease.directory);process.emit('SIGINT');`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', code, root], { encoding: 'utf8' });
    expect(result.status).toBe(130); expect(existsSync(result.stdout.trim())).toBe(false); expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(false);
  } finally { remove(root); }
});

test('restart reclaims only recorded dead-owner scratch, never live or unmarked paths', () => {
  const root = fixture();
  try {
    const code = `import {reserveStorage} from ${JSON.stringify(helper)};const lease=reserveStorage({root:process.argv[1],plannedBytes:128});lease.write('work','payload');process.kill(process.pid,'SIGKILL');`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', code, root], { encoding: 'utf8' });
    expectForcedStop(result);
    const record = JSON.parse(readFileSync(path.join(root, '.artifacts/.storage-reservation/reservation.json')));
    const unexpected = path.join(root, '.artifacts/.storage-reservation/foreign'); writeFileSync(unexpected, 'preserve');
    expect(() => recoverStorage(root)).toThrow(/unowned entry/); expect(readFileSync(unexpected, 'utf8')).toBe('preserve'); rmSync(unexpected);
    expect(existsSync(record.directory)).toBe(true); expect(recoverStorage(root)).toBe(true); expect(existsSync(record.directory)).toBe(false); expect(recoverStorage(root)).toBe(false);
    const live = reserveStorage({ root, plannedBytes: 1 }); try { expect(() => recoverStorage(root)).toThrow(/active or ambiguous/); } finally { live.cleanup(); }
  } finally { remove(root); }
});

test('admission recovers dead scratch before calculating the total', () => {
  const root = fixture(); let next;
  try {
    const code = `import {reserveStorage} from ${JSON.stringify(helper)};reserveStorage({root:process.argv[1],scratchParent:process.argv[1],plannedBytes:128});process.kill(process.pid,'SIGKILL');`;
    expectForcedStop(spawnSync(process.execPath, ['--input-type=module', '-e', code, root], { encoding: 'utf8' }));
    const record = JSON.parse(readFileSync(path.join(root, '.artifacts/.storage-reservation/reservation.json')));
    writeFileSync(path.join(record.directory, 'interrupted-output'), Buffer.alloc(8192));
    expect(storageTreeBytes(root)).toBeGreaterThan(4096);
    next = reserveStorage({ root, plannedBytes: 128, limits: { totalBytes: 4096 } });
    expect(existsSync(record.directory)).toBe(false);
  } finally { next?.cleanup(); remove(root); }
});

test('thin command wrapper shares bounded scratch and removes it after the existing command', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const code = "import{writeFileSync,readFileSync}from'node:fs';writeFileSync(process.argv[1],'command output');console.log(process.env.UD_STORAGE_DIRECTORY);console.log(readFileSync(process.argv[1],'utf8'));if(!process.env.UD_STORAGE_LEASE)process.exit(9);";
    const result = spawnSync(process.execPath, [executable, '--run', root, '1024', 'ordinary', '--', process.execPath, '--input-type=module', '-e', code, '{scratch}/out'], { encoding: 'utf8' });
    expect(result.status).toBe(0); expect(result.stdout.trim().split('\n')[1]).toBe('command output');
    expect(existsSync(result.stdout.trim().split('\n')[0])).toBe(false); expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(false);
  } finally { remove(root); }
});

test('command wrapper records an explicit eight GB reservation using bounded fixture free-space observations', () => {
  const root = fixture(), preload = path.join(root, 'free-space.mjs');
  try {
    // Only the free-space observation is modeled; the actual supervisor,
    // private records, child, small writes and cleanup use the native disk.
    writeFileSync(preload, `import fs from 'node:fs';import path from 'node:path';import{syncBuiltinESMExports}from'node:module';
const original=fs.statfsSync,root=${JSON.stringify(root)};
fs.statfsSync=(directory,...options)=>{const file=path.resolve(directory);return file===root||file.startsWith(root+path.sep)?{bavail:30000000000n,bsize:1n}:original(directory,...options)};
syncBuiltinESMExports();`);
    const code = "import{readFileSync,writeFileSync}from'node:fs';import path from'node:path';const token=JSON.parse(Buffer.from(process.env.UD_STORAGE_LEASE,'base64url'));console.log(readFileSync(path.join(token.lock,'reservation.json'),'utf8'));writeFileSync(path.join(process.env.UD_STORAGE_DIRECTORY,'data'),'small actual fixture');";
    const command = [fileURLToPath(helper), '--run', root, '8000000000', 'release', '--scratch-parent', root];
    const run = extra => spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, ...command, ...extra, '--', process.execPath, '--input-type=module', '-e', code], { encoding: 'utf8', timeout: 10000 });
    const refused = run([]); expect(refused.status).not.toBe(0); expect(refused.stderr).toMatch(/bounded scratch plan/);
    expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
    const result = run(['--transient-bytes', '8000000000']);
    expect(result.status, result.stderr).toBe(0);
    const record = JSON.parse(result.stdout);
    expect(record).toMatchObject({ profile: 'release', plannedBytes: 8_000_000_000, transient_allowance: { kind: 'explicit-local-operator-opt-in', bytes: 8_000_000_000 }, limits: { ...STORAGE_LIMITS, releaseBytes: 8_000_000_000 } });
    expect(existsSync(record.directory)).toBe(false); expect(existsSync(record.lock)).toBe(false);
  } finally { remove(root); }
}, 30_000);

test('command wrapper refuses invalid or repeated transient allowances before launching', () => {
  const root = fixture(), marker = path.join(root, 'launched');
  try {
    const cases = [
      ['ordinary', ['8000000000'], /release profile/],
      ['release', ['3999999999'], /between 4 and 48 GB/],
      ['release', ['48000000001'], /between 4 and 48 GB/],
      ...['0', '-1', '8000000000.5', '9007199254740992'].map(value => ['release', [value], /invalid owned storage option/]),
      ['release', ['8000000000', '8000000000'], /invalid owned storage option/],
    ];
    for (const [profile, values, error] of cases) {
      const result = spawnSync(process.execPath, [fileURLToPath(helper), '--run', root, '1', profile, ...values.flatMap(value => ['--transient-bytes', value]), '--', process.execPath, '-e', "require('node:fs').writeFileSync(process.argv[1],'must not launch')", marker], { encoding: 'utf8', timeout: 10000 });
      expect(result.status).not.toBe(0); expect(result.stderr).toMatch(error);
      expect(existsSync(marker)).toBe(false); expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
    }
  } finally { remove(root); }
}, 30_000);

test('command wrapper cannot raise an inherited parent transient allowance', () => {
  const root = fixture(), parent = reserveStorage({ root, plannedBytes: 1024 }), marker = path.join(root, 'launched');
  try {
    const result = spawnSync(process.execPath, [fileURLToPath(helper), '--run', root, '1', 'release', '--transient-bytes', '8000000000', '--', process.execPath, '-e', "require('node:fs').writeFileSync(process.argv[1],'must not launch')", marker], { encoding: 'utf8', timeout: 10000, env: { ...process.env, ...parent.env } });
    expect(result.status).not.toBe(0); expect(result.stderr).toMatch(/child cannot increase the parent transient allowance/);
    expect(existsSync(marker)).toBe(false); expect(existsSync(parent.directory)).toBe(true);
    expect(readFileSync(parent.write('owner', 'still owned'), 'utf8')).toBe('still owned');
  } finally { parent.cleanup(); remove(root); }
}, 30_000);

test('command wrapper refuses external owned bytes before launching', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const result = spawnSync(process.execPath, [executable, '--run', root, '1', 'ordinary', '--external-owned-bytes', String(STORAGE_LIMITS.totalBytes), '--', process.execPath, '-e', "throw Error('must not run')"], { encoding: 'utf8' });
    expect(result.status).not.toBe(0); expect(result.stderr).toMatch(/owned working total/); expect(result.stderr).not.toMatch(/must not run/);
    expect(existsSync(path.join(root, '.artifacts'))).toBe(false);
  } finally { remove(root); }
});

test('command wrapper retains a new report beyond its estimate and refuses overwrites', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const output = path.join(root, 'report');
    const code = "import{mkdirSync,writeFileSync}from'node:fs';mkdirSync(process.argv[1]);writeFileSync(process.argv[1]+'/observed','result');";
    const args = [executable, '--run', root, '128', 'ordinary', '--output', output, '--output-bytes', '1', '--', process.execPath, '--input-type=module', '-e', code, output];
    const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
    expect(result.status).toBe(0); expect(readFileSync(path.join(output, 'observed'), 'utf8')).toBe('result');
    const existing = spawnSync(process.execPath, args, { encoding: 'utf8' });
    expect(existing.status).not.toBe(0); expect(existing.stderr).toMatch(/new path/);
    expect(readFileSync(path.join(output, 'observed'), 'utf8')).toBe('result');
  } finally { remove(root); }
});

test('a supervised worker borrows only its recorded output and finite budgets', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const output = path.join(root, 'candidate');
    const code = `import {inheritedOutputStorage} from ${JSON.stringify(helper)};import{mkdirSync,writeFileSync}from'node:fs';const lease=inheritedOutputStorage({root:process.argv[1],output:process.argv[2],plannedBytes:128,plannedOutputBytes:16});try{mkdirSync(process.argv[2]);writeFileSync(process.argv[2]+'/result','ok');lease.check(2)}finally{lease.cleanup()}`;
    const args = [executable, '--run', root, '128', 'release', '--output', output, '--output-bytes', '16', '--', process.execPath, '--input-type=module', '-e', code, root, output];
    const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0); expect(readFileSync(path.join(output, 'result'), 'utf8')).toBe('ok');
    const other = path.join(root, 'other');
    const bad = spawnSync(process.execPath, [executable, '--run', root, '128', 'release', '--output', other, '--output-bytes', '16', '--', process.execPath, '--input-type=module', '-e', code, root, output], { encoding: 'utf8' });
    expect(bad.status).not.toBe(0); expect(bad.stderr).toMatch(/output reservation differs/); expect(existsSync(other)).toBe(false);
    expect(readFileSync(path.join(output, 'result'), 'utf8')).toBe('ok');
  } finally { remove(root); }
}, 30_000);

test('command wrapper stops owned work when its recorded caller is gone', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const marker = path.join(root, 'late');
    const result = spawnSync(process.execPath, [executable, '--run', root, '1024', 'ordinary', '--caller-pid', '2147483647', '--', process.execPath, '-e', "setTimeout(()=>require('node:fs').writeFileSync(process.argv[1],'late'),1500)", marker], { encoding: 'utf8', timeout: 5000 });
    expect(result.status).not.toBe(0); expect(result.stderr).toMatch(/caller stopped/); expect(existsSync(marker)).toBe(false);
    expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(false);
  } finally { remove(root); }
});

test('command wrapper preserves successful work beyond its estimate and cleans owned scratch', () => {
  const root = fixture();
  try {
    const executable = fileURLToPath(helper);
    const marker = path.join(root, 'completed');
    const code = "import {writeFileSync} from 'node:fs';console.log(process.env.UD_STORAGE_DIRECTORY);writeFileSync(process.argv[1],Buffer.alloc(4096));setTimeout(()=>writeFileSync(process.argv[2],'completed'),700);";
    const result = spawnSync(process.execPath, [executable, '--run', root, '1024', 'ordinary', '--', process.execPath, '--input-type=module', '-e', code, '{scratch}/growth', marker], { encoding: 'utf8', timeout: 6000 });
    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(result.stdout.trim())).toBe(false);
    expect(readFileSync(marker, 'utf8')).toBe('completed');
    expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(false);
  } finally { remove(root); }
});

test('command wrapper retains caller loss when an interrupted sealed fixture also prevents cleanup', () => {
  const root = fixture(); let scratch;
  try {
    const executable = fileURLToPath(helper);
    const code = "import{chmodSync,mkdirSync,writeFileSync}from'node:fs';import path from'node:path';console.log(process.env.UD_STORAGE_DIRECTORY);mkdirSync(process.argv[1]);writeFileSync(path.join(process.argv[1],'growth'),Buffer.alloc(4096));chmodSync(process.argv[1],0o500);setInterval(()=>{},1000);";
    const result = spawnSync(process.execPath, [executable, '--run', root, '1024', 'ordinary', '--caller-pid', '2147483647', '--', process.execPath, '--input-type=module', '-e', code, '{scratch}/sealed'], { encoding: 'utf8', timeout: 6000 });
    scratch = result.stdout.trim();
    expect(result.status).not.toBe(0); expect(result.signal).toBeNull();
    expect(result.stderr).toMatch(/supervising caller stopped/);
    // Windows directory read-only attributes and POSIX root do not prohibit
    // deletion; those native paths still exercise caller cancellation.
    if (process.platform !== 'win32' && process.getuid?.() !== 0) {
      expect(result.stderr).toMatch(/Storage command failed and owned cleanup also failed/);
      // Native recursive rm may report the denied unlink or its nonempty parent.
      expect(result.stderr).toMatch(/EACCES|EPERM|ENOTEMPTY/);
      expect(existsSync(path.join(scratch, 'sealed/growth'))).toBe(true);
      expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(true);
      expect(JSON.parse(readFileSync(path.join(root, '.artifacts/.storage-reservation/reservation.json'), 'utf8')).directory).toBe(scratch);
      chmodSync(path.join(scratch, 'sealed'), 0o700);
      remove(scratch); recoverStorage(root);
    }
    expect(existsSync(scratch)).toBe(false);
  } finally {
    if (scratch && existsSync(path.join(scratch, 'sealed'))) chmodSync(path.join(scratch, 'sealed'), 0o700);
    if (scratch) remove(scratch);
    if (existsSync(path.join(root, '.artifacts/.storage-reservation'))) recoverStorage(root);
    remove(root);
  }
});

function expectForcedStop(result) {
  expect(result.error).toBeUndefined();expect(result.stderr.toString()).toBe('');
  if (process.platform === 'win32') { expect(result.signal).toBeNull();expect(result.status).toBeTypeOf('number');expect(result.status).not.toBe(0); }
  else expect(result.signal).toBe('SIGKILL');
}
