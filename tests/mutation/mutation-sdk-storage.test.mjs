import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, closeSync, existsSync, lstatSync, mkdtempSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statfsSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { admittedEngineBytes, dockerSizeBounds, dockerStorageGrowth, dockerStorageSnapshot, inspectDocker, prepareSdk, retainedSdkContextInputs, retainedSdkInputs, sdkWorkspaceBytes, supervisedSdk } from '../../scripts/quality/mutation-sdk-storage.mjs';

vi.mock('node:fs', async importOriginal => {
  const original = await importOriginal();
  return { ...original, statfsSync: vi.fn(original.statfsSync), lstatSync: vi.fn(original.lstatSync) };
});

const originalFs = await vi.importActual('node:fs');
const hostTemporary = os.tmpdir(), hostUid = Object.getOwnPropertyDescriptor(process, 'getuid');
let fixtureRoot, posixMetadata = false, projectFixtureInodes = false;
const fixtureInodes = new Map();

function fixtureStat(file, options) {
  const info = originalFs.lstatSync(file, options);
  if (!posixMetadata || !info || typeof file !== 'string') return info;
  const resolved = path.resolve(file);
  if (resolved !== fixtureRoot && !resolved.startsWith(fixtureRoot + path.sep)) return info;
  // Windows exposes no POSIX owner/mode contract. Only portable export-policy
  // tests project NTFS IDs into safe JSON integers; native lease checks must
  // retain the actual file IDs used by the Windows ACL helper.
  const mask = typeof info.mode === 'bigint' ? ~0o077n : ~0o077;
  const uid = process.getuid();
  let inode = info.ino;
  if (projectFixtureInodes) {
    const native = typeof info.ino === 'bigint' ? info : originalFs.lstatSync(file, { bigint: true });
    const identity = `${native.dev}:${native.ino}`;
    if (!fixtureInodes.has(identity)) fixtureInodes.set(identity, fixtureInodes.size + 1);
    inode = typeof info.ino === 'bigint' ? BigInt(fixtureInodes.get(identity)) : fixtureInodes.get(identity);
  }
  return Object.assign(Object.create(Object.getPrototypeOf(info)), info, {
    mode: info.mode & mask, uid: typeof info.uid === 'bigint' ? BigInt(uid) : uid,
    ino: inode,
  });
}

function usePosixFixtureMetadata({ projectInodes = false } = {}) {
  posixMetadata = true;
  projectFixtureInodes = projectInodes;
  if (typeof process.getuid !== 'function') Object.defineProperty(process, 'getuid', { configurable: true, value: () => 0 });
}

beforeEach(() => {
  fixtureInodes.clear();
  // Child process.cwd() expands Windows short names. Use that same native
  // spelling for the fixture authority and its exact export journal binding.
  fixtureRoot = originalFs.realpathSync.native(mkdtempSync(path.join(hostTemporary, 'sdk-policy-fixture-')));
  // The lease directory must be outside the checkout fixture, but still inside
  // the test's metadata boundary. Each test's checkout is a child of this root.
  vi.spyOn(os, 'tmpdir').mockReturnValue(fixtureRoot);
  if (!hostUid) usePosixFixtureMetadata();
  vi.mocked(lstatSync).mockImplementation(fixtureStat);
});

afterEach(() => {
  posixMetadata = false;
  projectFixtureInodes = false;
  if (hostUid) Object.defineProperty(process, 'getuid', hostUid); else delete process.getuid;
  vi.mocked(lstatSync).mockReset();
  vi.restoreAllMocks();
  rmSync(fixtureRoot, { recursive: true, force: true });
});

const report = values => ['Images', 'Containers', 'Local Volumes', 'Build Cache']
  .map((Type, index) => JSON.stringify({ Type, Size: values[index] })).join('\n');

function journalExport(base, assets, file) {
  const info = lstatSync(file), owner = { pid: process.pid, owner: '01234567-89ab-cdef-0123-456789abcdef', root: base, endpoint: 'unix:///tmp/sdk.sock', daemon: 'daemon-a' };
  writeFileSync(path.join(assets, 'image-export.json'), JSON.stringify({ schema_version: 1, qualification: 'owned-SDK-image-export', root: base, assets,
    creator_pid: owner.pid, owner: owner.owner, path: path.basename(file), device: info.dev, inode: info.ino, docker: { endpoint: owner.endpoint, daemon_id: owner.daemon }, image_id: 'sha256:' + 'a'.repeat(64) }));
  return owner;
}

describe('SDK storage accounting', () => {
  test('engine inspection retries only the disappearing SDK mount and requires a fresh complete result', () => {
    const args = ['system', 'df', '--format', '{{json .}}'], env = { DOCKER_HOST: 'unix:///selected.sock' };
    const race = { status: 1, stdout: '', stderr: 'Error response from daemon: failed to calculate image disk usage: lstat /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/101/fs/sdk-inputs.tar.xz: no such file or directory\n' };
    const stdout = report(['1.0GB', '0B', '0B', '0B']);
    const recovered = vi.fn().mockReturnValueOnce(race).mockReturnValue({ status: 0, stdout, stderr: '' });
    expect(inspectDocker(args, env, { run: recovered, now: () => 0 })).toBe(stdout);
    expect(recovered).toHaveBeenCalledTimes(2);
    for (const call of recovered.mock.calls) expect(call).toEqual(['docker', args, { env, encoding: 'utf8', timeout: 5000, maxBuffer: 4 * 1024**2 }]);
    const persistent = vi.fn().mockReturnValue(race);
    expect(() => inspectDocker(args, env, { run: persistent, now: () => 0 })).toThrow(/cannot inspect engine storage/);
    expect(persistent).toHaveBeenCalledTimes(3);
    for (const failure of [{ ...race, error: new Error('timed out') }, { ...race, stderr: race.stderr.replace('sdk-inputs.tar.xz', 'foreign') }, { ...race, stderr: 'permission denied' }]) {
      const run = vi.fn().mockReturnValue(failure);
      expect(() => inspectDocker(args, env, { run, now: () => 0 })).toThrow(/cannot inspect engine storage/);
      expect(run).toHaveBeenCalledTimes(1);
    }
    const otherQuery = vi.fn().mockReturnValue(race);
    expect(() => inspectDocker(['info', '--format', '{{.ID}}'], env, { run: otherQuery, now: () => 0 })).toThrow(/cannot inspect engine storage/);
    expect(otherQuery).toHaveBeenCalledTimes(1);
    let elapsed = 0;
    const exhausted = vi.fn().mockImplementation(() => { elapsed = 5000; return race; });
    expect(() => inspectDocker(args, env, { run: exhausted, now: () => elapsed })).toThrow(/cannot inspect engine storage/);
    expect(exhausted).toHaveBeenCalledTimes(1);
    elapsed = 0;
    const late = vi.fn().mockImplementation(() => { elapsed = 5001; return { status: 0, stdout }; });
    expect(() => inspectDocker(args, env, { run: late, now: () => elapsed })).toThrow(/inspection deadline expired/);
    elapsed = 0;
    const shrinking = vi.fn().mockImplementationOnce(() => { elapsed = 1250; return race; }).mockImplementation(() => { elapsed = 2500; return { status: 0, stdout }; });
    expect(inspectDocker(args, env, { run: shrinking, now: () => elapsed })).toBe(stdout);
    expect(shrinking.mock.calls.map(call => call[2].timeout)).toEqual([5000, 3750]);
  });

  test('bounds rounded engine sizes and all four storage categories', () => {
    expect(dockerSizeBounds('1.2GB')).toEqual({ lower: 1_100_000_000, upper: 1_300_000_000 });
    expect(dockerSizeBounds('0B')).toEqual({ lower: 0, upper: 0 });
    expect(dockerSizeBounds('0.0GB')).toEqual({ lower: 0, upper: 100_000_000 });
    const before = dockerStorageSnapshot(report(['0B', '0B', '0B', '0B']));
    const after = dockerStorageSnapshot(report(['1.2MB', '0B', '2.0MB', '3.0MB']));
    expect(dockerStorageGrowth(before, after)).toBe(6_500_000);
    expect(admittedEngineBytes(after, 5_000_000)).toBe(10_200_000);
    expect(() => dockerStorageSnapshot(report(['0B', '0B', '0B', '0B']).split('\n').slice(1).join('\n'))).toThrow(/incomplete/);
    expect(() => dockerStorageSnapshot(report(['0B', '0B', '0B', 'not a size']))).toThrow(/size is unavailable/);
  });

  test('counts SDK temporary inputs and context separately from retained image', () => {
    const base = mkdtempSync(path.join(os.tmpdir(), 'sdk-storage-test-'));
    try {
      const assets = path.join(base, 'assets'), context = path.join(base, 'context');
      mkdirSync(assets); mkdirSync(context);
      writeFileSync(path.join(assets, 'sdk-image.tar'), 'image');
      writeFileSync(path.join(assets, 'sdk-image.partial.tar'), 'partial');
      writeFileSync(path.join(context, 'input'), 'source');
      expect(sdkWorkspaceBytes(assets, context)).toEqual({ scratch: 13, archive: 5 });
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test('only the active owned export receives output credit, including across final rename', () => {
    usePosixFixtureMetadata({ projectInodes: true });
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-export-'))), assets = path.join(base, 'assets');
    try {
      mkdirSync(assets);
      const partial = path.join(assets, 'sdk-image.' + 'a'.repeat(32) + '.tar'); writeFileSync(partial, 'partial', { mode: 0o600 });
      writeFileSync(path.join(assets, 'sdk-image.' + 'b'.repeat(32) + '.tar'), 'foreign');
      const owner = journalExport(base, assets, partial), uncredited = sdkWorkspaceBytes(assets);
      expect(sdkWorkspaceBytes(assets, undefined, { ...owner, owner: 'previous-owner' })).toEqual(uncredited);
      expect(sdkWorkspaceBytes(assets, undefined, owner)).toEqual({ scratch: uncredited.scratch - 7, archive: 7, exportBytes: 7 });
      renameSync(partial, path.join(assets, 'sdk-image.tar'));
      expect(sdkWorkspaceBytes(assets, undefined, owner)).toEqual({ scratch: uncredited.scratch - 7, archive: 7, exportBytes: 7 });
      const held = openSync(path.join(assets, 'sdk-image.tar'), 'r');
      try { writeFileSync(partial, 'replaced', { mode: 0o600 }); expect(() => sdkWorkspaceBytes(assets, undefined, owner)).toThrow(/export inode differs/); }
      finally { closeSync(held); }
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test('a growing owned export does not require the writer to become idle', async () => {
    usePosixFixtureMetadata({ projectInodes: true });
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-export-growth-'))), assets = path.join(base, 'assets');
    try {
      mkdirSync(assets);
      const partial = path.join(assets, 'sdk-image.' + 'a'.repeat(32) + '.tar'); writeFileSync(partial, 'partial', { mode: 0o600 });
      const owner = journalExport(base, assets, partial);
      vi.mocked(lstatSync).mockImplementation((file, options) => {
        if (file === partial && !options?.bigint) appendFileSync(partial, 'x');
        return fixtureStat(file, options);
      });
      const measured = sdkWorkspaceBytes(assets, undefined, owner);
      expect(measured.exportBytes).toBe(9); expect(measured.archive).toBe(9);
      expect(measured.scratch).toBeGreaterThan(0);
    } finally { vi.mocked(lstatSync).mockReset(); rmSync(base, { recursive: true, force: true }); }
  });

  test('absent POSIX ownership refuses export and retained-input credit instead of trusting Windows metadata', () => {
    usePosixFixtureMetadata({ projectInodes: true });
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-export-owner-'))), assets = path.join(base, 'assets');
    try {
      mkdirSync(assets);
      const partial = path.join(assets, 'sdk-image.' + 'a'.repeat(32) + '.tar');
      writeFileSync(partial, 'partial', { mode: 0o600 });
      const owner = journalExport(base, assets, partial), uncredited = sdkWorkspaceBytes(assets);
      posixMetadata = false;
      Object.defineProperty(process, 'getuid', { configurable: true, value: undefined });
      expect(() => sdkWorkspaceBytes(assets, undefined, owner)).toThrow(/export inode differs/);
      expect(sdkWorkspaceBytes(assets)).toEqual(uncredited);
      expect(readFileSync(partial, 'utf8')).toBe('partial');
      const rust = path.join(assets, 'mutation-rust-assets'), hash = data => createHash('sha256').update(data).digest('hex');
      mkdirSync(path.join(rust, 'export'), { recursive: true });
      writeFileSync(path.join(rust, 'export/tool'), 'tool', { mode: 0o444 });
      writeFileSync(path.join(base, 'recipe'), 'recipe');
      const receipt = JSON.stringify({ files: [{ path: 'tool', sha256: hash('tool'), size: 4 }] });
      writeFileSync(path.join(rust, 'rust-input-receipt.json'), receipt);
      writeFileSync(path.join(assets, 'native-inputs.json'), JSON.stringify({ qualification: 'original-locked-native-SDK-input-build-no-generated-variants', rust_receipt_sha256: hash(receipt) }));
      writeFileSync(path.join(assets, 'cross-build-receipt.json'), JSON.stringify({ qualification: 'native-original-guard-build-not-cross-build', source_inputs: [{ path: 'recipe', sha256: hash('recipe') }] }));
      expect(() => retainedSdkInputs(assets, base)).toThrow(/differs from its receipt/);
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test('POSIX export fixtures preserve replacement identity and leave native lease IDs unprojected by default', () => {
    const file = path.join(fixtureRoot, 'metadata'); writeFileSync(file, 'original');
    usePosixFixtureMetadata();
    const actual = originalFs.lstatSync(file);
    expect(lstatSync(file).ino).toBe(actual.ino);
    expect(lstatSync(file, { bigint: true }).ino).toBe(originalFs.lstatSync(file, { bigint: true }).ino);
    usePosixFixtureMetadata({ projectInodes: true });
    const observed = lstatSync(file);
    for (const key of ['dev', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) expect(observed[key]).toBe(actual[key]);
    expect(observed.isFile()).toBe(true); expect(observed.mode & 0o077).toBe(0);
    expect(Number.isSafeInteger(observed.ino)).toBe(true);
    expect(lstatSync(file, { bigint: true }).ino).toBe(BigInt(observed.ino));
    chmodSync(file, 0o444); expect(lstatSync(file).mode & 0o222).toBe(0);
    renameSync(file, file + '.previous'); writeFileSync(file, 'replacement');
    expect(lstatSync(file + '.previous').ino).toBe(observed.ino);
    expect(lstatSync(file).ino).not.toBe(observed.ino);
    expect(lstatSync(file + '.missing', { throwIfNoEntry: false })).toBeUndefined();
  });

  test('credits only completed byte-bound read-only inputs and detects replacements', () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-retained-')));
    const hash = text => createHash('sha256').update(text).digest('hex');
    try {
      const assets = path.join(base, '.artifacts/sdk'), rust = path.join(assets, 'mutation-rust-assets');
      mkdirSync(path.join(rust, 'export'), { recursive: true });
      writeFileSync(path.join(base, 'recipe'), 'recipe');
      const tool = path.join(rust, 'export/tool'); writeFileSync(tool, 'tool'); chmodSync(tool, 0o444);
      writeFileSync(path.join(assets, 'unknown-intermediate'), 'scratch');
      const receipt = JSON.stringify({ files: [{ path: 'tool', sha256: hash('tool'), size: 4 }] });
      writeFileSync(path.join(rust, 'rust-input-receipt.json'), receipt);
      writeFileSync(path.join(assets, 'native-inputs.json'), JSON.stringify({ qualification: 'original-locked-native-SDK-input-build-no-generated-variants', rust_receipt_sha256: hash(receipt) }));
      writeFileSync(path.join(assets, 'cross-build-receipt.json'), JSON.stringify({ qualification: 'native-original-guard-build-not-cross-build', source_inputs: [{ path: 'recipe', sha256: hash('recipe') }] }));
      const retained = retainedSdkInputs(assets, base);
      expect(retained()).toBe(4);
      expect(sdkWorkspaceBytes(assets).scratch).toBeGreaterThan(11);
      // Retain the admitted inode under another name while replacing its path.
      // This avoids inode reuse and Windows deletion of an open read-only file.
      const pinned = openSync(tool, 'r');
      try { renameSync(tool, tool + '.previous'); writeFileSync(tool, 'evil'); chmodSync(tool, 0o444); } finally { closeSync(pinned); }
      expect(() => retained()).toThrow(/identity changed/);
      expect(() => retainedSdkInputs(assets, base)).toThrow(/differs from its receipt/);
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test('rejects a remote Docker endpoint before recovery or writes', async () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-supervisor-remote-')));
    try {
      const assets = path.join(base, '.artifacts', 'sdk'), context = path.join(base, '.artifacts', 'context');
      mkdirSync(assets, { recursive: true }); mkdirSync(context);
      vi.stubEnv('DOCKER_CONTEXT', ''); vi.stubEnv('DOCKER_HOST', 'tcp://example.invalid:2375');
      const recover = vi.fn();
      await expect(supervisedSdk({ assets, context, mode: 'ensure', python: process.execPath }, { ownerRoot: base, recover }))
        .rejects.toThrow(/local Unix socket or local Windows named pipe/);
      expect(recover).not.toHaveBeenCalled();
      expect(existsSync(path.join(base, '.artifacts', '.storage-reservation'))).toBe(false);
    } finally { vi.unstubAllEnvs(); rmSync(base, { recursive: true, force: true }); }
  });

  test.each(['removed', 'replaced'])('completed context credit handles a %s path during its retirement lookup', disposition => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-context-credit-'))), hash = text => createHash('sha256').update(text).digest('hex');
    try {
      const assets = path.join(base, '.artifacts/sdk'), contexts = path.join(base, '.artifacts/context'), directory = path.join(contexts, 'context-' + 'a'.repeat(32)), context = path.join(directory, 'context');
      mkdirSync(path.join(assets, 'mutation-rust-assets/export'), { recursive: true }); mkdirSync(path.join(context, 'rust'), { recursive: true });
      writeFileSync(path.join(base, 'package-lock.json'), 'lock');
      const receipt = JSON.stringify({ files: [{ path: 'tool', size: 4, sha256: hash('tool') }] });
      writeFileSync(path.join(assets, 'mutation-rust-assets/rust-input-receipt.json'), receipt);
      writeFileSync(path.join(assets, 'mutation-rust-assets/export/tool'), 'tool');
      writeFileSync(path.join(assets, 'native-inputs.json'), JSON.stringify({ qualification: 'original-locked-native-SDK-input-build-no-generated-variants', rust_receipt_sha256: hash(receipt) }));
      writeFileSync(path.join(assets, 'cross-build-receipt.json'), JSON.stringify({ qualification: 'native-original-guard-build-not-cross-build', source_inputs: [{ path: 'package-lock.json', sha256: hash('lock') }] }));
      const info = lstatSync(directory); writeFileSync(path.join(directory, '.sdk-context-owner.json'), JSON.stringify({ root: base, assets, context: directory, device: info.dev, inode: info.ino }));
      writeFileSync(path.join(context, 'rust/tool'), 'tool'); writeFileSync(path.join(context, 'unknown'), 'unknown scratch');
      const credit = retainedSdkContextInputs(assets, contexts, base);
      expect(credit()).toBe(0); // Incomplete context cannot be promoted.
      writeFileSync(path.join(context, 'input-receipt.json'), JSON.stringify({ qualification: 'development-mutation-runner', platform: 'linux/arm64', package_lock_sha256: hash('lock') }));
      expect(credit()).toBe(4);
      expect(lstatSync(path.join(context, 'rust/tool')).mode & 0o222).toBe(0);
      const tool = path.join(context, 'rust/tool'); let raced = false;
      vi.mocked(lstatSync).mockImplementation((file, options) => {
        const observed = fixtureStat(file, options);
        if (file !== tool || raced) return observed;
        raced = true; rmSync(tool, { force: true });
        if (disposition === 'replaced') writeFileSync(tool, 'replacement');
        return Object.assign(Object.create(Object.getPrototypeOf(observed)), observed, { nlink: 0, ctimeMs: observed.ctimeMs + 1 });
      });
      if (disposition === 'removed') expect(credit()).toBe(0);
      else {
        expect(() => credit()).toThrow(/retained SDK context identity changed/);
        expect(readFileSync(tool, 'utf8')).toBe('replacement');
      }
      vi.mocked(lstatSync).mockImplementation(fixtureStat);
      rmSync(directory, { recursive: true }); expect(credit()).toBe(0);
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test('SDK growth does not invoke recursive or engine quota observers or replace a successful outcome', async () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-supervisor-growth-')));
    try {
      const assets = path.join(base, '.artifacts/sdk'), context = path.join(base, '.artifacts/context'), scripts = path.join(base, 'scripts/quality');
      mkdirSync(assets, { recursive: true }); mkdirSync(context); mkdirSync(scripts, { recursive: true });
      writeFileSync(path.join(scripts, 'prepare-mutation-runtime.py'), 'const fs=require("node:fs"),path=require("node:path");const root=process.argv[process.argv.indexOf("--asset-root")+1];fs.writeFileSync(path.join(root,"growth"),Buffer.alloc(4096));fs.writeFileSync(path.join(root,"sdk-image.tar"),Buffer.alloc(1024));setTimeout(()=>{},100);\n');
      const snapshot = vi.fn(() => { throw new Error('incidental engine quota observer must not run'); });
      await expect(supervisedSdk({ assets, context, mode: 'ensure', python: process.execPath }, {
        ownerRoot: base, snapshot, recover: () => {},
        authority: { transport: 'unix', endpoint: 'unix:///tmp/sdk.sock' }, readDaemon: () => 'daemon-a',
        scratchAllowance: 512, archiveAllowance: 512, interval: 20,
      })).resolves.toBeUndefined();
      expect(snapshot).not.toHaveBeenCalled();
      expect(readFileSync(path.join(assets, 'growth')).length).toBe(4096);
      expect(readFileSync(path.join(assets, 'sdk-image.tar')).length).toBe(1024);
      expect(existsSync(path.join(base, '.artifacts/.storage-reservation'))).toBe(false);
    } finally { rmSync(base, { recursive: true, force: true }); }
  }, 10000);

  test('admits an explicitly authorized local transient allowance and preserves unrelated files', async () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-supervisor-ok-')));
    try {
      const assets = path.join(base, '.artifacts', 'sdk'), context = path.join(base, '.artifacts', 'context');
      const scripts = path.join(base, 'scripts', 'quality');
      mkdirSync(assets, { recursive: true }); mkdirSync(context); mkdirSync(scripts, { recursive: true });
      writeFileSync(path.join(assets, 'unrelated'), 'keep');
      const script = 'const fs=require("node:fs"),path=require("node:path");const root=process.argv[process.argv.indexOf("--asset-root")+1];fs.writeFileSync(path.join(root,"sdk-image.tar"),"image");\n';
      writeFileSync(path.join(scripts, 'prepare-mutation-runtime.py'), script);
      const empty = dockerStorageSnapshot(report(['0B', '0B', '0B', '0B']));
      const options = { assets, context, mode: 'ensure', python: process.execPath, transientBytes: 5_000_000_000 };
      const overrides = {
        ownerRoot: base, externalBytes: 0, snapshot: () => empty, recover: () => {}, engineAllowance: 0,
        authority: { transport: 'unix', endpoint: 'unix:///tmp/sdk.sock' }, readDaemon: () => 'daemon-a',
        archiveAllowance: 512, interval: 20,
      };
      // Capacity is an input to this policy test, not a CI host prerequisite.
      vi.mocked(statfsSync).mockReturnValue({ bavail: 15_000_000_511n, bsize: 1n });
      await expect(supervisedSdk(options, overrides)).rejects.toThrow(/free reserve/);
      expect(existsSync(path.join(assets, 'sdk-image.tar'))).toBe(false);
      vi.mocked(statfsSync).mockReturnValue({ bavail: 30_000_000_000n, bsize: 1n });
      await expect(supervisedSdk(options, overrides)).resolves.toBeUndefined();
      expect(existsSync(path.join(assets, 'sdk-image.tar'))).toBe(true);
      expect(existsSync(path.join(assets, 'unrelated'))).toBe(true);
      expect(existsSync(path.join(base, '.artifacts', '.storage-reservation'))).toBe(false);
    } finally { vi.mocked(statfsSync).mockReset(); rmSync(base, { recursive: true, force: true }); }
  }, 10000);



  test('provider acquisition and native builds use separate owned leases on the same daemon', async () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-phases-')));
    try {
      const assets = path.join(base, '.artifacts/sdk'), context = path.join(base, '.artifacts/context'), scripts = path.join(base, 'scripts/quality');
      mkdirSync(assets, { recursive: true }); mkdirSync(context); mkdirSync(scripts, { recursive: true });
      writeFileSync(path.join(scripts, 'prepare-mutation-runtime.py'), 'const fs=require("node:fs"),path=require("node:path");const root=process.argv[process.argv.indexOf("--asset-root")+1],token=JSON.parse(Buffer.from(process.env.UD_STORAGE_LEASE,"base64url")),record=JSON.parse(fs.readFileSync(path.join(token.lock,"reservation.json"))),provider=process.argv.includes("--ensure-ci-provider");fs.appendFileSync(path.join(root,"phases"),JSON.stringify({provider,id:record.id})+"\\n");fs.writeFileSync(path.join(root,provider?"provider":"build"),Buffer.alloc(provider?1:1000));\n');
      const empty = dockerStorageSnapshot(report(['0B', '0B', '0B', '0B'])), provider = dockerStorageSnapshot(report(['1500B', '0B', '0B', '0B']));
      await prepareSdk({ assets, context, mode: 'ensure', python: process.execPath }, {
        ownerRoot: base, externalBytes: 0, snapshot: () => existsSync(path.join(assets, 'provider')) ? provider : empty, recover: () => {},
        authority: { transport: 'unix', endpoint: 'unix:///tmp/sdk.sock' }, readDaemon: () => 'daemon-a',
        engineAllowance: 2000, scratchAllowance: 2048, archiveAllowance: 512, interval: 20,
      });
      const phases = readFileSync(path.join(assets, 'phases'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
      expect(phases.map(row => row.provider)).toEqual([true, false]);
      expect(phases[0].id).not.toBe(phases[1].id);
      expect(existsSync(path.join(assets, 'provider'))).toBe(true); expect(existsSync(path.join(assets, 'build'))).toBe(true);
      expect(existsSync(path.join(base, '.artifacts/.storage-reservation'))).toBe(false);
    } finally { rmSync(base, { recursive: true, force: true }); }
  }, 10000);

  test('a changed daemon between phases rejects before native build launch', async () => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-phase-daemon-')));
    try {
      const assets = path.join(base, '.artifacts/sdk'), context = path.join(base, '.artifacts/context'), scripts = path.join(base, 'scripts/quality');
      mkdirSync(assets, { recursive: true }); mkdirSync(context); mkdirSync(scripts, { recursive: true });
      writeFileSync(path.join(scripts, 'prepare-mutation-runtime.py'), 'const fs=require("node:fs"),path=require("node:path");const root=process.argv[process.argv.indexOf("--asset-root")+1];fs.writeFileSync(path.join(root,process.argv.includes("--ensure-ci-provider")?"provider":"build"),"input");\n');
      const empty = dockerStorageSnapshot(report(['0B', '0B', '0B', '0B']));
      await expect(prepareSdk({ assets, context, mode: 'ensure', python: process.execPath }, {
        ownerRoot: base, externalBytes: 0, snapshot: () => empty, recover: () => {}, engineAllowance: 0,
        authority: { transport: 'unix', endpoint: 'unix:///tmp/sdk.sock' },
        readDaemon: () => existsSync(path.join(assets, 'provider')) && !existsSync(path.join(base, '.artifacts/.storage-reservation')) ? 'daemon-b' : 'daemon-a',
        scratchAllowance: 512, archiveAllowance: 512, interval: 20,
      })).rejects.toThrow(/daemon changed between SDK phases/);
      expect(existsSync(path.join(assets, 'provider'))).toBe(true);
      expect(existsSync(path.join(assets, 'build'))).toBe(false);
      expect(existsSync(path.join(base, '.artifacts/.storage-reservation'))).toBe(false);
    } finally { rmSync(base, { recursive: true, force: true }); }
  }, 10000);



  test.each(['command', 'daemon'])('a failed %s still rejects and releases the owned lease', async failure => {
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'sdk-failed-outcome-')));
    try {
      const assets = path.join(base, '.artifacts/sdk'), context = path.join(base, '.artifacts/context'), scripts = path.join(base, 'scripts/quality');
      mkdirSync(assets, { recursive: true }); mkdirSync(context); mkdirSync(scripts, { recursive: true });
      writeFileSync(path.join(scripts, 'prepare-mutation-runtime.py'), `const fs=require('node:fs'),path=require('node:path');const root=process.argv[process.argv.indexOf('--asset-root')+1];fs.writeFileSync(path.join(root,'completed'),'done');process.exit(${failure === 'command' ? 3 : 0});`);
      await expect(supervisedSdk({ assets, context, mode: 'ensure', python: process.execPath }, {
        ownerRoot: base, recover: () => {}, authority: { transport: 'unix', endpoint: 'unix:///tmp/sdk.sock' },
        readDaemon: () => failure === 'daemon' && existsSync(path.join(assets, 'completed')) ? 'daemon-b' : 'daemon-a',
        scratchAllowance: 512, archiveAllowance: 512,
      })).rejects.toThrow(failure === 'command' ? /did not complete successfully/ : /daemon changed during SDK preparation/);
      expect(existsSync(path.join(base, '.artifacts/.storage-reservation'))).toBe(false);
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

});
