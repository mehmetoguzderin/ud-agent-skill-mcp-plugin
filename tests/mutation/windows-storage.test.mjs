/** Windows native-helper protocol fixtures; real ACL execution is tested in Python on Windows. MIT. */
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { batchWindowsStorage, createWindowsStorage, verifyWindowsStorage, windowsStorageEnvironment, windowsStorageLeaseEnvironment } from '../../scripts/quality/windows-storage.mjs';

vi.mock('node:child_process', () => ({ spawnSync: vi.fn() }));
const actualProcess = process;
let root;
beforeEach(() => {
  root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-windows-acl-protocol-')));
  vi.stubGlobal('process', new Proxy(actualProcess, { get(target, key) {
    if (key === 'platform') return 'win32';
    if (key === 'env') return { ...target.env, UD_STORAGE_WINDOWS_PYTHON: target.execPath };
    return Reflect.get(target, key);
  } }));
  vi.mocked(spawnSync).mockReset().mockImplementation((_python, _args, options) => {
    const results = JSON.parse(options.input).map(row => {
      expect(row.path.startsWith(root + path.sep)).toBe(true);
      if (row.operation === 'create') {
        if (row.kind === 'directory') mkdirSync(row.path);
        else writeFileSync(row.path, Buffer.from(row.body, 'base64'), { flag: 'wx' });
      }
      const info = lstatSync(row.path, { bigint: true });
      return { device: String(info.dev), inode: String(info.ino) };
    });
    return { status: 0, stdout: JSON.stringify(results), stderr: '' };
  });
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); rmSync(root, { recursive: true, force: true }); });

test('selects the explicit existing Python and carries it into nested lease environments', () => {
  const environment = windowsStorageEnvironment(actualProcess.execPath, { UD_AGENT_PYTHON: 'unused-relative-path' });
  expect(environment.UD_STORAGE_WINDOWS_PYTHON).toBe(actualProcess.execPath);
  expect(windowsStorageLeaseEnvironment()).toEqual({ UD_STORAGE_WINDOWS_PYTHON: actualProcess.execPath });
  expect(() => windowsStorageEnvironment('python.exe', {})).toThrow(/selected absolute Python/);
  expect(() => windowsStorageEnvironment(root, {})).toThrow(/ordinary executable/);
  expect(spawnSync).not.toHaveBeenCalled();
});

test('batches lease ACL checks while preserving exact file identities and privacy requirements', () => {
  const directory = path.join(root, 'control'); mkdirSync(directory);
  const journal = path.join(directory, 'record.json'); writeFileSync(journal, '{}');
  const result = batchWindowsStorage(() => {
    verifyWindowsStorage(directory, 'directory', false);
    verifyWindowsStorage(journal, 'file', true);
    expect(spawnSync).not.toHaveBeenCalled();
    return 'verified-after-batch';
  });
  expect(result).toBe('verified-after-batch'); expect(spawnSync).toHaveBeenCalledTimes(1);
  const [python, args, options] = vi.mocked(spawnSync).mock.calls[0];
  expect(python).toBe(actualProcess.execPath); expect(args.slice(0, 2)).toEqual(['-I', '-B']);
  expect(args[2].endsWith('windows-storage-acl.py')).toBe(true);
  expect(options).toMatchObject({ timeout: 10_000, maxBuffer: 65536, windowsHide: true });
  expect(JSON.parse(options.input).map(row => [row.kind, row.private])).toEqual([['directory', false], ['file', true]]);
});

test('refuses failed native ACL evidence and changed ownership-record bytes', () => {
  const journal = path.join(root, 'record.json'); writeFileSync(journal, '{}');
  vi.mocked(spawnSync).mockReturnValueOnce({ status: 1, stdout: '', stderr: 'foreign DACL' });
  expect(() => verifyWindowsStorage(journal, 'file', true)).toThrow(/foreign DACL/);
  vi.mocked(spawnSync).mockImplementationOnce(() => {
    const before = lstatSync(journal, { bigint: true }); writeFileSync(journal, 'changed record');
    return { status: 0, stdout: JSON.stringify([{ device: String(before.dev), inode: String(before.ino) }]), stderr: '' };
  });
  expect(() => verifyWindowsStorage(journal, 'file', true)).toThrow(/identity changed/);
  expect(readFileSync(journal, 'utf8')).toBe('changed record');
});

test('creates only new controls and rejects malformed or foreign native identities', () => {
  const directory = path.join(root, 'control'), journal = path.join(directory, 'record.json');
  createWindowsStorage(directory, 'directory'); createWindowsStorage(journal, 'file', '{"owned":true}\n');
  expect(readFileSync(journal, 'utf8')).toBe('{"owned":true}\n');
  expect(() => createWindowsStorage(journal, 'file', 'replacement')).toThrow();
  expect(readFileSync(journal, 'utf8')).toBe('{"owned":true}\n');
  vi.mocked(spawnSync).mockReturnValueOnce({ status: 0, stdout: '[]', stderr: '' });
  expect(() => verifyWindowsStorage(journal, 'file', true)).toThrow(/incomplete/);
  vi.mocked(spawnSync).mockReturnValueOnce({ status: 0, stdout: '[{"device":"0","inode":"0"}]', stderr: '' });
  expect(() => verifyWindowsStorage(journal, 'file', true)).toThrow(/identity changed/);
  vi.mocked(spawnSync).mockReturnValueOnce({ status: 0, stdout: 'not JSON', stderr: '' });
  expect(() => verifyWindowsStorage(journal, 'file', true)).toThrow(/response is invalid/);
});
