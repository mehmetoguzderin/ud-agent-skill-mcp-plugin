import { test, expect } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { selectedNativeHelpers } from '../../scripts/release/native-helpers.mjs';

test('native and MCPB helper closure includes exactly host plus same-architecture Linux guest', () => {
  const lock = { native_helpers: Object.fromEntries(['darwin/arm64', 'darwin/x64', 'linux/arm64', 'linux/x64', 'win32/arm64', 'win32/x64'].map(host => [host, { guard: { path: host + '/guard' } }])) };
  expect(selectedNativeHelpers(lock, 'darwin-arm64').map(row => row.platform)).toEqual(['darwin/arm64', 'linux/arm64']);
  expect(selectedNativeHelpers(lock, 'win32-x64').map(row => row.platform)).toEqual(['win32/x64', 'linux/x64']);
  expect(selectedNativeHelpers(lock, 'linux-arm64').map(row => row.platform)).toEqual(['linux/arm64']);
  expect(selectedNativeHelpers(lock, 'all').map(row => row.platform)).toEqual(['darwin/arm64', 'linux/arm64', 'linux/x64', 'win32/arm64', 'win32/x64']);
  expect(() => selectedNativeHelpers({ native_helpers: { 'darwin/arm64': lock.native_helpers['darwin/arm64'] } }, 'darwin-arm64')).toThrow(/guest helper/);
});

test('global receipt metadata does not eagerly open absent off-platform helper files', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-selected-helpers-'));
  try {
    const lock = { native_helpers: Object.fromEntries(['darwin/arm64', 'darwin/x64', 'linux/arm64', 'linux/x64', 'win32/arm64', 'win32/x64'].map(host => [host, { guard: { path: 'runtime/helpers/' + host + '/guard' } }])) };
    for (const host of ['darwin/arm64', 'linux/arm64']) { const name = lock.native_helpers[host].guard.path, target = path.join(root, name); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, 'original nonexecuted helper fixture ' + host); chmodSync(target, 0o755); }
    const receipts = selectedNativeHelpers(lock, 'darwin-arm64').map(row => fileReceipt(root, row.guard.path));
    expect(receipts).toEqual(['darwin/arm64', 'linux/arm64'].map(host => {
      const bytes = Buffer.from('original nonexecuted helper fixture ' + host);
      // These are byte/metadata receipts, never Windows execution evidence.
      return { path: lock.native_helpers[host].guard.path, sha256: sha256(bytes), size: bytes.length, executable: process.platform !== 'win32' };
    }));
    expect(() => selectedNativeHelpers(lock, 'all').map(row => fileReceipt(root, row.guard.path))).toThrow();
  } finally { rmSync(root, { recursive: true, force: true }); }
});
