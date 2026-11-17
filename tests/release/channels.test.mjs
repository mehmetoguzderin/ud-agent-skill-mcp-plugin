import { test, expect } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';
import path from 'node:path';
import os from 'node:os';
import { releaseChannels } from '../../scripts/release/channels.mjs';

test('channels select the prerelease npm tag while keeping immutable OCI versions', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  expect(releaseChannels(root, '0.1.0-beta.1')).toEqual({ npm: 'beta', github_prerelease: true, oci: '0.1.0-beta.1' });
  expect(releaseChannels(root, '0.1.0')).toEqual({ npm: 'latest', github_prerelease: false, oci: '0.1.0' });
});
test('channel policy refuses mutation of promotion order and mutable aliases', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-channel-'));
  try {
    mkdirSync(path.join(root, 'release')); const file = path.join(root, 'release/channels.yaml'); writableFixtureCopy(path.resolve(import.meta.dirname, '../../release/channels.yaml'), file, root); const original = readFileSync(file, 'utf8');
    for (const text of [original.replace('mutable_latest: false', 'mutable_latest: true'), original.replace('require_all_targets_verified: true', 'require_all_targets_verified: false'), original + '\nschema_version: 1\n']) { writeFileSync(file, text); expect(() => releaseChannels(root, '0.1.0-beta.1')).toThrow(); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
