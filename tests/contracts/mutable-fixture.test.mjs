import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

test('a sealed original stays byte- and mode-identical while only its private copy becomes writable', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-mutable-fixture-'));
  try {
    const source = path.join(root, 'original'), privateRoot = path.join(root, 'private'); mkdirSync(source); mkdirSync(privateRoot);
    const original = path.join(source, 'data'); writeFileSync(original, 'original bytes'); chmodSync(original, 0o444); chmodSync(source, 0o555);
    const before = statSync(original), target = path.join(privateRoot, 'copy'); writableFixtureCopy(source, target, privateRoot);
    writeFileSync(path.join(target, 'data'), 'edited copy');
    assert.equal(readFileSync(original, 'utf8'), 'original bytes'); assert.equal(statSync(original).mode, before.mode); assert.equal(statSync(original).ino, before.ino);
    assert.equal(readFileSync(path.join(target, 'data'), 'utf8'), 'edited copy');
    assert.throws(() => writableFixtureCopy(source, path.join(root, 'escape'), privateRoot), /owned child/);
    assert.throws(() => writableFixtureCopy(source, privateRoot, privateRoot), /owned child/);
    assert.throws(() => writableFixtureCopy(source, target, privateRoot), /already exists/);
  } finally { chmodSync(path.join(root, 'original'), 0o700); chmodSync(path.join(root, 'original/data'), 0o600); rmSync(root, { recursive: true, force: true }); }
});
