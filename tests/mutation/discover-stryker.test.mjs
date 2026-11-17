import { test } from 'vitest';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { discoverStryker } from '../../scripts/quality/discover-stryker.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';

test('independently generates every owned source, records zero-mutant files, and binds canonical/raw aliases before outcomes', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-stryker-discovery-'));
  try {
    for (const directory of ['packages', 'scripts', 'workers', 'evals', 'tests']) mkdirSync(path.join(root, directory));
    writeFileSync(path.join(root, 'packages/source.mjs'), 'export const left = true; export const right = false;\n');
    writeFileSync(path.join(root, 'scripts/types.ts'), 'export type Identity<T> = T;\n');
    writeFileSync(path.join(root, 'workers/source.mjs'), 'export const value = true;\n');
    writeFileSync(path.join(root, 'evals/grade.mjs'), 'export const accepted = false;\n');
    writeFileSync(path.join(root, 'tests/ignored.test.mjs'), "throw new Error('discovery must not execute tests');\n");
    copyFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../package-lock.json'), path.join(root, 'package-lock.json'));
    const report = await discoverStryker(root);
    assert.equal(report.inventory_only, true); assert.equal(report.qualification, 'complete-operator-discovery-no-outcomes');
    assert.deepEqual(report.source_scope.map(item => item.path), ['evals/grade.mjs', 'packages/source.mjs', 'scripts/types.ts', 'workers/source.mjs']);
    assert.deepEqual(report.materialization.map(item => item.generated), [1, 2, 0, 1]);
    assert.equal(report.scheduled, 4);
    const sha = value => createHash('sha256').update(value).digest('hex');
    for (const mutant of report.mutants) {
      assert.equal(mutant.id, `${mutant.file}#${mutant.definition_sha256}`);
      assert.equal(mutant.definition_sha256, sha(canonicalJson(mutant.definition)));
      assert.equal(mutant.source_sha256, sha(readFileSync(path.join(root, mutant.file))));
      assert.match(mutant.raw_id, /#\d+$/);
      assert.equal('status' in mutant, false);
    }
    assert.equal(new Set(report.mutants.map(item => item.raw_id)).size, 4);
    assert.equal(report.runtime.dependency_closure_sha256, sha(canonicalJson(report.runtime.dependency_closure)));
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 30_000);
