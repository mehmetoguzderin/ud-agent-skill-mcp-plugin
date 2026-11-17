import { test, expect } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { verifyActualComponentClosure } from '../../scripts/release/component-closure.mjs';

test('actual release replay refuses a full-coverage claim that lacks retained inspection inputs', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-replay-input-gate-'));
  try {
    const recipe = 'runtime/materials/component-source-replay.json';
    mkdirSync(path.dirname(path.join(root, recipe)), { recursive: true });
    writeFileSync(path.join(root, recipe), '{"schema_version":1,"families":[]}');
    const source = { sha256: 'a'.repeat(64), files: [fileReceipt(root, recipe)] };
    const report = { schema_version: 1, qualification: 'replayed-actual-shipped-component-source-license-closure', complete_available_shipped_component_coverage: true, complete_product_coverage: true, source_inventory_sha256: source.sha256, runtime_lock_sha256: 'b'.repeat(64), unresolved_shipped_members: [], missing_distribution_subjects: [], subjects: [] };
    for (const inspection_inputs of [undefined, { qualification: 'observed-component-replay-inputs-no-unretained-input-waiver', unretained_inputs: ['private/sdk.lib'] }, { qualification: 'caller-declared-complete', unretained_inputs: [] }]) {
      writeFileSync(path.join(root, 'coverage.json'), JSON.stringify({ ...report, inspection_inputs }));
      const candidate = { runtime_lock_sha256: report.runtime_lock_sha256, artifacts: [{ id: 'component-source-coverage', ...fileReceipt(root, 'coverage.json') }] };
      expect(() => verifyActualComponentClosure(root, candidate, source)).toThrow(/unretained inspection inputs/);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
