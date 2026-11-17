import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openCalibrationLedger } from '../../evals/local/calibration.mjs';
test('resume cannot replenish a model allowance or spend another model allocation', t => {
  const directory = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-calibration-'));
  t.onTestFinished(() => rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'ledger.json');
  let ledger = openCalibrationLedger(file); ledger.selectModel('minicpm');
  for (let index = 0; index < 2; index++) { ledger.used++; ledger.onCharge(); }
  ledger = openCalibrationLedger(file); ledger.selectModel('minicpm');
  for (let index = 0; index < 2; index++) { ledger.used++; ledger.onCharge(); }
  ledger.used++; assert.throws(() => ledger.onCharge(), /BUDGET_EXCEEDED/);
  assert.equal(openCalibrationLedger(file).used, 4);
  ledger.selectModel('lfm3'); ledger.used++; ledger.onCharge();
  assert.equal(openCalibrationLedger(file).used, 5);
  assert.deepEqual(openCalibrationLedger(file).per_model, { minicpm: 4, lfm3: 1 });
});
