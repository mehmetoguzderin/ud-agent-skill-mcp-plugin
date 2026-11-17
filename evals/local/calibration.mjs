/** Durable calibration allowance shared by admission and resume. MIT. */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { MODELS } from './registry.mjs';

export function openCalibrationLedger(file) {
  const saved = existsSync(file) ? JSON.parse(readFileSync(file)) : { used: 0, maximum: 12, per_model: {} };
  const ids = new Set(MODELS.map(model => model.id));
  if (!Number.isSafeInteger(saved.used) || saved.used < 0 || saved.used > 12 || saved.maximum !== 12 || !saved.per_model
    || Object.entries(saved.per_model).some(([id, count]) => !ids.has(id) || !Number.isSafeInteger(count) || count < 0 || count > 4)
    || Object.values(saved.per_model).reduce((sum, count) => sum + count, 0) !== saved.used) throw new Error('CALIBRATION_LEDGER_INVALID');
  let active;
  const ledger = { ...saved, selectModel(id) { if (!ids.has(id)) throw new Error('CALIBRATION_MODEL_INVALID'); active = id; }, onCharge() {
    const previous = Object.values(ledger.per_model).reduce((sum, count) => sum + count, 0);
    if (!active || (ledger.per_model[active] ?? 0) >= 4 || previous >= 12 || ledger.used !== previous + 1) {
      ledger.used = previous; throw new Error('CALIBRATION_MODEL_BUDGET_EXCEEDED');
    }
    ledger.per_model[active] = (ledger.per_model[active] ?? 0) + 1;
    writeFileSync(file, JSON.stringify({ used: ledger.used, maximum: 12, per_model: ledger.per_model }) + '\n', { mode: 0o600, flush: true });
  } };
  return ledger;
}
