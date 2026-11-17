import { describe, it } from 'vitest';
import assert from 'node:assert/strict';
import { pythonFullSuiteDispatchErrors } from '../../scripts/quality/mutation-gate.mjs';

const source = 'a'.repeat(64);
const schedule = { tests: [{ id: 'tests/test_rule.py::first' }, { id: 'tests/test_rule.py::second' }], inventory: [{ id: 'example.x_observed__mutmut_1' }, { id: 'example.x_unobserved__mutmut_1' }, { id: 'example.x_unobserved__mutmut_2' }] };
const report = () => ({ schema_version: 1, strategy: 'full-discovered-original-suite-not-coverage-selection', source_tree_sha256: source,
  tests: schedule.tests.map(item => item.id), function_names: ['example.x_observed', 'example.x_unobserved'],
  observed_associations: { 'example.x_observed': ['tests/test_rule.py::first'] },
  observed_durations: { 'tests/test_rule.py::first': .01, 'tests/test_rule.py::second': .02 } });

describe('complete Python suite evidence', () => {
  it('accepts complete dispatch while preserving real sparse observations', () => {
    const evidence = report();
    assert.deepEqual(pythonFullSuiteDispatchErrors(evidence, schedule, source), []);
    assert.deepEqual(evidence.observed_associations, { 'example.x_observed': ['tests/test_rule.py::first'] });
  });
  it('rejects missing evidence, omitted functions/tests, stale source and altered durations', () => {
    for (const invalid of [null, { ...report(), function_names: ['example.x_observed'] }, { ...report(), tests: ['tests/test_rule.py::first'] }, { ...report(), source_tree_sha256: 'b'.repeat(64) }, { ...report(), observed_durations: { 'tests/test_rule.py::first': .01 } }, { ...report(), observed_associations: { 'example.x_observed': ['not-collected'] } }, { ...report(), observed_associations: 4 }]) {
      assert.ok(pythonFullSuiteDispatchErrors(invalid, schedule, source).length > 0);
    }
  });
});
