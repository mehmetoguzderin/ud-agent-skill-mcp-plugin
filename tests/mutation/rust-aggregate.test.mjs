import { test } from 'vitest';
import assert from 'node:assert/strict';
import { appendAssessment, finalizeMutationSummary } from '../../scripts/quality/mutation-gate.mjs';

const summary = () => ({ qualification: 'full-gate', errors: [], backends: {} });
const local = () => ({
  total: 3, killed: 2, equivalent: 1, errors: [],
  total_scheduled: 3, applicable_current: 3, killed_current: 2, equivalent_current: 1,
  pending_native: 0, qualification: 'passed-locally', applicability_verified: true,
});

test('a complete Rust assessment reaches the final gate with its locally applicable counts', () => {
  const result = summary();
  appendAssessment(result, 'cargo-mutants', local());
  assert.deepEqual(finalizeMutationSummary(result).rust_mutation, {
    total_scheduled: 3, applicable_current: 3, killed_current: 2, equivalent_current: 1,
    pending_native: 0, qualification: 'passed-locally', errors: 0,
  });
  assert.equal(result.status, 'passed');
  assert.equal(result.qualification, 'full-gate');
  assert.deepEqual(result.errors, []);
});

test('verified foreign Rust targets survive the handoff as pending native rather than detected mutants', () => {
  const result = summary();
  appendAssessment(result, 'cargo-mutants', {
    ...local(), total: 5, total_scheduled: 5, pending_native: 2, qualification: 'pending-native',
  });
  finalizeMutationSummary(result);
  assert.equal(result.status, 'pending-native');
  assert.equal(result.qualification, 'pending-native');
  assert.deepEqual(result.rust_mutation, {
    total_scheduled: 5, applicable_current: 3, killed_current: 2, equivalent_current: 1,
    pending_native: 2, qualification: 'pending-native', errors: 0,
  });
  assert.deepEqual(result.errors, []);
});

test('a Rust failure or unverified native gap cannot pass through the aggregate handoff', () => {
  for (const assessment of [
    { ...local(), errors: ['Rust test process crashed'], qualification: 'failed' },
    { ...local(), total: 5, total_scheduled: 5, pending_native: 2, qualification: 'pending-native', applicability_verified: false },
    { ...local(), killed: 1, killed_current: 1 },
  ]) {
    const result = summary();
    appendAssessment(result, 'cargo-mutants', assessment);
    assert.equal(finalizeMutationSummary(result).status, 'failed');
    assert.equal(result.rust_mutation.qualification, 'failed');
    assert.ok(result.errors.length > 0);
    if (assessment.errors.length) assert.ok(result.errors.includes('Rust test process crashed'));
  }
});
