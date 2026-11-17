/** Original planner data only; no generated program is executed. */
import { expect, test } from 'vitest';
import { PlanKind } from '@stryker-mutator/api/core';
import { executionScheduleScope, protectExecutionPlans } from '../../scripts/quality/stryker-evidence-reporter.mjs';

const run = (id, testFilter) => ({ plan: PlanKind.Run, mutant: { id, coveredBy: testFilter ?? [], static: false }, runOptions: { testFilter, timeout: 1000, hitLimit: 100, reloadEnvironment: false, disableBail: true, mutantActivation: 'runtime' } });

test('unattributed subprocess coverage schedules the complete original suite without fabricated hits', () => {
  const unknown = run('7', []), observed = run('8', ['tests/example.test.mjs#case']), all = run('9', undefined);
  const early = { plan: PlanKind.EarlyResult, mutant: { id: '10', status: 'CompileError' } };
  const policy = protectExecutionPlans([unknown, observed, all, early], { net: 100000, overhead: 20000 });
  expect(policy).toEqual({ schema_version: 1, kind: 'pristine-per-test-with-conservative-full-fallback', unattributed_full_suite: true, fallback_mutant_ids: ['7'], hit_limits: 'disabled', fresh_environment: true, opaque_executions: 'all-observed-cases-and-file-fixtures;global-uncertainty-full-suite', test_source_preprocessing: 'disabled', full_suite_timeout_ms: 270000 });
  expect(unknown.mutant.coveredBy).toEqual([]); expect(unknown.mutant.static).toBe(false);
  expect(unknown.runOptions.testFilter).toBeUndefined(); expect(unknown.runOptions.mutantActivation).toBe('static');
  expect(unknown.runOptions.timeout).toBe(270000);
  expect(observed.runOptions.testFilter).toEqual(['tests/example.test.mjs#case']);
  expect(observed.runOptions.timeout).toBe(1000);
  for (const item of [unknown, observed, all]) { expect(item.runOptions.hitLimit).toBeUndefined(); expect(item.runOptions.reloadEnvironment).toBe(true); expect(item.runOptions.disableBail).toBe(true); }
  expect(early).toEqual({ plan: PlanKind.EarlyResult, mutant: { id: '10', status: 'CompileError' } });
});

test('full-suite fallback retains finite bounds and rejects absent or invalid original timing', () => {
  expect(protectExecutionPlans([run('1', [])], { net: 0.01, overhead: 0 }).full_suite_timeout_ms).toBe(30001);
  expect(protectExecutionPlans([run('1', [])], { net: 1000000, overhead: 0 }).full_suite_timeout_ms).toBe(540000);
  for (const timing of [undefined, null, {}, { net: -1, overhead: 1 }, { net: Infinity, overhead: 0 }, { net: 1, overhead: NaN }]) expect(() => protectExecutionPlans([], timing)).toThrow(/original timing/);
  expect(() => protectExecutionPlans(null, { net: 1, overhead: 1 })).toThrow(/original timing/);
  for (const item of [{ plan: PlanKind.Run, mutant: { id: '../outside' }, runOptions: {} }, { plan: PlanKind.Run, mutant: { id: '1' } }]) expect(() => protectExecutionPlans([item], { net: 1, overhead: 1 })).toThrow(/identity/);
});

test('selected diagnostic schedules retain a pre-outcome incomplete-scope label',()=>{
 expect(executionScheduleScope({})).toEqual({scope_complete:true});
 const scope={schema_version:1,kind:'selected-stryker-diagnostic',scope_complete:false,source_tree_sha256:'a'.repeat(64),source_sha256:'b'.repeat(64),file:'packages/example.ts',range:'packages/example.ts:1:1-2:1'};
 const env={UD_STRYKER_DIAGNOSTIC_SCOPE:'/state/stryker-diagnostic-scope.json',UD_MUTATION_SNAPSHOT_SHA256:'a'.repeat(64)};
 expect(executionScheduleScope(env,()=>Buffer.from(JSON.stringify(scope)))).toEqual({scope_complete:false,qualification:'selected-diagnostic',diagnostic_scope:scope});
 expect(()=>executionScheduleScope({...env,UD_STRYKER_DIAGNOSTIC_SCOPE:'/foreign'},()=>Buffer.from(JSON.stringify(scope)))).toThrow(/fixed coordinator/);
 for(const change of[{scope_complete:true},{source_tree_sha256:'c'.repeat(64)},{range:'foreign:1:1-2:1'},{kind:'complete'}])expect(()=>executionScheduleScope(env,()=>Buffer.from(JSON.stringify({...scope,...change})))).toThrow(/source-bound/);
 expect(()=>executionScheduleScope(env,()=>Buffer.alloc(65537))).toThrow(/unbounded/);
});
