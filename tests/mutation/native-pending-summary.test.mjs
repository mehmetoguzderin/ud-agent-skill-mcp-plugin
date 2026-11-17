import { expect, test } from 'vitest';
import { finalizeMutationSummary } from '../../scripts/quality/mutation-gate.mjs';

function summary(pending = 2) {
  const rust = {total:5,killed:2,equivalent:1,total_scheduled:5,applicable_current:3,killed_current:2,equivalent_current:1,pending_native:pending,qualification:'pending-native',applicability_verified:true,errors:[]};
  return {qualification:'full-gate',errors:[],backends:{'cargo-mutants':rust}};
}
test('complete current-platform outcomes with verified foreign rows remain pending and non-certifying',()=>{
  const result=finalizeMutationSummary(summary());
  expect(result.status).toBe('pending-native');expect(result.qualification).toBe('pending-native');
  expect(result.rust_mutation).toEqual({total_scheduled:5,applicable_current:3,killed_current:2,equivalent_current:1,pending_native:2,qualification:'pending-native',errors:0});
});
test('native pending never masks local failures missing outcomes or unverified applicability',()=>{
  for(const patch of [{pending_native:1},{applicability_verified:false},{killed_current:1},{total_scheduled:0},{pending_native:-1},{pending_native:1.5},{errors:['runner failure']},{qualification:'passed-locally'}]){
    const value=summary();Object.assign(value.backends['cargo-mutants'],patch);expect(finalizeMutationSummary(value).status).toBe('failed');expect(value.errors.length).toBeGreaterThan(0);
  }
  const value=summary();value.errors.push('Python runner failure');expect(finalizeMutationSummary(value).status).toBe('failed');expect(value.rust_mutation.pending_native).toBe(2);
});
test('a complete current-only mutation run retains its previous successful gate semantics',()=>{
  const value=summary(0);Object.assign(value.backends['cargo-mutants'],{total:3,total_scheduled:3,qualification:'passed-locally'});
  expect(finalizeMutationSummary(value).status).toBe('passed');expect(value.qualification).toBe('full-gate');expect(value.rust_mutation.pending_native).toBe(0);
  const noRust={qualification:'full-gate',errors:[],backends:{}};expect(finalizeMutationSummary(noRust).status).toBe('passed');expect(noRust.rust_mutation).toBeUndefined();
});
