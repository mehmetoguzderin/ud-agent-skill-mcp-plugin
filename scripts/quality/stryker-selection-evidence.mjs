/** Independently replay pristine coverage and selected-baseline authority. */
import { createHash } from 'node:crypto';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { canonicalJson } from '../release/http-transports.mjs';
import { fileReceipt, readRecordedBytes, sourceReceipt } from '../release/candidate.mjs';
import { normalizeProtectedReport } from './stryker-protected-runner.mjs';
import { protectedCoverageSelection, requireCompiledTestCases, serializeScheduledMutation } from './stryker-child.mjs';
import { createStrykerAssertionVerifier, verifyCompiledSources } from './stryker-assertions.mjs';
import { normalizeSubprocessOpacity } from './stryker-opacity.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const authorities = new WeakMap();
const equal = (a, b) => canonicalJson(a) === canonicalJson(b);
const identity = ({ id, source, source_sha256, name, occurrence, upstream_id }) => ({ id, source, source_sha256, name, occurrence, upstream_id });
const demand = (value, message) => { if (!value) throw new Error(message); };

function cleanExecution(value) {
  return value && value.status === 0 && value.timed_out === false && (value.cancelled === undefined || value.cancelled === false) && Array.isArray(value.owned_descendants_cancelled) && value.owned_descendants_cancelled.length === 0 && Number.isSafeInteger(value.uid) && value.uid >= 100001 && value.handoff?.readonly_tree === true && /^[a-f0-9]{64}$/.test(value.handoff.inventory_sha256 ?? '') && /^[a-f0-9]{64}$/.test(value.handoff.source_inventory_sha256 ?? '') && /^[a-f0-9]{32}$/.test(value.execution_id ?? '');
}

/** readBaseline returns exact recorded bytes; readExecution reads owned control data. */
export async function verifyProtectedSelections({ schedule, records, sourceRoot, readBaseline, readExecution, immutableSdkContext, coverageAnalysis='perTest' }) {
  const errors = [], selected = new Map(), baselines = new Map(), seen = new Set(), executions = new Map(), uids = new Set();
  let full = null, fullReceipt = null;
  const control = (receipt, role) => {
    demand(cleanExecution(receipt?.execution), 'confined invocation receipt is missing');
    const claimed = receipt.execution, id = claimed.execution_id, binding = canonicalJson(receipt);
    if (executions.has(id)) {
      const previous = executions.get(id);
      demand(!role.startsWith('mutant:') && previous.role === role && previous.binding === binding, 'execution identity was reused for another role or mutation');
      return previous.control;
    }
    const actual = structuredClone(readExecution(id)), root = `/tmp/ud-mutation-jobs/${id}`;
    demand(cleanExecution(actual) && actual.collected === true && actual.qualification === 'protected-exec' && equal(actual.command, ['/opt/mutation/node/bin/node', '/opt/mutation/harness/stryker-child.mjs', `${root}/request.json`, `${root}/result.json`]) && Object.entries(claimed).every(([key, value]) => Object.hasOwn(actual, key) && equal(actual[key], value)), 'claimed invocation differs from fixed owned execution control');
    demand(!uids.has(actual.uid), 'fresh test UID was reused by another invocation');
    uids.add(actual.uid); executions.set(id, { role, binding, control: actual });
    return actual;
  };
  const load = (receipt, role) => {
    const execution = control(receipt, role), compressed = role.startsWith('mutant:');
    const file = receipt?.result;
    const pattern = compressed ? /^stryker-mutant-[1-9][0-9]{0,15}\.json\.gz$/ : /^stryker-baseline-[1-9][0-9]{0,15}\.json$/;
    demand(file && pattern.test(file.path ?? '') && /^[a-f0-9]{64}$/.test(file.sha256 ?? '') && Number.isSafeInteger(file.size) && file.size > 0 && file.size <= 32 * 1024 ** 2 + 65536, 'retained invocation bytes are missing or unbounded');
    const rawReceipt = compressed ? receipt.raw_result : file;
    demand(rawReceipt && /^[a-f0-9]{64}$/.test(rawReceipt.sha256 ?? '') && Number.isSafeInteger(rawReceipt.size) && rawReceipt.size > 0 && rawReceipt.size <= 32 * 1024 ** 2 && execution.result_sha256 === rawReceipt.sha256 && execution.result_size === rawReceipt.size, 'owned harvest differs from its retained raw report');
    const key = canonicalJson(file);
    if (!baselines.has(key)) {
      const bytes = readBaseline(file);
      demand(Buffer.isBuffer(bytes) && bytes.length === file.size && sha(bytes) === file.sha256, 'baseline retained bytes changed');
      const raw = compressed ? gunzipSync(bytes, { maxOutputLength: 32 * 1024 ** 2 }) : bytes;
      demand(raw.length === rawReceipt.size && sha(raw) === rawReceipt.sha256, 'decoded invocation differs from its owned harvest');
      const data = JSON.parse(raw.toString('utf8'));
      baselines.set(key, data);
    }
    const report = baselines.get(key);
    demand(report.child_root === `/tmp/ud-mutation-jobs/${execution.execution_id}/tree`, 'report identifies another private execution tree');
    return { report, execution };
  };
  try {
    demand(schedule?.tool === 'stryker' && Array.isArray(schedule.mutants) && schedule.mutants.length > 0 && Array.isArray(schedule.tests) && schedule.tests.length > 0 && Array.isArray(records) && typeof sourceRoot === 'string' && typeof readBaseline === 'function' && typeof readExecution === 'function', 'complete selection schedule and readers are required');
    demand(['off','perTest'].includes(coverageAnalysis),'unknown protected execution coverage mode');
    const mutants = new Map(schedule.mutants.map(item => [item.id.slice(item.file.length + 1), item]));
    demand(mutants.size === schedule.mutants.length && records.length === mutants.size, 'selection records omit or duplicate the complete mutation inventory');
    const policy = schedule.execution_policy;
    demand(policy?.opaque_executions==='all-observed-cases-and-file-fixtures;global-uncertainty-full-suite'&&policy.test_source_preprocessing==='disabled','pre-outcome opaque execution closure policy is missing');
    const fallbackIds = new Set();
    if (policy !== undefined) {
      demand(policy?.schema_version === 1 && policy.kind === 'pristine-per-test-with-conservative-full-fallback' && policy.unattributed_full_suite === true && policy.hit_limits === 'disabled' && policy.fresh_environment === true && Array.isArray(policy.fallback_mutant_ids) && Number.isSafeInteger(policy.full_suite_timeout_ms) && policy.full_suite_timeout_ms >= 30000 && policy.full_suite_timeout_ms <= 540000, 'pre-outcome execution policy is malformed');
      for (const id of policy.fallback_mutant_ids) {
        demand(typeof id === 'string' && mutants.has(id) && !fallbackIds.has(id), 'full fallback identifies an unknown or duplicate scheduled mutation');
        fallbackIds.add(id);
      }
    }
    const sourceSubject = sourceReceipt(sourceRoot);
    demand(sourceSubject.sha256 === schedule.source_tree_sha256, 'complete source snapshot differs from the independently scheduled subject');
    const sourceInventory = Object.fromEntries(sourceSubject.files.filter(item => item.path.startsWith('tests/')).map(item => [item.path, item.sha256]));
    for (const record of records) {
      try {
        const mutant = mutants.get(record?.mutant_id);
        demand(mutant && !seen.has(record.mutant_id) && record.schema_version === 1 && record.definition_sha256 === mutant.definition_sha256, 'selection identifies an unknown, duplicate or altered mutation');
        seen.add(record.mutant_id);
        const original = load(record.original_baseline, 'original');
        demand(equal(original.report.assertion_sdk_context ?? null, immutableSdkContext ?? null), 'original assertion SDK differs from verified runtime context');
        if (!full) {
          const normalized = normalizeProtectedReport(original.report, sourceRoot, schedule.tests);
          demand(normalized.result.status === 'complete' && (coverageAnalysis==='off'||original.report.result.mutantCoverage?.contract === 'pristine-per-test-coverage-v1') && !original.execution.handoff.materializations?.length && original.execution.handoff.inventory_sha256 === original.execution.handoff.source_inventory_sha256, 'complete pristine baseline or coverage is missing');
          demand(equal(original.report.tests.map(({ id, source, source_sha256, name, occurrence }) => ({ id, source, source_sha256, name, occurrence })), schedule.tests.map(({ id, source, source_sha256, name, occurrence }) => ({ id, source, source_sha256, name, occurrence }))), 'full coverage baseline differs from independently scheduled test identities');
          full = original.report; fullReceipt = record.original_baseline;
          demand(full.assertion_compiled_sources?.child_root===full.child_root,'pristine compiled assertions identify another actual job');
          verifyCompiledSources(full.assertion_compiled_sources,full.assertion_compiled_sources,{sourceRoot,sourceInventory});
          requireCompiledTestCases(full.assertion_compiled_sources,full.tests);
          if(coverageAnalysis==='perTest'){demand(equal(full.result.mutantCoverage.opacity,normalizeSubprocessOpacity(full.subprocess_opacity,full.tests)),'pristine opacity closure differs from complete actual original task observations');
          for (const counts of [full.result.mutantCoverage.static, ...Object.values(full.result.mutantCoverage.perTest), ...Object.values(full.result.mutantCoverage.staticByFile)]) demand(counts && Object.keys(counts).every(id => mutants.has(id)), 'pristine coverage contains an unscheduled mutant');}
        }
        demand(equal(record.original_baseline, fullReceipt), 'selection records use different pristine baseline authority');
        let expected;const selection=record.selection;
        if(coverageAnalysis==='off'){
          demand(selection===null&&record.selected_baseline===null,'full-suite execution contains an unauthorized narrowing or selected baseline');
          expected={cases:full.tests};
        }else{
          expected = protectedCoverageSelection(record.mutant_id, full.result.mutantCoverage, full.tests, { unattributedFullSuite: fallbackIds.has(record.mutant_id), requireOpacity:true });

        demand(!fallbackIds.has(record.mutant_id) || expected.strategy === 'unattributed-original-full-suite', 'full fallback contradicts measured original coverage');
        demand(selection?.strategy === expected.strategy && selection.sha256 === expected.sha256 && selection.mutant_id === expected.mutant_id && equal(selection.cases, expected.cases) && equal(selection.all_cases, full.tests.map(identity)) && selection.baseline_sha256 === fullReceipt.result.sha256 && selection.coverage_sha256 === sha(JSON.stringify(full.result.mutantCoverage)), 'required test selection differs from pristine coverage');
        const baseline = load(record.selected_baseline, 'selected:' + selection.sha256);
        demand(equal(baseline.report.assertion_sdk_context ?? null, immutableSdkContext ?? null), 'selected assertion SDK differs from verified runtime context');
        demand(baseline.execution.handoff.inventory_sha256 === original.execution.handoff.inventory_sha256 && baseline.execution.handoff.source_inventory_sha256 === original.execution.handoff.source_inventory_sha256 && baseline.execution.handoff.inventory_sha256 === baseline.execution.handoff.source_inventory_sha256 && !baseline.execution.handoff.materializations?.length, 'selected baseline was compiled from another source handoff');
        demand(normalizeProtectedReport(baseline.report, sourceRoot, expected.cases, selection).result.status === 'complete', 'unmutated selected test set did not pass');
        demand(baseline.report.assertion_compiled_sources?.child_root===baseline.report.child_root,'selected compiled assertions identify another actual job');
        verifyCompiledSources(full.assertion_compiled_sources,baseline.report.assertion_compiled_sources,{sourceRoot,sourceInventory});
        requireCompiledTestCases(baseline.report.assertion_compiled_sources,baseline.report.tests);
        }
        const candidate = load(record.mutant_report, 'mutant:' + record.mutant_id);
        demand(equal(candidate.report.assertion_sdk_context ?? null, immutableSdkContext ?? null), 'mutant assertion SDK differs from verified runtime context');
        demand(/^[a-f0-9]{32}$/.test(record.execution ?? '') && candidate.execution.execution_id === record.execution && candidate.execution.uid === record.uid && record.required_tests_completed === expected.cases.length && candidate.execution.handoff.source_inventory_sha256 === original.execution.handoff.source_inventory_sha256, 'mutant invocation differs from its required source or case inventory');
        const originalSource = fileReceipt(sourceRoot, mutant.file);
        demand(originalSource.sha256 === mutant.source_sha256 && sha(canonicalJson(mutant.definition)) === mutant.definition_sha256, 'mutation source or definition changed');
        const originalBytes = readRecordedBytes(sourceRoot, originalSource, 16 * 1024 ** 2);
        const program = await serializeScheduledMutation(new TextDecoder('utf-8', { fatal: true }).decode(originalBytes), mutant.definition, path.join(sourceRoot, mutant.file));
        const bytes = Buffer.from(program.content);
        const materialization = { path: mutant.file, before_sha256: mutant.source_sha256, after_sha256: sha(bytes), materializer_version: program.materializer_version, serialized_replacement: program.serialized_replacement, size: bytes.length };
        demand(equal(candidate.report.materialization, materialization) && equal(record.mutant_report.materialization, materialization), 'harvested mutant is not the independently reconstructed AST program');
        const handoff = candidate.execution.handoff.materializations;
        demand(Array.isArray(handoff) && handoff.length === 1 && equal(Object.keys(handoff[0]).sort(), ['path', 'before_sha256', 'after_sha256', 'size'].sort()) && /^[a-f0-9]{64}$/.test(handoff[0].before_sha256 ?? '') && handoff[0].path === materialization.path && handoff[0].after_sha256 === materialization.after_sha256 && handoff[0].size === materialization.size, 'owned materialization differs from the exact candidate');
        demand(candidate.report.assertion_compiled_sources?.child_root===candidate.report.child_root,'mutant compiled assertions identify another actual job');
        verifyCompiledSources(full.assertion_compiled_sources,candidate.report.assertion_compiled_sources,{sourceRoot,sourceInventory});
        requireCompiledTestCases(candidate.report.assertion_compiled_sources,candidate.report.tests);
        const verifyAssertion = await createStrykerAssertionVerifier({ sourceRoot, childRoot: candidate.report.child_root, sourceInventory, immutableSdkContext,compiledSources:full.assertion_compiled_sources });
        const originalTests=new Map(full.tests.map(test=>[test.id,test]));for(const test of candidate.report.tests??[]){const original=originalTests.get(test.id);demand(original&&equal(test.startPosition,original.startPosition)&&test.source===original.source&&test.name===original.name&&test.occurrence===original.occurrence,'mutant case declaration differs from actual pristine collection');}
        const normalized = normalizeProtectedReport(candidate.report, sourceRoot, expected.cases, selection, verifyAssertion);
        demand(['killed', 'survived'].includes(normalized.result.status) && normalized.result.nrOfTests === expected.cases.length, 'mutant report lacks a complete clean outcome');
        const origins=new Map();for(const failure of normalized.failures){const test=normalized.tests.find(test=>test.id===failure.test_id);for(const error of failure.errors){const origin=verifyAssertion(test,error);demand(origin.valid===true,'host assertion origin replay failed');origins.set(sha(canonicalJson([test.id,error])),structuredClone(origin));}}
        selected.set(mutant.id, { origins, tests: new Set(expected.cases.map(item => item.id)), status: normalized.result.status === 'killed' ? 'Killed' : 'Survived', killedBy: normalized.result.killedBy ?? [], failures: normalized.failures });
      } catch (error) { errors.push(`Invalid protected selection ${record?.mutant_id ?? '<missing>'}: ${error.message}`); }
    }
    for (const mutant of mutants.values()) if (!selected.has(mutant.id)) errors.push(`Protected selection has no valid outcome: ${mutant.id}`);
    demand(sourceReceipt(sourceRoot).sha256 === sourceSubject.sha256, 'source changed while independently replaying selected outcomes');
  } catch (error) { errors.push(`Protected selection authority: ${error.message}`); }
  const proof = Object.freeze({ total: selected.size, errors: Object.freeze(errors) });
  if (!errors.length) authorities.set(proof, { schedule: sha(canonicalJson(schedule)), selected });
  return proof;
}

/** Supplied JSON cannot manufacture this independently verified authority. */
export function verifiedSelectionTests(proof, schedule) {
  const value = authorities.get(proof);
  if (!value) return null;
  try { if (value.schedule !== sha(canonicalJson(schedule))) return null; } catch { return null; }
  return Object.freeze({ get: id => value.selected.has(id) ? new Set(value.selected.get(id).tests) : null, outcome: id => value.selected.has(id) ? structuredClone({ status: value.selected.get(id).status, killedBy: value.selected.get(id).killedBy, failures: value.selected.get(id).failures }) : null });
}

/** A child-supplied assertion_origin is never authority. Only an exact error
 * independently replayed from the owned invocation can retrieve this result.
 */
export function verifiedAssertionOrigin(proof,schedule,mutantId,testId,error){
  const authority=authorities.get(proof);if(!authority)return null;
  try{if(authority.schedule!==sha(canonicalJson(schedule)))return null;const origin=authority.selected.get(mutantId)?.origins.get(sha(canonicalJson([testId,error])));return origin?structuredClone(origin):null;}catch{return null;}
}
export const verifyProtectedExecutions=verifyProtectedSelections;
