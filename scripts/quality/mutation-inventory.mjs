/** Canonical scheduled mutations and exact outcome reconciliation. */
import { createHash } from 'node:crypto';
import { canonicalJson } from '../release/http-transports.mjs';
import { reviewedEquivalent } from './equivalents.mjs';
import { summarizeAssertionObligations } from './assertion-obligations.mjs';
import { verifiedSelectionTests } from './stryker-selection-evidence.mjs';
import { verifiedMutationMaterializations } from '../release/mutation-backends.mjs';
const sha = value => createHash('sha256').update(value).digest('hex');
const HEX = /^[0-9a-f]{64}$/;
const cleanAssertions=errors=>Array.isArray(errors)&&errors.length>0&&errors.every(error=>error&&['AssertionError','AssertionError [ERR_ASSERTION]','VitestAssertionError'].includes(error.name)&&(error.code===undefined||error.code===null||error.code==='ERR_ASSERTION'));
function insist(value, message) { if (!value) throw new Error(message); }

function offset(source, position) {
  insist(position && Number.isInteger(position.line) && position.line >= 0 && Number.isInteger(position.column) && position.column >= 0, 'Invalid mutation source position.');
  const lines = source.split('\n'); insist(position.line < lines.length && position.column <= lines[position.line].length, 'Mutation source position exceeds its source.');
  return lines.slice(0, position.line).reduce((sum, line) => sum + line.length + 1, 0) + position.column;
}

export function mutationDefinition(file, source, mutant, { tool = 'stryker', version = '10.1.1' } = {}) {
  insist(typeof file === 'string' && /^(?:packages|workers|scripts|runtime|quality|contracts|evals|\.github)\//.test(file) && !file.split('/').some(part => !part || part === '.' || part === '..') && typeof source === 'string', 'Invalid mutation source identity.');
  insist(mutant && typeof mutant.mutatorName === 'string' && mutant.mutatorName.length > 0 && typeof mutant.replacement === 'string', 'Invalid mutation definition.');
  const start = offset(source, mutant.location?.start), end = offset(source, mutant.location?.end);
  insist(end >= start, 'Mutation source range is reversed.');
  const definition = { tool, version, operator: mutant.mutatorName, location: mutant.location, original: source.slice(start, end), replacement: mutant.replacement };
  return { id: `${file}#${mutant.id}`, file, source_sha256: sha(Buffer.from(source)), definition_sha256: sha(Buffer.from(canonicalJson(definition))), definition };
}

export function reconcileScheduledMutations(schedule, outcomes, failures, sourceHashes, {exceptions=[],used=new Set(),readReview,selectionProof,assertionClassifier,requireIndependentBehavior=false} = {}) {
  const errors = []; const result = { total: 0, killed: 0, equivalent: 0, errors };
  if (!schedule || schedule.schema_version !== 1 || schedule.tool !== 'stryker' || schedule.tool_version !== '10.1.1' || !Array.isArray(schedule.mutants) || !schedule.mutants.length || !Array.isArray(schedule.tests) || !schedule.tests.length || !Array.isArray(outcomes) || !Array.isArray(failures)) {
    errors.push('Scheduled mutation inventory or structured outcomes are missing.'); return result;
  }
  if(requireIndependentBehavior){result.independent_behavior_killed=0;result.behavior_pending=0;result.assertion_obligations=[];if(typeof assertionClassifier!=='function')errors.push('Source-bound independent assertion-obligation authority is missing.');}
  const expected = new Map(); const definitions = new Set();
  for (const item of schedule.mutants) {
    const identity = `${item?.file}\0${item?.definition_sha256}`;
    if (!item || expected.has(item.id) || definitions.has(identity) || sourceHashes[item.file] !== item.source_sha256 || !HEX.test(item.source_sha256 ?? '') || !HEX.test(item.definition_sha256 ?? '') || !item.definition || sha(Buffer.from(canonicalJson(item.definition))) !== item.definition_sha256) errors.push(`Invalid or duplicate scheduled mutation: ${item?.id}`);
    else { expected.set(item.id, item); definitions.add(identity); }
  }
  const tests = new Set();
  for (const test of schedule.tests) {
    if (!test || typeof test.id !== 'string' || tests.has(test.id) || sourceHashes[test.source] !== test.source_sha256 || test.status !== 'Success') errors.push('Invalid or duplicate discovered mutation test.');
    else tests.add(test.id);
  }
  const selected = selectionProof ? verifiedSelectionTests(selectionProof, schedule) : null;
  if (selectionProof && !selected) errors.push('Mutation test selections have no independently verified pristine authority.');
  const failureMap = new Map();
  for (const event of failures) {
    const mutantId = String(event?.mutant_id); const events = failureMap.get(mutantId) ?? []; events.push(event); failureMap.set(mutantId, events);
    if (!tests.has(event?.test_id) || !['assertion', 'runtime'].includes(event?.failure_kind)) errors.push(`Invalid structured mutation failure: ${mutantId}`);
  }
  const seen = new Set();
  for (const outcome of outcomes) {
    result.total++;
    const id = `${outcome.file}#${outcome.id}`, expectedMutant = expected.get(id);
    if (!expectedMutant || seen.has(id) || outcome.definition_sha256 !== expectedMutant.definition_sha256) { errors.push(`Unknown, duplicate or changed mutation outcome: ${id}`); continue; }
    seen.add(id);
    const required = selected ? selected.get(id) : tests;
    if(!required||!Number.isInteger(outcome.testsCompleted)||outcome.testsCompleted!==required.size){errors.push(`Mutation outcome did not complete every independently scheduled test: ${id}`);continue;}
    const events = failureMap.get(String(outcome.id)) ?? [];
    if (selected) {
      const verified = selected.outcome(id);
      if (!verified || verified.status !== outcome.status || canonicalJson(verified.killedBy) !== canonicalJson(outcome.killedBy ?? []) || canonicalJson(verified.failures) !== canonicalJson(events.map(({ mutant_id, ...event }) => event))) { errors.push(`Mutation outcome differs from its exact harvested invocation: ${id}`); continue; }
    }
    if (outcome.status === 'Survived' && events.length === 0 && reviewedEquivalent({exceptions,used,tool:'stryker',id,file:outcome.file,hashes:sourceHashes,definition:expectedMutant.definition,readReview})) { result.equivalent++; continue; }
    if (outcome.status !== 'Killed') { errors.push(`Unresolved scheduled mutation ${outcome.status ?? 'missing status'}: ${id}`); continue; }
    if (!Array.isArray(outcome.killedBy) || !outcome.killedBy.length || outcome.killedBy.some(test => !required.has(test)) || !events.length || events.some(event => !required.has(event.test_id)||event.failure_kind !== 'assertion'||!cleanAssertions(event.errors)) || outcome.killedBy.some(test => !events.some(event => event.test_id === test))) errors.push(`Mutation kill lacks clean structured assertion evidence: ${id}`);
    else {
      result.killed++;
      if(requireIndependentBehavior){
        const classifications=[];
        for(const event of events){const test=schedule.tests.find(test=>test.id===event.test_id);for(const error of event.errors){try{classifications.push(typeof assertionClassifier==='function'?assertionClassifier(test,error,{mutant_id:id}):{classification:'unclassified'});}catch(cause){classifications.push({classification:'invalid_assertion'});errors.push(`Assertion-obligation replay failed for ${id}: ${cause.message}`);}}}
        const assessment=summarizeAssertionObligations(classifications);
        result.assertion_obligations.push({id,file:expectedMutant.file,source_sha256:expectedMutant.source_sha256,definition_sha256:expectedMutant.definition_sha256,...assessment,sites:classifications});
        if(assessment.independent_behavior_detected)result.independent_behavior_killed++;else{result.behavior_pending++;errors.push(`Mutation lacks independently reviewed behavior assertion evidence (${assessment.qualification}): ${id}`);}
      }
    }
  }
  for (const id of expected.keys()) if (!seen.has(id)) errors.push(`Scheduled mutation has no outcome: ${id}`);
  const scheduledRawIds = new Set(schedule.mutants.map(item => item.id.slice(item.id.lastIndexOf('#') + 1)));
  for (const id of failureMap.keys()) if (!scheduledRawIds.has(id)) errors.push(`Test evidence identifies an unscheduled mutant: ${id}`);
  return result;
}

/** Bind mutmut's independently materialized definitions to every final metadata row. */
export function reconcilePythonSchedule(plan, report, metadata, hashes, snapshot, generation = undefined) {
  const errors=[];
  if (!plan || plan.tool!=='mutmut' || plan.tool_version!=='3.8.1' || plan.source_tree_sha256!==snapshot || report?.source_tree_sha256!==snapshot || !Array.isArray(plan.inventory) || !plan.inventory.length || plan.scheduled!==plan.inventory.length || !Array.isArray(plan.tests) || !plan.tests.length || !Array.isArray(report.outcomes)) return ['Python independent mutation/test schedule or outcomes are missing.'];
  const expected=new Map(), definitions=new Set(), tests=new Set();
  const compact=plan.definition_representation==='mutmut-control-spans-v1';
  let known;
  if(plan.definition_representation!==undefined&&!compact)errors.push('Python definition representation is unsupported.');
  if(compact){
    try{
      const verified=verifiedMutationMaterializations(generation);
      if(verified.backend.tool!=='mutmut'||verified.backend.version!=='3.8.1'||verified.source_materializations.some(row=>hashes[row.source]!==row.source_sha256)||verified.inventory.length!==plan.inventory.length)throw Error('different source/backend/inventory');
      known=new Map(verified.inventory.map(row=>[row.id,row]));
    }catch{errors.push('Python compact schedule lacks complete verified generation authority.');}
  }
  for (const test of plan.tests) {
    if (!test || typeof test.id!=='string' || tests.has(test.id) || !test.source?.startsWith('tests/') || hashes[test.source]!==test.source_sha256) errors.push('Python discovered test inventory is duplicate, unbound or stale.');
    else tests.add(test.id);
  }
  for (const item of plan.inventory) {
    const definition=item?.definition, signature=`${item?.file}\0${item?.definition_sha256}`;
    const verified=known?.get(item?.id);
    const validDefinition=compact
      ? !Object.hasOwn(item??{},'definition')&&item?.definition_ref?.kind==='mutmut-control-spans-v1'&&verified&&['id','file','source_sha256','definition_sha256'].every(field=>verified[field]===item[field])
      : definition&&definition.tool==='mutmut'&&definition.version==='3.8.1'&&definition.file===item.file&&Number.isInteger(definition.location?.line)&&definition.location.line>=1&&Number.isInteger(definition.location?.end_line)&&definition.location.end_line>=definition.location.line&&typeof definition.original_function==='string'&&typeof definition.replacement_function==='string'&&definition.original_function!==definition.replacement_function&&definition.diff&&sha(canonicalJson(definition))===item.definition_sha256;
    if (!item || expected.has(item.id) || definitions.has(signature) || hashes[item.file]!==item.source_sha256 || !validDefinition) errors.push(`Python scheduled definition is duplicate, unbound or stale: ${item?.id}`);
    else {expected.set(item.id,item);definitions.add(signature);}
  }
  const outcomes=new Map();
  for (const item of report.outcomes) {
    const scheduled=expected.get(item?.id);
    if (!scheduled || outcomes.has(item.id) || item.file!==scheduled.file || metadata[item.file]?.exit_code_by_key?.[item.id]!==item.exit_code || item.type_check_error) errors.push(`Python outcome differs from its exact scheduled definition or metadata: ${item?.id}`);
    else outcomes.set(item.id,item);
  }
  const actual=new Set();
  for (const [file, value] of Object.entries(metadata)) for (const id of Object.keys(value?.exit_code_by_key??{})) {
    if (actual.has(id) || expected.get(id)?.file!==file) errors.push(`Python metadata contains an unscheduled or duplicate mutation: ${id}`);
    actual.add(id);
  }
  for (const id of expected.keys()) if (!outcomes.has(id) || !actual.has(id)) errors.push(`Python scheduled mutation has no exact outcome: ${id}`);
  return errors;
}
