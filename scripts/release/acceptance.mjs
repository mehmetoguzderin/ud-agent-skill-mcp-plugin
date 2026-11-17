/** Reconcile signed results with the frozen acceptance inventory. */
import { isAcceptanceSource } from './discover-acceptance.mjs';
import { canonicalJson } from './http-transports.mjs';
const SHA = /^[0-9a-f]{64}$/;
function requireValue(condition, message) { if (!condition) throw new Error(`Acceptance inventory: ${message}`); }

export function validateAcceptanceInventory(inventory, requiredSuites) {
  requireValue(inventory?.schema_version === 1 && inventory.state === 'frozen' && Array.isArray(inventory.suites), 'a frozen suite inventory is required');
  requireValue(Array.isArray(requiredSuites) && requiredSuites.length > 0, 'required suite list is missing');
  const suites = new Map();
  for (const suite of inventory.suites) {
    requireValue(typeof suite?.id === 'string' && !suites.has(suite.id), 'duplicate or invalid suite');
    requireValue(Array.isArray(suite.tests) && suite.tests.length > 0, `empty test inventory: ${suite.id}`);
    const testIds = new Set();
    for (const test of suite.tests) {
      requireValue(typeof test?.id === 'string' && test.id.length > 0 && !testIds.has(test.id) && isAcceptanceSource(test.source), `invalid test inventory: ${suite.id}`);
      testIds.add(test.id);
    }
    if (suite.id.startsWith('mutation-')) {
      requireValue(Array.isArray(suite.mutants) && suite.mutants.length > 0, `empty mutation inventory: ${suite.id}`);
      const mutantIds = new Set();
      for (const mutant of suite.mutants) {
        const bounded = suite.id === 'mutation-bounded' && suite.bounded_policy?.cases?.find(row => row.id === mutant?.id && row.file === mutant.file && row.source_sha256 === mutant.source_sha256);
        requireValue(typeof mutant?.id === 'string' && mutant.id.length > 0 && !mutantIds.has(mutant.id) && typeof mutant.file === 'string' && (bounded || /^(?:packages|workers|scripts|runtime|quality|contracts|evals|\.github)\//.test(mutant.file)) && SHA.test(mutant.source_sha256 ?? '') && SHA.test(mutant.definition_sha256 ?? ''), `invalid mutation inventory: ${suite.id}`);
        mutantIds.add(mutant.id);
      }
    }
    if (suite.id === 'mutation-bounded') {
      requireValue(inventory.profile === 'bounded' && inventory.policy === 'bounded-reviewed-v1' && inventory.exhaustive === false && suite.profile === 'bounded' && suite.policy === inventory.policy && suite.qualification === 'bounded-reviewed-corpus' && suite.exhaustive === false && suite.mutants.length === 18 && suite.bounded_policy?.scheduled === 18 && SHA.test(suite.bounded_policy?.corpus?.sha256 ?? ''), 'bounded inventory lacks its explicit reviewed corpus policy');
      requireValue(suite.bounded_policy.cases.length === 18 && new Set(suite.bounded_policy.cases.map(row => row.id)).size === 18 && suite.bounded_policy.cases.every(row => suite.mutants.some(mutant => mutant.id === row.id && mutant.file === row.file && mutant.source_sha256 === row.source_sha256 && mutant.definition_sha256 === row.definition_sha256)), 'bounded inventory omits a declared corpus case');
    }
    if (/^(?:install|runtime)-(?:linux|macos|windows)-(?:amd64|arm64)$/.test(suite.id)) {
      requireValue(suite.native_platform === suite.id.replace(/^(?:install|runtime)-/, ''), `missing native platform: ${suite.id}`);
    }
    suites.set(suite.id, suite);
  }
  requireValue(requiredSuites.every(id => suites.has(id)) && suites.size === requiredSuites.length, 'suite inventory does not match requirements');
  return suites;
}

export function reconcileSuiteInventory(suite, report) {
  requireValue(suite?.id === report?.suite_id && Array.isArray(report.tests) && report.tests.length === suite.tests.length, `test outcomes incomplete: ${suite?.id}`);
  if (suite.id === 'unit') {
    const native = suite.native_applicability;
    if (native === undefined) requireValue(report.native_applicability === undefined && report.pending_native_scopes === undefined, 'unscheduled native unit obligations');
    else {
      requireValue(report.native_applicability !== undefined && canonicalJson(report.native_applicability) === canonicalJson(native), 'native unit applicability receipt differs from frozen source');
      requireValue(report.environment?.os === native.environment_os, 'native unit execution platform differs from its applicability receipt');
      const pending = native.scopes.filter(row => row.status === 'pending-native');
      requireValue(Array.isArray(report.pending_native_scopes) && canonicalJson(report.pending_native_scopes) === canonicalJson(pending), 'native unit pending obligations were omitted or changed');
      requireValue(pending.length === 0, 'foreign native unit obligations remain pending; applicable-case local success is not complete native unit evidence');
    }
  }
  const expectedTests = new Map(suite.tests.map(test => [test.id, test]));
  const seenTests = new Set();
  for (const test of report.tests) {
    const expected = expectedTests.get(test.id);
    requireValue(!seenTests.has(test.id) && expected?.source === test.source && test.status === 'passed' && (!expected.execution_kind || expected.execution_kind === test.execution_kind), `unexpected test outcome: ${suite.id}`);
    seenTests.add(test.id);
  }
  if (suite.mutants) {
    requireValue(Array.isArray(report.mutants) && report.mutants.length === suite.mutants.length, `mutation outcomes incomplete: ${suite.id}`);
    const expectedMutants = new Map(suite.mutants.map(mutant => [mutant.id, mutant]));
    const seenMutants = new Set();
    for (const mutant of report.mutants) {
      const expected = expectedMutants.get(mutant.id);
      requireValue(expected && !seenMutants.has(mutant.id) && mutant.file === expected.file && mutant.source_sha256 === expected.source_sha256 && mutant.definition_sha256 === expected.definition_sha256, `unexpected mutation outcome: ${suite.id}`);
      seenMutants.add(mutant.id);
    }
  }
  if (suite.id === 'mutation-bounded') {
    requireValue(report.profile === 'bounded' && report.policy === 'bounded-reviewed-v1' && report.qualification === 'bounded-reviewed-corpus' && report.exhaustive === false && report.scheduled === 18 && report.killed === 18 && report.corpus_sha256 === suite.bounded_policy.corpus.sha256 && Array.isArray(report.equivalent_exceptions) && report.equivalent_exceptions.length === 0, 'bounded outcomes lack exact corpus scope or complete kills');
    requireValue(['survivors', 'uncovered', 'timeouts', 'invalid', 'missing'].every(name => report[name] === 0) && report.mutants.every(row => row.status === 'killed'), 'bounded outcomes contain unresolved cases');
    const languages = suite.bounded_policy.per_language;
    requireValue(report.per_language && Object.keys(report.per_language).sort().join(',') === Object.keys(languages).sort().join(',') && Object.entries(languages).every(([language, count]) => report.per_language[language]?.scheduled === count && report.per_language[language]?.killed === count), 'bounded language counts differ from the frozen corpus');
  }
  if (suite.native_platform) requireValue(report.environment?.native_platform === suite.native_platform && report.environment?.emulated === false, `native platform evidence missing: ${suite.id}`);
}
