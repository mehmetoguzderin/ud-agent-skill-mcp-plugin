/** Match actual original-test observations to the independent runner catalog. */
import path from 'node:path';
import { canonicalJson } from '../release/http-transports.mjs';
import { fileReceipt } from '../release/candidate.mjs';
import { verifyNativeTestApplicability } from './native-test-scopes.mjs';

const need = (ok, message) => { if (!ok) throw new Error(`Original acceptance: ${message}`); };
function sourcePath(root, filename) {
  need(typeof filename === 'string' && path.isAbsolute(filename), 'test source must be absolute');
  const relative = path.relative(root, filename).split(path.sep).join('/');
  need(relative && !relative.startsWith('../') && !relative.includes('\\'), 'test source escaped the checkout');
  return relative;
}
export function originalVitestOutcomes(root, data) {
  need(data?.success === true && ['numFailedTests', 'numPendingTests', 'numTodoTests', 'numFailedTestSuites', 'numPendingTestSuites'].every(key => data[key] === 0), 'Vitest has failed, pending, skipped or missing totals');
  need(['numTotalTestSuites', 'numPassedTestSuites', 'numTotalTests', 'numPassedTests'].every(key => Number.isSafeInteger(data[key]) && data[key] > 0), 'Vitest positive totals are missing or invalid');
  need(Array.isArray(data.testResults) && data.testResults.length > 0 && data.numTotalTestSuites >= data.testResults.length && data.numTotalTestSuites === data.numPassedTestSuites, 'Vitest suite inventory is empty or incomplete');
  const rows = data.testResults.flatMap(suite => {
    const source = sourcePath(root, suite.name);
    need(suite.status === 'passed' && Array.isArray(suite.assertionResults) && suite.assertionResults.length > 0, 'Vitest suite failed or has no observations');
    return suite.assertionResults.map(test => {
      need(test.status === 'passed' && Array.isArray(test.failureMessages) && test.failureMessages.length === 0 && typeof test.title === 'string' && test.title.length > 0 && Array.isArray(test.ancestorTitles) && test.ancestorTitles.every(value => typeof value === 'string'), 'Vitest test did not pass cleanly');
      const titles = [...test.ancestorTitles, test.title];
      need(test.fullName === titles.join(' '), 'Vitest original names disagree');
      // Vitest list joins ancestry with ` > `; its JSON execution reporter
      // joins fullName with spaces. Reconstruct from the actual ancestry,
      // preserving literal separators inside titles rather than splitting it.
      return { runner: 'vitest', source, name: titles.join(' > '), status: 'passed' };
    });
  });
  need(rows.length === data.numTotalTests && rows.length === data.numPassedTests, 'Vitest totals differ from actual observations');
  return rows;
}
export function originalPythonOutcomes(data) {
  need(data?.schema_version === 1 && data.kind === 'original-unittest-execution' && data.successful === true && Array.isArray(data.cases) && data.cases.length > 0 && data.tests_run === data.cases.length, 'Python execution is empty or incomplete');
  return data.cases.map(test => {
    need(typeof test.id === 'string' && typeof test.source === 'string' && /^[a-f0-9]{64}$/.test(test.source_sha256 ?? '') && test.completed === true && canonicalJson(test.events) === canonicalJson([{ kind: 'success' }]), 'Python test failed, skipped or has missing completion');
    return { runner: 'python', source: test.source, source_sha256: test.source_sha256, name: test.id, status: 'passed' };
  });
}
export function originalRustOutcomes(source, stdout, expectedCount) {
  const summary = [...stdout.matchAll(/^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;.*$/gm)];
  need(summary.length === 1 && Number(summary[0][1]) === expectedCount && summary[0].slice(2, 6).every(value => Number(value) === 0), 'Rust summary contains missing, ignored, filtered or failed tests');
  const rows = [...stdout.matchAll(/^test (.+) \.\.\. (.+)$/gm)].map(([, name, status]) => {
    need(status === 'ok', 'Rust test did not pass');
    return { runner: 'rust', source, name, status: 'passed' };
  });
  need(rows.length === expectedCount, 'Rust observations differ from discovery');
  return rows;
}
export function reconcileOriginalOutcomes(root, catalog, observations) {
  need(catalog?.kind === 'acceptance-discovery' && Array.isArray(catalog.tests) && catalog.tests.length > 0 && Array.isArray(observations), 'independent test discovery is missing');
  verifyNativeTestApplicability(root, catalog.native_applicability, catalog.environment?.os);
  const expected = new Map(), occurrences = new Map(), used = new Set();
  for (const test of catalog.tests) {
    const key = canonicalJson([test.runner, test.source, test.name, test.occurrence]);
    need(!expected.has(key), 'duplicate discovered test'); expected.set(key, test);
  }
  const rows = observations.map(actual => {
    const key = canonicalJson([actual.runner, actual.source, actual.name]), occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    const test = expected.get(canonicalJson([actual.runner, actual.source, actual.name, occurrence]));
    need(test && !used.has(test.id) && actual.status === 'passed', 'unexpected, duplicated or failed test outcome');
    need(fileReceipt(root, test.source).sha256 === test.source_sha256 && (!actual.source_sha256 || actual.source_sha256 === test.source_sha256), 'test source changed after independent discovery');
    used.add(test.id); return { id: test.id, source: test.source, source_sha256: test.source_sha256, name: test.name, occurrence, runner: test.runner, status: 'passed' };
  });
  need(used.size === expected.size && rows.length === catalog.tests.length, 'independently discovered tests have missing outcomes');
  return rows.sort((a, b) => a.id.localeCompare(b.id, 'en'));
}
