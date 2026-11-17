/** Execute named defect canaries only inside a copied, disposable source tree. */
import { readFileSync, writeFileSync, existsSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function run(command, args, cwd, env, timeout = 120_000) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', timeout, maxBuffer: 16 * 1024 * 1024 });
  return { status: result.status, signal: result.signal, error: result.error?.message,
    stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function vitestReport(filename, assertion, expectedFailure) {
  try {
    const data = JSON.parse(readFileSync(filename, 'utf8'));
    const matches = (data.testResults ?? []).flatMap(file => file.assertionResults ?? []).filter(test => typeof test.fullName === 'string' && test.fullName.includes(assertion));
    if (!Number.isInteger(data.numTotalTests) || data.numTotalTests < 1 || data.numPendingTests || data.numTodoTests || matches.length !== 1) return false;
    if (!expectedFailure) return data.success === true && data.numFailedTests === 0 && matches[0].status === 'passed';
    const message = (matches[0].failureMessages ?? []).join('\n');
    return data.success === false && data.numFailedTests >= 1 && matches[0].status === 'failed' && (/AssertionError|expected/i.test(message) || (/promise resolved[\s\S]*instead of rejecting/i.test(message) && message.includes('Assertion.__VITEST_REJECTS__')));
  } catch { return false; }
}

function junitReport(filename, assertion, expectedFailure) {
  try {
    const text = readFileSync(filename, 'utf8');
    if (!/<testcase\b/.test(text) || /<(?:error|skipped)\b/.test(text) || !text.includes(assertion)) return false;
    return expectedFailure ? /<failure\b/.test(text) : !/<failure\b/.test(text);
  } catch { return false; }
}

function testCase(test, env, root, report, python) {
  const isVitest = test.runner === 'vitest';
  if (!isVitest && test.runner !== 'pytest') throw new Error('Unknown canary test runner');
  const command = isVitest ? process.execPath : python;
  const args = isVitest
    ? [path.join(root, 'node_modules/vitest/vitest.mjs'), 'run', test.test, '--reporter=json', `--outputFile=${report}`]
    : ['-m', 'pytest', test.test, '-q', '--junitxml', report];
  return run(command, args, root, env);
}

export function runFaultCanaries({ root, originalRoot, reportDir, python, env, cases }) {
  if (path.resolve(root) === path.resolve(originalRoot)) throw new Error('Fault canaries require a disposable source copy.');
  if (!Array.isArray(cases) || cases.length === 0) throw new Error('Fault canary inventory is empty.');
  const seen = new Set();
  const baselineCache = new Map();
  const outcomes = [];
  for (const test of cases) {
    if (!test || typeof test.id !== 'string' || !test.id || seen.has(test.id)) throw new Error('Invalid or duplicate fault canary ID.');
    seen.add(test.id);
    if (test.unavailable) { outcomes.push({ id: test.id, status: 'Uncovered', reason: test.unavailable }); continue; }
    const target = path.resolve(root, test.file);
    if (!target.startsWith(path.resolve(root) + path.sep) || !existsSync(target) || !test.find || !test.assertion || !test.test) {
      outcomes.push({ id: test.id, status: 'RunnerError', reason: 'Invalid canary target or definition.' }); continue;
    }
    // Resolve aliases and reject a live checkout even if a caller supplies an
    // incorrect originalRoot. Mutation targets must be independent regular
    // files, never symlinks or hardlinks back into another source tree.
    const resolvedRoot = realpathSync(root);
    if (existsSync(path.join(resolvedRoot, '.git')) || (existsSync(originalRoot) && resolvedRoot === realpathSync(originalRoot))) throw new Error('Fault canaries require a disposable source copy.');
    let cursor = resolvedRoot;
    for (const part of path.relative(root, target).split(path.sep)) {
      cursor = path.join(cursor, part);
      if (lstatSync(cursor).isSymbolicLink()) throw new Error('Fault canary target aliases another source tree.');
    }
    const info = lstatSync(target);
    if (!info.isFile() || info.nlink !== 1) throw new Error('Fault canary target must be an independent ordinary source copy.');
    const original = readFileSync(target, 'utf8');
    const first = original.indexOf(test.find);
    if (first < 0 || first !== original.lastIndexOf(test.find)) {
      outcomes.push({ id: test.id, status: 'RunnerError', reason: 'Mutation anchor is missing or not unique.' }); continue;
    }
    const cacheKey = `${test.runner}:${test.test}:${test.assertion}`;
    let baseline = baselineCache.get(cacheKey);
    if (!baseline) {
      const baselineFile = path.join(reportDir, `canary-${test.id}-baseline.${test.runner === 'vitest' ? 'json' : 'xml'}`);
      const execution = testCase(test, env, root, baselineFile, python);
      const valid = execution.status === 0 && !execution.signal && !execution.error &&
        (test.runner === 'vitest' ? vitestReport(baselineFile, test.assertion, false) : junitReport(baselineFile, test.assertion, false));
      baseline = { valid, execution };
      baselineCache.set(cacheKey, baseline);
    }
    if (!baseline.valid) {
      outcomes.push({ id: test.id, status: 'RunnerError', reason: 'Pristine targeted test did not pass with a complete nonempty report.', detail: baseline.execution.error ?? baseline.execution.stderr.slice(-4000) });
      continue;
    }
    const report = path.join(reportDir, `canary-${test.id}-mutant.${test.runner === 'vitest' ? 'json' : 'xml'}`);
    try {
      writeFileSync(target, original.slice(0, first) + test.replace + original.slice(first + test.find.length));
      const execution = testCase(test, env, root, report, python);
      const valid = execution.status === 1 && !execution.signal && !execution.error &&
        (test.runner === 'vitest' ? vitestReport(report, test.assertion, true) : junitReport(report, test.assertion, true));
      outcomes.push({ id: test.id, status: valid ? 'Killed' : execution.status === 0 ? 'Survived' : 'RunnerError',
        ...(!valid ? { reason: execution.error ?? `Targeted test exit ${execution.status}; intended assertion failure was not verified.` } : {}) });
    } finally { writeFileSync(target, original); }
  }
  return outcomes;
}
