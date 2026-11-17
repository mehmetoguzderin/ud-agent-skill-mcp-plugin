/** Receipt checks for the first publisher beta's CI and exact package smoke. */
import path from 'node:path';
import { readRecordedBytes } from './candidate.mjs';

const HASH = /^[0-9a-f]{64}$/;
const OWNED_SMOKE = 'diagnostic-native-apple-provider-probe';
const REQUIRED_REPORTS = ['github-ci', 'installed-smoke'];
const FORMATS = { native: 'native-macos-arm64', mcpb: 'mcpb-macos-arm64' };
const passed = row => row?.status === 'completed' && row.conclusion === 'success';

function insist(condition, message) {
  if (!condition) throw new Error(`Publisher beta acceptance: ${message}`);
}

function verifyCI(candidate, policy, receipt) {
  const run = receipt?.run;
  const jobs = receipt?.jobs?.jobs;
  insist(candidate.publisher_commit === candidate.source_commit && passed(run) &&
    Number.isSafeInteger(run.id) && run.id > 0 &&
    run.path === policy.workflow_path && run.event === 'push' && run.head_branch === 'main' &&
    run.head_sha === candidate.source_commit && run.repository?.full_name === policy.repository &&
    run.head_repository?.full_name === policy.repository, 'CI did not pass on the candidate commit.');
  const expected = new Set(policy.jobs);
  const plannedSkip = job => job.name === policy.skipped_job && job.status === 'completed' && job.conclusion === 'skipped';
  insist(expected.size > 0 && expected.size === policy.jobs.length && Array.isArray(jobs) &&
    receipt.jobs.total_count === jobs.length && jobs.filter(plannedSkip).length <= 1 &&
    jobs.every(job => job.run_id === run.id && job.head_sha === run.head_sha &&
      (plannedSkip(job) || (passed(job) && expected.delete(job.name)))) && expected.size === 0,
  'CI did not pass every required job.');
}

function verifySmoke(candidate, smoke) {
  insist(smoke?.qualification === OWNED_SMOKE && smoke.status === 'passed' &&
    smoke.workload_passed === true && smoke.cleanup_passed === true &&
    Array.isArray(smoke.packages) && smoke.packages.length === Object.keys(FORMATS).length,
  'Installed package smoke did not pass.');
  const formats = new Set();
  for (const row of smoke.packages) {
    const artifact = candidate.artifacts.find(item => item.id === FORMATS[row?.format]);
    const { checked, payload } = row ?? {};
    insist(artifact && !formats.has(row.format) && row.status === 'passed' &&
      row.archive === path.posix.basename(artifact.path) && row.sha256 === 'sha256:' + artifact.sha256 &&
      checked?.verified === true && checked.qualification === 'verified-original-package-extraction' &&
      checked.archive_sha256 === artifact.sha256 && checked.archive_size_bytes === artifact.size &&
      checked.kind === 'native' && checked.platform === 'darwin-arm64' &&
      payload?.kind === checked.kind && payload.platform === checked.platform &&
      HASH.test(checked.inventory_sha256 ?? '') && payload.inventory_sha256 === checked.inventory_sha256 &&
      payload.source_tree_sha256 === candidate.source_tree_sha256 &&
      payload.runtime_lock_sha256 === candidate.runtime_lock_sha256,
    'Installed smoke is not bound to the candidate archive, source and runtime.');
    formats.add(row.format);
    const eras = new Set(['modern', 'legacy']);
    insist(Array.isArray(row.rows) && row.rows.length === eras.size &&
      row.rows.every(result => eras.delete(result?.era) && result.tools === 104 &&
        /^\d{4}-\d{2}-\d{2}$/.test(result.protocol ?? '') &&
        result.runtime === 'apple-container' && HASH.test(result.report_sha256 ?? '')),
    'Installed smoke did not complete both MCP validation workflows.');
  }
}

export function verifyBetaAcceptance(root, candidate, policy) {
  insist(typeof policy.repository === 'string' && typeof policy.workflow_path === 'string' &&
    Array.isArray(policy.jobs) && Array.isArray(candidate.evidence), 'Invalid beta requirements.');
  const reports = new Map(candidate.evidence.map(item => [item.suite_id, item]));
  insist(candidate.evidence.length === REQUIRED_REPORTS.length &&
    REQUIRED_REPORTS.every(id => reports.has(id)), 'Required CI or installed smoke evidence is missing.');
  const read = id => JSON.parse(readRecordedBytes(root, reports.get(id), 1024 * 1024).toString('utf8'));
  verifyCI(candidate, policy, read('github-ci'));
  verifySmoke(candidate, read('installed-smoke'));
  return reports.size;
}
