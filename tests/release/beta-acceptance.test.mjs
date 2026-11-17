import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'vitest';
import { verifyBetaAcceptance } from '../../scripts/release/beta-acceptance.mjs';
import { fileReceipt } from '../../scripts/release/candidate.mjs';

test('the beta requires every green CI job on the final commit and smoke from the actual archive', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-beta-acceptance-'));
  try {
    const policy = JSON.parse(readFileSync(new URL('../../quality/requirements.json', import.meta.url))).publisher_beta_acceptance;
    const candidate = {
      source_commit: '1'.repeat(40),
      publisher_commit: '1'.repeat(40),
      source_tree_sha256: '2'.repeat(64),
      runtime_lock_sha256: '3'.repeat(64),
      artifacts: [
        { id: 'native-macos-arm64', path: 'out/macos.tar.gz', size: 123, sha256: '4'.repeat(64) },
        { id: 'mcpb-macos-arm64', path: 'out/macos.mcpb', size: 456, sha256: '8'.repeat(64) },
      ],
    };
    const { source_commit: head_sha } = candidate;
    const success = { status: 'completed', conclusion: 'success' };
    const repo = { full_name: policy.repository };
    const run = { ...success, id: 13, event: 'push', head_branch: 'main', head_sha, path: policy.workflow_path, repository: repo, head_repository: repo };
    const jobs = policy.jobs.map(name => ({ ...success, run_id: run.id, head_sha, name }));
    const ci = { run, jobs: { total_count: jobs.length, jobs } };
    const inventory_sha256 = '5'.repeat(64);
    const installed = {
      qualification: 'diagnostic-native-apple-provider-probe', status: 'passed', workload_passed: true,
      cleanup_passed: true,
      packages: candidate.artifacts.map((archive, index) => ({
        format: index === 0 ? 'native' : 'mcpb', status: 'passed',
        archive: path.basename(archive.path), sha256: 'sha256:' + archive.sha256,
        checked: {
          verified: true, qualification: 'verified-original-package-extraction', kind: 'native',
          platform: 'darwin-arm64', archive_sha256: archive.sha256, archive_size_bytes: archive.size, inventory_sha256,
        },
        payload: {
          kind: 'native', platform: 'darwin-arm64', inventory_sha256,
          source_tree_sha256: candidate.source_tree_sha256, runtime_lock_sha256: candidate.runtime_lock_sha256,
        },
        rows: [['modern', '2026-07-28'], ['legacy', '2025-11-25']].map(([era, protocol]) =>
          ({ era, protocol, runtime: 'apple-container', tools: 104, report_sha256: '6'.repeat(64) })),
      })),
    };
    function verify(ciReport = ci, installedReport = installed) {
      candidate.evidence = Object.entries({ 'github-ci': ciReport, 'installed-smoke': installedReport }).map(([suite_id, report]) => {
        const file = suite_id + '.json';
        writeFileSync(path.join(root, file), JSON.stringify(report));
        return { suite_id, ...fileReceipt(root, file) };
      });
      return verifyBetaAcceptance(root, candidate, policy);
    }
    assert.equal(verify(), 2);
    const skipped = { ...success, conclusion: 'skipped', run_id: run.id, head_sha, name: policy.skipped_job };
    const withSkip = { ...ci, jobs: { total_count: jobs.length + 1, jobs: [...jobs, skipped] } };
    assert.equal(verify(withSkip), 2);
    assert.throws(() => verify({ ...ci, jobs: { ...withSkip.jobs, jobs: [...jobs, { ...skipped, conclusion: 'failure' }] } }), /every required job/);
    assert.throws(() => verify({ ...ci, run: { ...run, head_sha: '7'.repeat(40) } }), /candidate commit/);
    assert.throws(() => verify({ ...ci, jobs: { ...ci.jobs, jobs: [...jobs.slice(1), jobs[1]] } }), /every required job/);
    assert.throws(() => verify(ci, { ...installed, cleanup_passed: false }), /smoke did not pass/);
    assert.throws(() => verify(ci, { ...installed, packages: installed.packages.slice(1) }), /smoke did not pass/);
    const changed = structuredClone(installed);
    changed.packages[0].checked.archive_size_bytes++;
    assert.throws(() => verify(ci, changed), /candidate archive/);
    changed.packages[0].checked.archive_size_bytes--;
    changed.packages[0].rows[1].era = 'modern';
    assert.throws(() => verify(ci, changed), /both MCP validation/);
    candidate.evidence.pop();
    assert.throws(() => verifyBetaAcceptance(root, candidate, policy), /evidence is missing/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
