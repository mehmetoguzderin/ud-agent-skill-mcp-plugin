import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

test('publisher workflow grants write authority only after exact candidate verification', () => {
  const workflow = parse(readFileSync('.github/workflows/release-publish.yml', 'utf8'));
  assert.deepEqual(workflow.permissions, {}); assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  assert.equal(workflow.concurrency['cancel-in-progress'], false);
  const { verify, publish } = workflow.jobs;
  assert.deepEqual(verify.permissions, { contents: 'read', actions: 'read' }); assert.equal(publish.needs, 'verify'); assert.equal(publish.environment, 'release-publishing');
  assert.deepEqual(publish.permissions, { contents: 'write', packages: 'write', actions: 'read' });
  for (const job of [verify, publish]) {
    assert.ok(Number.isSafeInteger(job['timeout-minutes']) && job['timeout-minutes'] > 0);
    for (const step of job.steps.filter(step => step.uses)) assert.match(step.uses, /^[A-Za-z0-9-]+\/[A-Za-z0-9-]+@[a-f0-9]{40}$/);
    const downloaded = job.steps.find(step => step.uses?.startsWith('actions/download-artifact@')); assert.equal(downloaded.with.name, 'accepted-release'); assert.equal(downloaded.with.path, '.artifacts/accepted-release'); assert.equal(downloaded.with['run-id'], '${{ inputs.candidate_run_id }}');
  }
  const write = publish.steps.find(step => step.env?.NPM_TOKEN);
  assert.ok(publish.steps.findIndex(step => step.run?.startsWith('node scripts/release/verify.mjs --production')) < publish.steps.indexOf(write));
  assert.equal(write.env.UD_RELEASE_EXPECTED_CANDIDATE_SHA256, '${{ needs.verify.outputs.candidate_sha256 }}');
  const commands = write.run.trim().split('\n'); assert.equal(commands.length, 2); assert.ok(commands[0].includes('publisher.mjs --reconcile')); assert.ok(commands[1].includes('publisher.mjs --promote'));
  assert.ok(publish.steps.filter(step => step !== write).every(step => !step.env?.NPM_TOKEN && !step.env?.MCP_REGISTRY_TOKEN));
});
