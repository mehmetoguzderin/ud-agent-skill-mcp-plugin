#!/usr/bin/env node
/** Future publisher entry point; production authority is checked before I/O. */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileReceipt, readRecordedBytes, safeRelative } from './candidate.mjs';
import { publicationPlan, publicationAdapters, publicationPromotions } from './publication-plan.mjs';
import { reconcilePublication, promotePublication, withVerifiedPublication } from './publication.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
function insist(value, message) { if (!value) throw new Error(message); }

export async function publishCandidate(root, operation, candidatePath, journalPath, credentials = {}) {
  insist(['--plan', '--reconcile', '--promote'].includes(operation), 'Invalid publication operation.');
  safeRelative(candidatePath);
  const bytes = readRecordedBytes(root, fileReceipt(root, candidatePath));
  const plan = publicationPlan(root, bytes);
  if (operation === '--plan') return { schema_version: 1, qualification: plan.qualification, manifest_sha256: plan.manifest_sha256, source_commit: plan.source_commit ?? null, targets: plan.targets, promotions: publicationPromotions(plan), remote_requests: 0 };
  safeRelative(journalPath);
  if (process.env.UD_RELEASE_EXPECTED_CANDIDATE_SHA256 !== undefined) insist(process.env.UD_RELEASE_EXPECTED_CANDIDATE_SHA256 === plan.manifest_sha256, 'Candidate changed after the independent workflow verification job.');
  const signature = JSON.parse(readRecordedBytes(root, fileReceipt(root, candidatePath + '.sig.json')).toString('utf8'));
  return await withVerifiedPublication(root, bytes, signature, async verification => {
    const adapters = await publicationAdapters(root, plan, { manifestBytes: bytes, signature, credentials, verification });
    try {
      const directory = path.join(root, ...journalPath.split('/'));
      if (operation === '--reconcile') return await reconcilePublication(root, bytes, signature, plan.targets, adapters, directory, { verification });
      return await promotePublication(root, bytes, signature, plan.targets, adapters, directory, publicationPromotions(plan), { verification });
    } finally { for (const adapter of Object.values(adapters)) adapter.close?.(); }
  });
}

async function main(args) {
  insist((args.length === 2 && args[0] === '--plan') || (args.length === 3 && ['--reconcile', '--promote'].includes(args[0])), 'Usage: publisher.mjs --plan <relative-candidate.json> | --reconcile|--promote <relative-candidate.json> <relative-private-journal>');
  return await publishCandidate(projectRoot, args[0], args[1], args[2], { github: process.env.GITHUB_TOKEN, npm: process.env.NPM_TOKEN, ghcr: process.env.GHCR_TOKEN ?? process.env.GITHUB_TOKEN, mcp: process.env.MCP_REGISTRY_TOKEN });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2)))); }
  catch (error) { console.error(`Publication stopped: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; }
}
