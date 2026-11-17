/** Source-bound channel policy; no mutable latest OCI alias. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import { canonicalJson } from './http-transports.mjs';
const expected = { schema_version: 1, prerelease: { npm: 'beta', github_prerelease: true }, stable: { npm: 'latest', github_prerelease: false }, oci: { mutable_latest: false, versioned_tags_only: true }, promotion: { require_all_targets_verified: true, rewrite_artifacts: false } };
export function releaseChannels(root, version) {
  const value = parse(readFileSync(path.join(root, 'release/channels.yaml'), 'utf8'), { uniqueKeys: true });
  if (canonicalJson(value) !== canonicalJson(expected) || typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(version)) throw new Error('Release channel policy differs from its supported immutable contract.');
  return { ...(version.includes('-') ? value.prerelease : value.stable), oci: version };
}
