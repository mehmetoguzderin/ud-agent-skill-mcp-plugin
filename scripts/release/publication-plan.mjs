/** Candidate-bound publication coordinates and concrete transport construction. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileReceipt, readRecordedBytes, safeRelative, verifyRecordedFile } from './candidate.mjs';
import { requireVerifiedPublication } from './publication.mjs';
import { loadDistributionIdentity } from './host-adapters.mjs';
import { HttpTransport, NpmRegistryAdapter, GithubReleaseAdapter, McpRegistryAdapter, canonicalJson } from './http-transports.mjs';
import { OciArchivePublicationAdapter } from './oci-publication.mjs';
import { releaseChannels } from './channels.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function insist(value, message) { if (!value) throw new Error(message); }
const CATALOGS = Object.freeze({ 'catalog-claude': '.claude-plugin/marketplace.json', 'catalog-codex': 'packaging/codex/marketplace.json', 'catalog-grok': '.grok-plugin/marketplace.json', 'catalog-grok-index': '.grok-plugin/plugin-index.json' });

/** Catalogs are part of the signed source commit; publishing cannot rewrite it. */
export class GithubSourceCatalogAdapter {
  constructor(http, owner, repository, revision, sourcePath, expected) {
    insist(http instanceof HttpTransport && /^[a-z0-9-]+$/.test(owner) && /^[a-z0-9-]+$/.test(repository) && /^[0-9a-f]{40}$/.test(revision), 'Invalid catalog source authority.');
    safeRelative(sourcePath); this.http = http; this.url = `/repos/${owner}/${repository}/contents/${sourcePath.split('/').map(encodeURIComponent).join('/')}?ref=${revision}`; this.expected = expected;
  }
  async inspect(_item, size) {
    const response = await this.http.request('GET', this.url, { expected: [200, 404] });
    if (response.status === 404) { await response.body?.cancel(); return null; }
    const chunks = []; let total = 0; for await (const chunk of response.body) { total += chunk.length; insist(total <= 8 * 1024 * 1024, 'Catalog source metadata exceeds bound.'); chunks.push(chunk); }
    const record = JSON.parse(Buffer.concat(chunks).toString('utf8')); insist(record.type === 'file' && record.encoding === 'base64' && typeof record.content === 'string', 'Catalog source response is not an ordinary file.');
    const bytes = Buffer.from(record.content.replace(/\n/g, ''), 'base64'); insist(bytes.length <= size, 'Catalog source exceeds accepted bound.');
    return { sha256: sha(bytes), size: bytes.length };
  }
  async publish(_item, bytes) {
    insist(sha(bytes) === this.expected.sha256 && bytes.length === this.expected.size, 'Catalog differs from its source-bound artifact.');
    const actual = await this.inspect(null, bytes.length); insist(actual?.sha256 === sha(bytes) && actual.size === bytes.length, 'Accepted publisher commit must already contain the exact catalog; publication cannot rewrite signed source.');
  }
}

export function publicationPlan(root, manifestBytes) {
  const manifest = JSON.parse(manifestBytes.toString('utf8')), identity = loadDistributionIdentity(root);
  const channels = releaseChannels(root, identity.version);
  const manualNpm = manifest.signing_profile === 'publisher-beta';
  insist(manifest.schema_version === 1 && manifest.product_version === identity.version && Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0, 'Publication candidate identity is incomplete.');
  const artifacts = new Map(), filenames = new Set(), targets = [];
  for (const item of manifest.artifacts) {
    insist(item && typeof item.id === 'string' && !artifacts.has(item.id), 'Publication artifact inventory is duplicate.'); safeRelative(item.path);
    const filename = path.posix.basename(item.path); insist(/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(filename) && !filenames.has(filename), 'Publication asset filenames collide.');
    verifyRecordedFile(root, item); artifacts.set(item.id, item); filenames.add(filename); targets.push({ target: 'github', coordinate: `${identity.github_owner}/${identity.repository}@v${identity.version}/${filename}`, artifact_id: item.id, filename });
  }
  for (const id of ['npm', 'core-oci-index', 'render-oci-index', 'mcp-registry-record', ...Object.keys(CATALOGS)]) insist(artifacts.has(id), `Publication artifact missing: ${id}`);
  const npmTarget = { target: 'npm', coordinate: `${identity.npm}@${identity.version}`, artifact_id: 'npm' };
  if (!manualNpm) targets.push(npmTarget);
  const runtimeBytes = readFileSync(path.join(root, 'runtime/runtime.lock.json'));
  insist(sha(runtimeBytes) === manifest.runtime_lock_sha256, 'Publication runtime lock differs from candidate.'); const runtime = JSON.parse(runtimeBytes);
  for (const pack of ['core', 'render']) { const image = runtime.packs?.[pack]; insist(image && /^sha256:[0-9a-f]{64}$/.test(image.index_digest), 'Publication OCI index identity is missing.'); targets.push({ target: `ghcr-${pack}`, coordinate: `${identity[`ghcr_${pack}`]}@${image.index_digest}`, artifact_id: `${pack}-oci-index` }); }
  const mcp = artifacts.get('mcp-registry-record'), expectedMcp = Buffer.from(canonicalJson(JSON.parse(readFileSync(path.join(root, 'registry/server.json'), 'utf8'))));
  insist(readRecordedBytes(root, mcp).equals(expectedMcp), 'MCP registry payload differs from source coordinates.');
  if (manualNpm) targets.push(npmTarget);
  targets.push({ target: 'mcp-registry', coordinate: `${identity.mcpName}@${identity.version}`, artifact_id: mcp.id });
  for (const [id, source] of Object.entries(CATALOGS)) { const artifact = artifacts.get(id), original = fileReceipt(root, source); insist(original.sha256 === artifact.sha256 && original.size === artifact.size, 'Owned catalog differs from signed source.'); targets.push({ target: id, coordinate: `${identity.repositoryUrl}@${manifest.source_commit ?? 'uncommitted'}/${source}`, artifact_id: id, source_path: source }); }
  return { schema_version: 1, qualification: manifest.status === 'accepted_candidate' ? 'requires-production-authority-verification' : 'local-plan-not-production-authority', manifest_sha256: sha(manifestBytes), identity, channels, targets, runtime, artifacts, source_commit: manifest.source_commit, manualNpm };
}

/** @param {string} root @param {any} plan
 * @param {{fixtureHttp?: HttpTransport, credentials?: {github?: string, npm?: string, ghcr?: string, mcp?: string}, timeoutMs?: number, manifestBytes?: Buffer, signature?: object, verification?:object}} [options] */
export async function publicationAdapters(root, plan, { fixtureHttp, credentials = {}, timeoutMs = 300_000, manifestBytes, signature, verification } = {}) {
  const fixture = fixtureHttp !== undefined;
  if (fixture) insist(fixtureHttp instanceof HttpTransport && fixtureHttp.base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(fixtureHttp.base.hostname) && [...fixtureHttp.downloadOrigins].every(value => ['localhost', '127.0.0.1', '[::1]'].includes(new URL(value).hostname)), 'Publication fixtures require only local HTTP authorities.');
  const downloadOrigins = {
    'https://api.github.com': ['https://release-assets.githubusercontent.com'],
    'https://ghcr.io': ['https://pkg-containers.githubusercontent.com'],
  };
  const create = (base, token) => fixtureHttp ?? new HttpTransport(base, { token, allowRemote: true, timeoutMs, downloadOrigins: downloadOrigins[base] ?? [] });
  if (!fixture) {
    insist(Buffer.isBuffer(manifestBytes) && sha(manifestBytes) === plan.manifest_sha256, 'Production adapters require the exact accepted candidate.');
    requireVerifiedPublication(root, manifestBytes, signature, verification);
    const manualNpm = JSON.parse(manifestBytes.toString('utf8')).signing_profile === 'publisher-beta';
    insist(plan.manualNpm === manualNpm, 'npm publication mode differs from the verified candidate.');
    const names = manualNpm ? ['github', 'ghcr'] : ['github', 'npm', 'ghcr', 'mcp'];
    for (const name of names) insist(typeof credentials[name] === 'string' && credentials[name].length > 0 && !/[\r\n]/.test(credentials[name]), `Publisher credential is required: ${name}`);
  }
  const id = plan.identity, github = create('https://api.github.com', credentials.github), uploads = create('https://uploads.github.com', credentials.github), adapters = {};
  try {
    adapters.github = new GithubReleaseAdapter(github, id.github_owner, id.repository, `v${id.version}`, uploads, { sourceCommit: plan.source_commit });
    adapters.npm = new NpmRegistryAdapter(create('https://registry.npmjs.org', plan.manualNpm ? undefined : credentials.npm), id.npm, id.version, { manual: plan.manualNpm });
    const mcpToken = credentials.mcp === '' ? undefined : credentials.mcp;
    const manualRecordPath = plan.manualNpm && !mcpToken ? plan.artifacts.get('mcp-registry-record').path : undefined;
    adapters['mcp-registry'] = new McpRegistryAdapter(create('https://registry.modelcontextprotocol.io', mcpToken), id.mcpName, id.version, { manualRecordPath });
    for (const pack of ['core', 'render']) {
      const artifact = plan.artifacts.get(`${pack}-oci-index`), image = plan.runtime.packs[pack], repository = `${id.github_owner}/${id.repository}-${pack}`;
      let registry = fixtureHttp;
      if (!fixture) {
        // PAT/GITHUB_TOKEN is a registry login credential, not a distribution
        // Bearer token. Exchange it only at GHCR's fixed same-origin endpoint.
        const login = create('https://ghcr.io');
        const query = new URLSearchParams({ service: 'ghcr.io', scope: `repository:${repository}:pull,push` });
        const authenticate = async () => {
          const response = await login.json('GET', `/token?${query}`, { headers: { authorization: `Basic ${Buffer.from(`${id.github_owner}:${credentials.ghcr}`).toString('base64')}` } });
          return response?.token;
        };
        registry = new HttpTransport('https://ghcr.io', { authenticate, allowRemote: true, timeoutMs, downloadOrigins: downloadOrigins['https://ghcr.io'] });
      }
      adapters[`ghcr-${pack}`] = new OciArchivePublicationAdapter(registry, repository, path.join(root, artifact.path), artifact, image.index_digest, image.platforms);
    }
    for (const target of plan.targets.filter(target => target.source_path)) { insist(/^[0-9a-f]{40}$/.test(plan.source_commit ?? ''), 'Catalog transport requires the accepted exact publisher source commit.'); adapters[target.target] = new GithubSourceCatalogAdapter(github, id.github_owner, id.repository, plan.source_commit, target.source_path, plan.artifacts.get(target.artifact_id)); }
    return adapters;
  } catch (error) { for (const adapter of Object.values(adapters)) adapter.close?.(); throw error; }
}

/** Channels move only after reconcilePublication has verified every target. */
export function publicationPromotions(plan) {
  const find = target => { const item = plan.targets.find(item => item.target === target); insist(item, `Promotion target missing: ${target}`); return item.coordinate; };
  insist(plan.channels && ['beta', 'latest'].includes(plan.channels.npm) && plan.channels.oci === plan.identity.version, 'Verified release channel policy is missing.');
  const github = { target: 'github', coordinate: find('github') };
  const npm = { target: 'npm', coordinate: find('npm'), channel: plan.channels.npm };
  const images = ['core', 'render'].map(pack => ({ target: `ghcr-${pack}`, coordinate: find(`ghcr-${pack}`), channel: plan.channels.oci }));
  return plan.manualNpm ? [...images, github, npm] : [github, npm, ...images];
}
