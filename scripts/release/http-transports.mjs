/** Publication transports. Remote endpoints require an explicit verified publisher policy. */
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { PinnedArtifact, MAX_RELEASE_ASSET } from './artifact-stream.mjs';
import { verifyRecordedFile } from './candidate.mjs';
import { assertLocalHttpConnection, requestLocalHttp } from './local-http-connection.mjs';
import { npmManifestFromTarball } from './npm-package.mjs';

const HEX = /^[0-9a-f]{64}$/;
const OCI = /^sha256:[0-9a-f]{64}$/;
const MAX_JSON = 8 * 1024 * 1024;
const MAX_OBJECT = 512 * 1024 * 1024;
function insist(value, message) { if (!value) throw new Error(message); }
function transient(message) { return Object.assign(new Error(message), { transient: true }); }
function sha(bytes, algorithm = 'sha256') { return createHash(algorithm).update(bytes).digest('hex'); }

export class HttpTransport {
  #authenticate;
  #refreshing;

  /** @param {string} baseUrl @param {{token?:string,authenticate?:()=>Promise<string>,allowRemote?:boolean,timeoutMs?:number,downloadOrigins?:string[],localConnection?:object}} options */
  constructor(baseUrl, { token, authenticate, allowRemote = false, timeoutMs = 30_000, downloadOrigins = [], localConnection } = {}) {
    const url = new URL(baseUrl);
    insist(!url.username && !url.password && !url.search && !url.hash && ['http:', 'https:'].includes(url.protocol), 'Invalid publication endpoint.');
    const local = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
    insist(local || (allowRemote === true && url.protocol === 'https:'), 'Remote publication requires an explicit verified publisher policy.');
    insist(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 300_000, 'Invalid publication timeout.');
    insist(token === undefined || (typeof token === 'string' && token.length > 0 && !/[\r\n]/.test(token)), 'Invalid publisher credential.');
    insist(authenticate === undefined || (token === undefined && typeof authenticate === 'function'), 'Invalid publisher credential provider.');
    insist(Array.isArray(downloadOrigins), 'Invalid download origin policy.');
    this.downloadOrigins = new Set(downloadOrigins.map(value => {
      const origin = new URL(value); const localOrigin = ['127.0.0.1', '[::1]', 'localhost'].includes(origin.hostname);
      insist(!origin.username && !origin.password && origin.href === `${origin.origin}/` && (localOrigin || (allowRemote === true && origin.protocol === 'https:')), 'Invalid download origin policy.');
      return origin.origin;
    }));
    if (localConnection !== undefined) { assertLocalHttpConnection(localConnection); insist(local && url.protocol === 'http:', 'Local HTTP connection requires a local HTTP authority.'); }
    this.localConnection = localConnection;
    this.base = url; this.token = token; this.timeoutMs = timeoutMs;
    this.#authenticate = authenticate;
  }
  async #refreshToken(previous) {
    if (this.token !== previous) return;
    this.#refreshing ??= this.#authenticate().then(token => {
      insist(typeof token === 'string' && token.length > 0 && token.length <= 64 * 1024 && !/[\r\n]/.test(token), 'Invalid publisher credential.');
      this.token = token;
    }).finally(() => { this.#refreshing = undefined; });
    await this.#refreshing;
  }
  endpoint(relative) {
    const url = new URL(relative, this.base);
    insist(url.origin === this.base.origin && !url.username && !url.password && !url.hash, 'Publication URL escapes its authorized origin.');
    return url;
  }
  /** @param {string} method @param {string|URL} relative @param {{bytes?:Buffer,json?:any,headers?:Record<string,string>,expected?:number[],maxJsonBytes?:number,source?:PinnedArtifact}} options */
  async request(method, relative, { bytes, json, headers = {}, expected = [200], maxJsonBytes = MAX_JSON, source } = {}) {
    insist(bytes === undefined || (Buffer.isBuffer(bytes) && bytes.length <= MAX_OBJECT), 'Publication object exceeds its bound.');
    insist(source === undefined || source instanceof PinnedArtifact && bytes === undefined && json === undefined, 'Invalid pinned upload source.');
    insist(source === undefined || this.#authenticate === undefined, 'Refreshable publication requests require a replayable body.');
    const url = this.endpoint(relative);
    if (this.#authenticate && this.token === undefined) await this.#refreshToken(undefined);
    const upload = source ? Readable.from(source.chunks()) : undefined;
    const jsonBody = json === undefined ? undefined : Buffer.from(JSON.stringify(json));
    const body = upload ?? jsonBody ?? bytes;
    if (jsonBody !== undefined) { insist(Number.isSafeInteger(maxJsonBytes) && maxJsonBytes >= MAX_JSON && maxJsonBytes <= MAX_OBJECT, 'Invalid publication metadata bound.'); insist(jsonBody.length <= maxJsonBytes, 'Publication metadata exceeds its bound.'); }
    const send = () => (this.localConnection ? (url, options) => requestLocalHttp(this.localConnection, url, options) : fetch)(url, {
      method, redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs),
      headers: { ...(this.token ? { authorization: `Bearer ${this.token}` } : {}), ...(json === undefined ? {} : { 'content-type': 'application/json' }), ...headers, ...(source ? { 'content-length': String(source.record.size) } : {}) }, ...(body === undefined ? {} : { body, ...(source ? { duplex: 'half' } : {}) }) });
    let response;
    const suppliedToken = this.token;
    try {
      response = await send();
      if (upload) { await finished(upload); insist(source.complete, 'Pinned upload did not complete.'); }
    } catch (error) { if (upload) { upload.destroy(); await finished(upload).catch(() => {}); await response?.body?.cancel(); if (source.error) throw source.error; } throw transient(`Publication transport failed: ${error.name}`); }
    if (this.#authenticate && response.status === 401) {
      await response.body?.cancel();
      await this.#refreshToken(suppliedToken);
      try { response = await send(); }
      catch (error) { throw transient(`Publication transport failed: ${error.name}`); }
    }
    if (!expected.includes(response.status)) {
      await response.body?.cancel();
      if ([408, 425, 429, 500, 502, 503, 504].includes(response.status)) throw transient(`Publication HTTP ${response.status}.`);
      throw Object.assign(new Error(`Publication HTTP ${response.status}.`), { status: response.status });
    }
    return response;
  }
  async json(method, relative, options = {}) {
    const response = await this.request(method, relative, options);
    const bytes = await boundedBytes(response, MAX_JSON);
    return bytes.length ? JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) : null;
  }
  async inspectBytes(relative, expectedSize = MAX_OBJECT, headers = {}, maximum = MAX_OBJECT) {
    insist(Number.isSafeInteger(maximum) && maximum >= 0 && maximum <= MAX_RELEASE_ASSET && Number.isSafeInteger(expectedSize) && expectedSize >= 0 && expectedSize <= maximum, 'Invalid publication download bound.');
    let url = this.endpoint(relative); let response;
    for (let redirects = 0; ; redirects++) {
      if (url.origin === this.base.origin) response = await this.request('GET', url.href, { headers, expected: [200, 404, 301, 302, 303, 307, 308] });
      else {
        insist(!this.localConnection && this.downloadOrigins.has(url.origin), 'Download origin is not authorized.');
        try { response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs), headers: Object.fromEntries(Object.entries(headers).filter(([key]) => !['authorization', 'cookie', 'proxy-authorization'].includes(key.toLowerCase()))) }); }
        catch (error) { throw transient(`Publication download failed: ${error.name}`); }
      }
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      const location = response.headers.get('location'); await response.body?.cancel();
      insist(redirects < 3 && location, 'Publication download redirect limit exceeded.');
      url = new URL(location, url); insist(!url.username && !url.password && !url.hash && (url.origin === this.base.origin || this.downloadOrigins.has(url.origin)), 'Download redirect escapes authorized origins.');
    }
    if (response.status === 404) { await response.body?.cancel(); return null; }
    insist(response.status === 200, `Publication download HTTP ${response.status}.`);
    const hash = createHash('sha256'); let size = 0;
    for await (const part of response.body) { size += part.length; insist(size <= expectedSize && size <= maximum, 'Retrieved publication object exceeds its bound.'); hash.update(part); }
    return { sha256: hash.digest('hex'), size };
  }
}

async function boundedBytes(response, limit) {
  const parts = []; let size = 0;
  for await (const part of response.body) { size += part.length; insist(size <= limit, 'Publication response exceeds its bound.'); parts.push(Buffer.from(part)); }
  return Buffer.concat(parts);
}
function repository(value) { insist(typeof value === 'string' && /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(value), 'Invalid OCI repository.'); return value; }

export class OciDistributionAdapter {
  constructor(transport, repo) { insist(transport instanceof HttpTransport, 'HTTP transport required.'); this.http = transport; this.repo = repository(repo); }
  async inspectBlob(digest, size) { insist(OCI.test(digest), 'Invalid OCI blob digest.'); return this.http.inspectBytes(`/v2/${this.repo}/blobs/${digest}`, size); }
  async publishBlob(digest, bytes) {
    insist(Buffer.isBuffer(bytes) && `sha256:${sha(bytes)}` === digest, 'OCI blob identity mismatch.');
    const started = await this.http.request('POST', `/v2/${this.repo}/blobs/uploads/`, { expected: [202] });
    const location = started.headers.get('location'); await started.body?.cancel(); insist(location, 'OCI upload location is missing.');
    const url = this.http.endpoint(location); url.searchParams.set('digest', digest);
    const response = await this.http.request('PUT', url.href, { bytes, headers: { 'content-type': 'application/octet-stream' }, expected: [201, 202] });
    const reported = response.headers.get('docker-content-digest'); await response.body?.cancel();
    insist(!reported || reported === digest, 'OCI registry returned a different blob identity.');
  }
  async inspectManifest(reference, size) { insist(OCI.test(reference) || /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(reference), 'Invalid OCI reference.'); return this.http.inspectBytes(`/v2/${this.repo}/manifests/${reference}`, size, { accept: 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json' }); }
  async publishManifest(reference, bytes, mediaType) {
    insist(OCI.test(reference) && `sha256:${sha(bytes)}` === reference && ['application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json'].includes(mediaType), 'OCI manifest identity mismatch.');
    const response = await this.http.request('PUT', `/v2/${this.repo}/manifests/${reference}`, { bytes, headers: { 'content-type': mediaType }, expected: [201, 202] });
    const reported = response.headers.get('docker-content-digest'); await response.body?.cancel(); insist(!reported || reported === reference, 'OCI registry returned a different manifest identity.');
  }
  async promote(tag, bytes, mediaType) {
    insist(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag), 'Invalid OCI channel.');
    const response = await this.http.request('PUT', `/v2/${this.repo}/manifests/${tag}`, { bytes, headers: { 'content-type': mediaType }, expected: [201, 202] }); await response.body?.cancel();
  }
}

export class NpmRegistryAdapter {
  constructor(transport, name, version, { manual = false } = {}) {
    insist(transport instanceof HttpTransport && /^@[a-z0-9._-]+\/[a-z0-9._-]+$/.test(name) && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version), 'Invalid npm publication identity.');
    this.http = transport; this.name = name; this.version = version; this.path = `/${encodeURIComponent(name)}`;
    this.manual = manual;
  }
  async inspect(_item, size) {
    const response = await this.http.request('GET', `${this.path}/${encodeURIComponent(this.version)}`, { expected: [200, 404] });
    if (response.status === 404) { await response.body?.cancel(); return null; }
    const info = JSON.parse((await boundedBytes(response, MAX_JSON)).toString('utf8'));
    insist(info.name === this.name && info.version === this.version && typeof info.dist?.tarball === 'string', 'npm registry returned a different package identity.');
    const actual = await this.http.inspectBytes(info.dist.tarball, size);
    insist(actual, 'npm tarball is missing.'); return actual;
  }
  async publish(_item, bytes, packageInfo = {}) {
    insist(!this.manual, 'Publish the verified npm tarball with the local npm CLI and rerun reconciliation.');
    const manifest = npmManifestFromTarball(bytes);
    insist(manifest.name === this.name && manifest.version === this.version, 'npm tarball differs from its accepted publication identity.');
    insist(packageInfo && Object.getPrototypeOf(packageInfo) === Object.prototype && Object.entries(packageInfo).every(([key, value]) => JSON.stringify(value) === JSON.stringify(manifest[key])), 'npm publication metadata differs from its accepted tarball.');
    const filename = `${this.name.split('/')[1]}-${this.version}.tgz`;
    const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
    const metadata = { ...manifest, name: this.name, version: this.version, dist: { shasum: sha(bytes, 'sha1'), integrity, tarball: this.http.endpoint(`${this.path}/-/${filename}`).href } };
    const response = await this.http.request('PUT', this.path, { maxJsonBytes: 192 * 1024 * 1024, json: { _id: this.name, name: this.name, access: 'public', versions: { [this.version]: metadata }, 'dist-tags': { 'candidate': this.version }, _attachments: { [filename]: { content_type: 'application/octet-stream', data: bytes.toString('base64'), length: bytes.length } } }, expected: [200, 201, 202] }); await response.body?.cancel();
  }
  async promote(channel) {
    insist(!this.manual, 'Set the beta dist-tag with the local npm CLI and rerun promotion.');
    insist(/^[a-z][a-z0-9._-]*$/.test(channel), 'Invalid npm channel.');
    const response = await this.http.request('PUT', `/-/package/${encodeURIComponent(this.name)}/dist-tags/${channel}`, { json: this.version, expected: [200, 201] }); await response.body?.cancel();
  }
  async verifyPromotion(channel) {
    const response = await this.http.request('GET', `/-/package/${encodeURIComponent(this.name)}/dist-tags`, { expected: [200, 404] });
    if (response.status === 404) { await response.body?.cancel(); return false; }
    const tags = JSON.parse((await boundedBytes(response, MAX_JSON)).toString('utf8'));
    return Object.hasOwn(tags, channel) && tags[channel] === this.version;
  }
}

export class GithubReleaseAdapter {
  /** @param {HttpTransport} transport @param {string} owner @param {string} repo @param {string} tag @param {HttpTransport} uploadTransport @param {{sourceCommit?:string}} options */
  constructor(transport, owner, repo, tag, uploadTransport = transport, { sourceCommit } = {}) {
    insist(transport instanceof HttpTransport && [owner, repo].every(value => /^[A-Za-z0-9_.-]+$/.test(value)) && /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag), 'Invalid GitHub release identity.');
    insist(uploadTransport instanceof HttpTransport, 'GitHub upload transport required.');
    this.http = transport; this.uploadHttp = uploadTransport; this.path = `/repos/${owner}/${repo}/releases`; this.tag = tag;
    insist(sourceCommit === undefined || /^[0-9a-f]{40}$/.test(sourceCommit), 'Invalid release source commit.'); this.sourceCommit = sourceCommit;
  }
  async verifyTag() {
    if (!this.sourceCommit) return false;
    const response = await this.http.request('GET', this.path.replace(/\/releases$/, '') + '/git/ref/tags/' + encodeURIComponent(this.tag), { expected: [200, 404] });
    if (response.status === 404) { await response.body?.cancel(); return false; }
    let object = JSON.parse((await boundedBytes(response, MAX_JSON)).toString('utf8')).object;
    for (let depth = 0; object?.type === 'tag'; depth++) { insist(depth < 4 && /^[0-9a-f]{40}$/.test(object.sha), 'Invalid release tag chain.'); object = (await this.http.json('GET', this.path.replace(/\/releases$/, '') + '/git/tags/' + object.sha)).object; }
    insist(object?.type === 'commit' && object.sha === this.sourceCommit, 'Immutable release tag points at another source commit.');
    return true;
  }
  async findRelease() {
    if (this.releaseId !== undefined) return this.http.json('GET', `${this.path}/${this.releaseId}`);
    // GitHub's release-by-tag endpoint only returns published releases.
    // The authenticated list also includes drafts, including after a restart.
    let match;
    const pageSize = 10;
    for (let page = 1; ; page++) {
      const releases = await this.http.json('GET', `${this.path}?per_page=${pageSize}&page=${page}`);
      insist(Array.isArray(releases) && releases.length <= pageSize, 'Invalid GitHub release listing.');
      for (const release of releases) {
        if (release.tag_name !== this.tag) continue;
        insist(!match, 'Duplicate GitHub releases for the same tag.');
        match = release;
      }
      if (releases.length < pageSize) return match;
    }
  }
  async release(create = false) {
    const tagged = await this.verifyTag();
    let info = await this.findRelease();
    if (!info) {
      if (!create) return null;
      info = await this.http.json('POST', this.path, { json: { tag_name: this.tag, name: this.tag, ...(this.sourceCommit ? { target_commitish: this.sourceCommit } : {}), draft: true, prerelease: this.tag.includes('-') }, expected: [201] });
    }
    insist(info.tag_name === this.tag && Number.isSafeInteger(info.id) && info.id > 0 && (this.releaseId === undefined || this.releaseId === info.id) && typeof info.draft === 'boolean' && Array.isArray(info.assets), 'GitHub returned a different release identity.');
    if (this.sourceCommit) insist(info.draft ? info.target_commitish === this.sourceCommit : tagged, 'GitHub release is not bound to the accepted source commit.');
    this.releaseId = info.id;
    return info;
  }
  asset(release, filename) {
    const matches = release.assets.filter(asset => asset.name === filename);
    insist(matches.length <= 1, 'Duplicate GitHub release asset.');
    const asset = matches[0];
    if (asset) {
      insist(Number.isSafeInteger(asset.id) && asset.id > 0, 'Invalid GitHub release asset identity.');
      insist(asset.state === 'uploaded' || (release.draft && asset.state === 'starter' && asset.size === 0), 'Unexpected GitHub release asset state.');
    }
    return asset;
  }
  async inspect(item, size) {
    const release = await this.release(); if (!release) return null;
    const asset = this.asset(release, item.filename);
    if (!asset || asset.state === 'starter') return null;
    return this.http.inspectBytes(`${this.path}/assets/${asset.id}`, size, { accept: 'application/octet-stream' }, MAX_RELEASE_ASSET);
  }
  async uploadUrl(filename) {
    insist(typeof filename === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(filename), 'Invalid release asset name.');
    const release = await this.release(true);
    insist(release.draft, 'Cannot upload assets to a published release.');
    const existing = this.asset(release, filename);
    if (existing) {
      if (existing.state === 'uploaded') throw Object.assign(new Error('GitHub release asset already exists.'), { status: 409 });
      // GitHub can retain a zero-byte starter after a failed upload.
      const response = await this.http.request('DELETE', `${this.path}/assets/${existing.id}`, { expected: [204, 404] });
      await response.body?.cancel();
    }
    const location = release.upload_url?.replace(/\{.*$/, ''); insist(typeof location === 'string', 'GitHub release upload location is missing.');
    const url = this.uploadHttp.endpoint(location); url.searchParams.set('name', filename);
    return url;
  }
  async publish(item, bytes) {
    const url = await this.uploadUrl(item.filename);
    await this.uploadHttp.json('POST', url.href, { bytes, headers: { 'content-type': 'application/octet-stream' }, expected: [201] });
  }
  verifyArtifact(artifact, root) { verifyRecordedFile(root, artifact); insist(artifact.size <= MAX_RELEASE_ASSET, 'GitHub release asset exceeds its documented per-file bound.'); }
  async publishArtifact(item, artifact, root) {
    const source = new PinnedArtifact(root, artifact);
    try {
      const url = await this.uploadUrl(item.filename);
      await this.uploadHttp.json('POST', url.href, { source, headers: { 'content-type': 'application/octet-stream' }, expected: [201] });
    } finally { source.close(); }
  }
  async promote() { const release = await this.release(); insist(release, 'Cannot promote a missing release.'); await this.http.json('PATCH', `${this.path}/${release.id}`, { json: { draft: false, make_latest: this.tag.includes('-') ? 'false' : 'true' } }); }
  async verifyPromotion() { return (await this.release())?.draft === false; }
}

/** MCP Registry and owned catalog records use immutable versioned JSON bytes. */
export class JsonCatalogAdapter {
  constructor(transport, { inspectPath, publishPath, channelPath }) {
    insist(transport instanceof HttpTransport && typeof inspectPath === 'string' && typeof publishPath === 'string', 'Invalid catalog endpoints.');
    this.http = transport; this.inspectPath = inspectPath; this.publishPath = publishPath; this.channelPath = channelPath;
    transport.endpoint(inspectPath); transport.endpoint(publishPath); if (channelPath) transport.endpoint(channelPath);
  }
  async inspect(_item, size) { return this.http.inspectBytes(this.inspectPath, size); }
  async publish(_item, bytes) { JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); const response = await this.http.request('POST', this.publishPath, { bytes, headers: { 'content-type': 'application/json' }, expected: [200, 201, 202] }); await response.body?.cancel(); }
  async promote(_channel, bytes) { insist(this.channelPath, 'Catalog channel promotion is unsupported.'); const response = await this.http.request('PUT', this.channelPath, { bytes, headers: { 'content-type': 'application/json' }, expected: [200, 201, 202] }); await response.body?.cancel(); }
  async verifyPromotion(_channel, bytes) { const actual = await this.http.inspectBytes(this.channelPath, bytes.length); return actual?.sha256 === sha(bytes) && actual.size === bytes.length; }
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { insist(Number.isFinite(value), 'Nonfinite catalog number.'); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  insist(value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype, 'Invalid canonical catalog value.');
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

/** Official MCP Registry API: publisher payload is separate from registry metadata. */
export class McpRegistryAdapter {
  constructor(transport, name, version, { manualRecordPath = undefined } = {}) {
    insist(transport instanceof HttpTransport && /^[a-z0-9.-]+\/[a-z0-9._-]+$/.test(name) && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version), 'Invalid MCP publication identity.');
    this.http = transport; this.name = name; this.version = version; this.manualRecordPath = manualRecordPath;
  }
  async inspect(_item, size) {
    const response = await this.http.request('GET', `/v0.1/servers/${encodeURIComponent(this.name)}/versions/${encodeURIComponent(this.version)}`, { expected: [200, 404] });
    if (response.status === 404) { await response.body?.cancel(); return null; }
    const result = JSON.parse((await boundedBytes(response, MAX_JSON)).toString('utf8'));
    insist(result.server?.name === this.name && result.server.version === this.version, 'MCP registry returned a different identity.');
    const bytes = Buffer.from(canonicalJson(result.server)); insist(bytes.length <= size, 'MCP registry payload exceeds its bound.');
    return { sha256: sha(bytes), size: bytes.length };
  }
  async publish(_item, bytes) {
    const server = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    insist(server.name === this.name && server.version === this.version && Buffer.from(canonicalJson(server)).equals(bytes), 'MCP publisher payload must use its accepted canonical identity.');
    if (this.manualRecordPath) throw new Error(`Run mcp-publisher login github, then mcp-publisher publish with the accepted record at ${this.manualRecordPath}. Rerun reconciliation to verify the public record.`);
    await this.http.json('POST', '/v0.1/publish', { bytes, headers: { 'content-type': 'application/json' }, expected: [200, 201] });
  }
}

export function assertObjectIdentity(item, bytes) { insist(Buffer.isBuffer(bytes) && HEX.test(item.sha256 ?? '') && item.size === bytes.length && sha(bytes) === item.sha256, 'Publication bytes differ from the accepted artifact.'); }
