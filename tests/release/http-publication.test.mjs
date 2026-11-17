import { posixTest } from '../fixtures/native-scope.mjs';
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID, createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { openSync, closeSync, unlinkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, copyFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { HttpTransport, OciDistributionAdapter, NpmRegistryAdapter, GithubReleaseAdapter, McpRegistryAdapter, canonicalJson } from '../../scripts/release/http-transports.mjs';
import { reconcilePublication, promotePublication, PublicationJournal, requireVerifiedPublication } from '../../scripts/release/publication.mjs';
import { OciArchivePublicationAdapter } from '../../scripts/release/oci-publication.mjs';
import { localHttpConnection } from '../../scripts/release/local-http-connection.mjs';
import { createOciFixture, fixtureTar } from './oci-fixture.mjs';
import { publicationPlan, publicationAdapters, publicationPromotions } from '../../scripts/release/publication-plan.mjs';
import { publishCandidate } from '../../scripts/release/publisher.mjs';

const npmManifest = { name: '@owner/package', version: '0.1.0-beta.1', bin: { 'ud-agent': 'cli.cjs' }, engines: { node: '>=24 <27' }, license: 'MIT', publishConfig: { access: 'public' } };
const npmBytes = () => gzipSync(fixtureTar([['package/package.json', JSON.stringify(npmManifest)], ['package/cli.cjs', '#!/usr/bin/env node\n']]));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(work) {
  const state = { blobs: new Map(), manifests: new Map(), packages: new Map(), tarballs: new Map(), npmChannels: new Map(), mcp: new Map(), releases: [], calls: [], catalogs: new Map(), loseNpmResponse: false };
  const server = createServer(async (request, response) => {
    try {
      const chunks = []; for await (const part of request) chunks.push(part); const bytes = Buffer.concat(chunks);
      const url = new URL(request.url, 'http://local'); state.calls.push({ method: request.method, path: url.pathname, authorization: request.headers.authorization });
      const json = value => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); };
      url.pathname = url.pathname.replace('/repos/mehmetoguzderin/ud-agent-skill-mcp-plugin/', '/repos/owner/repo/').replace('/%40mehmetoguzderin%2Fud-agent-skill-mcp-plugin', '/%40owner%2Fpackage').replace('/-/package/%40mehmetoguzderin%2Fud-agent-skill-mcp-plugin/', '/-/package/%40owner%2Fpackage/').replace(/\/v2\/mehmetoguzderin\/ud-agent-skill-mcp-plugin-(core|render)\//, '/v2/product/core/');
      if (url.pathname.startsWith('/repos/owner/repo/contents/') && request.method === 'GET') { const source = decodeURIComponent(url.pathname.slice('/repos/owner/repo/contents/'.length)), value = state.catalogs.get(source); assert.equal(url.searchParams.get('ref'), state.sourceCommit); response.statusCode = value ? 200 : 404; return json(value ? { type: 'file', encoding: 'base64', content: value.toString('base64') } : {}); }
      if (url.pathname === '/repos/owner/repo/git/ref/tags/v0.1.0-beta.1' && request.method === 'GET') { response.statusCode = state.tagCommit ? 200 : 404; return json(state.tagCommit ? { object: { type: 'commit', sha: state.tagCommit } } : {}); }
      if (url.pathname === '/restricted') { response.statusCode = request.headers.authorization === 'Bearer fixture-fresh' ? 200 : 401; return json({ ok: response.statusCode === 200 }); }
      if (url.pathname === '/v2/product/core/blobs/uploads/' && request.method === 'POST') { response.writeHead(202, { location: '/upload/one' }); return response.end(); }
      if (url.pathname === '/upload/one' && request.method === 'PUT') { const digest = url.searchParams.get('digest'); if (`sha256:${sha(bytes)}` !== digest) { response.statusCode = 400; return response.end(); } state.blobs.set(digest, bytes); response.writeHead(201, { 'docker-content-digest': digest }); return response.end(); }
      if (url.pathname.startsWith('/v2/product/core/blobs/') && request.method === 'GET') { const data = state.blobs.get(url.pathname.split('/').at(-1)); response.statusCode = data ? 200 : 404; return response.end(data); }
      if (url.pathname.startsWith('/v2/product/core/manifests/')) { const name = url.pathname.split('/').at(-1); if (request.method === 'PUT') { state.manifests.set(name, bytes); response.statusCode = 201; return response.end(); } const data = state.manifests.get(name); response.statusCode = data ? 200 : 404; return response.end(data); }
      if (url.pathname === '/%40owner%2Fpackage' && request.method === 'PUT') {
        const info = JSON.parse(bytes); const [version, metadata] = Object.entries(info.versions)[0]; assert.equal(info.access, 'public'); assert.deepEqual(metadata.bin, npmManifest.bin); assert.deepEqual(metadata.engines, npmManifest.engines); assert.equal(metadata.private, undefined); state.packages.set(version, metadata);
        for (const [name, data] of Object.entries(info._attachments)) state.tarballs.set(name, Buffer.from(data.data, 'base64'));
        if (state.loseNpmResponse) { state.loseNpmResponse = false; request.socket.destroy(); return; }
        response.statusCode = 201; return json({ ok: true });
      }
      if (url.pathname.startsWith('/%40owner%2Fpackage/-/') && request.method === 'GET') { const data = state.tarballs.get(url.pathname.split('/').at(-1)); response.statusCode = data ? 200 : 404; return response.end(data); }
      if (url.pathname.startsWith('/%40owner%2Fpackage/') && request.method === 'GET') { const info = state.packages.get(url.pathname.split('/').at(-1)); response.statusCode = info ? 200 : 404; return json(info ?? {}); }
      if (url.pathname.startsWith('/-/package/%40owner%2Fpackage/dist-tags/') && request.method === 'PUT') { state.npmChannels.set(url.pathname.split('/').at(-1), JSON.parse(bytes)); return json({ ok: true }); }
      if (url.pathname === '/-/package/%40owner%2Fpackage/dist-tags' && request.method === 'GET') { return json(Object.fromEntries(state.npmChannels)); }
      if (url.pathname === '/v0.1/publish' && request.method === 'POST') { const info = JSON.parse(bytes); state.mcp.set(`${info.name}@${info.version}`, info); return json({ server: info, _meta: { fixture: true } }); }
      if (url.pathname.startsWith('/v0.1/servers/') && request.method === 'GET') { const pieces = url.pathname.split('/'); const info = state.mcp.get(`${decodeURIComponent(pieces[3])}@${pieces[5]}`); response.statusCode = info ? 200 : 404; return json(info ? { _meta: { fixture: true }, server: info } : {}); }
      const releaseMetadata = release => ({ ...release, assets: release.assets.map(({ bytes: _bytes, ...metadata }) => metadata) });
      if (url.pathname === '/repos/owner/repo/releases/tags/v0.1.0-beta.1') { const release = state.releases.find(item => item.tag_name === 'v0.1.0-beta.1' && !item.draft); response.statusCode = release ? 200 : 404; return json(release ? releaseMetadata(release) : {}); }
      if (url.pathname === '/repos/owner/repo/releases' && request.method === 'GET') {
        const count = Number(url.searchParams.get('per_page')), start = (Number(url.searchParams.get('page')) - 1) * count;
        return json(state.releases.slice(start, start + count).map(releaseMetadata));
      }
      if (url.pathname === '/repos/owner/repo/releases' && request.method === 'POST') {
        const info = JSON.parse(bytes); const release = { ...info, id: state.releases.length + 1, assets: [], upload_url: `${state.base}/upload-assets{?name,label}` }; state.releases.push(release);
        if (state.loseDraftResponse) { state.loseDraftResponse = false; request.socket.destroy(); return; }
        response.statusCode = 201; return json(release);
      }
      if (url.pathname === '/upload-assets' && request.method === 'POST') {
        const assets = state.releases[0].assets, name = url.searchParams.get('name');
        if (assets.some(asset => asset.name === name)) { response.statusCode = 422; return json({}); }
        const asset = { id: assets.length + 1, name, state: 'uploaded', size: bytes.length, bytes }; assets.push(asset);
        if (state.failUpload) { state.failUpload = false; Object.assign(asset, { state: 'starter', size: 0, bytes: Buffer.alloc(0) }); response.statusCode = 502; return json({}); }
        if (state.loseUploadResponse) { state.loseUploadResponse = false; request.socket.destroy(); return; }
        response.statusCode = 201; return json({ id: asset.id, name: asset.name });
      }
      if (url.pathname.startsWith('/repos/owner/repo/releases/assets/') && request.method === 'GET') { const asset = state.releases[0]?.assets.find(item => item.id === Number(url.pathname.split('/').at(-1))); response.statusCode = asset ? 200 : 404; return response.end(asset?.bytes); }
      if (url.pathname.startsWith('/repos/owner/repo/releases/assets/') && request.method === 'DELETE') {
        const assets = state.releases[0].assets, index = assets.findIndex(item => item.id === Number(url.pathname.split('/').at(-1)));
        if (index >= 0) assets.splice(index, 1);
        response.statusCode = index >= 0 ? 204 : 404; return response.end();
      }
      if (/^\/repos\/owner\/repo\/releases\/\d+$/.test(url.pathname) && request.method === 'GET') {
        const release = state.releases.find(item => item.id === Number(url.pathname.split('/').at(-1)));
        response.statusCode = release ? 200 : 404; return json(release ? releaseMetadata(release) : {});
      }
      if (url.pathname === '/repos/owner/repo/releases/1' && request.method === 'PATCH') {
        Object.assign(state.releases[0], JSON.parse(bytes)); state.tagCommit = state.releases[0].target_commitish;
        return json(releaseMetadata(state.releases[0]));
      }
      response.statusCode = 404; response.end();
    } catch (error) { response.statusCode = 500; response.end(error.message); }
  });
  const socketRoot = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'uh-')));
  const provided = process.env.UD_NATIVE_QUALITY_HTTP_SOCKETS;
  const endpoints = provided === undefined ? [process.platform === 'win32' ? `\\\\.\\pipe\\LOCAL\\ud-http-${randomUUID()}` : path.join(socketRoot, 's')] : JSON.parse(provided);
  assert.ok(Array.isArray(endpoints) && endpoints.length > 0 && endpoints.length <= 32 && new Set(endpoints).size === endpoints.length, 'Root-issued HTTP socket inventory must be nonempty, bounded and unique.');
  for (const endpoint of endpoints) localHttpConnection(endpoint);
  let socketPath, claim, claimFd;
  for (const endpoint of endpoints) {
    const marker = path.join(os.tmpdir(), `.ud-http-${sha(Buffer.from(endpoint))}.claim`);
    try { claimFd = openSync(marker, 'wx', 0o600); claim = marker; socketPath = endpoint; break; }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  assert.ok(socketPath, 'Every root-issued HTTP endpoint is already exclusively claimed.');
  state.connection = localHttpConnection(socketPath); state.base = 'http://localhost';
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
    await work(state);
  } finally { server.closeAllConnections(); if (server.listening) await new Promise(resolve => server.close(resolve)); if (claimFd !== undefined) { closeSync(claimFd); unlinkSync(claim); } rmSync(socketRoot, { recursive: true, force: true }); }
}

test('real HTTP adapters round-trip OCI blobs/manifests, npm, MCP and GitHub bytes', async () => fixture(async state => {
  const http = new HttpTransport(state.base, { token: 'fixture-token', localConnection: state.connection });
  const bytes = Buffer.from('actual immutable package bytes'); const digest = `sha256:${sha(bytes)}`;
  const oci = new OciDistributionAdapter(http, 'product/core');
  assert.equal(await oci.inspectBlob(digest, bytes.length), null);
  await oci.publishBlob(digest, bytes); assert.deepEqual(await oci.inspectBlob(digest, bytes.length), { sha256: sha(bytes), size: bytes.length });
  const manifest = Buffer.from('{"schemaVersion":2}'); const manifestDigest = `sha256:${sha(manifest)}`;
  await oci.publishManifest(manifestDigest, manifest, 'application/vnd.oci.image.index.v1+json');
  assert.deepEqual(await oci.inspectManifest(manifestDigest, manifest.length), { sha256: sha(manifest), size: manifest.length });
  const npm = new NpmRegistryAdapter(http, '@owner/package', '0.1.0-beta.1');
  const packageBytes = npmBytes(); await npm.publish({}, packageBytes); assert.deepEqual(await npm.inspect({}, packageBytes.length), { sha256: sha(packageBytes), size: packageBytes.length });
  await assert.rejects(npm.publish({}, packageBytes, { bin: { 'ud-agent': 'wrong.cjs' } }), /differs/);
  await assert.rejects(npm.publish({}, bytes), /header|gzip/);
  await assert.rejects(new NpmRegistryAdapter(http, '@owner/other', '0.1.0-beta.1').publish({}, packageBytes), /identity/);
  const manualNpm = new NpmRegistryAdapter(http, '@owner/package', '0.1.0-beta.1', { manual: true });
  assert.deepEqual(await manualNpm.inspect({}, packageBytes.length), { sha256: sha(packageBytes), size: packageBytes.length });
  const npmRequestCount = state.calls.length;
  await assert.rejects(manualNpm.publish({}, packageBytes), /local npm CLI/);
  await assert.rejects(manualNpm.promote('beta'), /local npm CLI/);
  assert.equal(state.calls.length, npmRequestCount);
  assert.equal(await manualNpm.verifyPromotion('beta'), false);
  const mcp = new McpRegistryAdapter(http, 'io.github.owner/product', '0.1.0-beta.1');
  const server = Buffer.from(canonicalJson({ version: '0.1.0-beta.1', name: 'io.github.owner/product', description: 'fixture' }));
  await mcp.publish({}, server); assert.deepEqual(await mcp.inspect({}, server.length), { sha256: sha(server), size: server.length });
  const github = new GithubReleaseAdapter(http, 'owner', 'repo', 'v0.1.0-beta.1');
  await github.publish({ filename: 'package.tgz' }, bytes); assert.deepEqual(await github.inspect({ filename: 'package.tgz' }, bytes.length), { sha256: sha(bytes), size: bytes.length });
  assert.ok(state.calls.every(call => call.authorization === 'Bearer fixture-token'));
  assert.throws(() => new HttpTransport('https://registry.npmjs.org'), /verified publisher/);
  assert.throws(() => new HttpTransport('https://registry.npmjs.org', { allowRemote: true, localConnection: state.connection }), /local HTTP authority/);
  assert.throws(() => new HttpTransport(state.base, { localConnection: { socketPath: 'unbranded' } }), /explicit socket capability/);
  assert.throws(() => http.endpoint('http://example.com/escape'), /escapes/);
  const attachmentSizedJson = { pad: 'x'.repeat(8 * 1024 * 1024) };
  await assert.rejects(http.request('PUT', '/large-fixture', { json: attachmentSizedJson, expected: [404] }), /metadata exceeds/);
  const accepted = await http.request('PUT', '/large-fixture', { json: attachmentSizedJson, maxJsonBytes: 16 * 1024 * 1024, expected: [404] });
  await accepted.body?.cancel();
  assert.ok(state.calls.some(call => call.path === '/large-fixture'));
  await assert.rejects(http.request('PUT', '/unused', { json: {}, maxJsonBytes: 0 }), /Invalid publication metadata bound/);
}));

test('publication authorization is lazy, refreshes once and remains on its origin', async () => fixture(async state => {
  let exchanges = 0;
  const http = new HttpTransport(state.base, { localConnection: state.connection, authenticate: async () => ++exchanges === 1 ? 'fixture-expired' : 'fixture-fresh' });
  await assert.rejects(http.request('GET', 'https://example.com/escape'), /escapes/);
  assert.equal(exchanges, 0);
  assert.deepEqual(await http.json('GET', '/restricted'), { ok: true });
  assert.deepEqual(await http.json('GET', '/restricted'), { ok: true });
  assert.equal(exchanges, 2);
  assert.deepEqual(state.calls.map(call => call.authorization), ['Bearer fixture-expired', 'Bearer fixture-fresh', 'Bearer fixture-fresh']);

  const denied = new HttpTransport(state.base, { localConnection: state.connection, authenticate: async () => { exchanges++; return 'fixture-denied'; } });
  await assert.rejects(denied.json('GET', '/restricted'), /HTTP 401/);
  assert.equal(exchanges, 4);
  assert.throws(() => requireVerifiedPublication('/fixture', Buffer.from('{}'), null, { verified: true }), /different command or candidate/);
}));

posixTest('durable reconciliation recovers a lost publication response and delays promotion', async () => fixture(async state => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-http-release-'))); mkdirSync(path.join(root, '.artifacts'));
  const bytes = npmBytes(); const record = { id: 'npm', path: '.artifacts/package.tgz', sha256: sha(bytes), size: bytes.length }; writeFileSync(path.join(root, record.path), bytes);
  const manifest = Buffer.from(JSON.stringify({ status: 'local_candidate', artifacts: [record] }));
  const targets = [{ target: 'npm', coordinate: '@owner/package@0.1.0-beta.1', artifact_id: 'npm' }];
  const adapters = { npm: new NpmRegistryAdapter(new HttpTransport(state.base, { localConnection: state.connection }), '@owner/package', '0.1.0-beta.1') };
  const journal = path.join(root, '.artifacts/journal');
  try {
    await assert.rejects(promotePublication(root, manifest, null, targets, adapters, journal, [{ target: 'npm', coordinate: targets[0].coordinate, channel: 'beta' }]), /every immutable/);
    state.loseNpmResponse = true;
    const first = await reconcilePublication(root, manifest, null, targets, adapters, journal);
    assert.equal(first.targets[`npm:${targets[0].coordinate}`].state, 'verified');
    assert.equal(first.qualification, 'local_http_fixture_only');
    const writes = state.calls.filter(call => call.method === 'PUT' && call.path === '/%40owner%2Fpackage').length;
    await reconcilePublication(root, manifest, null, targets, adapters, journal);
    assert.equal(state.calls.filter(call => call.method === 'PUT' && call.path === '/%40owner%2Fpackage').length, writes);
    await promotePublication(root, manifest, null, targets, adapters, journal, [{ target: 'npm', coordinate: targets[0].coordinate, channel: 'beta' }]);
    assert.equal(state.npmChannels.get('beta'), '0.1.0-beta.1');
    state.tarballs.set('package-0.1.0-beta.1.tgz', Buffer.from('different'));
    await assert.rejects(reconcilePublication(root, manifest, null, targets, adapters, journal), /Immutable target conflict/);
    assert.equal(JSON.parse(readFileSync(path.join(journal, 'publication-state.json'))).manifest_sha256, sha(manifest));
    assert.throws(() => new PublicationJournal(journal, 'invalid'), /identity/);
  } finally { rmSync(root, { recursive: true, force: true }); }
}));

posixTest('GitHub release reconciliation streams the accepted file and compares its returned bytes', async () => fixture(async state => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-github-stream-'))); mkdirSync(path.join(root, '.artifacts'));
  const bytes = Buffer.alloc(1024 * 1024 + 13, 82), item = { id: 'source-materials-000', path: '.artifacts/source-part.tar.gz', sha256: sha(bytes), size: bytes.length }; writeFileSync(path.join(root, item.path), bytes);
  const manifest = Buffer.from(JSON.stringify({ status: 'local_candidate', artifacts: [item] }));
  const http = new HttpTransport(state.base, { localConnection: state.connection });
  const newAdapter = () => new GithubReleaseAdapter(http, 'owner', 'repo', 'v0.1.0-beta.1', http, { sourceCommit: 'a'.repeat(40) });
  const adapter = newAdapter();
  const targets = [{ target: 'github', coordinate: 'owner/repo@v0.1.0-beta.1/source-part.tar.gz', filename: 'source-part.tar.gz', artifact_id: item.id }];
  try {
    state.loseDraftResponse = true; state.failUpload = true; state.loseUploadResponse = true;
    const ledger = await reconcilePublication(root, manifest, null, targets, { github: adapter }, path.join(root, '.artifacts/journal'));
    assert.equal(ledger.targets['github:'+targets[0].coordinate].state, 'verified'); assert.deepEqual(state.releases[0].assets[0].bytes, bytes);
    assert.equal(state.releases.length, 1);
    assert.equal(state.calls.filter(call => call.path.endsWith('/releases') && call.method === 'POST').length, 1);
    assert.equal(state.calls.filter(call => call.path === '/upload-assets').length, 2);
    assert.equal(state.calls.filter(call => call.method === 'DELETE').length, 1);
    assert.deepEqual(await newAdapter().inspect(targets[0], bytes.length), { sha256: sha(bytes), size: bytes.length });
    writeFileSync(path.join(root, item.path), 'corrupt');
    await assert.rejects(reconcilePublication(root, manifest, null, targets, { github: adapter }, path.join(root, '.artifacts/journal')), /receipt mismatch/);
    assert.equal(state.releases[0].assets.length, 1);
    const draft = state.releases[0];
    await assert.rejects(adapter.publish(targets[0], Buffer.from('alternate')), /already exists/);
    draft.target_commitish = 'b'.repeat(40);
    await assert.rejects(newAdapter().release(true), /accepted source commit/);
    draft.target_commitish = 'a'.repeat(40);
    for (let index = 1; index < 10; index++) state.releases.push({ ...draft, id: index + 1, tag_name: `other-${index}` });
    state.releases.push({ ...draft, id: 11 });
    await assert.rejects(newAdapter().release(true), /Duplicate GitHub releases/);
    assert.equal(state.calls.filter(call => call.method === 'DELETE').length, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
}));

posixTest('OCI publication reconciles every blob and manifest from the verified archive', async () => fixture(async state => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-oci-publication-'))); mkdirSync(path.join(root, '.artifacts'));
  const image = createOciFixture('publication'); const filename = path.join(root, '.artifacts/core.oci.tar'); writeFileSync(filename, image.bytes);
  const artifact = { id: 'core-oci-index', path: '.artifacts/core.oci.tar', sha256: sha(image.bytes), size: image.bytes.length, oci_digest: image.index_digest };
  const adapter = new OciArchivePublicationAdapter(new HttpTransport(state.base, { localConnection: state.connection }), 'product/core', filename, artifact, image.index_digest, image.platforms);
  try {
    const manifest = Buffer.from(JSON.stringify({ status: 'local_candidate', artifacts: [artifact] }));
    const targets = [{ target: 'ghcr', coordinate: `product/core@${image.index_digest}`, artifact_id: artifact.id }];
    const result = await reconcilePublication(root, manifest, null, targets, { ghcr: adapter }, path.join(root, '.artifacts/journal'));
    assert.equal(result.targets[`ghcr:${targets[0].coordinate}`].state, 'verified');
    assert.equal(state.manifests.size, 3);
    assert.ok(state.blobs.size >= 3);
    const [digest] = state.blobs.keys(); state.blobs.set(digest, Buffer.from('corrupt'));
    await assert.rejects(adapter.inspect(), /OCI blob conflict|exceeds/);
    adapter.close(); assert.throws(() => adapter.check(), /closed/);
  } finally { adapter.close(); rmSync(root, { recursive: true, force: true }); }
}));

posixTest('candidate publication plan wires every real transport and binds catalogs and release tag to source', async () => fixture(async state => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-publication-plan-')));
  const records = [], put = (id, filename, bytes) => { const relative = '.artifacts/' + filename; mkdirSync(path.dirname(path.join(root, relative)), { recursive: true }); writeFileSync(path.join(root, relative), bytes); const item = { id, path: relative, sha256: sha(bytes), size: bytes.length }; records.push(item); return item; };
  const copied = ['release/identity.yaml', 'release/product.yaml', 'release/channels.yaml', 'registry/server.json', '.claude-plugin/marketplace.json', 'packaging/codex/marketplace.json', '.grok-plugin/marketplace.json', '.grok-plugin/plugin-index.json'];
  for (const source of copied) { mkdirSync(path.dirname(path.join(root, source)), { recursive: true }); copyFileSync(source, path.join(root, source)); }
  const images = Object.fromEntries(['core', 'render'].map(name => [name, createOciFixture('plan-' + name)]));
  for (const [pack, image] of Object.entries(images)) put(`${pack}-oci-index`, pack + '.oci.tar', image.bytes);
  const runtime = { packs: Object.fromEntries(Object.entries(images).map(([name, value]) => [name, { index_digest: value.index_digest, platforms: value.platforms }])) };
  mkdirSync(path.join(root, 'runtime')); const runtimeBytes = Buffer.from(JSON.stringify(runtime)); writeFileSync(path.join(root, 'runtime/runtime.lock.json'), runtimeBytes);
  const publicManifest = { ...npmManifest, name: '@mehmetoguzderin/ud-agent-skill-mcp-plugin' };
  put('npm', 'product.tgz', gzipSync(fixtureTar([['package/package.json', JSON.stringify(publicManifest)], ['package/cli.cjs', '#!/usr/bin/env node\n']])));
  put('mcp-registry-record', 'mcp.json', Buffer.from(canonicalJson(JSON.parse(readFileSync(path.join(root, 'registry/server.json'))))));
  for (const [id, source] of [['catalog-claude', '.claude-plugin/marketplace.json'], ['catalog-codex', 'packaging/codex/marketplace.json'], ['catalog-grok', '.grok-plugin/marketplace.json'], ['catalog-grok-index', '.grok-plugin/plugin-index.json']]) { const bytes = readFileSync(path.join(root, source)); put(id, id + '.json', bytes); state.catalogs.set(source, bytes); }
  state.sourceCommit = 'a'.repeat(40); // Local fixture authority; no Git commit is created.
  const manifestBytes = Buffer.from(JSON.stringify({ schema_version: 1, status: 'local_candidate', product_version: '0.1.0-beta.1', source_commit: state.sourceCommit, runtime_lock_sha256: sha(runtimeBytes), artifacts: records }));
  const plan = publicationPlan(root, manifestBytes), http = new HttpTransport(state.base, { localConnection: state.connection });
  let adapters;
  try {
    assert.equal(plan.targets.length, 16); assert.equal(plan.qualification, 'local-plan-not-production-authority');
    const betaBytes = Buffer.from(JSON.stringify({ ...JSON.parse(manifestBytes), signing_profile: 'publisher-beta' }));
    const betaPlan = publicationPlan(root, betaBytes);
    assert.equal(betaPlan.manualNpm, true);
    assert.deepEqual(betaPlan.targets.filter(item => item.target !== 'github').slice(0, 4).map(item => item.target), ['ghcr-core', 'ghcr-render', 'npm', 'mcp-registry']);
    assert.deepEqual(publicationPromotions(betaPlan).map(item => item.target), ['ghcr-core', 'ghcr-render', 'github', 'npm']);
    writeFileSync(path.join(root, '.artifacts/candidate.json'), manifestBytes);
    const localPlan = await publishCandidate(root, '--plan', '.artifacts/candidate.json'); assert.equal(localPlan.remote_requests, 0); assert.equal(localPlan.manifest_sha256, sha(manifestBytes));
    assert.deepEqual(localPlan.targets, plan.targets);
    await assert.rejects(publicationAdapters(root, plan, { manifestBytes }), /key|signature|accepted|candidate|release/i);
    assert.equal(state.calls.length, 0, 'Unaccepted production adapters must fail before any network request.');
    adapters = await publicationAdapters(root, plan, { fixtureHttp: http });
    const journal = path.join(root, '.artifacts/journal'), promotions = publicationPromotions(plan);
    await assert.rejects(promotePublication(root, manifestBytes, null, plan.targets, adapters, journal, promotions), /every immutable/);
    const ledger = await reconcilePublication(root, manifestBytes, null, plan.targets, adapters, journal);
    assert.equal(Object.values(ledger.targets).filter(item => item.state === 'verified').length, 16);
    assert.equal(state.releases[0].target_commitish, state.sourceCommit); assert.equal(state.releases[0].draft, true);
    assert.equal(state.npmChannels.has('beta'), false); assert.equal(state.manifests.has('0.1.0-beta.1'), false);
    await promotePublication(root, manifestBytes, null, plan.targets, adapters, journal, promotions);
    assert.equal(state.releases[0].draft, false); assert.equal(state.npmChannels.get('beta'), '0.1.0-beta.1');
    assert.ok(state.calls.some(call => call.path === '/v2/mehmetoguzderin/ud-agent-skill-mcp-plugin-core/manifests/' + images.core.index_digest));
    const writes = state.calls.filter(call => ['PUT', 'POST', 'PATCH'].includes(call.method)).length;
    await reconcilePublication(root, manifestBytes, null, plan.targets, adapters, journal);
    assert.equal(state.calls.filter(call => ['PUT', 'POST', 'PATCH'].includes(call.method)).length, writes);
    state.mcp.clear();
    const betaJournal = path.join(root, '.artifacts/beta-journal');
    const anonymous = await publicationAdapters(root, betaPlan, { fixtureHttp: http });
    const credentialed = await publicationAdapters(root, betaPlan, { fixtureHttp: http, credentials: { mcp: 'fixture-registry-token' } });
    try {
      await assert.rejects(reconcilePublication(root, betaBytes, null, betaPlan.targets, anonymous, betaJournal), /mcp-publisher publish.*\.artifacts\/mcp\.json/);
      assert.equal(state.calls.filter(call => ['PUT', 'POST', 'PATCH'].includes(call.method)).length, writes);
      await reconcilePublication(root, betaBytes, null, betaPlan.targets, credentialed, betaJournal);
      const resumed = await reconcilePublication(root, betaBytes, null, betaPlan.targets, anonymous, betaJournal);
      assert.equal(Object.values(resumed.targets).filter(target => target.state === 'verified').length, 16);
      assert.equal(state.calls.filter(call => ['PUT', 'POST', 'PATCH'].includes(call.method)).length, writes + 1);
    } finally {
      for (const group of [anonymous, credentialed]) for (const adapter of Object.values(group)) adapter.close?.();
    }
    state.tagCommit = 'b'.repeat(40);
    await assert.rejects(adapters.github.inspect(plan.targets[0], records[0].size), /another source commit/);
    state.tagCommit = state.sourceCommit; state.catalogs.set('.grok-plugin/marketplace.json', Buffer.from('{}'));
    await assert.rejects(reconcilePublication(root, manifestBytes, null, plan.targets, adapters, journal), /Immutable target conflict/);
  } finally { for (const adapter of Object.values(adapters ?? {})) adapter.close?.(); rmSync(root, { recursive: true, force: true }); }
}), 30_000);

if (process.platform === 'win32') test('publication journal refuses Windows mode metadata before creating publication state', () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-publication-refusal-')));
  try {
    assert.throws(() => new PublicationJournal(root, 'a'.repeat(64)), /Publication journal must be private and owned/);
    assert.deepEqual(readdirSync(root), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
