import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { bindRuntimeAssets, reconcileRuntimeAssetLinks, runtimeAssetInventory, verifyRuntimeEngineImage, reconcileRuntimeFixture, cleanupRuntimeFixture } from '../../evals/local/runtime-assets.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
test('diagnostic runtime binding requires an actual completed native build and keeps source locks unchanged', async (t) => {
  const root = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-runtime-binding-'));
  t.onTestFinished(() => rmSync(root, { recursive: true, force: true }));
  const installation = path.join(root, '.artifacts/installation'), buildRoot = path.join(root, '.artifacts/build');
  mkdirSync(path.join(installation, 'runtime'), { recursive: true }); mkdirSync(path.join(root, 'runtime'));
  const lock = JSON.stringify({ schema_version: 1, state: 'unbuilt', packs: {} });
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), lock); writeFileSync(path.join(installation, 'runtime/runtime.lock.json'), lock);
  await assert.rejects(bindRuntimeAssets(root, installation, { buildRoot }), /RUNTIME_BUILD_REQUIRED/);
  mkdirSync(buildRoot); writeFileSync(path.join(buildRoot, 'build-receipt.json'), JSON.stringify({ qualification: 'native-build-unaccepted', platform: 'linux/amd64', emulated: true }));
  await assert.rejects(bindRuntimeAssets(root, installation, { buildRoot }), /native ARM64 build evidence/);
  assert.equal(readFileSync(path.join(root, 'runtime/runtime.lock.json'), 'utf8'), lock);
  assert.equal(readFileSync(path.join(installation, 'runtime/runtime.lock.json'), 'utf8'), lock);
});

test('runtime reuse inventory checks exact cached bytes and never invents provider readiness', (t) => {
  const root = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-runtime-inventory-'));
  t.onTestFinished(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'runtime'));
  const bytes = Buffer.from('inert archive bytes'), descriptor = { path: 'worker.tar', sha256: sha(bytes), size_bytes: bytes.length };
  writeFileSync(path.join(root, 'worker.tar'), bytes);
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ state: 'frozen', packs: { core: { images: { 'linux/arm64': { transports: [descriptor] } } } } }));
  const first = runtimeAssetInventory(root);
  assert.deepEqual(first.files, [descriptor]); assert.equal(first.ready, undefined); assert.equal(first.reusedAssets, undefined);
  assert.equal(runtimeAssetInventory(root).sha256, first.sha256);
  writeFileSync(path.join(root, 'worker.tar'), 'tampered');
  assert.throws(() => runtimeAssetInventory(root), /runtime asset changed/);
});

posixTest('private runtime reconciliation hardlinks only exact known copies and preserves byte inventories', (t) => {
  const root = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-runtime-links-')), installation = path.join(root, '.artifacts/installation'), packs = {};
  t.onTestFinished(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, '.artifacts/build'), { recursive: true }); mkdirSync(path.join(installation, 'runtime'), { recursive: true });
  for (const name of ['core', 'render']) {
    const bytes = Buffer.from(name), relative = `.artifacts/build/${name}.tar`, descriptor = { path: relative, sha256: sha(bytes), size_bytes: bytes.length, format: 'oci-archive' };
    writeFileSync(path.join(root, relative), bytes); mkdirSync(path.dirname(path.join(installation, relative)), { recursive: true }); writeFileSync(path.join(installation, relative), bytes); chmodSync(path.join(installation, relative), 0o400);
    packs[name] = { index_digest: sha(name + '-index'), index_transport: descriptor, images: { 'linux/arm64': { transports: [descriptor] } } };
  }
  const workerBytes = Buffer.from(JSON.stringify({ packs })), workerPath = '.artifacts/build/worker-receipt.json'; writeFileSync(path.join(root, workerPath), workerBytes);
  writeFileSync(path.join(installation, 'runtime/runtime.lock.json'), JSON.stringify({ state: 'frozen', packs }));
  writeFileSync(path.join(installation, 'LOCAL-EVAL-RUNTIME.json'), JSON.stringify({ qualification: 'local-eval-native-runtime-not-release-acceptance', worker_receipt: { path: workerPath, sha256: sha(workerBytes), size_bytes: workerBytes.length } }));
  const first = reconcileRuntimeAssetLinks(root, installation); assert.equal(first.links.length, 2);
  for (const { path: relative } of first.links) {
    const source = lstatSync(path.join(root, relative)), installed = lstatSync(path.join(installation, relative));
    assert.equal(source.ino, installed.ino); assert.equal(source.dev, installed.dev); assert.equal(source.nlink, 2); assert.equal(source.mode & 0o777, 0o400);
    assert.equal(sha(readFileSync(path.join(installation, relative))), packs[path.basename(relative, '.tar')].index_transport.sha256);
  }
  assert.ok(reconcileRuntimeAssetLinks(root, installation).links.every((row) => row.reused));
  const changed = path.join(installation, '.artifacts/build/core.tar'); rmSync(changed); writeFileSync(changed, 'other'); chmodSync(changed, 0o400);
  assert.throws(() => reconcileRuntimeAssetLinks(root, installation), /exact known copy/);
});

if (process.platform === 'win32') test('Windows refuses unverified POSIX archive sealing before replacing private runtime copies', (t) => {
  const root = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-runtime-sealing-refusal-')), installation = path.join(root, '.artifacts/installation');
  t.onTestFinished(() => rmSync(root, { recursive: true, force: true }));
  const relative = '.artifacts/build/core.tar', source = path.join(root, relative), target = path.join(installation, relative), bytes = Buffer.from('exact source archive');
  mkdirSync(path.dirname(source), { recursive: true }); mkdirSync(path.dirname(target), { recursive: true }); mkdirSync(path.join(installation, 'runtime'));
  writeFileSync(source, bytes); chmodSync(source, 0o400); writeFileSync(target, bytes); chmodSync(target, 0o400);
  const descriptor = { path: relative, sha256: sha(bytes), size_bytes: bytes.length, format: 'oci-archive' };
  const packs = { core: { index_digest: sha('index'), index_transport: descriptor, images: { 'linux/arm64': { transports: [descriptor] } } } };
  const workerPath = '.artifacts/build/worker-receipt.json', workerBytes = Buffer.from(JSON.stringify({ packs }));
  writeFileSync(path.join(root, workerPath), workerBytes); writeFileSync(path.join(installation, 'runtime/runtime.lock.json'), JSON.stringify({ state: 'frozen', packs }));
  writeFileSync(path.join(installation, 'LOCAL-EVAL-RUNTIME.json'), JSON.stringify({ qualification: 'local-eval-native-runtime-not-release-acceptance', worker_receipt: { path: workerPath, sha256: sha(workerBytes), size_bytes: workerBytes.length } }));
  const before = lstatSync(target, { bigint: true });
  assert.throws(() => reconcileRuntimeAssetLinks(root, installation), /transport sealing changed its identity/);
  const after = lstatSync(target, { bigint: true });
  assert.equal(after.ino, before.ino); assert.equal(after.dev, before.dev); assert.equal(after.nlink, 1n);
  assert.deepEqual(readFileSync(source), bytes); assert.deepEqual(readFileSync(target), bytes);
});

test('cold runtime reuse needs unchanged cache/engine identities, a real readiness probe and completed matching operation', () => {
  const cache = [{ sha256: sha('archive'), inode: '12', device: '3' }], engine = { daemon: 'fixture-daemon', images: [{ image_digest: sha('image') }] };
  const fixture = { qualification: 'input-only-cold-runtime-fixture', readiness_probes_created: false, initial_readiness_absent: true, cache, engine };
  const events = [{ type: 'operation_step', step: 'runtime_readiness', observation: { stage: 'initial', result: { ready: false } } }, { type: 'operation_result', response: { structuredContent: { execution: { status: 'completed' }, provenance: { image_digest: sha('image') } } } }];
  const probes = [{ value: { image: { digest: sha('image') } }, path: 'probe.json' }];
  const observation = reconcileRuntimeFixture(fixture, { cache, engine, probes, events });
  assert.equal(observation.verified, true); assert.equal(observation.initiallyReady, false); assert.equal(observation.reusedAssets, true);
  assert.equal(reconcileRuntimeFixture(fixture, { cache, engine, probes: [], events }).verified, false);
  assert.equal(reconcileRuntimeFixture(fixture, { cache, engine, probes, events: events.slice(0, 1) }).reusedAssets, undefined);
  assert.throws(() => reconcileRuntimeFixture(fixture, { cache: [{ ...cache[0], inode: 'new' }], engine, probes, events }), /identities changed/);
  assert.throws(() => reconcileRuntimeFixture(fixture, { cache, engine: { ...engine, daemon: 'different' }, probes, events }), /engine identity changed/);
});

test('runtime cache binds both config-based and receipt-verified Docker descriptor identities', () => {
  const row = { pack: 'core', image_digest: sha('manifest'), config_digest: sha('config'), engine_descriptor_digests: [sha('manifest')], diff_ids: [sha('layer')] };
  const value = [{ Id: sha('manifest'), Architecture: 'arm64', Os: 'linux', RootFS: { Layers: row.diff_ids } }];
  assert.equal(verifyRuntimeEngineImage(row, value).engine_id, sha('manifest'));
  value[0].Id = sha('config'); assert.equal(verifyRuntimeEngineImage(row, value).config_digest, sha('config'));
  value[0].Id = sha('other'); assert.throws(() => verifyRuntimeEngineImage(row, value), /differs/);
  value[0].Id = sha('manifest'); value[0].RootFS.Layers = [sha('other-layer')]; assert.throws(() => verifyRuntimeEngineImage(row, value), /differs/);
});

test('fixture cleanup requires released execution and removes only the exact seeded archive identities', (t) => {
  const installation = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-runtime-cleanup-'));
  t.onTestFinished(() => rmSync(installation, { recursive: true, force: true }));
  const state = path.join(installation, 'state'), images = path.join(state + '-docker', 'images'), packs = {}, cache = [];
  mkdirSync(images, { recursive: true }); mkdirSync(path.join(installation, 'runtime'));
  for (const pack of ['core', 'render']) {
    const bytes = Buffer.from(pack), digest = sha(bytes), file = path.join(images, digest.slice(7) + '.tar');
    writeFileSync(file, bytes); chmodSync(file, 0o400); const info = lstatSync(file);
    const image = { digest: sha(pack + '-image'), config_digest: sha(pack + '-config'), diff_ids: [sha(pack + '-layer')], transports: [{ format: 'docker-archive', path: pack + '.tar', sha256: digest, size_bytes: bytes.length }] };
    packs[pack] = { images: { 'linux/arm64': image } };
    cache.push({ pack, path: file, sha256: digest, size_bytes: bytes.length, device: String(info.dev), inode: String(info.ino), image_digest: image.digest, config_digest: image.config_digest, engine_descriptor_digests: [], diff_ids: image.diff_ids });
  }
  writeFileSync(path.join(installation, 'runtime/runtime.lock.json'), JSON.stringify({ state: 'frozen', packs }));
  writeFileSync(path.join(images, 'unknown.txt'), 'preserve me');
  const fixture = { installation, state, cache };
  assert.throws(() => cleanupRuntimeFixture(fixture, { nativeCleanupVerified: true, pendingOperations: 1 }), /verified execution release/);
  assert.ok(cache.every((row) => existsSync(row.path)));
  const wrong = { ...fixture, cache: cache.map((row) => ({ ...row, inode: 'foreign' })) };
  assert.throws(() => cleanupRuntimeFixture(wrong, { nativeCleanupVerified: true, pendingOperations: 0 }), /identity changed/);
  const result = cleanupRuntimeFixture(fixture, { nativeCleanupVerified: true, pendingOperations: 0 });
  assert.equal(result.verified, true); assert.equal(result.removed.length, 2);
  assert.ok(cache.every((row) => !existsSync(row.path)));
  assert.equal(readFileSync(path.join(images, 'unknown.txt'), 'utf8'), 'preserve me');
});
