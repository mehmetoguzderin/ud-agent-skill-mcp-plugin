import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { deriveStrykerAssertionSdk, STRYKER_ASSERTION_SDK_FILE, STRYKER_ASSERTION_SERIALIZER_FILE, STRYKER_ASSERTION_CHAI_FILE } from '../../scripts/quality/stryker-assertion-sdk.mjs';
import {originalVitestAssertionSdk,originalVitestSerializerSdk,originalChaiAssertionSdk} from '../fixtures/assertion-sdk.mjs';
import { verifyRecordedStrykerSdk } from '../../scripts/quality/stryker-sdk-evidence.mjs';

function fixture() {
  const require = createRequire(import.meta.url), directory = path.dirname(require.resolve('vitest/package.json'));
  const original = originalVitestAssertionSdk(directory), serializer=originalVitestSerializerSdk(directory), chai=originalChaiAssertionSdk(path.dirname(require.resolve('chai/package.json'))), derived = deriveStrykerAssertionSdk(original,{serializerOriginal:serializer,chaiOriginal:chai});
  const before = { schema_version: 1, files: [{ path: STRYKER_ASSERTION_SDK_FILE, sha256: sha256(original), size: original.length, mode: 0o444 }, {path:STRYKER_ASSERTION_SERIALIZER_FILE,sha256:sha256(serializer),size:serializer.length,mode:0o444}, {path:STRYKER_ASSERTION_CHAI_FILE,sha256:sha256(chai),size:chai.length,mode:0o444}, { path: 'other.js', sha256: 'a'.repeat(64), size: 2, mode: 0o444 }], links: [] };
  const after = structuredClone(before);after.files[2]={...after.files[2],sha256:sha256(derived.chaiDerived),size:derived.chaiDerived.length}; after.files[1]={...after.files[1],sha256:sha256(derived.serializerDerived),size:derived.serializerDerived.length};after.files[0] = { ...after.files[0], sha256: sha256(derived.derived), size: derived.derived.length };
  const installation = { qualification: 'locked-native-sdk-data-preparation-no-lifecycle-execution', inputs: { 'package-lock.json': 'b'.repeat(64) }, closure: { sha256: sha256(JSON.stringify(before) + '\n'), files: 4, links: 0 } };
  const stored = {}, descriptor = (name, bytes) => { stored['runtime-' + name] = bytes; return { path: name, size_bytes: bytes.length, sha256: sha256(bytes) }; };
  const json = value => Buffer.from(JSON.stringify(value) + '\n');
  const runtime = { package_lock_sha256: 'b'.repeat(64), node_dependencies: descriptor('node-dependencies.json', json(after)), node_installation: descriptor('node-installation-receipt.json', json(installation)), node_assertion_sdk: { receipt: descriptor('node-assertion-sdk.json', json(derived.receipt)), upstream_source: descriptor('node-assertion-sdk-upstream.js', original),serializer_upstream_source:descriptor('node-assertion-sdk-serializer-upstream.js',serializer), chai_upstream_source:descriptor('node-assertion-sdk-chai-upstream.js',chai), upstream_dependencies: descriptor('node-upstream-dependencies.json', json(before)) } };
  stored['runtime-node-assertion-sdk-derived.js'] = derived.derived;stored['runtime-node-assertion-sdk-serializer-derived.js']=derived.serializerDerived;stored['runtime-node-assertion-sdk-chai-derived.js']=derived.chaiDerived;
  return { runtime, stored, descriptor, json, before, after, read: name => stored[name] };
}
test('replays the exact upstream source, transformation and complete dependency difference from retained evidence', () => {
  const f = fixture();
  assert.deepEqual(verifyRecordedStrykerSdk(f.runtime, f.read), { schema_version: 1, root: '/opt/mutation/node_modules', receipt_sha256: f.runtime.node_dependencies.sha256 });
});
test('an authentic-looking supplied receipt cannot replace upstream bytes, transformation or unrelated SDK files', () => {
  for (const change of [
    f => { f.stored['runtime-node-assertion-sdk-upstream.js'] = Buffer.from('forged upstream'); },
    f => { f.stored['runtime-node-assertion-sdk-derived.js'] = Buffer.from('forged derived'); },
    f => { f.after.files[1].sha256 = 'c'.repeat(64); f.runtime.node_dependencies = f.descriptor('node-dependencies.json', f.json(f.after)); },
    f => { f.runtime.package_lock_sha256 = 'c'.repeat(64); },
  ]) { const f = fixture(); change(f); assert.throws(() => verifyRecordedStrykerSdk(f.runtime, f.read)); }
});
test('missing, foreign-path, wrong-size or absent derivation outcomes are rejected', () => {
  for (const change of [
    f => { delete f.runtime.node_assertion_sdk; },
    f => { f.runtime.node_dependencies.path = '../other'; },
    f => { f.runtime.node_assertion_sdk.receipt.size_bytes++; },
    f => { delete f.stored['runtime-node-assertion-sdk-derived.js']; },
  ]) { const f = fixture(); change(f); assert.throws(() => verifyRecordedStrykerSdk(f.runtime, f.read)); }
});
