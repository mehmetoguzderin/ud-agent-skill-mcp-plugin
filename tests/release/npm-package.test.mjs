import { test } from 'vitest';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fixtureTar } from './oci-fixture.mjs';
import { npmManifestFromTarball, publishedNpmManifest } from '../../scripts/release/npm-package.mjs';
const manifest = { name: '@owner/package', version: '0.1.0-beta.1', bin: { 'ud-agent': 'cli.cjs' }, engines: { node: '>=24 <27' }, license: 'MIT', publishConfig: { access: 'public' } };
const archive = (value = manifest, extra = []) => gzipSync(fixtureTar([['package/package.json', JSON.stringify(value)], ['package/cli.cjs', '#!/usr/bin/env node\n'], ...extra]));

test('public npm preparation preserves entry points and rejects private or redirected publication', () => {
  assert.deepEqual(publishedNpmManifest(manifest), manifest);
  const template = JSON.parse(readFileSync(new URL('../../packages/npm-distribution/package.json.in', import.meta.url)));
  assert.deepEqual(publishedNpmManifest(template).publishConfig, { access: 'public' });
  assert.equal(publishedNpmManifest(template).private, undefined);
  for (const privateValue of [true, 'true', 1, null]) assert.throws(() => publishedNpmManifest({ ...manifest, private: privateValue }), /Private/);
  assert.equal(publishedNpmManifest({ ...manifest, private: false }).private, undefined);
  assert.throws(() => publishedNpmManifest({ ...manifest, publishConfig: { access: 'restricted' } }), /public access/);
  assert.throws(() => publishedNpmManifest({ ...manifest, publishConfig: { access: 'public', registry: 'https://foreign.invalid' } }), /authorized registry/);
});

test('accepted npm bytes supply their actual public manifest and reject hostile framing', () => {
  assert.deepEqual(npmManifestFromTarball(archive()), manifest);
  assert.throws(() => npmManifestFromTarball(archive({ ...manifest, bin: { 'ud-agent': '../outside' } })), /executable metadata/);
  assert.throws(() => npmManifestFromTarball(archive({ ...manifest, bin: { 'ud-agent': 'missing.cjs' } })), /executable metadata/);
  assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/cli.cjs/child', 'x']])), /ordinary-file parent/);
  assert.throws(() => npmManifestFromTarball(archive({ ...manifest, private: true })), /Private/);
  assert.throws(() => npmManifestFromTarball(archive({ ...manifest, publishConfig: undefined })), /declare public/);
  assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/../escape', 'x']])), /Unsafe/);
  assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/CLI.CJS', 'x']])), /Duplicate/);
  assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/package.json', '{}']])), /Duplicate/);
  assert.throws(() => npmManifestFromTarball(gzipSync(fixtureTar([['package/cli.cjs', 'x']]))), /no complete/);
  const damaged = fixtureTar([['package/package.json', JSON.stringify(manifest)]]); damaged[0] ^= 1;
  assert.throws(() => npmManifestFromTarball(gzipSync(damaged)), /header/);
  const linked = fixtureTar([['package/package.json', JSON.stringify(manifest)]]); linked[156] = 50; linked.fill(32, 148, 156); const sum = linked.subarray(0, 512).reduce((a, b) => a + b, 0); linked.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  assert.throws(() => npmManifestFromTarball(gzipSync(linked)), /Unsafe/);
  assert.throws(() => npmManifestFromTarball(gzipSync(damaged.subarray(0, 1024))), /header|ending|manifest/);
});


test('the actual offline npm pack fixture retains public npx entry metadata', () => {
  const receipt = JSON.parse(readFileSync(new URL('../fixtures/source-materials/npm-public-fixture.json', import.meta.url)));
  const bytes = readFileSync(new URL('../fixtures/source-materials/npm-public-fixture.tgz', import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), receipt.sha256);
  assert.equal(bytes.length, receipt.size_bytes);
  assert.equal(receipt.qualification, 'actual-offline-npm-pack-first-party-fixture');
  assert.deepEqual(receipt.command, ['npm', 'pack', '--offline', '--ignore-scripts', '--json']);
  assert.deepEqual(receipt.manifest, manifest);
  assert.deepEqual(npmManifestFromTarball(bytes), manifest);
});

test('npm collision keys use frozen full Unicode16 folding and portable names', () => {
  for (const [first, second] of [['Straße.txt', 'STRASSE.txt'], ['Σ.txt', 'ς.txt'], ['é.txt', 'e\u0301.txt'], ['ẞ.txt', 'SS.txt']]) assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/' + first, 'one'], ['package/' + second, 'two']])), /Duplicate/);
  for (const name of ['CON.txt', 'trailing.', 'space ', 'a\\escape', '.git/config', 'newline\nname']) assert.throws(() => npmManifestFromTarball(archive(manifest, [['package/' + name, 'x']])), /Unsafe/);
  const mark = String.fromCodePoint(0x1acf);
  assert.deepEqual(npmManifestFromTarball(archive(manifest, [['package/A\u0315' + mark + '.txt', 'one'], ['package/A' + mark + '\u0315.txt', 'two']])), manifest);
  assert.throws(() => npmManifestFromTarball(archive({ ...manifest, bin: { 'ud-agent': 'CLI.CJS' } })), /executable metadata/);
});
