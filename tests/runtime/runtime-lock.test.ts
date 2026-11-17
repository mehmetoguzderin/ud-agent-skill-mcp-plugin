import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { loadImageReceipt, loadNativeGuardReceipt } from '../../packages/runtime-manager/src/receipt.js';
import Ajv2020 from 'ajv/dist/2020.js';
import { posixTest } from '../fixtures/native-scope.mjs';

const sha = (n: string) => `sha256:${n.repeat(64)}`;
it('reads unified image identities without publication and independently admits native helpers', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-runtime-lock-')));
  try {
    await mkdir(path.join(root, 'runtime/helpers/darwin/arm64'), { recursive: true });
    const guardBytes = Buffer.from('#!/bin/sh\nexit 0\n');
    const guardPath = 'runtime/helpers/darwin/arm64/ud-agent-guard';
    await writeFile(path.join(root, guardPath), guardBytes, { mode: 0o700 });
    const lock = {
      schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen',
      packs: { core: {
        context_sha256: sha('1'), index_digest: sha('2'), platforms: { 'linux/arm64': sha('3') },
        images: { 'linux/arm64': {
          digest: sha('3'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}`,
          config_digest: sha('4'), diff_ids: [sha('5')],
          transports: [{ format: 'docker-archive', path: 'runtime/images/core.tar', sha256: sha('6'), size_bytes: 1024 }],
        } },
      } },
      native_helpers: { 'darwin/arm64': { guard: { path: guardPath, sha256: `sha256:${createHash('sha256').update(guardBytes).digest('hex')}`, size_bytes: guardBytes.length } } },
    };
    const save = () => writeFile(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify(lock));
    await save();
    expect(await loadImageReceipt(root, 'core', 'arm64')).toMatchObject({ digest: sha('3'), configDigest: sha('4'), diffIds: [sha('5')], transports: [{ format: 'docker-archive', path: 'runtime/images/core.tar', sizeBytes: 1024 }] });
    expect(await loadNativeGuardReceipt(root, { platform: 'darwin', arch: 'arm64' })).toMatchObject({ guard: path.join(root, guardPath), guardSha256: lock.native_helpers['darwin/arm64'].guard.sha256 });
    lock.packs.core.platforms['linux/arm64'] = sha('7'); await save();
    await expect(loadImageReceipt(root, 'core', 'arm64')).rejects.toThrow('disagree');
    lock.packs.core.platforms['linux/arm64'] = sha('3'); await save();
    await writeFile(path.join(root, guardPath), Buffer.from('#!/bin/sh\nexit 1\n'));
    await expect(loadNativeGuardReceipt(root, { platform: 'darwin', arch: 'arm64' })).rejects.toThrow('digest');
  } finally { await rm(root, { recursive: true, force: true }); }
});

posixTest('native helper admission rejects writable POSIX executable permissions', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-runtime-mode-')));
  try {
    await mkdir(path.join(root, 'runtime'));
    const bytes = Buffer.from('nonexecuted helper fixture'), guard = path.join(root, 'runtime/guard');
    await writeFile(guard, bytes, { mode: 0o700 });
    await writeFile(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', native_helpers: { 'darwin/arm64': { guard: { path: 'runtime/guard', size_bytes: bytes.length, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}` } } } }));
    expect((await loadNativeGuardReceipt(root, { platform: 'darwin', arch: 'arm64' })).guard).toBe(guard);
    await chmod(guard, 0o777);
    await expect(loadNativeGuardReceipt(root, { platform: 'darwin', arch: 'arm64' })).rejects.toThrow('NATIVE_HELPER_RECEIPT_INVALID');
    expect(await readFile(guard)).toEqual(bytes);
  } finally { await rm(root, { recursive: true, force: true }); }
});

it('keeps an optional archive index distinct from the pack index and rejects Docker or malformed index claims', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-transport-index-')));
  try {
    await mkdir(path.join(root, 'runtime'));
    const filename = path.join(root, 'runtime/runtime.lock.json');
    const transport = { format: 'oci-archive', path: 'runtime/images/core-arm64.oci.tar', sha256: sha('6'), size_bytes: 1024, index_digest: sha('7') };
    const save = (value: Record<string, unknown>) => writeFile(filename, JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: { core: { context_sha256: sha('1'), index_digest: sha('2'), platforms: { 'linux/arm64': sha('3') }, images: { 'linux/arm64': { digest: sha('3'), reference: `ghcr.io/mehmetoguzderin/core@${sha('3')}`, config_digest: sha('4'), diff_ids: [sha('5')], transports: [value] } } } } }));
    await save(transport); expect((await loadImageReceipt(root, 'core', 'arm64')).transports).toEqual([{ format: 'oci-archive', path: transport.path, sha256: sha('6'), sizeBytes: 1024, indexDigest: sha('7') }]);
    const { index_digest: _index, ...legacy } = transport; await save(legacy); expect((await loadImageReceipt(root, 'core', 'arm64')).transports?.[0]).not.toHaveProperty('indexDigest');
    for (const changed of [{ ...transport, format: 'docker-archive' }, ...[null, 1, '', 'sha256:ABC', '7'.repeat(64)].map(index_digest => ({ ...transport, index_digest }))]) {
      await save(changed); await expect(loadImageReceipt(root, 'core', 'arm64')).rejects.toThrow('transport index identity');
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

it('strict runtime schema permits optional OCI transport index identity and forbids applying it to Docker archives', async () => {
  const schema = JSON.parse(await readFile('contracts/schema/runtime-lock.schema.json', 'utf8'));
  const validate = new Ajv2020({ strict: true }).compile({ $schema: schema.$schema, $defs: schema.$defs, $ref: '#/$defs/transport' });
  const file = { path: 'runtime/images/core.tar', sha256: sha('6'), size_bytes: 1 };
  for (const value of [{ ...file, format: 'oci-archive' }, { ...file, format: 'oci-archive', index_digest: sha('7') }, { ...file, format: 'docker-archive' }]) expect(validate(value), JSON.stringify(validate.errors)).toBe(true);
  for (const value of [{ ...file, format: 'docker-archive', index_digest: sha('7') }, ...[null, 1, '', '7'.repeat(64), 'sha256:BAD'].map(index_digest => ({ ...file, format: 'oci-archive', index_digest }))]) expect(validate(value)).toBe(false);
});
