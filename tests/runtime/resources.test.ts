import { mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';

describe('authorized immutable resources', () => {
  it('returns exact bytes, snapshot-bound pages and rejects changed cursors or workspace grants', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-resources-')));
    try {
      const store = await ResourceStore.open(root, ['/granted/workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
      const bytes = Buffer.alloc(150_000, 0x61); bytes[70_000] = 0x62;
      const ref = await store.put('reports', bytes, 'application/json');
      const page = JSON.parse((await store.read(new URL(ref.uri))).contents[0]!.text!);
      expect(Buffer.from(page.content_base64, 'base64')).toEqual(bytes.subarray(0, 65536));
      const second = JSON.parse((await store.read(new URL(`${ref.uri}?cursor=${page.next_cursor}`))).contents[0]!.text!);
      expect(Buffer.from(second.content_base64, 'base64')).toEqual(bytes.subarray(65536, 131072));
      await expect(store.read(new URL(`${ref.uri}?cursor=${page.next_cursor}x`))).rejects.toThrow('RESOURCE_CURSOR_INVALID');
      const other = await ResourceStore.open(root, ['/other'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
      await expect(other.read(new URL(ref.uri))).rejects.toThrow('RESOURCE_ACCESS_DENIED');
      const ref2 = await store.put('reports', bytes, 'application/json');
      await expect(store.read(new URL(`${ref2.uri}?cursor=${page.next_cursor}`))).rejects.toThrow('RESOURCE_CURSOR_INVALID');
      const id = new URL(ref.uri).pathname.slice(1);
      await writeFile(path.join(root, id, 'data'), Buffer.alloc(bytes.length, 0x63));
      await expect(store.read(new URL(ref.uri))).rejects.toThrow('RESOURCE_INTEGRITY_FAILED');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rejects expired, missing and symlinked resources without reading arbitrary paths', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-resources-')));
    try {
      const store = await ResourceStore.open(root, ['/workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
      const ref = await store.put('artifacts', Buffer.from('verified'), 'text/plain');
      expect((await store.read(new URL(ref.uri))).contents[0]!.text).toBe('verified');
      const folder = path.join(root, new URL(ref.uri).pathname.slice(1));
      const metadata = JSON.parse(await readFile(path.join(folder, 'metadata.json'), 'utf8'));
      metadata.retention.expires_at = '2000-01-01T00:00:00.000Z';
      await writeFile(path.join(folder, 'metadata.json'), JSON.stringify(metadata));
      await expect(store.read(new URL(ref.uri))).rejects.toThrow('RESOURCE_EXPIRED');
      await expect(store.read(new URL('ud://reports/00000000-0000-4000-8000-000000000000'))).rejects.toThrow('RESOURCE_NOT_FOUND');
      const target = path.join(root, 'linked'); await symlink(root, target);
      await expect(ResourceStore.open(target, ['/workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined)).rejects.toThrow('RESOURCE_STATE_INVALID');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
