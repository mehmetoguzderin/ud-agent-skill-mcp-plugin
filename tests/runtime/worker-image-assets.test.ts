import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { acquireWorkerImageTransport } from '../../packages/runtime-manager/src/worker-image-assets.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const bytes = Buffer.from('closed image transport byte fixture');
const sha256 = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const transport = { format: 'oci-archive' as const, path: 'runtime/images/core-linux-arm64.oci.tar', sha256, sizeBytes: bytes.length };
async function fixture(action: (input: { sourceRoot: string; stateRoot: string; guard: string; transport: typeof transport; network: 'offline' | 'bootstrap_only' }, root: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-worker-assets-')));
  try { const sourceRoot = path.join(root, 'installation'), stateRoot = path.join(root, 'state'); await mkdir(path.join(sourceRoot, 'runtime/images'), { recursive: true, mode: 0o700 }); await action({ sourceRoot, stateRoot, guard, transport, network: 'offline' }, root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
describe('published worker transport acquisition', () => {
  it('imports exact local bytes into a private immutable cache and reuses it without network or source files', async () => fixture(async input => {
    const source = path.join(input.sourceRoot, transport.path); await writeFile(source, bytes);
    const filename = await acquireWorkerImageTransport({ ...input, fetcher: async () => { throw new Error('unintended download'); } }); expect(filename).toBe(path.join(input.stateRoot, 'images', `${sha256.slice(7)}.tar`)); expect(await readFile(filename!)).toEqual(bytes);
    const before = await lstat(filename!); expect(before.nlink).toBe(1); if (process.platform !== 'win32') expect(before.mode & 0o222).toBe(0);
    await rm(source); expect(await acquireWorkerImageTransport(input)).toBe(filename); expect((await lstat(filename!)).ino).toBe(before.ino); expect((await readdir(path.dirname(filename!))).some(name => name.startsWith('.image-import-'))).toBe(false);
  }));
  it('acquires the exact published archive through bounded allowed redirects, then works offline', async () => fixture(async input => {
    const urls: string[] = []; const fetcher: typeof fetch = async (url, init) => { urls.push(String(url)); expect(init?.redirect).toBe('manual'); return urls.length === 1 ? new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/pinned/core.tar' } }) : new Response(bytes, { headers: { 'content-length': String(bytes.length) } }); };
    const filename = await acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher }); expect(await readFile(filename!)).toEqual(bytes); expect(urls).toEqual(['https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/core-linux-arm64.oci.tar', 'https://release-assets.githubusercontent.com/pinned/core.tar']);
    expect(await acquireWorkerImageTransport({ ...input, fetcher: async () => { throw new Error('offline means no network'); } })).toBe(filename);
  }));
  it('distinguishes genuine availability failures from malformed, truncated and corrupt payloads', async () => {
    for (const status of [403, 404, 408, 429, 500, 502, 503, 504]) await fixture(async input => { expect(await acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => new Response(null, { status }) })).toBeNull(); expect((await readdir(path.join(input.stateRoot, 'images'))).some(name => name.endsWith('.tar') || name.startsWith('.image-import-'))).toBe(false); });
    for (const payload of [Buffer.from('short'), Buffer.alloc(bytes.length), Buffer.alloc(bytes.length + 1)]) await fixture(async input => { await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => new Response(payload) })).rejects.toThrow(/INTEGRITY_FAILED|SIZE_MISMATCH/); });
    await fixture(async input => { await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => new Response(bytes, { headers: { 'content-length': '1' } }) })).rejects.toThrow('SIZE_MISMATCH'); });
  });
  it('never downloads in offline mode and never repairs corrupt local or cached files implicitly', async () => fixture(async input => {
    let downloads = 0; const fetcher: typeof fetch = async () => { downloads++; return new Response(bytes); };
    expect(await acquireWorkerImageTransport({ ...input, fetcher })).toBeNull(); expect(downloads).toBe(0);
    const source = path.join(input.sourceRoot, transport.path); await writeFile(source, Buffer.alloc(bytes.length)); await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher })).rejects.toThrow('INTEGRITY_FAILED'); expect(downloads).toBe(0);
    await writeFile(source, bytes); const filename = (await acquireWorkerImageTransport(input))!; await chmod(filename, 0o600); await writeFile(filename, Buffer.alloc(bytes.length)); await chmod(filename, 0o400);
    await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher })).rejects.toThrow('digest'); expect(downloads).toBe(0); expect(await readFile(filename)).toEqual(Buffer.alloc(bytes.length));
  }));
  it('rejects redirect escapes, cycles and malformed transport paths before publishing bytes', async () => {
    for (const location of ['http://github.com/file', 'https://evil.invalid/file', 'https://user@github.com/file', 'https://github.com:444/file']) await fixture(async input => { await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => new Response(null, { status: 302, headers: { location } }) })).rejects.toThrow('REDIRECT_INVALID'); });
    await fixture(async input => { let count = 0; await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => { count++; return new Response(null, { status: 302, headers: { location: '/again' } }); } })).rejects.toThrow('REDIRECT_INVALID'); expect(count).toBe(6); });
    for (const name of ['/escape.tar', '../escape.tar', 'runtime/../escape.tar', 'C:/escape.tar', 'runtime\\escape.tar', 'runtime/\0/escape.tar']) await fixture(async input => { await expect(acquireWorkerImageTransport({ ...input, transport: { ...transport, path: name } })).rejects.toThrow('TRANSPORT_INVALID'); await expect(readdir(input.stateRoot)).rejects.toMatchObject({ code: 'ENOENT' }); });
  });
  it('recognizes bounded network IO failures without suppressing arbitrary programming errors', async () => fixture(async input => {
    expect(await acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => { throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } }); } })).toBeNull();
    await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => { throw new TypeError('bad fixture implementation'); } })).rejects.toThrow('bad fixture implementation');
  }));
  it('propagates cancellation and cleans only the interrupted acquisition', async () => fixture(async input => {
    const cancelled = new AbortController(); cancelled.abort(); await expect(acquireWorkerImageTransport({ ...input, signal: cancelled.signal })).rejects.toThrow('WORKER_CANCELLED'); await expect(readdir(input.stateRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    const active = new AbortController(); await expect(acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', signal: active.signal, fetcher: async () => { active.abort(); return new Response(bytes); } })).rejects.toThrow('WORKER_CANCELLED');
    const root = path.join(input.stateRoot, 'images'); expect((await readdir(root)).some(name => name.endsWith('.tar') || name.startsWith('.image-import-'))).toBe(false);
    await writeFile(path.join(root, 'foreign'), 'retain'); const recovered = await acquireWorkerImageTransport({ ...input, network: 'bootstrap_only', fetcher: async () => new Response(bytes) }); expect(await readFile(recovered!)).toEqual(bytes); expect(await readFile(path.join(root, 'foreign'), 'utf8')).toBe('retain');
  }));
});
