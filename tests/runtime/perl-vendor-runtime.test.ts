import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { acquirePerlVendorArchive, validatePerlVendorRecipe } from '../../packages/runtime-manager/src/userspace-perl-runtime.js';

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
function recipe(bytes = Buffer.from('verified-vendor-archive')) {
  return { schema_version: 1, provider: 'conda-vc-runtime', platform: 'win32/arm64', executable: 'bin/perl.exe', archive: { url: 'https://conda.anaconda.org/conda-forge/win-arm64/vc14_runtime-14.51.36247-build.conda', sha256: createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length }, base_files: [{ source: 'bin/perl.exe', path: 'bin/perl.exe', sha256: 'a'.repeat(64), size_bytes: 128 }], files: [{ source: 'Library/bin/vcruntime140.dll', path: 'bin/vcruntime140.dll', sha256: 'b'.repeat(64), size_bytes: 128 }] };
}
describe('private vendor runtime', () => {
  it('binds only Windows fixed vendor URLs and closed file identities', () => {
    const original = recipe(); expect(validatePerlVendorRecipe(original, { platform: 'win32', arch: 'arm64' })).toEqual(original);
    for (const change of [value => { value.archive.url += '?redirect=1'; }, value => { value.archive.url = value.archive.url.replace('win-arm64', 'win-64'); }, value => { value.files[0].path = '../outside.dll'; }, value => { value.base_files[0].path = 'bin/other.exe'; }, value => { value.files.push({ ...value.files[0] }); }]) { const value = structuredClone(original); change(value); expect(() => validatePerlVendorRecipe(value, { platform: 'win32', arch: 'arm64' })).toThrow(); }
    expect(() => validatePerlVendorRecipe(original, { platform: 'darwin', arch: 'arm64' })).toThrow();
  });
  it('acquires once, reuses offline, and refuses corrupt authoritative bytes', async () => {
    const cache = await mkdtemp(path.join(os.tmpdir(), 'ud-vendor-')); roots.push(cache); const bytes = Buffer.from('verified-vendor-archive'), value = validatePerlVendorRecipe(recipe(bytes), { platform: 'win32', arch: 'arm64' }); let downloads = 0;
    const fetcher: typeof fetch = async (url, options) => { downloads++; expect(url).toBe(value.archive.url); expect(options?.redirect).toBe('error'); return new Response(bytes, { headers: { 'content-length': String(bytes.length) } }); };
    const file = await acquirePerlVendorArchive(value, cache, 'bootstrap_only', fetcher); expect(await readFile(file)).toEqual(bytes);
    expect(await acquirePerlVendorArchive(value, cache, 'offline', fetcher)).toBe(file); expect(downloads).toBe(1);
    await writeFile(file, Buffer.alloc(bytes.length)); await expect(acquirePerlVendorArchive(value, cache, 'bootstrap_only', fetcher)).rejects.toThrow(); expect(downloads).toBe(1);
  });
  it('binds the separate supplier archive to the relocated Perl executable', async () => {
    const cache = await mkdtemp(path.join(os.tmpdir(), 'ud-perl-supplier-'));
    roots.push(cache);
    const bytes = Buffer.from('verified-perl-supplier-archive');
    const value = {
      ...recipe(),
      base_files: [{ source: 'lib/core/Test.pm', path: 'lib/core/Test.pm', sha256: 'a'.repeat(64), size_bytes: 128 }],
      supplier: {
        archive: {
          url: 'https://conda.anaconda.org/anaconda/win-arm64/perl-5.44.0.tar.bz2',
          size_bytes: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex'),
        },
        files: [{ source: 'Library/bin/perl.exe', path: 'bin/perl.exe', sha256: 'b'.repeat(64), size_bytes: 128 }],
      },
    };
    const host = { platform: 'win32', arch: 'arm64' } as const;
    const validated = validatePerlVendorRecipe(value, host);
    const archive = await acquirePerlVendorArchive(validated.supplier!, cache, 'bootstrap_only', async () => new Response(bytes));
    expect(path.basename(archive)).toBe(value.supplier.archive.sha256 + '.tar.bz2');
    const wrong = structuredClone(value);
    wrong.supplier.files[0].source = 'bin/perl.exe';
    expect(() => validatePerlVendorRecipe(wrong, host)).toThrow('INVENTORY_INVALID');
    expect(() => validatePerlVendorRecipe({ ...value, supplier: undefined }, host)).toThrow();
  });
  it('has no offline network fallback and removes incomplete downloads', async () => {
    const cache = await mkdtemp(path.join(os.tmpdir(), 'ud-vendor-')); roots.push(cache); const value = validatePerlVendorRecipe(recipe(), { platform: 'win32', arch: 'arm64' }); let downloads = 0;
    const fetcher: typeof fetch = async () => { downloads++; return new Response('wrong'); };
    await expect(acquirePerlVendorArchive(value, cache, 'offline', fetcher)).rejects.toThrow('OFFLINE_CACHE_MISS'); expect(downloads).toBe(0);
    await expect(acquirePerlVendorArchive(value, cache, 'bootstrap_only', fetcher)).rejects.toThrow('INTEGRITY_FAILED'); expect(await readdir(cache)).toEqual([]);
  });
  it('bounds fetch and body cancellation and leaves no unadmitted bytes', async () => {
    const cache = await mkdtemp(path.join(os.tmpdir(), 'ud-vendor-')); roots.push(cache); const staging = await mkdtemp(path.join(os.tmpdir(), 'ud-vendor-stage-')); roots.push(staging); const value = validatePerlVendorRecipe(recipe(), { platform: 'win32', arch: 'arm64' }); let downloads = 0;
    const before = new AbortController(); before.abort();
    await expect(acquirePerlVendorArchive(value, cache, 'bootstrap_only', async () => { downloads++; return new Response(); }, { signal: before.signal, temporaryRoot: staging })).rejects.toThrow(); expect(downloads).toBe(0);
    await expect(acquirePerlVendorArchive(value, cache, 'bootstrap_only', async () => new Promise(() => {}), { timeoutMs: 15, temporaryRoot: staging })).rejects.toThrow('TIMEOUT');
    const during = new AbortController(); let started!: () => void; const barrier = new Promise<void>(resolve => { started = resolve; });
    const fetcher: typeof fetch = async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array([1])); started(); } }));
    const pending = acquirePerlVendorArchive(value, cache, 'bootstrap_only', fetcher, { signal: during.signal, temporaryRoot: staging }); await barrier; during.abort(); await expect(pending).rejects.toThrow('CANCELLED');
    expect(await readdir(cache)).toEqual([]); expect(await readdir(staging)).toEqual([]);
  });
});
