/** A vendor dependency is acquired privately, never redistributed or installed globally. */
import { createHash, randomUUID } from 'node:crypto';
import { link, lstat, open, rm } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from './profiles.js';
import { verifyArchive } from './receipt.js';
import { portablePathKey, validPortablePath } from '../../workspace/src/portable-path.js';

type File = { source: string; path: string; sha256: string; size_bytes: number };
type Archive = { url: string; sha256: string; size_bytes: number };
export type PerlVendorRecipe = { schema_version: 1; provider: 'conda-vc-runtime'; platform: string; executable: 'bin/perl.exe'; archive: Archive; base_files: File[]; files: File[]; supplier?: { archive: Archive; files: File[] } };
const bareHash = /^[a-f0-9]{64}$/;
function relative(value: unknown): value is string { return typeof value === 'string' && value.length <= 4096 && validPortablePath(value); }
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('USERSPACE_PERL_VENDOR_RECIPE_INVALID'); return value as Record<string, unknown>; }
function validArchive(archive: Record<string, unknown>, authority: RegExp): boolean {
  return typeof archive.url === 'string' && authority.test(archive.url) && typeof archive.sha256 === 'string' && bareHash.test(archive.sha256) &&
    Number.isSafeInteger(archive.size_bytes) && (archive.size_bytes as number) > 0 && (archive.size_bytes as number) <= 32 * 1024 ** 2;
}
export function validatePerlVendorRecipe(value: unknown, host: Host): PerlVendorRecipe {
  const item = object(value), archive = object(item.archive);
  const supplier = item.supplier === undefined ? undefined : object(item.supplier);
  if (host.platform !== 'win32' || !['arm64', 'x64'].includes(host.arch) || item.schema_version !== 1 || item.provider !== 'conda-vc-runtime' || item.platform !== `${host.platform}/${host.arch}` || item.executable !== 'bin/perl.exe' || !Array.isArray(item.files) || !Array.isArray(item.base_files) || item.files.length < 1 || item.files.length > 32 || item.base_files.length < 1 || item.base_files.length > (supplier ? 5000 : 32)) throw new Error('USERSPACE_PERL_VENDOR_RECIPE_INVALID');
  const architecture = host.arch === 'arm64' ? 'win-arm64' : 'win-64';
  if (!validArchive(archive, new RegExp(`^https://conda\\.anaconda\\.org/conda-forge/${architecture}/vc14_runtime-[A-Za-z0-9_.-]+\\.conda$`))) throw new Error('USERSPACE_PERL_VENDOR_AUTHORITY_INVALID');
  const supplierFiles = supplier?.files ?? [];
  const supplierAuthority = host.arch === 'arm64'
    ? /^https:\/\/conda\.anaconda\.org\/anaconda\/win-arm64\/perl-[A-Za-z0-9_.-]+\.tar\.bz2$/
    : /^https:\/\/conda\.anaconda\.org\/conda-forge\/win-64\/perl-[A-Za-z0-9_.-]+\.conda$/;
  if (!Array.isArray(supplierFiles) || supplier && (supplierFiles.length < 1 || supplierFiles.length > 256 || !validArchive(object(supplier.archive), supplierAuthority))) throw new Error('USERSPACE_PERL_SUPPLIER_AUTHORITY_INVALID');
  const seen = new Set<string>();
  for (const [kind, rows] of [['base', item.base_files], ['vendor', item.files], ['supplier', supplierFiles]] as const) for (const value of rows) {
    const row = object(value);
    if (!relative(row.source) || !relative(row.path) || typeof row.sha256 !== 'string' || !bareHash.test(row.sha256) || !Number.isSafeInteger(row.size_bytes) || (row.size_bytes as number) < 0 || (row.size_bytes as number) > 32 * 1024 ** 2 || seen.has(portablePathKey(row.path))) throw new Error('USERSPACE_PERL_VENDOR_INVENTORY_INVALID');
    const validDestination = kind === 'base'
      ? (supplier ? row.source === row.path && /^(?:bin|lib)\//.test(row.path) : /^bin\/[^/]+\.(?:exe|dll)$/.test(row.path))
      : kind === 'vendor'
        ? /^bin\/vcruntime[0-9_a-z]*\.dll$/i.test(row.path) || row.path.startsWith('licenses/vendor/')
        : /^(?:bin|lib)\/.+\.(?:exe|dll)$/i.test(row.path) && row.source === (host.arch === 'arm64' ? 'Library/' : '') + row.path;
    if (!validDestination) throw new Error('USERSPACE_PERL_VENDOR_INVENTORY_INVALID');
    seen.add(portablePathKey(row.path));
  }
  if (!(supplier ? supplierFiles : item.base_files).some(value => object(value).path === item.executable)) throw new Error('USERSPACE_PERL_VENDOR_EXECUTABLE_MISSING');
  return item as unknown as PerlVendorRecipe;
}

export async function acquirePerlVendorArchive(recipe: { archive: Archive }, cache: string, network: 'offline' | 'bootstrap_only', fetcher: typeof fetch = fetch, options: { signal?: AbortSignal; temporaryRoot?: string; timeoutMs?: number } = {}): Promise<string> {
  const timeout = options.timeoutMs ?? 120000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 600000) throw new Error('USERSPACE_PERL_VENDOR_TIMEOUT_INVALID');
  options.signal?.throwIfAborted();
  const descriptor = recipe.archive;
  const file = path.join(cache, descriptor.sha256 + (descriptor.url.endsWith('.tar.bz2') ? '.tar.bz2' : '.conda'));
  const verify = async () => { const info = await lstat(file); if (!info.isFile() || info.isSymbolicLink() || info.size !== descriptor.size_bytes) throw new Error('USERSPACE_PERL_VENDOR_INTEGRITY_FAILED'); await verifyArchive(file, `sha256:${descriptor.sha256}`, options.signal); };
  try { await lstat(file); await verify(); return file; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  if (network === 'offline') throw new Error('USERSPACE_PERL_VENDOR_OFFLINE_CACHE_MISS');
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout);
  let abortListener: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => { abortListener = () => reject(new Error(options.signal?.aborted ? 'USERSPACE_SETUP_CANCELLED' : 'USERSPACE_PERL_VENDOR_TIMEOUT')); signal.addEventListener('abort', abortListener, { once: true }); if (signal.aborted) abortListener(); });
  try {
  const response = await Promise.race([fetcher(descriptor.url, { redirect: 'error', signal }), aborted]);
  if (response.status !== 200 || !response.body || response.headers.get('content-length') !== null && Number(response.headers.get('content-length')) !== descriptor.size_bytes) throw new Error('USERSPACE_PERL_VENDOR_DOWNLOAD_FAILED');
  // Setup supplies its journal-owned environment as the temporary root. A
  // killed download then belongs to existing orphan-environment recovery;
  // the reusable cache contains only fully verified content-addressed files.
  const temporary = path.join(options.temporaryRoot ?? cache, '.vendor-' + randomUUID()), handle = await open(temporary, 'wx', 0o600); let size = 0; const digest = createHash('sha256');
  const reader = response.body.getReader();
  try {
    try { for (;;) { const chunk = await Promise.race([reader.read(), aborted]); if (chunk.done) break; size += chunk.value.byteLength; if (size > descriptor.size_bytes) throw new Error('USERSPACE_PERL_VENDOR_INTEGRITY_FAILED'); digest.update(chunk.value); await handle.writeFile(chunk.value); } signal.throwIfAborted(); await handle.sync(); } finally { await handle.close(); void reader.cancel().catch(() => {}); }
    if (size !== descriptor.size_bytes || digest.digest('hex') !== descriptor.sha256) throw new Error('USERSPACE_PERL_VENDOR_INTEGRITY_FAILED');
    try { await link(temporary, file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    await verify(); return file;
  } finally { await rm(temporary, { force: true }); }
  } finally { if (abortListener) signal.removeEventListener('abort', abortListener); }
}
