import { createHash, randomUUID } from 'node:crypto';
import { link, lstat, mkdir, open, rm } from 'node:fs/promises';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import type { Host } from './profiles.js';

export type UvDownload = { url: string; sha256: string; size: number };
export type UvVendorDownload = UvDownload & { executable: { sha256: string; size: number; offset: number; compressed_size: number } };
export type ManagedPythonDownload = UvDownload & { version: string; release: string; filename: string; os: 'macos' | 'linux' | 'windows'; arch: 'aarch64' | 'x86_64'; libc: 'none' | 'gnu' };
const RELEASE = /^https:\/\/github\.com\/mehmetoguzderin\/ud-agent-skill-mcp-plugin\/releases\/download\/v0\.1\.0-beta\.1\/uv-(?:darwin|linux|win32)-(?:arm64|x64)(?:\.exe)?$/;
const REDIRECT_HOSTS = new Set(['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
const EDGE_REDIRECT_HOSTS = new Set(['msedge.sf.dl.delivery.mp.microsoft.com', 'msedge.sf.tlu.dl.delivery.mp.microsoft.com', 'msedge.f.dl.delivery.mp.microsoft.com']);
const GOOGLE_BROWSER_HOSTS = new Set(['storage.googleapis.com']);

/** Only unavailable network/HTTP errors permit the caller to use system Python. */
export class UvAcquisitionUnavailable extends Error {}

export function validateUvDownload(record: unknown): UvDownload {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Invalid uv download receipt.');
  const data = record as Record<string, unknown>;
  if (Object.keys(data).sort().join(',') !== 'sha256,size,url' || typeof data.url !== 'string' || !RELEASE.test(data.url) || typeof data.sha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(data.sha256) || !Number.isSafeInteger(data.size) || (data.size as number) < 1 || (data.size as number) > 128 * 1024 * 1024) throw new Error('Invalid uv download receipt.');
  return { url: data.url, sha256: data.sha256, size: data.size as number };
}

/** The build records one exact deflate member in a verified Astral archive. */
export function validateUvVendorDownload(input: unknown, host: Host): UvVendorDownload {
  const triple = host.platform === 'win32' && (host.arch === 'arm64' ? 'aarch64' : host.arch === 'x64' ? 'x86_64' : undefined);
  const archive = input as UvVendorDownload | undefined;
  if (!triple || !archive || typeof archive !== 'object' || Object.keys(archive).sort().join(',') !== 'executable,sha256,size,url' || typeof archive.url !== 'string') throw new Error('Invalid vendor uv receipt.');
  const url = new RegExp(`^https://github\\.com/astral-sh/uv/releases/download/[0-9]+\\.[0-9]+\\.[0-9]+/uv-${triple}-pc-windows-msvc\\.zip$`);
  const hex = /^sha256:[0-9a-f]{64}$/;
  const validSize = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 32 * 1024 * 1024;
  const exe = archive.executable;
  if (!url.test(archive.url) || typeof archive.sha256 !== 'string' || !hex.test(archive.sha256) || !validSize(archive.size) || !exe || typeof exe !== 'object' || Object.keys(exe).sort().join(',') !== 'compressed_size,offset,sha256,size' || typeof exe.sha256 !== 'string' || !hex.test(exe.sha256) || !validSize(exe.size) || !validSize(exe.offset) || !validSize(exe.compressed_size) || exe.offset + exe.compressed_size > archive.size) throw new Error('Invalid vendor uv receipt.');
  return archive;
}

/** Accept only a pinned CPython standalone release for the selected host. */
export function validateManagedPythonDownload(record: unknown, host: Host): ManagedPythonDownload {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Invalid managed Python receipt.');
  const data = record as Record<string, unknown>;
  if (Object.keys(data).sort().join(',') !== 'sha256,size,url,version' || typeof data.version !== 'string' || !/^3\.(?:14|15)\.\d+$/.test(data.version) || typeof data.url !== 'string' || typeof data.sha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(data.sha256) || !Number.isSafeInteger(data.size) || (data.size as number) < 1 || (data.size as number) > 512 * 1024 * 1024) throw new Error('Invalid managed Python receipt.');
  const parsed = new URL(data.url);
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com' || parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.port && parsed.port !== '443')) throw new Error('Untrusted managed Python source.');
  const match = /^\/astral-sh\/python-build-standalone\/releases\/download\/(\d{8})\/([^/]+)$/.exec(parsed.pathname);
  if (!match?.[1] || !match[2]) throw new Error('Untrusted managed Python source.');
  const filename = decodeURIComponent(match[2]);
  const arch = host.arch === 'arm64' ? 'aarch64' : host.arch === 'x64' ? 'x86_64' : undefined;
  const triple = host.platform === 'darwin' ? 'apple-darwin' : host.platform === 'linux' ? 'unknown-linux-gnu' : host.platform === 'win32' ? 'pc-windows-msvc' : undefined;
  const os = host.platform === 'darwin' ? 'macos' : host.platform === 'linux' ? 'linux' : host.platform === 'win32' ? 'windows' : undefined;
  if (!arch || !triple || !os || ![ `cpython-${data.version}+${match[1]}-${arch}-${triple}-install_only.tar.gz`, `cpython-${data.version}+${match[1]}-${arch}-${triple}-install_only_stripped.tar.gz` ].includes(filename)) throw new Error('Managed Python receipt targets a different host or version.');
  return { url: data.url, sha256: data.sha256, size: data.size as number, version: data.version, release: match[1], filename, os, arch, libc: host.platform === 'linux' ? 'gnu' : 'none' };
}

async function privateDirectory(dir: string): Promise<void> {
  try { await mkdir(dir, { mode: 0o700 }); } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  const directory = await lstat(dir);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (process.platform !== 'win32' && ((directory.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && directory.uid !== process.getuid())))) throw new Error('Userspace download cache is not private and user-owned.');
}

/** Download the exact product-locked raw uv asset into product-owned storage. */
export async function acquireVerifiedUv(record: UvDownload, stateRoot: string, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  const expected = validateUvDownload(record);
  if (!path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('Invalid uv acquisition request.');
  const tools = path.join(stateRoot, 'tools');
  await privateDirectory(tools);
  const target = path.join(tools, `uv-${expected.sha256.slice(7)}${process.platform === 'win32' ? '.exe' : ''}`);
  return acquireAsset(expected, target, network, fetcher, true);
}

/** Acquire a Windows uv archive from Astral and publish only its exact uv.exe. */
export async function acquireVendorUv(record: UvVendorDownload, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  const expected = validateUvVendorDownload(record, host);
  if (!path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('Invalid uv acquisition request.');
  const tools = path.join(stateRoot, 'tools');
  await privateDirectory(tools);
  const member = expected.executable;
  const target = path.join(tools, `uv-${member.sha256.slice(7)}.exe`);
  const verifyExecutable = async () => {
    const bytes = await readBoundedReceiptBytes(target, member.size);
    if (bytes.length !== member.size || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== member.sha256) throw new Error('Cached vendor uv executable does not match its receipt.');
  };
  try {
    await verifyExecutable();
    return target;
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const archive = await acquireAsset(expected, path.join(tools, `uv-${expected.sha256.slice(7)}.zip`), network, fetcher, false);
  if (!archive) return undefined;
  const payload = await readBoundedReceiptBytes(archive, expected.size);
  if (payload.length !== expected.size || `sha256:${createHash('sha256').update(payload).digest('hex')}` !== expected.sha256) throw new Error('Cached vendor uv archive does not match its receipt.');
  const binary = inflateRawSync(payload.subarray(member.offset, member.offset + member.compressed_size), { maxOutputLength: member.size });
  if (binary.length !== member.size || `sha256:${createHash('sha256').update(binary).digest('hex')}` !== member.sha256) throw new Error('Vendor uv executable does not match its receipt.');
  const temporary = path.join(tools, `.uv-${randomUUID()}.tmp`);
  try {
    const output = await open(temporary, 'wx', 0o700);
    try { await output.writeFile(binary); await output.sync(); } finally { await output.close(); }
    try { await link(temporary, target); }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; await verifyExecutable(); }
    return target;
  } finally { await rm(temporary, { force: true }); }
}

/** Lazy render packs use the same bounded, hash-verified acquisition path. */
export async function acquireRenderArchive(record: UvDownload, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  if (record.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-render-${host.platform}-${host.arch}.tar.gz` || !/^sha256:[0-9a-f]{64}$/.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 2 * 1024 ** 3 || !path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('Invalid render download receipt.');
  const cache = path.join(stateRoot, 'render-cache'); await privateDirectory(cache);
  return acquireAsset(record, path.join(cache, `${record.sha256.slice(7)}.tar.gz`), network, fetcher, false);
}

/** Selected-host core packs use the same verified, bounded release transport. */
export async function acquireCoreArchive(record: UvDownload, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  if (record.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-userspace-${host.platform}-${host.arch}.tar.gz` || !/^sha256:[0-9a-f]{64}$/.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 2 * 1024 ** 3 || !path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('Invalid core download receipt.');
  const cache = path.join(stateRoot, 'core-cache'); await privateDirectory(cache);
  return acquireAsset(record, path.join(cache, `${record.sha256.slice(7)}.tar.gz`), network, fetcher, false);
}

/** Only the selected platform/provider's closed release asset pack is acquired. */
export async function acquireProviderArchive(record: UvDownload, stateRoot: string, engine: 'apple-container' | 'lima-nerdctl' | 'wslc', host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  if (record.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-provider-${engine}-${host.platform}-${host.arch}.tar.gz` || !/^sha256:[0-9a-f]{64}$/.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 4 * 1024 ** 3 || !path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('PROVIDER_ASSET_DOWNLOAD_RECEIPT_INVALID');
  const cache = path.join(stateRoot, 'provider-cache'); await privateDirectory(cache);
  return acquireAsset(record, path.join(cache, `${record.sha256.slice(7)}.tar.gz`), network, fetcher, false);
}

/** Vendor browser bytes stay vendor-acquired; the published pack carries its recipe. */
export async function acquireMicrosoftEdgeMsi(record: UvDownload, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  if (host.platform !== 'win32' || host.arch !== 'arm64' || !/^https:\/\/msedge\.sf\.dl\.delivery\.mp\.microsoft\.com\/filestreamingservice\/files\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/MicrosoftEdgeEnterpriseARM64\.msi$/.test(record.url) || !/^sha256:[0-9a-f]{64}$/.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 512 * 1024 ** 2 || !path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('USERSPACE_RENDER_VENDOR_RECEIPT_INVALID');
  const cache = path.join(stateRoot, 'render-vendor-cache'); await privateDirectory(cache);
  try { return await acquireAsset(record, path.join(cache, `${record.sha256.slice(7)}.msi`), network, fetcher, false, EDGE_REDIRECT_HOSTS); }
  catch (error) { if (error instanceof UvAcquisitionUnavailable) throw new Error('USERSPACE_RENDER_VENDOR_DOWNLOAD_UNAVAILABLE', { cause: error }); throw error; }
}

/** Google supplies the browser archive directly; product packs carry its recipe. */
export async function acquireGoogleBrowserArchive(record: UvDownload, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<string | undefined> {
  const platform = ({ 'darwin/arm64': 'mac-arm64', 'darwin/x64': 'mac-x64', 'linux/arm64': 'linux-arm64', 'linux/x64': 'linux64', 'win32/x64': 'win64' } as Record<string, string>)[`${host.platform}/${host.arch}`];
  const pattern = platform && new RegExp(`^https://storage\\.googleapis\\.com/chrome-for-testing-public/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/${platform}/chrome-headless-shell-${platform}\\.zip$`);
  if (!pattern || !pattern.test(record.url) || !/^sha256:[0-9a-f]{64}$/.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 512 * 1024 ** 2 || !path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('USERSPACE_RENDER_VENDOR_RECEIPT_INVALID');
  const cache = path.join(stateRoot, 'render-vendor-cache'); await privateDirectory(cache);
  try { return await acquireAsset(record, path.join(cache, `${record.sha256.slice(7)}.zip`), network, fetcher, false, GOOGLE_BROWSER_HOSTS); }
  catch (error) { if (error instanceof UvAcquisitionUnavailable) throw new Error('USERSPACE_RENDER_VENDOR_DOWNLOAD_UNAVAILABLE', { cause: error }); throw error; }
}

/** Cache a frozen standalone Python archive at the layout expected by uv's local mirror. */
export async function acquireManagedPythonArchive(record: unknown, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch = fetch): Promise<{ archive: string; mirror: string; receipt: ManagedPythonDownload } | undefined> {
  const receipt = validateManagedPythonDownload(record, host);
  if (!path.isAbsolute(stateRoot) || !['bootstrap_only', 'offline'].includes(network)) throw new Error('Invalid Python acquisition request.');
  const mirror = path.join(stateRoot, 'python-mirror'); await privateDirectory(mirror);
  const release = path.join(mirror, receipt.release); await privateDirectory(release);
  const archive = await acquireAsset(receipt, path.join(release, receipt.filename), network, fetcher, false);
  return archive ? { archive, mirror, receipt } : undefined;
}

async function acquireAsset(expected: UvDownload, target: string, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch, executable: boolean, redirectHosts: ReadonlySet<string> = REDIRECT_HOSTS): Promise<string | undefined> {
  try {
    const existing = await lstat(target);
    if (!existing.isFile() || existing.isSymbolicLink() || existing.size !== expected.size || (executable && process.platform !== 'win32' && (existing.mode & 0o111) === 0)) throw new Error('Cached asset does not match its receipt.');
    await verifyArchive(target, expected.sha256);
    return target;
  } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  if (network === 'offline') return undefined;
  let url = expected.url;
  let response: Response | undefined;
  for (let count = 0; count < 5; count++) {
    try { response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(Math.min(600_000, Math.max(20_000, Math.ceil(expected.size / (1024 * 1024)) * 1000 + 10_000))) }); }
    catch (error) { if (error instanceof Error && error.name === 'AbortError') throw error; throw new UvAcquisitionUnavailable('The pinned asset download is unavailable.'); }
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    const location = response.headers.get('location');
    await response.body?.cancel();
    if (!location) throw new Error('Invalid uv download redirect.');
    const next = new URL(location, url);
    if (next.protocol !== 'https:' || !redirectHosts.has(next.hostname) || next.username || next.password || (next.port && next.port !== '443')) throw new Error('Untrusted uv download redirect.');
    url = next.href; response = undefined;
  }
  if (!response) throw new Error('Too many uv download redirects.');
  if (!response.ok || !response.body) { await response.body?.cancel(); throw new UvAcquisitionUnavailable('The pinned asset download is unavailable.'); }
  const declared = response.headers.get('content-length');
  if (declared !== null && declared !== String(expected.size)) { await response.body.cancel(); throw new Error('Downloaded asset exceeds its receipt size.'); }
  const temporary = path.join(path.dirname(target), `.download-${randomUUID()}.tmp`);
  try {
    const out = await open(temporary, 'wx', executable ? 0o700 : 0o600);
    try {
      const digest = createHash('sha256'); let size = 0;
      for await (const chunk of response.body) {
        const bytes = Buffer.from(chunk); size += bytes.length;
        if (size > expected.size) throw new Error('Downloaded asset exceeds its receipt size.');
        digest.update(bytes);
        let offset = 0;
        while (offset < bytes.length) { const result = await out.write(bytes, offset, bytes.length - offset); if (!result.bytesWritten) throw new Error('Writing uv download failed.'); offset += result.bytesWritten; }
      }
      if (size !== expected.size || `sha256:${digest.digest('hex')}` !== expected.sha256) throw new Error('Downloaded asset does not match its receipt.');
      await out.sync();
    } finally { await out.close(); }
    // The target is content-addressed; if another setup won the race, verify
    // its bytes instead of overwriting them.
    try { await link(temporary, target); }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; await verifyArchive(target, expected.sha256); }
    return target;
  } finally { await rm(temporary, { force: true }); }
}
