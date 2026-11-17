import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { acquireGoogleBrowserArchive, acquireManagedPythonArchive, acquireMicrosoftEdgeMsi, acquireVendorUv, acquireVerifiedUv, UvAcquisitionUnavailable, validateManagedPythonDownload, validateUvDownload } from '../../packages/runtime-manager/src/userspace-download.js';

const content = 'authentic-uv-fixture';
const receipt = { url: 'https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/uv-darwin-arm64', sha256: `sha256:${createHash('sha256').update(content).digest('hex')}`, size: Buffer.byteLength(content) };

describe('product-owned uv acquisition', () => {
  it('acquires one Windows uv member from verified vendor bytes and reuses it offline', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-vendor-uv-test-'));
    const host = { platform: 'win32', arch: 'arm64' } as const;
    const prefix = Buffer.from('zip header');
    const compressed = deflateRawSync(content);
    const archive = Buffer.concat([prefix, compressed]);
    const descriptor = {
      ...receipt,
      url: 'https://github.com/astral-sh/uv/releases/download/0.13.7/uv-aarch64-pc-windows-msvc.zip',
      sha256: `sha256:${createHash('sha256').update(archive).digest('hex')}`,
      size: archive.length,
      executable: { sha256: receipt.sha256, size: receipt.size, offset: prefix.length, compressed_size: compressed.length },
    };
    let calls = 0;
    const fetcher = async () => { calls++; return new Response(new Uint8Array(archive)); };
    try {
      await expect(acquireVendorUv(descriptor, state, { ...host, arch: 'x64' }, 'bootstrap_only', fetcher)).rejects.toThrow('receipt');
      expect(await acquireVendorUv(descriptor, state, host, 'offline', fetcher)).toBeUndefined();
      expect(calls).toBe(0);
      const wrong = { ...descriptor, executable: { ...descriptor.executable, sha256: 'sha256:' + '0'.repeat(64) } };
      await expect(acquireVendorUv(wrong, state, host, 'bootstrap_only', fetcher)).rejects.toThrow('executable does not match');
      const file = await acquireVendorUv(descriptor, state, host, 'offline', fetcher);
      expect(await readFile(file!, 'utf8')).toBe(content);
      expect(calls).toBe(1);
      await writeFile(file!, 'different');
      await expect(acquireVendorUv(descriptor, state, host, 'offline', fetcher)).rejects.toThrow();
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('does not download offline, then verifies and reuses exact cached bytes', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-uv-test-')); let calls = 0;
    const fetcher = async () => { calls++; return new Response(content, { status: 200 }); };
    try {
      expect(await acquireVerifiedUv(receipt, state, 'offline', fetcher as typeof fetch)).toBeUndefined(); expect(calls).toBe(0);
      const file = await acquireVerifiedUv(receipt, state, 'bootstrap_only', fetcher as typeof fetch);
      expect(file).toBeDefined(); expect(await readFile(file!, 'utf8')).toBe(content); expect(calls).toBe(1);
      expect(await acquireVerifiedUv(receipt, state, 'offline', fetcher as typeof fetch)).toBe(file); expect(calls).toBe(1);
      await writeFile(file!, 'different');
      await expect(acquireVerifiedUv(receipt, state, 'bootstrap_only', fetcher as typeof fetch)).rejects.toThrow();
      expect(calls).toBe(1);
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('rejects corrupted downloads and untrusted redirects without retaining files', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-uv-test-'));
    try {
      await expect(acquireVerifiedUv(receipt, state, 'bootstrap_only', (async () => new Response('bad', { status: 200 })) as typeof fetch)).rejects.toThrow('receipt');
      expect(await readdir(path.join(state, 'tools'))).toEqual([]);
      const redirect = async () => new Response(null, { status: 302, headers: { location: 'https://attacker.example/uv' } });
      await expect(acquireVerifiedUv(receipt, state, 'bootstrap_only', redirect as typeof fetch)).rejects.toThrow('Untrusted');
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('distinguishes unavailable network from untrusted receipts', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-uv-test-'));
    try {
      await expect(acquireVerifiedUv(receipt, state, 'bootstrap_only', (async () => { throw new TypeError('offline'); }) as typeof fetch)).rejects.toBeInstanceOf(UvAcquisitionUnavailable);
      expect(() => validateUvDownload({ ...receipt, url: 'https://attacker.example/uv' })).toThrow('receipt');
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('verifies a pinned Python archive before putting it in the local uv mirror', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-python-test-'));
    const host = { platform: 'darwin', arch: 'arm64' } as const;
    const record = { url: 'https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10%2B20261026-aarch64-apple-darwin-install_only_stripped.tar.gz', version: '3.14.10', sha256: hashContent(), size: Buffer.byteLength(content) };
    try {
      const fetcher = async () => new Response(content, { status: 200 });
      expect(await acquireManagedPythonArchive(record, state, host, 'offline', fetcher as typeof fetch)).toBeUndefined();
      const archive = await acquireManagedPythonArchive(record, state, host, 'bootstrap_only', fetcher as typeof fetch);
      expect(archive?.receipt.version).toBe('3.14.10');
      expect(await readFile(archive!.archive, 'utf8')).toBe(content);
      expect((await acquireManagedPythonArchive(record, state, host, 'offline', fetcher as typeof fetch))?.archive).toBe(archive?.archive);
      await writeFile(archive!.archive, 'corrupt');
      await expect(acquireManagedPythonArchive(record, state, host, 'offline', fetcher as typeof fetch)).rejects.toThrow();
      expect(() => validateManagedPythonDownload(record, { platform: 'linux', arch: 'arm64' })).toThrow('different host');
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('acquires vendor browser bytes only for native Windows ARM64 and reuses them offline', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-edge-test-'));
    const edge = { ...receipt, url: 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/12345678-1234-1234-1234-123456789abc/MicrosoftEdgeEnterpriseARM64.msi' };
    const host = { platform: 'win32', arch: 'arm64' } as const; let calls = 0;
    const fetcher = async () => { calls++; return new Response(content, { status: 200, headers: { 'content-length': String(edge.size) } }); };
    try {
      expect(await acquireMicrosoftEdgeMsi(edge, state, host, 'offline', fetcher as typeof fetch)).toBeUndefined();
      const file = await acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', fetcher as typeof fetch);
      expect(await readFile(file!, 'utf8')).toBe(content);
      expect(await acquireMicrosoftEdgeMsi(edge, state, host, 'offline', fetcher as typeof fetch)).toBe(file); expect(calls).toBe(1);
      await writeFile(file!, 'corrupt');
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', fetcher as typeof fetch)).rejects.toThrow('receipt'); expect(calls).toBe(1);
      await expect(acquireMicrosoftEdgeMsi(edge, state, { platform: 'win32', arch: 'x64' }, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
      await expect(acquireMicrosoftEdgeMsi({ ...edge, url: edge.url.replace('msedge.sf.dl.delivery.mp.microsoft.com', 'attacker.example') }, state, host, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('rejects vendor corruption and foreign redirects, and preserves cancellation', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-edge-test-'));
    const edge = { ...receipt, url: 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/12345678-1234-1234-1234-123456789abc/MicrosoftEdgeEnterpriseARM64.msi' };
    const host = { platform: 'win32', arch: 'arm64' } as const;
    try {
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', (async () => new Response('bad', { status: 200 })) as typeof fetch)).rejects.toThrow('receipt');
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', (async () => new Response(content, { status: 200, headers: { 'content-length': '999' } })) as typeof fetch)).rejects.toThrow('size');
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', (async () => new Response(null, { status: 302, headers: { location: 'https://github.com/file' } })) as typeof fetch)).rejects.toThrow('Untrusted');
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', (async () => { throw new DOMException('cancelled', 'AbortError'); }) as typeof fetch)).rejects.toMatchObject({ name: 'AbortError' });
      await expect(acquireMicrosoftEdgeMsi(edge, state, host, 'bootstrap_only', (async () => new Response('missing', { status: 404 })) as typeof fetch)).rejects.toThrow('VENDOR_DOWNLOAD_UNAVAILABLE');
      expect(await readdir(path.join(state, 'render-vendor-cache'))).toEqual([]);
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it.each([
    ['darwin', 'arm64', 'mac-arm64'], ['darwin', 'x64', 'mac-x64'], ['linux', 'arm64', 'linux-arm64'], ['linux', 'x64', 'linux64'], ['win32', 'x64', 'win64'],
  ] as const)('acquires only the frozen native Google browser for %s/%s', async (platform, arch, vendorPlatform) => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-google-browser-'));
    const browser = { ...receipt, url: `https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.38/${vendorPlatform}/chrome-headless-shell-${vendorPlatform}.zip` }; let calls = 0;
    const fetcher = async () => { calls++; return new Response(content, { status: 200 }); };
    try {
      expect(await acquireGoogleBrowserArchive(browser, state, { platform, arch }, 'offline', fetcher as typeof fetch)).toBeUndefined(); expect(calls).toBe(0);
      const file = await acquireGoogleBrowserArchive(browser, state, { platform, arch }, 'bootstrap_only', fetcher as typeof fetch);
      expect(await readFile(file!, 'utf8')).toBe(content); expect(await acquireGoogleBrowserArchive(browser, state, { platform, arch }, 'offline', fetcher as typeof fetch)).toBe(file); expect(calls).toBe(1);
      await writeFile(file!, 'corrupt');
      await expect(acquireGoogleBrowserArchive(browser, state, { platform, arch }, 'bootstrap_only', fetcher as typeof fetch)).rejects.toThrow('receipt'); expect(calls).toBe(1);
    } finally { await rm(state, { recursive: true, force: true }); }
  });

  it('rejects foreign Google browser sources, wrong architectures and failed integrity without retaining a download', async () => {
    const state = await mkdtemp(path.join(os.tmpdir(), 'ud-google-browser-invalid-'));
    const browser = { ...receipt, url: 'https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.38/mac-arm64/chrome-headless-shell-mac-arm64.zip' }, host = { platform: 'darwin', arch: 'arm64' } as const;
    try {
      await expect(acquireGoogleBrowserArchive(browser, state, { platform: 'win32', arch: 'arm64' }, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
      await expect(acquireGoogleBrowserArchive(browser, state, { platform: 'darwin', arch: 'x64' }, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
      await expect(acquireGoogleBrowserArchive({ ...browser, url: browser.url + '?alternate=unlocked' }, state, host, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
      await expect(acquireGoogleBrowserArchive({ ...browser, url: browser.url.replace('storage.googleapis.com', 'attacker.example') }, state, host, 'offline')).rejects.toThrow('VENDOR_RECEIPT_INVALID');
      await expect(acquireGoogleBrowserArchive(browser, state, host, 'bootstrap_only', (async () => new Response(content + 'extra')) as typeof fetch)).rejects.toThrow('size');
      await expect(acquireGoogleBrowserArchive(browser, state, host, 'bootstrap_only', (async () => new Response(null, { status: 302, headers: { location: 'https://github.com/foreign.zip' } })) as typeof fetch)).rejects.toThrow('Untrusted');
      await expect(acquireGoogleBrowserArchive(browser, state, host, 'bootstrap_only', (async () => new Response('absent', { status: 404 })) as typeof fetch)).rejects.toThrow('VENDOR_DOWNLOAD_UNAVAILABLE');
      expect(await readdir(path.join(state, 'render-vendor-cache'))).toEqual([]);
    } finally { await rm(state, { recursive: true, force: true }); }
  });
});

function hashContent(): string { return `sha256:${createHash('sha256').update(content).digest('hex')}`; }
