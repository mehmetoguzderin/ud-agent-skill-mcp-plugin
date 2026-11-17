import { describe, expect, it } from 'vitest';
import { validateProviderReceipt } from '../../packages/runtime-manager/src/provider-receipt.js';

const sha = `sha256:${'a'.repeat(64)}`;
const base = { schema_version: 1, executable_sha256: sha };
const lima = { ...base, instance: 'ud-agent', nerdctl: '/usr/bin/nerdctl', nerdctl_sha256: sha, containerd: '/usr/bin/containerd', containerd_sha256: sha, address: '/run/user/1000/containerd.sock', guest_uid: 1000, guest_home: '/home/user', architecture: 'amd64' };
describe('versioned provider receipts', () => {
  it('binds dedicated provider schemas and optional owned offline Lima provisioning', () => {
    expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, lima)).not.toThrow();
    expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, { ...lima, ctr: '/usr/local/bin/ctr', ctr_sha256: sha })).not.toThrow();
    expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, { ...lima, nsenter: '/usr/bin/nsenter', nsenter_sha256: sha })).not.toThrow();
    for (const fields of [{ nsenter: '/usr/bin/nsenter' }, { nsenter_sha256: sha }, { nsenter: '../nsenter', nsenter_sha256: sha }, { nsenter: '/usr/bin/nsenter', nsenter_sha256: 'invalid' }]) expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, { ...lima, ...fields })).toThrow('PROVIDER_RECEIPT');
    for (const fields of [{ ctr: '/usr/local/bin/ctr' }, { ctr_sha256: sha }, { ctr: '../ctr', ctr_sha256: sha }, { ctr: '/usr/local/bin/ctr', ctr_sha256: 'invalid' }]) expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, { ...lima, ...fields })).toThrow('PROVIDER_RECEIPT');
    const provisioning = { template_path: 'runtime/lima.yaml', template_sha256: sha, offline_ready: true, assets: [{ key: 'guest', path: 'runtime/guest.img', sha256: sha, size_bytes: 1024 }] };
    expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, { ...lima, provisioning })).not.toThrow();
    for (const changed of [{ ...lima, guest_uid: 0 }, { ...lima, nerdctl: '/../host' }, { ...lima, guest_home: 'relative' }, { ...lima, instance: '--bad' }, { ...lima, architecture: 'arm64' }, { ...lima, provisioning: { ...provisioning, assets: [{ ...provisioning.assets[0], path: '../escape' }] } }]) expect(() => validateProviderReceipt('lima-nerdctl', { platform: 'darwin', arch: 'x64' }, changed)).toThrow('PROVIDER_RECEIPT');
  });
  it('requires the complete Apple kernel/init closure and the WSL SDK identity', () => {
    const apple = { ...base, kernel: { path: 'runtime/apple/kernel', sha256: sha }, init_image: { digest: sha, reference: `ghcr.io/mehmetoguzderin/init@${sha}`, context_sha256: sha, config_digest: sha, diff_ids: [sha] } };
    expect(() => validateProviderReceipt('apple-container', { platform: 'darwin', arch: 'arm64' }, apple)).not.toThrow();
    expect(() => validateProviderReceipt('apple-container', { platform: 'darwin', arch: 'arm64' }, { ...apple, init_image: { ...apple.init_image, reference: `localhost/ud-agent-skill-mcp-plugin-init@${sha}` } })).not.toThrow();
    expect(() => validateProviderReceipt('apple-container', { platform: 'darwin', arch: 'arm64' }, { ...apple, init_image: { ...apple.init_image, reference: `localhost/unrelated@${sha}` } })).toThrow('PROVIDER_RECEIPT_INVALID');
    for (const changed of [{ ...apple, kernel: { path: '../kernel', sha256: sha } }, { ...apple, init_image: { ...apple.init_image, config_digest: undefined } }, { ...apple, executable_sha256: 'invalid' }]) expect(() => validateProviderReceipt('apple-container', { platform: 'darwin', arch: 'arm64' }, changed)).toThrow('PROVIDER_RECEIPT_INVALID');
    expect(() => validateProviderReceipt('apple-container', { platform: 'darwin', arch: 'x64' }, apple)).toThrow('PROVIDER_RECEIPT_INVALID');
    expect(() => validateProviderReceipt('wslc', { platform: 'win32', arch: 'arm64' }, { ...base, sdk: 'runtime/wsl-sdk.dll', sdk_sha256: sha })).not.toThrow();
    expect(() => validateProviderReceipt('wslc', { platform: 'win32', arch: 'x64' }, { ...base, sdk: 'C:\\Program Files\\WSL\\wsl-sdk.dll', sdk_sha256: sha })).not.toThrow();
    expect(() => validateProviderReceipt('wslc', { platform: 'win32', arch: 'x64' }, { ...base, sdk: 'runtime/wsl-sdk.dll' })).toThrow('PROVIDER_RECEIPT_INVALID');
  });
});
