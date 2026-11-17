import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { parse } from 'yaml';
import { ensureOwnedLimaInstance, validateOwnedLimaTemplate } from '../../packages/runtime-manager/src/lima-provision.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';
const sha = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const success = (value: unknown = '') => ({ code: 0, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });

describe('owned Lima acquisition and resume', () => {
  it('creates only product-owned VMs from verified local assets, resumes start, and reuses warm state', async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-lp-')); const root = await realpath(temporary);
    try {
      const executable = path.join(root, 'limactl'); const asset = path.join(root, 'guest.img'); const template = path.join(root, 'template.yaml'); const home = path.join(root, 'lima-home'); const script = path.join(root, 'dependency.sh'); const scriptBody = '#!/bin/sh\nprintf offline\n';
      await writeFile(executable, 'lima'); await writeFile(asset, 'guest bytes'); await writeFile(script, scriptBody);
      const yaml = `arch: aarch64\nvmType: vz\ncpus: 2\nmemory: 4GiB\nmounts: []\nimages:\n- location: '{{asset:guest}}'\n  digest: '${sha('guest bytes')}'\ncontainerd:\n  user: true\n  system: false\nssh:\n  loadDotSSHPubKeys: false\n  forwardAgent: false\nprovision:\n- mode: dependency\n  skipDefaultDependencyResolution: true\n  file:\n    url: '{{asset:dependencies}}'\n    digest: '${sha(scriptBody)}'\n`;
      await writeFile(template, yaml);
      const receipt = { schema_version: 1 as const, executable, binarySha256: sha('lima'), instance: 'ud-agent', home, nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: sha('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: sha('containerd'), address: '/run/user/1000/containerd/containerd.sock', guestUid: 1000, guestHome: '/home/test', architecture: 'arm64' as const };
      const provisioning = { template, templateSha256: sha(yaml), offlineReady: true, assets: [{ key: 'guest', path: asset, sha256: sha('guest bytes'), sizeBytes: 11 }, { key: 'dependencies', path: script, sha256: sha(scriptBody), sizeBytes: Buffer.byteLength(scriptBody) }], generatedConfig: { networksSha256: sha('pinned default networks\n') } };
      let status: 'Running' | 'Stopped' | undefined; let startFails = true; const commands: string[][] = []; const cancellation = new AbortController();
      const runner: typeof runCommand = async (_exe, args, options) => {
        expect(options.limaHome).toBe(home); commands.push([...args]);
        if (_exe === '/usr/bin/ssh-keygen') { expect(args).toEqual(['-y', '-f', path.join(home, '_config/user')]); return success('ssh-ed25519 AAECAwQF\n'); }
        if (args[0] === '--version') return success('limactl version 2.0.0\n');
        if (args[0] === 'list') return success(status ? [{ name: 'ud-agent', status, arch: 'aarch64', vmType: 'vz' }] : []);
        if (args[0] === 'create') { await mkdir(path.join(home, 'ud-agent')); await writeFile(path.join(home, 'ud-agent/lima.yaml'), await readFile(args.at(-1)!)); await mkdir(path.join(home, '_config'), { mode: 0o700 }); await writeFile(path.join(home, '_config/user'), 'private generated key', { mode: 0o600 }); await writeFile(path.join(home, '_config/user.pub'), 'ssh-ed25519 AAECAwQF lima\n', { mode: 0o600 }); status = 'Stopped'; cancellation.abort(); return success(); }
        if (args[0] === 'start') { if (startFails) return { ...success(), code: 1 }; await writeFile(path.join(home, '_config/networks.yaml'), 'pinned default networks\n', { mode: 0o600 }); status = 'Running'; return success(); }
        throw new Error('unexpected command');
      };
      await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner, cancellation.signal)).rejects.toThrow('LIMA_SETUP_CANCELLED');
      expect(JSON.parse(await readFile(path.join(root, 'lima-instance.json'), 'utf8')).phase).toBe('creating');
      await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).rejects.toThrow('LIMA_START_FAILED');
      expect(commands.filter(args => args[0] === 'create')).toHaveLength(1); startFails = false;
      expect(await ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).toEqual({ created: false, started: true });
      expect(await ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).toEqual({ created: false, started: false });
      expect(commands.filter(args => args[0] === 'create')).toHaveLength(1); expect(commands.filter(args => args[0] === 'start')).toHaveLength(2);
      expect(commands.some(args => args.includes('stop') || args.includes('delete'))).toBe(false);
      expect(JSON.parse(await readFile(path.join(root, 'lima-generated-config.json'), 'utf8')).files).toHaveLength(3);
      await writeFile(path.join(home, '_config/override.yaml'), 'mounts: []'); await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).rejects.toThrow('LIMA_UNDECLARED_GLOBAL_CONFIG'); await rm(path.join(home, '_config/override.yaml'));
      await writeFile(path.join(home, '_config/networks.yaml'), 'changed'); await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).rejects.toThrow('LIMA_DEFAULT_NETWORK_CONFIG_CHANGED'); await writeFile(path.join(home, '_config/networks.yaml'), 'pinned default networks\n');
      await writeFile(path.join(home, '_config/user.pub'), 'ssh-ed25519 changed'); await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).rejects.toThrow('LIMA_GENERATED_CONFIG_CHANGED'); await writeFile(path.join(home, '_config/user.pub'), 'ssh-ed25519 AAECAwQF lima\n');
      const config = parse(await readFile(path.join(home, 'ud-agent/lima.yaml'), 'utf8')); expect(config.images[0].location).toBe(pathToFileURL(path.join(home, '_assets', sha('guest bytes').slice(7))).href);
      expect(config.provision).toEqual([{ mode: 'dependency', skipDefaultDependencyResolution: true, script: scriptBody }]);
      await writeFile(path.join(home, 'ud-agent/lima.yaml'), 'changed'); await expect(ensureOwnedLimaInstance(receipt, provisioning, guard, root, 'offline', runner)).rejects.toThrow('TEMPLATE_INVALID');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rejects shared-home mounts, unfrozen downloads and offline-incomplete templates', () => {
    const valid = { arch: 'x86_64', vmType: 'qemu', cpus: 2, memory: '4GiB', mounts: [], images: [{ location: 'file:///owned/guest', digest: sha('guest') }], containerd: { user: true, system: false }, ssh: { loadDotSSHPubKeys: false, forwardAgent: false } };
    expect(() => validateOwnedLimaTemplate(valid, 'amd64')).not.toThrow();
    expect(() => validateOwnedLimaTemplate({ ...valid, mounts: [{ location: '~' }] }, 'amd64')).toThrow('POLICY_FAILED');
    expect(() => validateOwnedLimaTemplate({ ...valid, images: [{ location: 'https://example.invalid/guest', digest: sha('guest') }] }, 'amd64')).toThrow('POLICY_FAILED');
    expect(() => validateOwnedLimaTemplate({ ...valid, ssh: { ...valid.ssh, forwardAgent: true } }, 'amd64')).toThrow('POLICY_FAILED');
    expect(() => validateOwnedLimaTemplate({ ...valid, vmOpts: { vz: { rosetta: { enabled: true } } } }, 'amd64')).toThrow('HOST_ACCESS_FORBIDDEN');
  });
});
