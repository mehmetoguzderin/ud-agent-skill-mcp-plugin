import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadPodmanAuthority, verifyPodmanAuthority } from '../../packages/runtime-manager/src/podman-authority.js';
import { posixTest } from '../fixtures/native-scope.mjs';

const hash = (value: Buffer | string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
async function fixture<T>(run: (item: any) => Promise<T>): Promise<T> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-podman-authority-'));
  const root = await realpath(temporary);
  try {
    await mkdir(path.join(root, 'runtime'));
    const paths = Object.fromEntries(['engine', 'tracer', 'guard', 'seccomp', 'containersConf', 'defaultMounts'].map(name => [name, path.join(root, name)])) as Record<string, string>;
    const content: Record<string, string> = { engine: 'engine', tracer: 'tracer', guard: 'guard', seccomp: '{"defaultAction":"SCMP_ACT_ERRNO"}', containersConf: '[containers]\nmounts = []\n[engine]\nhooks_dir = []\n', defaultMounts: '' };
    for (const [name, file] of Object.entries(paths)) await writeFile(file, content[name] ?? '', { mode: ['engine', 'tracer', 'guard'].includes(name) ? 0o700 : 0o600 });
    const imageDigest = `sha256:${'a'.repeat(64)}`;
    const imageLock = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: { core: { context_sha256: `sha256:${'b'.repeat(64)}`, images: { 'linux/amd64': { digest: imageDigest, reference: `ghcr.io/mehmetoguzderin/ud-core@${imageDigest}` } } } } };
    const policyLock = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', platforms: { 'linux/amd64': { engine_sha256: hash(content.engine ?? ''), tracer_sha256: hash(content.tracer ?? ''), guard_sha256: hash(content.guard ?? ''), seccomp_sha256: hash(content.seccomp ?? ''), containers_conf_sha256: hash(content.containersConf ?? '') } } };
    await writeFile(path.join(root, 'runtime', 'runtime.lock.json'), JSON.stringify(imageLock));
    await writeFile(path.join(root, 'runtime', 'podman-policy.lock.json'), JSON.stringify(policyLock));
    return await run({ root, paths, content, imageLock, policyLock });
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

describe('Podman product authority', () => {
  posixTest('binds frozen product identities and rejects copied or serialized capabilities', async () => fixture(async ({ root, paths, content }) => {
    const authority = await loadPodmanAuthority(root, 'amd64', paths);
    expect(authority).toMatchObject({ architecture: 'amd64', engineSha256: hash(content.engine), image: { digest: `sha256:${'a'.repeat(64)}` } });
    expect(Object.isFrozen(authority)).toBe(true); expect(Object.isFrozen(authority.image)).toBe(true);
    const use = { architecture: 'amd64' as const, paths, image: authority.image };
    await expect(verifyPodmanAuthority(authority, use)).resolves.toBeUndefined();
    await expect(verifyPodmanAuthority({ ...authority }, use)).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
    await expect(verifyPodmanAuthority(JSON.parse(JSON.stringify(authority)), use)).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
  }));
  posixTest('rejects stale binary, policy, and image receipts on later verification', async () => fixture(async ({ root, paths }) => {
    const authority = await loadPodmanAuthority(root, 'amd64', paths);
    const use = { architecture: 'amd64' as const, paths, image: authority.image };
    await expect(verifyPodmanAuthority(authority, { ...use, paths: { ...paths, engine: paths.tracer } })).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_MISMATCH');
    await expect(verifyPodmanAuthority(authority, { ...use, architecture: 'arm64' })).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_MISMATCH');
    await expect(verifyPodmanAuthority(authority, { ...use, image: { ...authority.image, contextSha256: `sha256:${'c'.repeat(64)}` } })).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_MISMATCH');
    await writeFile(paths.tracer, 'replacement');
    await expect(verifyPodmanAuthority(authority, use)).rejects.toThrow('digest');
    await writeFile(paths.tracer, 'tracer');
    const receipt = path.join(root, 'runtime', 'runtime.lock.json');
    const original = await readFile(receipt); await writeFile(receipt, Buffer.concat([original, Buffer.from(' ')]));
    await expect(verifyPodmanAuthority(authority, use)).rejects.toThrow('PODMAN_RECEIPT_CHANGED');
    await writeFile(receipt, original);
    const policy = path.join(root, 'runtime', 'podman-policy.lock.json');
    await writeFile(policy, '{}');
    await expect(verifyPodmanAuthority(authority, use)).rejects.toThrow('PODMAN_RECEIPT_CHANGED');
  }));
  it('rejects unfrozen, missing, wrong-version, wrong-platform and invalid policy receipts', async () => fixture(async ({ root, paths, policyLock }) => {
    const policy = path.join(root, 'runtime', 'podman-policy.lock.json');
    for (const invalid of [{ ...policyLock, state: 'unbuilt' }, { ...policyLock, product_version: '0.0.0' }, { ...policyLock, platforms: {} }, { ...policyLock, platforms: { 'linux/amd64': { ...policyLock.platforms['linux/amd64'], engine_sha256: 'incorrect' } } }]) {
      await writeFile(policy, JSON.stringify(invalid));
      await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow();
    }
    await rm(policy);
    await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow('PODMAN_POLICY_RECEIPT_NOT_FROZEN');
  }));
  posixTest('rejects symlinked, writable, unexpected or untrusted runtime assets', async () => fixture(async ({ root, paths }) => {
    await chmod(paths.engine, 0o777);
    await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow('trusted regular file');
    await chmod(paths.engine, 0o700);
    await rm(paths.tracer); await symlink(paths.engine, paths.tracer);
    await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow('trusted regular file');
    await rm(paths.tracer); await writeFile(paths.tracer, 'tracer', { mode: 0o700 });
    await writeFile(paths.defaultMounts, '/etc:/etc');
    await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow('must be empty');
  }));
  if (process.platform === 'win32') it('Windows refuses legacy POSIX Podman executable authority without altering runtime or policy bytes', async () => fixture(async ({ root, paths }) => {
    const files = [...Object.values(paths) as string[], path.join(root, 'runtime/runtime.lock.json'), path.join(root, 'runtime/podman-policy.lock.json')];
    const before = await Promise.all(files.map(file => readFile(file)));
    await expect(loadPodmanAuthority(root, 'amd64', paths)).rejects.toThrow('Podman runtime executable is not a trusted regular file.');
    expect(await Promise.all(files.map(file => readFile(file)))).toEqual(before);
  }));
});
