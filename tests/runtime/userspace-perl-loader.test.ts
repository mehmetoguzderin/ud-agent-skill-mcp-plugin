import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it, vi } from 'vitest';
// Linux executable-policy fixture; physical Windows ACL behavior is tested separately.
vi.mock('node:fs/promises', async original => (await import('./posix-policy-fixture.js')).posixPolicyFixture(await original<typeof import('node:fs/promises')>()));
import { verifyUserspacePack } from '../../packages/runtime-manager/src/userspace.js';

const hash = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
it('admits only receipt-bound Linux Perl loaders and rejects missing, changed or ambient native libraries', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-perl-loader-contract-')));
  try {
    const rules = Object.fromEntries(['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'].map(name => [name, hash('{}').slice(7)]));
    const assets = new Map<string, Buffer | string>([
      ['runtime/worker/worker.py', ''], ['runtime/upstream/udtools.py', ''], ['runtime/bootstrap.py', ''], ['runtime/requirements.txt', ''],
      ['runtime/helpers/guard', await readFile(path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : '')))],
      ['runtime/context/context.json', JSON.stringify({ rule_dir: 'rules', rules, context_sha256: hash(JSON.stringify(rules)).slice(7) })],
      ...Object.keys(rules).map(name => [`runtime/context/rules/${name}`, '{}'] as [string, string]),
      ['runtime/perl/bin/perl', '#!/bin/sh\nexit 0\n'], ['runtime/perl/lib/strict.pm', 'package strict; 1;'],
      ['runtime/perl/native/ld-linux.so', '#!/bin/sh\nexit 0\n'], ['runtime/perl/native/libc.so.6', 'fixed native library fixture'],
    ]);
    for (const [name, bytes] of assets) { const file = path.join(root, name); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, bytes); }
    await mkdir(path.join(root, 'runtime/wheels'));
    for (const name of ['runtime/helpers/guard', 'runtime/perl/bin/perl', 'runtime/perl/native/ld-linux.so']) await chmod(path.join(root, name), 0o700);
    const perl = { executable: 'runtime/perl/bin/perl', library_dirs: ['runtime/perl/lib'], loader: { executable: 'runtime/perl/native/ld-linux.so', library_dirs: ['runtime/perl/native'] } };
    const platform = { worker: 'runtime/worker', upstream: 'runtime/upstream', bootstrap: 'runtime/bootstrap.py', requirements: 'runtime/requirements.txt', guard: 'runtime/helpers/guard', context: 'runtime/context/context.json', wheels: 'runtime/wheels', packs: ['core'], perl, files: [...assets].map(([name, bytes]) => ({ path: name, sha256: hash(bytes), size: Buffer.byteLength(bytes) })) };
    const host = { platform: 'linux' as const, arch: process.arch };
    // This is a Linux manifest policy fixture; its state path remains native to
    // the executing host instead of deriving a Linux home from Windows env.
    const state = path.join(root, 'state');
    const save = async (selected = platform, selectedHost = host) => {
      const manifest = JSON.stringify({ schema_version: 1, format_revision: 2, product_version: '0.1.0-beta.1', state: 'frozen', platforms: { [`${selectedHost.platform}/${selectedHost.arch}`]: selected } });
      await writeFile(path.join(root, 'runtime/userspace.lock.json'), manifest);
      await writeFile(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(manifest) }));
    };
    await save(); expect(await verifyUserspacePack(root, host, state)).toMatchObject({ packs: ['core'] });
    await writeFile(path.join(root, 'runtime/perl/native/unlisted.so'), 'ambient injection');
    await expect(verifyUserspacePack(root, host, state)).rejects.toThrow('unlisted file'); await rm(path.join(root, 'runtime/perl/native/unlisted.so'));
    await writeFile(path.join(root, 'runtime/perl/native/libc.so.6'), 'changed native library');
    await expect(verifyUserspacePack(root, host, state)).rejects.toThrow(); await writeFile(path.join(root, 'runtime/perl/native/libc.so.6'), assets.get('runtime/perl/native/libc.so.6')!);
    await save({ ...platform, perl: { ...perl, loader: { ...perl.loader, executable: '../ambient/loader' } } });
    await expect(verifyUserspacePack(root, host, state)).rejects.toThrow('USERSPACE_PRIVATE_PERL_LOADER_INVALID');
    await save({ ...platform, perl: { ...perl, loader: { ...perl.loader, library_dirs: [] } } });
    await expect(verifyUserspacePack(root, host, state)).rejects.toThrow('USERSPACE_PRIVATE_PERL_LOADER_INVALID');
    await save({ ...platform, files: platform.files.filter(file => file.path !== perl.loader.executable) });
    await expect(verifyUserspacePack(root, host, state)).rejects.toThrow('loader is missing');
  } finally { await rm(root, { recursive: true, force: true }); }
});
