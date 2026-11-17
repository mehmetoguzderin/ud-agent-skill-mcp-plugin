import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSync } from 'esbuild';
import { userspaceStateRoot } from '../../packages/runtime-manager/src/userspace.js';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { posixTest } from '../fixtures/native-scope.mjs';

let entry: string;
let installed: string;
let isolatedEnvironment: NodeJS.ProcessEnv;
beforeAll(() => {
  installed = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-installed-')));
  const profile = path.join(installed, 'profile'), emptyBin = path.join(profile, 'bin'), temporary = path.join(profile, 'tmp');
  mkdirSync(emptyBin, { recursive: true, mode: 0o700 }); mkdirSync(temporary, { mode: 0o700 });
  isolatedEnvironment = { HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile, XDG_DATA_HOME: profile, PATH: emptyBin, TMPDIR: temporary, TMP: temporary, TEMP: temporary, LANG: 'C.UTF-8', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
  writableFixtureCopy(path.resolve('contracts'), path.join(installed, 'contracts'), installed);
  writableFixtureCopy(path.resolve('release'), path.join(installed, 'release'), installed);
  mkdirSync(path.join(installed, 'runtime/helpers'), { recursive: true });
  const relativeGuard = `runtime/helpers/guard${process.platform === 'win32' ? '.exe' : ''}`;
  const guard = path.join(installed, relativeGuard);
  copyFileSync(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), guard);
  chmodSync(guard, 0o700); const bytes = readFileSync(guard);
  writeFileSync(path.join(installed, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: {}, native_helpers: { [`${process.platform}/${process.arch}`]: { guard: { path: relativeGuard, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, size_bytes: bytes.length } } } }));
  entry = path.join(installed, 'coordinator.mjs');
  buildSync({ entryPoints: [path.resolve('packages/coordinator/src/entry.ts')], outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'], banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' } });
});
afterAll(() => { if (installed) rmSync(installed, { recursive: true, force: true }); });
function run(...args: string[]) {
  return spawnSync(process.execPath, [entry, ...args], { env: isolatedEnvironment, encoding: 'utf8', timeout: 10_000 });
}

describe('CLI', () => {
  it('provides help and a read-only environment inquiry', () => {
    const help = run('--help');
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('ud-agent validate');
    const check = run('check', '--offline');
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const result = JSON.parse(check.stdout);
    expect(result.operation).toBe('check_ud_environment');
    expect(result.result.ready).toBe(false);
    expect(result.result.next_call.arguments.network).toBe('offline');
    expect(result.result.working_tree_changes).toEqual([]);
  });

  it('writes opt-in skill-name shell aliases, preserves existing files and supplies command-refusal guidance', () => {
    cpSync(path.resolve('skills'), path.join(installed, 'skills'), { recursive: true });
    const bin = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-aliases-')));
    try {
      expect(run('shell-aliases', '--bin', 'relative/bin').status).toBe(1);
      const dry = run('shell-aliases', '--bin', bin, '--dry-run', '--json');
      expect(dry.status, dry.stderr).toBe(0);
      expect(JSON.parse(dry.stdout).written).toContain(path.join(bin, 'ud-validate'));
      expect(existsSync(path.join(bin, 'ud-validate'))).toBe(false);
      writeFileSync(path.join(bin, 'ud-edit'), 'keep');
      const wrote = JSON.parse(run('shell-aliases', '--bin', bin, '--json').stdout);
      expect(wrote.kept).toEqual([path.join(bin, 'ud-edit')]);
      expect(readFileSync(path.join(bin, 'ud-edit'), 'utf8')).toBe('keep');
      const script = readFileSync(path.join(bin, 'ud-validate'), 'utf8');
      expect(script).toMatch(/^#!\/bin\/sh\n/); expect(script).toContain('ud-validate'); expect(script).toContain(' "$@"\nexit 127\n');
      const guidance = run('ud-validate', 'treebank.conllu');
      expect(guidance.error).toBeUndefined(); expect(guidance.signal).toBeNull(); expect(guidance.status, guidance.stderr).toBe(1);
      expect(guidance.stderr).toMatch(/ud-validate is a skill \(an instructions document\), not a command\. Read it first: cat /);
    } finally { rmSync(bin, { recursive: true, force: true }); }
  });

  posixTest('generated POSIX skill aliases execute only skill-load guidance and exit 127', () => {
    cpSync(path.resolve('skills'), path.join(installed, 'skills'), { recursive: true });
    const bin = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-shell-aliases-')));
    try {
      const generated = run('shell-aliases', '--bin', bin, '--json');
      expect(generated.status, generated.stderr).toBe(0);
      const alias = spawnSync('/bin/sh', [path.join(bin, 'ud-validate'), 'treebank.conllu'], { env: isolatedEnvironment, encoding: 'utf8', timeout: 10_000 });
      expect(alias.error).toBeUndefined(); expect(alias.signal).toBeNull(); expect(alias.status, alias.stderr).toBe(127);
      expect(alias.stderr).toMatch(/ud-validate is a skill \(an instructions document\), not a command\. Read it first: cat /);
    } finally { rmSync(bin, { recursive: true, force: true }); }
  });

  it('refuses unsupported engines and missing language rather than guessing', () => {
    const badEngine = run('check', '--engine', 'unknown');
    expect(badEngine.status).toBe(1);
    expect(badEngine.stderr).toBeTruthy();
    const missingLanguage = run('validate', '--working-tree', process.cwd());
    expect(missingLanguage.status).toBe(1);
    expect(missingLanguage.stderr).toContain('--lang');
  });

  it('returns a nonzero result when isolated validation is not ready', () => {
    const result = run('validate', '--working-tree', process.cwd(), '--lang', 'en', '--no-setup');
    expect(result.status).toBe(1);
    const envelope = JSON.parse(result.stdout);
    expect(envelope.operation).toBe('validation_report');
    expect(envelope.result.code).toBe('ENVIRONMENT_NOT_READY');
    expect(envelope.result.status).toBe('incomplete');
  });

  it('previews and cleans only product-owned cache when explicitly requested', () => {
    const temp = mkdtempSync(path.join(os.tmpdir(), 'ud-cli-clean-'));
    try {
      const home = realpathSync(temp);
      const env = { ...process.env, HOME: home, USERPROFILE: home, LOCALAPPDATA: home, XDG_DATA_HOME: home };
      const state = userspaceStateRoot({ platform: process.platform, arch: process.arch }, env);
      const cache = path.join(state, 'uv-cache');
      mkdirSync(cache, { recursive: true, mode: 0o700 });
      writeFileSync(path.join(cache, 'owned'), 'cached');
      writeFileSync(path.join(home, 'unrelated'), 'keep');
      const command = (...args: string[]) => spawnSync(process.execPath, [entry, ...args], { env, encoding: 'utf8', timeout: 10_000 });
      const preview = command('clean', '--dry-run');
      expect(preview.status, preview.stderr).toBe(0);
      expect(JSON.parse(preview.stdout)).toMatchObject({ action: 'cache', dry_run: true, paths: ['uv-cache'] });
      expect(existsSync(path.join(cache, 'owned'))).toBe(true);
      const cleaned = command('clean', '--cache');
      expect(cleaned.status, cleaned.stderr).toBe(0);
      expect(existsSync(cache)).toBe(false);
      expect(existsSync(path.join(home, 'unrelated'))).toBe(true);
      expect(command('uninstall').status).toBe(1);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  }, 30_000);

  it('dispatches explicit owned-runtime cleanup without acquiring or reconfiguring any engine', () => {
    const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-engines-')));
    try {
      const env = { ...process.env, HOME: temp, USERPROFILE: temp, LOCALAPPDATA: temp, XDG_DATA_HOME: temp };
      const command = (...args: string[]) => spawnSync(process.execPath, [entry, ...args], { env, encoding: 'utf8', timeout: 10_000 });
      const all = command('uninstall', '--owned-runtime', '--all', '--dry-run');
      expect(all.status, all.stderr).toBe(0);
      const result = JSON.parse(all.stdout);
      expect(result.scope).toBe('owned-runtimes'); expect(result.dry_run).toBe(true);
      expect(result.providers.length).toBeGreaterThan(0);
      expect(result.providers.every((provider: { status: string; paths: unknown[]; resources: unknown[] }) => provider.status === 'absent' && provider.paths.length === 0 && provider.resources.length === 0)).toBe(true);
      const privateOnly = command('clean', '--cache', '--engine', 'userspace', '--dry-run');
      expect(privateOnly.status, privateOnly.stderr).toBe(0); expect(JSON.parse(privateOnly.stdout)).toMatchObject({ scope: 'userspace', providers: [], paths: [], dry_run: true });
      expect(command('clean', '--cache', '--engine', 'unknown').status).toBe(1);
      expect(command('clean', '--cache', '--engine', 'userspace', '--all').status).toBe(1);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  }, 45_000);

  it('cleans an offline-seeded provider cache through the installed CLI before any image import', async () => {
    const home = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-seeded-images-')));
    const lockFile = path.join(installed, 'runtime/runtime.lock.json'), originalLock = readFileSync(lockFile);
    try {
      const env = { ...isolatedEnvironment, HOME: home, USERPROFILE: home, LOCALAPPDATA: home, XDG_DATA_HOME: home };
      const state = `${userspaceStateRoot({ platform: process.platform, arch: process.arch }, env)}-docker`;
      mkdirSync(state, { recursive: true, mode: 0o700 });
      const guard = path.join(installed, `runtime/helpers/guard${process.platform === 'win32' ? '.exe' : ''}`);
      await JournalStore.open(state, guard);
      const images = path.join(state, 'images'); mkdirSync(images, { mode: 0o700 });
      const bytes = Buffer.from('independent offline transport bytes\n'), digest = createHash('sha256').update(bytes).digest('hex');
      const archive = path.join(images, `${digest}.tar`), unknown = path.join(images, `${'a'.repeat(64)}.tar`);
      writeFileSync(archive, bytes, { mode: 0o400 }); chmodSync(archive, 0o400);
      writeFileSync(unknown, 'foreign transport: preserve', { mode: 0o400 }); chmodSync(unknown, 0o400);
      const lock = JSON.parse(originalLock.toString('utf8'));
      lock.packs = { core: { images: { 'linux/arm64': { transports: [{ sha256: `sha256:${digest}`, size_bytes: bytes.length }] } } } };
      writeFileSync(lockFile, JSON.stringify(lock));
      const command = (...args: string[]) => spawnSync(process.execPath, [entry, ...args], { env, encoding: 'utf8', timeout: 15_000 });
      const dry = command('clean', '--cache', '--engine', 'docker', '--dry-run');
      expect(dry.status, dry.stderr + dry.stdout).toBe(0);
      expect(JSON.parse(dry.stdout).providers).toEqual([expect.objectContaining({ status: 'dry_run', paths: [`images/${digest}.tar`], protected_paths: [`images/${'a'.repeat(64)}.tar`] })]);
      expect(readFileSync(archive)).toEqual(bytes);
      expect(existsSync(path.join(images, 'locks'))).toBe(false);
      expect(existsSync(path.join(images, 'transactions'))).toBe(false);
      const cleaned = command('clean', '--cache', '--engine', 'docker');
      expect(cleaned.status, cleaned.stderr + cleaned.stdout).toBe(0);
      expect(JSON.parse(cleaned.stdout).providers).toEqual([expect.objectContaining({ status: 'complete', resources: [], recovered_jobs: [], paths: [`images/${digest}.tar`], protected_paths: [`images/${'a'.repeat(64)}.tar`] })]);
      expect(existsSync(archive)).toBe(false);
      expect(readFileSync(unknown, 'utf8')).toBe('foreign transport: preserve');
      expect(existsSync(path.join(images, 'locks'))).toBe(true);
      expect(existsSync(path.join(images, 'transactions'))).toBe(true);
      const retry = command('uninstall', '--owned-runtime', '--engine', 'docker');
      expect(retry.status, retry.stderr + retry.stdout).toBe(0);
      expect(JSON.parse(retry.stdout).providers[0]).toMatchObject({ status: 'complete', paths: [], resources: [], protected_paths: [`images/${'a'.repeat(64)}.tar`] });
      expect(readFileSync(unknown, 'utf8')).toBe('foreign transport: preserve');
    } finally { writeFileSync(lockFile, originalLock); rmSync(home, { recursive: true, force: true }); }
  }, 60_000);
});
