import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, openSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { expect, it, vi } from 'vitest';
import { captureOperationSnapshot } from '../../packages/workspace/src/input-broker.js';
import { captureGitMetadata } from '../../packages/workspace/src/git-metadata.js';
import { guardedGrant, guardedReadStream } from '../../packages/workspace/src/guard.js';
import { streamVerifiedSnapshot } from '../../packages/workspace/src/snapshot-transfer.js';
import { writeNativeEngine } from './native-engine-fixture.js';
import { posixTest } from '../fixtures/native-scope.mjs';
// Each fixture compiles native shims with rustc and runs real Git (about
// 0.4-2 s idle). Under CPU load the 5 s default expired mid-fixture, and the
// still-running callback kept its fixture PATH, so later tests could not find
// rustc. A file budget keeps one slow fixture from cascading; assertions are
// unchanged.
vi.setConfig({ testTimeout: 60_000 });
const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const nativeGit = (() => {
  // Original discovery excludes PATHEXT; where.exe needs the exact suffix.
  const windows = process.platform === 'win32';
  const found = spawnSync(windows ? 'where.exe' : '/usr/bin/which', [windows ? 'git.exe' : 'git'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 65_536 });
  if (found.error || found.status !== 0 || !found.stdout.trim()) throw new Error('Fixture requires installed Git: ' + (found.error?.message ?? found.stderr.trim()).slice(-2048));
  return found.stdout.trim().split(/\r?\n/)[0]!;
})();
const historical = Buffer.from('# sent_id = old\r\n1\told\t_\tNOUN\t_\t_\t0\troot\t_\t_\r\n\r\n');
function runGit(args: string[], input?: Buffer): Buffer { const result = spawnSync(nativeGit, args, { input, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' } }); expect(result.status, result.stderr.toString()).toBe(0); return result.stdout; }
async function fixture(root: string, algorithm: 'sha1' | 'sha256' = 'sha1', reftable = false) {
  const workspace = path.join(root, 'workspace'), metadata = path.join(workspace, '.git'); await mkdir(workspace);
  runGit(['init', '--quiet', '--initial-branch=main', `--object-format=${algorithm}`, ...(reftable ? ['--ref-format=reftable'] : []), workspace]);
  const store = async (type: string, bytes: Buffer) => {
    const body = Buffer.concat([Buffer.from(`${type} ${bytes.length}\0`), bytes]), oid = createHash(algorithm).update(body).digest('hex');
    const folder = path.join(metadata, 'objects', oid.slice(0, 2)); await mkdir(folder, { recursive: true }); await writeFile(path.join(folder, oid.slice(2)), deflateSync(body)); return oid;
  };
  const blob = await store('blob', historical), tree = await store('tree', Buffer.concat([Buffer.from('100644 main.conllu\0'), Buffer.from(blob, 'hex')]));
  const commit = await store('commit', Buffer.from(`tree ${tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n`));
  runGit(['--git-dir', metadata, 'update-ref', 'refs/heads/main', commit]);
  await writeFile(path.join(workspace, 'main.conllu'), '# sent_id = current\n');
  const bin = path.join(root, 'bin'), log = path.join(root, 'git-calls.jsonl'); await mkdir(bin);
  await writeNativeEngine({ root: bin, name: 'git', program: `const fs=require('node:fs'),cp=require('node:child_process');const a=process.argv.slice(2);fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({args:a,cwd:process.cwd()})+'\\n');const r=cp.spawnSync(${JSON.stringify(nativeGit)},a,{stdio:'inherit',env:process.env});process.exit(r.status??126);` });
  return { workspace, metadata, bin, log, blob, tree, commit, store, args: { working_tree_path: workspace, base_revision: 'HEAD', ud_context_path: '' } };
}
async function withFixture(callback: (f: Awaited<ReturnType<typeof fixture>>, root: string) => Promise<void>, algorithm: 'sha1' | 'sha256' = 'sha1', reftable = false) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-git-snapshot-'))), previous = process.env.PATH;
  try { const f = await fixture(root, algorithm, reftable); process.env.PATH = f.bin; await callback(f, root); }
  finally { if (previous === undefined) delete process.env.PATH; else process.env.PATH = previous; await rm(root, { recursive: true, force: true }); }
}
async function calls(file: string): Promise<{args:string[];cwd:string}[]> { try { return (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []; throw e; } }

it('binds historical byte-preserving corpus to independently hashed commit/tree/blob objects and private Git inputs', async () => withFixture(async f => {
  const captured = await captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review');
  try {
    expect(captured.brokerEvidence).toMatchObject({ snapshot_sha256: captured.snapshot.sha256, git_base: { requested_revision: 'HEAD', resolved_commit: f.commit, tree_oid: f.tree, files: { 'main.conllu': { blob_oid: f.blob, size_bytes: historical.length } } } });
    const file = captured.snapshot.files.find(item => item.path.endsWith('/tree/main.conllu'))!; expect(await readFile(path.join(captured.snapshot.directory, file.path))).toEqual(historical);
    const frames = []; for await (const frame of streamVerifiedSnapshot(guard, captured.snapshot)) frames.push(frame);
    expect(frames[0]).toMatchObject({ type: 'begin', snapshot_sha256: captured.snapshot.sha256 }); expect(frames.at(-1)).toEqual({ type: 'end', snapshot_sha256: captured.snapshot.sha256 });
    for (const call of await calls(f.log)) { expect(call.cwd).not.toBe(f.workspace); expect(call.cwd).toContain('.git-private-'); expect(call.args).not.toContain(f.metadata); }
    await expect((await import('node:fs/promises')).readdir(captured.snapshot.directory).then(names => names.some(name => name.startsWith('.git-private-')))).resolves.toBe(false);
  } finally { await captured.snapshot.cleanup(); }
  // An object stored under an unrelated valid OID cannot supply successful bytes.
  await writeFile(path.join(f.metadata, 'objects', f.blob.slice(0, 2), f.blob.slice(2)), deflateSync(Buffer.from('blob 3\0bad')));
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow(/GIT_OBJECT_CONTENT_MISMATCH|GIT_BASE_REVISION_UNAVAILABLE/);
}));

it('denies gitfiles, commondir, direct config includes and alternate object stores before ANY Git invocation', async () => withFixture(async (f, root) => {
  const outside = path.join(root, 'outside'); await mkdir(outside); await writeFile(path.join(outside, 'poison.cfg'), 'this must never be parsed by Git');
  const config = await readFile(path.join(f.metadata, 'config'));
  await writeFile(path.join(f.metadata, 'config'), Buffer.concat([config, Buffer.from(`\n[include]\npath = ${path.join(outside, 'poison.cfg').split(path.sep).join('/')}\n`)]));
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside'); expect(await calls(f.log)).toEqual([]);
  await writeFile(path.join(f.metadata, 'config'), config); await writeFile(path.join(f.metadata, 'commondir'), outside + '\n');
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside'); expect(await calls(f.log)).toEqual([]);
  await rm(path.join(f.metadata, 'commondir')); await mkdir(path.join(f.metadata, 'objects/info'), { recursive: true }); await writeFile(path.join(f.metadata, 'objects/info/alternates'), outside + '\n');
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside'); expect(await calls(f.log)).toEqual([]);
  await rm(f.metadata, { recursive: true }); await writeFile(f.metadata, `gitdir: ${outside}\n`);
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside'); expect(await calls(f.log)).toEqual([]);
}));

it('admits only active conditional includes and resolves onbranch against the private backend', async () => withFixture(async (f, root) => {
  const outside = path.join(root, 'outside'); await mkdir(outside); const poison = path.join(outside, 'poison.cfg').split(path.sep).join('/'); await writeFile(poison, 'invalid config');
  const original = await readFile(path.join(f.metadata, 'config'));
  for (const condition of ['gitdir:never-a-match/', 'onbranch:other', 'hasconfig:remote.*.url:https://other.invalid/**']) {
    await writeFile(path.join(f.metadata, 'config'), Buffer.concat([original, Buffer.from(`\n[remote "origin"]\nurl=https://example.invalid/repo\n[includeIf "${condition}"]\npath=${poison}\n`)]));
    const result = await captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review'); await result.snapshot.cleanup();
  }
  for (const condition of [`gitdir:${f.metadata.split(path.sep).join('/')}`, 'onbranch:main', 'hasconfig:remote.*.url:https://example.invalid/**']) {
    await rm(f.log, { force: true }); await writeFile(path.join(f.metadata, 'config'), Buffer.concat([original, Buffer.from(`\n[remote "origin"]\nurl=https://example.invalid/repo\n[includeIf "${condition}"]\npath=${poison}\n`)]));
    await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside');
    const invocations = await calls(f.log); expect(invocations).toHaveLength(condition.startsWith('onbranch:') ? 1 : 0); if (invocations.length) expect(invocations[0]!.args).toContain('symbolic-ref');
  }
}));

it('uses granted include settings and separate common metadata without reading original operational settings', async () => withFixture(async (f, root) => {
  const common = path.join(root, 'common'); await (await import('node:fs/promises')).rename(f.metadata, common); await mkdir(f.metadata);
  await writeFile(path.join(f.metadata, 'HEAD'), 'ref: refs/heads/main\n'); await writeFile(path.join(f.metadata, 'commondir'), common + '\n');
  const extra = path.join(root, 'config-scope'); await mkdir(extra); await writeFile(path.join(extra, 'safe.cfg'), '[branch "main"]\nremote=origin\nmerge=refs/heads/main\n[remote "origin"]\nfetch=+refs/heads/*:refs/remotes/origin/*\nurl=ssh://must-not-connect.invalid/repo\n[core]\nfsmonitor=/ungranted/exec\nhooksPath=/ungranted/hooks\n');
  const original = await readFile(path.join(common, 'config')); await writeFile(path.join(common, 'config'), Buffer.concat([original, Buffer.from(`\n[include]\npath=${path.join(extra, 'safe.cfg').split(path.sep).join('/')}\n`)]));
  await mkdir(path.join(common,'refs/remotes/origin'),{recursive:true}); await writeFile(path.join(common,'refs/remotes/origin/main'),f.commit+'\n');
  expect(runGit(['--git-dir',f.metadata,'rev-parse','@{upstream}^{commit}']).toString('ascii').trim()).toBe(f.commit);
  const result = await captureOperationSnapshot(guard, {...f.args,base_revision:'@{upstream}'}, [f.workspace, common, extra], undefined, undefined, 'changes_review');
  try { expect((result.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); } finally { await result.snapshot.cleanup(); }
  const staged = path.join(root, 'private'); await mkdir(staged); const meta = await captureGitMetadata(guard, f.workspace, [f.workspace, common, extra], staged);
  try { const config = await readFile(path.join(meta.commonDir, 'config'), 'utf8'); expect(config).toContain('remote = "origin"'); expect(config).not.toContain('must-not-connect'); expect(config).not.toContain('/ungranted'); await writeFile(path.join(extra, 'safe.cfg'), '[core]\nbare=false\n'); await expect(meta.verify()).rejects.toThrow('GIT_METADATA_CHANGED_DURING_SNAPSHOT'); } finally { await meta.cleanup(); }
}));

it('supports SHA256 object identity without narrowing the public broker workflow', async () => withFixture(async f => {
  const result = await captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'treebank_review');
  try { expect((result.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); expect(f.commit).toHaveLength(64); } finally { await result.snapshot.cleanup(); }
}, 'sha256'));

it('supports reftable HEAD and active onbranch includes through safe private queries', async () => withFixture(async (f, root) => {
  const included = path.join(f.workspace, 'selected.cfg'); await writeFile(included, '[branch "main"]\nmerge=refs/heads/main\n');
  const original = await readFile(path.join(f.metadata, 'config')); await writeFile(path.join(f.metadata, 'config'), Buffer.concat([original, Buffer.from('\n[includeIf "onbranch:main"]\npath=../selected.cfg\n')]));
  const result = await captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review');
  try { expect((result.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); } finally { await result.snapshot.cleanup(); }
  const outside = path.join(root, 'outside'); await mkdir(outside); await writeFile(path.join(outside, 'poison'), 'poison'); await writeFile(path.join(f.metadata, 'config'), Buffer.concat([original, Buffer.from(`\n[includeIf "onbranch:main"]\npath=${path.join(outside, 'poison').split(path.sep).join('/')}\n`)]));
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('outside');
}, 'sha1', true));

it('streams a genuine pack larger than64MiB and preserves ordinary metadata safety and cancellation', async () => withFixture(async (f, root) => {
  const large = await f.store('blob', Buffer.alloc(65 * 1024 * 1024, 0x61)); let packPath = path.join(f.metadata, 'objects/pack/large.pack'), fd = openSync(packPath, 'wx', 0o600);
  try { const packed = spawnSync(nativeGit, ['--git-dir', f.metadata, 'pack-objects', '--stdout', '--compression=0'], { input: Buffer.from([f.commit, f.tree, f.blob, large].join('\n') + '\n'), stdio: ['pipe', fd, 'pipe'], maxBuffer: 1024 * 1024 }); expect(packed.status, packed.stderr?.toString()).toBe(0); } finally { closeSync(fd); }
  const io = await import('node:fs/promises'); const packOid = runGit(['--git-dir', f.metadata, 'index-pack', packPath]).toString('ascii').trim();
  const finalPack = path.join(f.metadata, 'objects/pack', `pack-${packOid}.pack`); await io.rename(packPath, finalPack); await io.rename(packPath.replace(/\.pack$/, '.idx'), finalPack.replace(/\.pack$/, '.idx')); packPath = finalPack;
  runGit(['--git-dir', f.metadata, 'multi-pack-index', 'write']);
  for (const oid of [large, f.blob, f.tree, f.commit]) await rm(path.join(f.metadata, 'objects', oid.slice(0, 2), oid.slice(2)));
  expect(runGit(['--git-dir',f.metadata,'rev-parse','HEAD^{commit}']).toString('ascii').trim()).toBe(f.commit);
  const stat = await io.stat(packPath); expect(stat.size).toBeGreaterThan(64 * 1024 * 1024);
  const staged = path.join(root, 'private'); await mkdir(staged); const meta = await captureGitMetadata(guard, f.workspace, [f.workspace], staged);
  // Compare the 65 MiB packs by length and digest: a structural toEqual walks
  // every byte index as a property key and exhausted the default V8 heap on
  // 6 GB hosts (macOS arm64). A digest match still proves byte identity.
  const digest = (bytes: Buffer) => [bytes.length, createHash('sha256').update(bytes).digest('hex')];
  try { expect(digest(await readFile(path.join(meta.gitDir, 'objects/pack', path.basename(packPath))))).toEqual(digest(await readFile(packPath))); } finally { await meta.cleanup(); }
  const captured = await captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review'); try { expect((captured.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); } finally { await captured.snapshot.cleanup(); }
  const controller = new AbortController(); controller.abort(); await expect(captureOperationSnapshot(guard, f.args, [f.workspace], controller.signal, undefined, 'changes_review')).rejects.toThrow('CANCELLED');
  const outside = path.join(root, 'outside'); await mkdir(outside); await symlink(outside, path.join(f.metadata, 'escaped'), process.platform === 'win32' ? 'junction' : 'dir');
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
}), 120_000);

it('decodes quoted alternate paths before grants and supplies only rewritten private paths to Git', async () => withFixture(async (f, root) => {
  const io = await import('node:fs/promises'), original = path.join(f.metadata,'objects'), alternate = path.join(root,'objects space');
  await io.rename(original,alternate); await mkdir(path.join(original,'info'),{recursive:true});
  const quoted = '"' + alternate.split(path.sep).join('/').replace(/ /g,'\\040') + '"\n';
  await writeFile(path.join(original,'info/alternates'),'# comment\n'+quoted);
  const real = runGit(['--git-dir',f.metadata,'rev-parse','HEAD^{commit}']).toString('ascii').trim(); expect(real).toBe(f.commit);
  await expect(captureOperationSnapshot(guard,f.args,[f.workspace],undefined,undefined,'changes_review')).rejects.toThrow('outside'); expect(await calls(f.log)).toEqual([]);
  const captured = await captureOperationSnapshot(guard,f.args,[f.workspace,alternate],undefined,undefined,'changes_review');
  try { expect((captured.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); } finally { await captured.snapshot.cleanup(); }
}));

it('cancels and reaps an actual native metadata stream while its bounded output pipe is held', async () => {
  const io = await import('node:fs/promises'), root = await io.realpath(await io.mkdtemp(path.join(os.tmpdir(),'ud-git-stream-cancel-')));
  try { const file = await io.open(path.join(root,'large.pack'),'wx'); try { await file.truncate(70*1024*1024); } finally { await file.close(); }
    const id = await guardedGrant(guard,root,[root]), control = new AbortController(), stream = guardedReadStream(guard,root,'large.pack',70*1024*1024,id,control.signal);
    const first = await stream.next(); expect(first.done).toBe(false); expect(first.value!.length).toBeGreaterThan(0); control.abort(); await expect(stream.next()).rejects.toThrow('WORKER_CANCELLED');
  } finally { await io.rm(root,{recursive:true,force:true}); }
});

async function expandedConfigFixture(kind: 'prefix' | 'named-user', f: Awaited<ReturnType<typeof fixture>>, root: string) {
  const target = path.join(root,'scope','selected.cfg'); await mkdir(path.dirname(target)); await writeFile(target,'[branch "main"]\nmerge=refs/heads/main\n');
  const probe = path.join(root,'probe.cfg'), quoted = (value:string)=>'"'+value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"';
  const expand = async (literal:string) => { await writeFile(probe,'[paths]\nvalue='+quoted(literal)+'\n'); return runGit(['config','--no-includes','--file',probe,'--null','--path','paths.value']).subarray(0,-1).toString('utf8'); };
  // The POSIX root account remains available when the confined test UID has
  // no passwd entry. This only expands a path; it never reads that home.
  const marker = kind === 'prefix' ? '%(prefix)/' : '~root/';
  const base = await expand(marker);
  const literals = [marker+path.relative(base,target).split(path.sep).join('/')];
  const original = await readFile(path.join(f.metadata,'config'));
  for (const literal of literals) {
    await rm(f.log,{force:true}); await writeFile(path.join(f.metadata,'config'),Buffer.concat([original,Buffer.from('\n[include]\npath='+quoted(literal)+'\n')]));
    await expect(captureOperationSnapshot(guard,f.args,[f.workspace],undefined,undefined,'changes_review')).rejects.toThrow('outside');
    const denied = await calls(f.log); expect(denied).toHaveLength(1); expect(denied[0]!.args).toContain('--no-includes'); expect(denied[0]!.args).not.toContain('--git-dir'); expect(denied[0]!.cwd).toContain('.git-private-');
    await rm(f.log,{force:true}); const captured = await captureOperationSnapshot(guard,f.args,[f.workspace,path.dirname(target)],undefined,undefined,'changes_review');
    try { expect((captured.brokerEvidence!.git_base as {resolved_commit:string}).resolved_commit).toBe(f.commit); const all = await calls(f.log); expect(all.filter(call=>call.args.includes('--no-includes'))).toHaveLength(1); for (const call of all) expect(call.args).not.toContain(path.join(f.metadata,'config')); } finally { await captured.snapshot.cleanup(); }
  }
}
it('preserves Git installation-prefix expansion using only isolated product-authored config', async () => withFixture((f, root) => expandedConfigFixture('prefix', f, root)), process.platform === 'win32' ? 60_000 : 15_000);
posixTest('preserves native POSIX Git named-user expansion using only isolated product-authored config', async () => withFixture((f, root) => expandedConfigFixture('named-user', f, root)), 15_000);
if (process.platform === 'win32') it('Windows Git named-user expansion refusal stops before repository invocation and preserves source config', async () => withFixture(async f => {
  const config = path.join(f.metadata, 'config');
  const selected = Buffer.concat([await readFile(config), Buffer.from(`\n[include]\npath=~${os.userInfo().username}/ud-fixture-selected.cfg\n`)]);
  await writeFile(config, selected); await rm(f.log, { force: true });
  await expect(captureOperationSnapshot(guard, f.args, [f.workspace], undefined, undefined, 'changes_review')).rejects.toThrow('GIT_CONFIG_PATH_EXPANSION_UNAVAILABLE');
  const denied = await calls(f.log); expect(denied).toHaveLength(1);
  expect(denied[0]!.args).toContain('--no-includes'); expect(denied[0]!.args).not.toContain('--git-dir');
  expect(denied[0]!.cwd).toContain('.git-private-'); expect(await readFile(config)).toEqual(selected);
}), 60_000);
