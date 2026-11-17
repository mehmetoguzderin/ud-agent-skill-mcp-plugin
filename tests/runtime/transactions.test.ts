import { describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { JournalStore, sha256 } from '../../packages/workspace/src/journal.js';
import { GuardedWorkspace, TransactionBroker } from '../../packages/workspace/src/transactions.js';
import type { Candidate, SecureWorkspace } from '../../packages/workspace/src/transactions.js';

const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');

async function fixture<T>(run: (context: { root: string; store: JournalStore; files: SecureWorkspace; guarded: GuardedWorkspace }) => Promise<T>): Promise<T> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-tx-'));
  try {
    const workspace = path.join(base, 'workspace');
    const state = path.join(base, 'state');
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(workspace, 'a.conllu'), 'first\r\n', { mode: 0o640 });
    await chmod(path.join(workspace, 'a.conllu'), 0o640);
    await writeFile(path.join(workspace, 'b.conllu'), 'second\n', { mode: 0o600 });
    const root = await realpath(workspace);
    const guarded = await GuardedWorkspace.open(root, guard, [root]);
    const files: SecureWorkspace = {
      root: guarded.root, identity: guarded.identity, metadataPreservationVerified: guarded.metadataPreservationVerified,
      read: filename => guarded.read(filename),
      replace: (filename, before, bytes) => guarded.replace(filename, before, bytes),
      readOptional: filename => guarded.readOptional(filename),
      create: (filename, bytes, metadata) => guarded.create(filename, bytes, metadata),
      remove: (filename, before, metadata) => guarded.remove(filename, before, metadata),
      releaseMetadata: (filename, metadata) => guarded.releaseMetadata(filename, metadata),
      metadata: (filename, before) => guarded.metadata(filename, before),
      flushParent: filename => guarded.flushParent(filename),
      missingParents: filename => guarded.missingParents(filename),
      createDirectory: (filename, token) => guarded.createDirectory(filename, token),
      releaseDirectory: (filename, token, identity) => guarded.releaseDirectory(filename, token, identity),
      removeDirectory: (filename, token, identity) => guarded.removeDirectory(filename, token, identity),
    };
    return await run({ root, store: await JournalStore.open(state, guard), files, guarded });
  } finally { await rm(base, { recursive: true, force: true }); }
}

function candidate(filename: string, before: string, after: string): Candidate {
  return { path: filename, before_sha256: sha256(Buffer.from(before)), after_base64: Buffer.from(after).toString('base64') };
}

function failSecondReplace(files: SecureWorkspace, afterWrite: boolean): SecureWorkspace {
  let count = 0;
  return {
    root: files.root, identity: files.identity, metadataPreservationVerified: files.metadataPreservationVerified,
    read: filename => files.read(filename),
    replace: async (filename, before, bytes) => {
      count++;
      if (count === 2 && !afterWrite) throw new Error('injected write failure');
      await files.replace(filename, before, bytes);
      if (count === 2 && afterWrite) throw new Error('injected post-rename failure');
    },
  };
}

describe('recoverable transactions', () => {
  it('rejects corrupt persisted state before recovery and retains compatible version-one journals', async () => fixture(async ({ root, store, files }) => {
    const id = sha256('persisted-state');
    const original = { version: 1 as const, id, request_hash: sha256('request'), workspace: root, identity: files.identity, phase: 'prepared' as const, entries: [{ path: 'a.conllu', before: sha256('first\r\n'), after: sha256('next'), state: 'pending' as const }] };
    await store.create(original);
    const target = path.join(store.root, 'transactions', id, 'journal.json');
    const corrupt: unknown[] = [null, [], { ...original, id: sha256('wrong') }, { ...original, version: 2 }, { ...original, workspace: 'relative' }, { ...original, identity: { device: 1, inode: '1' } }, { ...original, request_hash: 'invalid' }, { ...original, phase: 'success' }, { ...original, entries: [] }, { ...original, entries: Array(1001).fill(original.entries[0]) }, { ...original, message: '\0' }, { ...original, entries: [{ ...original.entries[0], path: '../escape' }] }, { ...original, entries: [{ ...original.entries[0], path: 'a\\escape' }] }, { ...original, entries: [original.entries[0], { ...original.entries[0], path: 'A.CONLLU' }] }, { ...original, entries: [{ ...original.entries[0], before: undefined }] }, { ...original, entries: [{ ...original.entries[0], before: null, after: null }] }, { ...original, entries: [{ ...original.entries[0], after: sha256('next').toUpperCase() }] }, { ...original, entries: [{ ...original.entries[0], state: 'done' }] }, { ...original, entries: [{ ...original.entries[0], metadata: [] }] }, { ...original, directories: [{ path: 'new', token: 'invalid', state: 'planned' }] }, { ...original, directories: [{ path: '../new', token: sha256('token'), state: 'planned' }] }, { ...original, directories: [{ path: 'new', token: sha256('token'), state: 'created' }] }, { ...original, directories: [{ path: 'new', token: sha256('token'), state: 'created', identity: { device: '1', inode: '-1' } }] }, { ...original, directories: [{ path: 'new', token: sha256('token'), state: 'unknown' }] }];
    for (const value of corrupt) {
      await writeFile(target, JSON.stringify(value));
      await expect(store.load(id)).rejects.toThrow('Transaction journal is invalid.');
    }
    await writeFile(target, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])); await expect(store.load(id)).rejects.toThrow('Transaction journal is invalid.');
    const legacy = { ...original, extension: { retained: true } };
    await writeFile(target, JSON.stringify(legacy));
    expect(await store.load(id)).toEqual(legacy);
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    await expect(store.saveAsset(id, 1000, 'before', Buffer.alloc(0))).rejects.toThrow('asset identity');
    await expect(store.saveAsset(id, 0, '../journal.json' as 'before', Buffer.alloc(0))).rejects.toThrow('asset identity');
    await expect(store.loadAsset(id, -1, 'after', sha256(''))).rejects.toThrow('asset identity');
    await expect(store.loadAsset(id, 0, 'after', 'invalid')).rejects.toThrow('asset fingerprint');
  }));

  it('stops after grant cancellation between files and retains recoverable originals', async () => fixture(async ({ root, store, files }) => {
    const controller = new AbortController(); let writes = 0;
    const cancelAfterFirst: SecureWorkspace = { ...files, replace: async (name, before, bytes) => { await files.replace(name, before, bytes); writes++; controller.abort(); } };
    const broker = new TransactionBroker(store, cancelAfterFirst);
    const edits = [candidate('a.conllu', 'first\r\n', 'new first\n'), candidate('b.conllu', 'second\n', 'new second\n')];
    await expect(broker.apply(edits, 'cancelled-write', controller.signal)).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED: TRANSACTION_CANCELLED');
    expect(writes).toBe(1); expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('new first\n'); expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('second\n');
    expect((await new TransactionBroker(store, files).recover(sha256(`${root}\0cancelled-write`))).status).toBe('rolled_back');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    await expect(new TransactionBroker(store, files).apply(edits, 'already-cancelled', controller.signal)).rejects.toThrow('TRANSACTION_CANCELLED');
    expect(await store.load(sha256(`${root}\0already-cancelled`))).toBeUndefined();
  }));

  it('creates nested output parents and removes every ownership marker after commit', async () => fixture(async ({ root, store, guarded }) => {
    const broker = new TransactionBroker(store, guarded);
    const edits: Candidate[] = [{ path: 'new/deep/output.txt', before_sha256: null, after_base64: Buffer.from('exported').toString('base64') }];
    expect((await broker.preview(edits)).status).toBe('preview');
    expect(await guarded.readOptional('new/deep/output.txt')).toBeNull();
    expect(await broker.apply(edits, 'nested-create')).toMatchObject({ status: 'completed' });
    expect(await readFile(path.join(root, 'new/deep/output.txt'), 'utf8')).toBe('exported');
    expect(await readdir(path.join(root, 'new'))).toEqual(['deep']);
    expect(await readdir(path.join(root, 'new/deep'))).toEqual(['output.txt']);
    expect(await broker.apply(edits, 'nested-create')).toMatchObject({ status: 'completed', replayed: true });
  }));

  it('reconciles lost directory-create responses and preserves unrecognized contents', async () => fixture(async ({ root, store, files, guarded }) => {
    const faulty: SecureWorkspace = { ...files, createDirectory: async (filename, token) => { await guarded.createDirectory(filename, token); throw new Error('lost directory response'); } };
    const edit: Candidate[] = [{ path: 'new/output.txt', before_sha256: null, after_base64: Buffer.from('output').toString('base64') }];
    await expect(new TransactionBroker(store, faulty).apply(edit, 'lost-directory')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    const broker = new TransactionBroker(store, guarded);
    expect(await broker.recover(sha256(`${root}\0lost-directory`))).toMatchObject({ status: 'rolled_back' });
    expect(await guarded.readOptional('new/output.txt')).toBeNull();
    const next: SecureWorkspace = { ...files, create: async () => { throw new Error('stop before file'); } };
    await expect(new TransactionBroker(store, next).apply(edit, 'unrecognized-directory')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    await writeFile(path.join(root, 'new', 'external.txt'), 'retain');
    expect(await broker.recover(sha256(`${root}\0unrecognized-directory`))).toMatchObject({ status: 'conflict' });
    expect(await readFile(path.join(root, 'new/external.txt'), 'utf8')).toBe('retain');
  }));

  it('retries after interruption between transaction directory creation and its first journal write', async () => fixture(async ({ root, store, files }) => {
    const key = 'empty-orphan';
    const id = sha256(`${root}\0${key}`);
    const directory = path.join(store.root, 'transactions', id);
    await mkdir(directory, { mode: 0o700 }); // Simulates the precise pre-journal crash window.
    expect(await store.load(id)).toBeUndefined();
    const broker = new TransactionBroker(store, files);
    const edits = [candidate('a.conllu', 'first\r\n', 'new')];
    expect(await broker.apply(edits, key)).toMatchObject({ status: 'completed', transaction_id: id });
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('new');
    expect(await broker.apply(edits, key)).toMatchObject({ status: 'completed', replayed: true });
  }));

  it('retains unknown orphan contents and never starts an edit', async () => fixture(async ({ root, store, files }) => {
    const key = 'unknown-orphan';
    const directory = path.join(store.root, 'transactions', sha256(`${root}\0${key}`));
    await mkdir(directory, { mode: 0o700 });
    const evidence = path.join(directory, 'unrecognized');
    await writeFile(evidence, 'retain me', { mode: 0o600 });
    const broker = new TransactionBroker(store, files);
    await expect(broker.apply([candidate('a.conllu', 'first\r\n', 'new')], key)).rejects.toThrow('TRANSACTION_ORPHAN_NOT_EMPTY');
    expect(await readFile(evidence, 'utf8')).toBe('retain me');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
  }));

  it('does not adopt symlinked or nonprivate transaction directories', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, files);
    const edit = [candidate('a.conllu', 'first\r\n', 'new')];
    const external = path.join(store.root, 'external'); await mkdir(external, { mode: 0o700 });
    const symlinkId = sha256(`${root}\0symlink-orphan`);
    await symlink(external, path.join(store.root, 'transactions', symlinkId));
    await expect(broker.apply(edit, 'symlink-orphan')).rejects.toThrow(process.platform === 'win32' ? 'Filesystem guard rejected' : 'not private and user-owned');
    const unsafeId = sha256(`${root}\0nonprivate-orphan`);
    const unsafe = path.join(store.root, 'transactions', unsafeId);
    await mkdir(unsafe, { mode: 0o700 }); await chmod(unsafe, 0o755);
    if (process.platform === 'win32') execFileSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe'), [unsafe, '/grant', '*S-1-1-0:(RX)'], { stdio: 'pipe' });
    await expect(broker.apply(edit, 'nonprivate-orphan')).rejects.toThrow(process.platform === 'win32' ? 'Filesystem guard rejected' : 'not private and user-owned');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
  }));

  it('does not replace a journal created by a competing attempt', async () => fixture(async ({ root, store, files }) => {
    const id = sha256(`${root}\0competing`);
    const journal = { version: 1 as const, id, request_hash: sha256('request'), workspace: root, identity: files.identity, phase: 'prepared' as const, entries: [{ path: 'a.conllu', before: sha256('first\r\n'), after: sha256('new'), state: 'pending' as const }] };
    await store.create(journal);
    const filename = path.join(store.root, 'transactions', id, 'journal.json');
    const before = await readFile(filename, 'utf8');
    await expect(store.create({ ...journal, request_hash: sha256('other request') })).rejects.toThrow('TRANSACTION_ORPHAN_NOT_EMPTY');
    expect(await readFile(filename, 'utf8')).toBe(before);
  }));

  it('does not replace a corrupt preexisting journal', async () => fixture(async ({ root, store, files }) => {
    const key = 'corrupt-journal';
    const directory = path.join(store.root, 'transactions', sha256(`${root}\0${key}`));
    await mkdir(directory, { mode: 0o700 });
    const journal = path.join(directory, 'journal.json'); await writeFile(journal, '{', { mode: 0o600 });
    const broker = new TransactionBroker(store, files);
    await expect(broker.apply([candidate('a.conllu', 'first\r\n', 'new')], key)).rejects.toThrow();
    expect(await readFile(journal, 'utf8')).toBe('{');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
  }));

  it('previews without mutation, applies exact bytes, preserves modes, and returns idempotent outcomes', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, files);
    const mode = (await stat(path.join(root, 'a.conllu'))).mode & 0o777;
    const edit = [candidate('a.conllu', 'first\r\n', 'changed\n')];
    expect((await broker.preview(edit)).status).toBe('preview');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect((await broker.apply(edit, 'request-1')).status).toBe('completed');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('changed\n');
    expect((await stat(path.join(root, 'a.conllu'))).mode & 0o777).toBe(mode);
    expect(await broker.apply(edit, 'request-1')).toMatchObject({ status: 'completed', replayed: true });
    await expect(broker.apply([candidate('a.conllu', 'changed\n', 'other')], 'request-1')).rejects.toThrow('IDEMPOTENCY_KEY_REUSED');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('changed\n');
  }));

  it('enables native apply only when the helper advertises metadata preservation', async () => fixture(async ({ root, store, files, guarded }) => {
    const edits = [candidate('a.conllu', 'first\r\n', 'new')];
    const broker = new TransactionBroker(store, { ...files, metadataPreservationVerified: false });
    expect((await broker.preview(edits)).status).toBe('preview');
    await expect(broker.apply(edits, 'metadata-check')).rejects.toThrow('METADATA_PRESERVATION_UNVERIFIED');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect((await new TransactionBroker(store, guarded).apply(edits, 'native-metadata')).status).toBe('completed');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('new');
  }));

  it('previews and commits exclusive creation and checked deletion with idempotent replay', async () => fixture(async ({ root, store, guarded }) => {
    const broker = new TransactionBroker(store, guarded);
    const edits: Candidate[] = [
      { path: 'created.conllu', before_sha256: null, after_base64: Buffer.from('created\r\n').toString('base64') },
      { path: 'b.conllu', before_sha256: sha256('second\n'), after_base64: null },
    ];
    expect((await broker.preview(edits)).status).toBe('preview');
    expect(await guarded.readOptional('created.conllu')).toBeNull();
    expect(await broker.apply(edits, 'create-delete')).toMatchObject({ status: 'completed' });
    expect(await readFile(path.join(root, 'created.conllu'), 'utf8')).toBe('created\r\n');
    expect(await guarded.readOptional('b.conllu')).toBeNull();
    expect(await broker.apply(edits, 'create-delete')).toMatchObject({ status: 'completed', replayed: true });
    await expect(broker.apply([{ ...edits[0]!, after_base64: Buffer.from('clobber').toString('base64') }], 'different')).rejects.toThrow('STALE_PRECONDITION');
  }));

  it('restores deleted bytes and metadata after an interrupted rename plan', async () => fixture(async ({ root, store, files, guarded }) => {
    const mode = (await stat(path.join(root, 'a.conllu'))).mode;
    const faulty: SecureWorkspace = { ...files, create: async () => { throw new Error('injected create failure'); } };
    const edits: Candidate[] = [
      { path: 'a.conllu', before_sha256: sha256('first\r\n'), after_base64: null },
      { path: 'renamed.conllu', before_sha256: null, after_base64: Buffer.from('first\r\n').toString('base64') },
    ];
    await expect(new TransactionBroker(store, faulty).apply(edits, 'rename-interrupted')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    expect(await guarded.readOptional('a.conllu')).toBeNull();
    expect(await new TransactionBroker(store, guarded).recover(sha256(`${root}\0rename-interrupted`))).toMatchObject({ status: 'rolled_back' });
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect((await stat(path.join(root, 'a.conllu'))).mode).toBe(mode);
    expect(await guarded.readOptional('renamed.conllu')).toBeNull();
  }));

  it('restores verified backups after interruption between file replacements', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, failSecondReplace(files, false));
    const edits = [candidate('a.conllu', 'first\r\n', 'A'), candidate('b.conllu', 'second\n', 'B')];
    await expect(broker.apply(edits, 'request-2')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('A');
    expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('second\n');
    const id = sha256(`${root}\0request-2`);
    expect(await broker.recover(id)).toMatchObject({ status: 'rolled_back', replayed: true });
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('second\n');
    expect(await broker.apply(edits, 'request-2')).toMatchObject({ status: 'rolled_back', replayed: true });
  }));

  it('reconciles a lost response after all replacements without repeating the edit', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, failSecondReplace(files, true));
    const edits = [candidate('a.conllu', 'first\r\n', 'A'), candidate('b.conllu', 'second\n', 'B')];
    await expect(broker.apply(edits, 'request-3')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    expect(await broker.recover(sha256(`${root}\0request-3`))).toMatchObject({ status: 'completed', replayed: true });
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('A');
    expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('B');
  }));

  it('retains evidence and does not overwrite a conflicting external edit', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, failSecondReplace(files, false));
    const edits = [candidate('a.conllu', 'first\r\n', 'A'), candidate('b.conllu', 'second\n', 'B')];
    await expect(broker.apply(edits, 'request-4')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    await writeFile(path.join(root, 'b.conllu'), 'external');
    expect(await broker.recover(sha256(`${root}\0request-4`))).toMatchObject({ status: 'conflict' });
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('A');
    expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('external');
  }));

  it('does not follow a substituted recovery asset or overwrite the source', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, failSecondReplace(files, false));
    const edits = [candidate('a.conllu', 'first\r\n', 'A'), candidate('b.conllu', 'second\n', 'B')];
    await expect(broker.apply(edits, 'asset-swap')).rejects.toThrow('TRANSACTION_RECOVERY_REQUIRED');
    const id = sha256(`${root}\0asset-swap`);
    const asset = path.join(store.root, 'transactions', id, '0.before');
    await unlink(asset);
    await symlink('/etc/passwd', asset);
    await expect(broker.recover(id)).rejects.toThrow();
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('A');
    expect(await readFile(path.join(root, 'b.conllu'), 'utf8')).toBe('second\n');
  }));

  it('rejects stale fingerprints, path traversal, collisions, and stale locks', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, files);
    await expect(broker.preview([candidate('a.conllu', 'wrong', 'new')])).rejects.toThrow('STALE_PRECONDITION');
    await expect(broker.preview([candidate('../a.conllu', 'first\r\n', 'new')])).rejects.toThrow('unsafe');
    await expect(broker.preview([candidate('a.conllu', 'first\r\n', 'A'), candidate('A.conllu', 'first\r\n', 'B')])).rejects.toThrow('collide');
    const lock = path.join(store.root, 'locks', sha256(root));
    await mkdir(lock);
    await expect(broker.apply([candidate('a.conllu', 'first\r\n', 'new')], 'request-5')).rejects.toThrow('WORKSPACE_LOCKED_OR_STALE');
    expect((await stat(lock)).isDirectory()).toBe(true);
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
  }));

  it('rejects stale apply before creating recovery evidence or changing bytes', async () => fixture(async ({ root, store, files }) => {
    const broker = new TransactionBroker(store, files);
    const key = 'independent-stale-apply';
    await expect(broker.apply([candidate('a.conllu', 'outdated source', 'replacement')], key)).rejects.toThrow('STALE_PRECONDITION');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect(await store.load(sha256(`${root}\0${key}`))).toBeUndefined();
  }));

  it('refuses an unauthorized workspace and rejects a replaced root identity', async () => fixture(async ({ root, store, files }) => {
    await expect(GuardedWorkspace.open(root, guard, [])).rejects.toThrow('authorized roots');
    const moved = `${root}-original`;
    await rename(root, moved);
    await mkdir(root);
    await writeFile(path.join(root, 'a.conllu'), 'first\r\n');
    const broker = new TransactionBroker(store, files);
    await expect(broker.apply([candidate('a.conllu', 'first\r\n', 'new')], 'root-swap')).rejects.toThrow('WORKSPACE_ROOT_CHANGED');
    expect(await readFile(path.join(root, 'a.conllu'), 'utf8')).toBe('first\r\n');
    expect(await readFile(path.join(moved, 'a.conllu'), 'utf8')).toBe('first\r\n');
  }));
});
