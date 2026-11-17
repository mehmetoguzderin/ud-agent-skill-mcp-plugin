import path from 'node:path';
import { guardedCapabilities, guardedCreate, guardedFlushParent, guardedGrant, guardedList, guardedMetadata, guardedOwnedDirectory, guardedRead, guardedReadOptional, guardedReleaseMetadata, guardedRemove, guardedReplace } from './guard.js';
import type { GuardIdentity, GuardMetadata } from './guard.js';
import { JournalStore, sha256 } from './journal.js';
import type { Journal, JournalDirectory, JournalEntry } from './journal.js';
import { randomUUID } from 'node:crypto';
import { portablePathKey, validPortablePath } from './portable-path.js';

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TRANSACTION_BYTES = 512 * 1024 * 1024;
const MAX_ENTRIES = 1000;

export type Candidate = { path: string; before_sha256: string | null; after_base64: string | null };
export type ReadPrecondition = { path: string; sha256: string | null };
export type TransactionOutcome = {
  status: 'preview' | 'completed' | 'rolled_back' | 'conflict'; transaction_id?: string;
  files: { path: string; before_sha256: string | null; after_sha256: string | null }[];
  replayed?: boolean; message?: string; limitations: string[];
};
type Prepared = { path: string; before: string | null; after: string | null; bytes: Buffer | null };
const LIMITATIONS = [
  'Replacements are atomic per file, not globally atomic across multiple files.',
  'Uncooperative writers can race the fingerprint check and replacement; there is no portable filesystem compare-and-swap.',
];

export interface SecureWorkspace {
  readonly root: string;
  readonly identity: GuardIdentity;
  readonly metadataPreservationVerified: boolean;
  readonly metadataModel?: string | undefined;
  read(relative: string): Promise<Buffer>;
  replace(relative: string, beforeSha256: string, bytes: Buffer): Promise<void>;
  readOptional?(relative: string): Promise<Buffer | null>;
  metadata?(relative: string, beforeSha256: string): Promise<GuardMetadata>;
  create?(relative: string, bytes: Buffer, metadata?: GuardMetadata): Promise<void>;
  remove?(relative: string, beforeSha256: string, metadata?: GuardMetadata): Promise<void>;
  releaseMetadata?(relative: string, metadata: GuardMetadata): Promise<void>;
  flushParent?(relative: string): Promise<void>;
  missingParents?(relative: string): Promise<string[]>;
  createDirectory?(relative: string, token: string): Promise<GuardIdentity>;
  releaseDirectory?(relative: string, token: string, expected: GuardIdentity): Promise<void>;
  removeDirectory?(relative: string, token: string, expected?: GuardIdentity): Promise<void>;
}

/** All reads and replacements use a guard-bound directory identity. */
export class GuardedWorkspace implements SecureWorkspace {
  private constructor(readonly root: string, readonly identity: GuardIdentity, private readonly guard: string, readonly metadataPreservationVerified: boolean, readonly metadataModel?: string) {}
  static async open(requestedRoot: string, guard: string, grantedRoots: readonly string[]): Promise<GuardedWorkspace> {
    if (!path.isAbsolute(requestedRoot) || !path.isAbsolute(guard)) throw new Error('Workspace and guard paths must be absolute.');
    const root = path.resolve(requestedRoot);
    const identity = await guardedGrant(guard, requestedRoot, grantedRoots);
    const capabilities = await guardedCapabilities(guard, root, identity);
    return new GuardedWorkspace(root, identity, guard, capabilities.metadataPreservation, capabilities.metadataModel);
  }
  async read(relative: string): Promise<Buffer> { return guardedRead(this.guard, this.root, relative, MAX_FILE_BYTES, this.identity); }
  async replace(relative: string, before: string, bytes: Buffer): Promise<void> { await guardedReplace(this.guard, this.root, relative, this.identity, before, bytes); }
  async readOptional(relative: string): Promise<Buffer | null> { return guardedReadOptional(this.guard, this.root, relative, this.identity); }
  async metadata(relative: string, before: string): Promise<GuardMetadata> { return guardedMetadata(this.guard, this.root, relative, this.identity, before); }
  async create(relative: string, bytes: Buffer, metadata?: GuardMetadata): Promise<void> { await guardedCreate(this.guard, this.root, relative, this.identity, bytes, metadata); }
  async remove(relative: string, before: string, metadata?: GuardMetadata): Promise<void> { await guardedRemove(this.guard, this.root, relative, this.identity, before, metadata); }
  async releaseMetadata(relative: string, metadata: GuardMetadata): Promise<void> { await guardedReleaseMetadata(this.guard, this.root, relative, this.identity, metadata); }
  async flushParent(relative: string): Promise<void> { await guardedFlushParent(this.guard, this.root, relative, this.identity); }
  async missingParents(relative: string): Promise<string[]> {
    const parts = relative.split('/'); parts.pop();
    let parent = '.';
    for (let index = 0; index < parts.length; index++) {
      const found = (await guardedList(this.guard, this.root, parent, this.identity)).find(item => item.name === parts[index]);
      if (!found) return parts.slice(index).map((_, offset) => parts.slice(0, index + offset + 1).join('/'));
      if (found.kind !== 'directory') throw new Error('Output parent is not an ordinary directory.');
      parent = parts.slice(0, index + 1).join('/');
    }
    return [];
  }
  async createDirectory(relative: string, token: string): Promise<GuardIdentity> {
    const created = await guardedOwnedDirectory(this.guard, this.root, relative, this.identity, token, 'mkdir-owned');
    if (!created) throw new Error('Owned directory was not created.'); return created;
  }
  async releaseDirectory(relative: string, token: string, expected: GuardIdentity): Promise<void> { await guardedOwnedDirectory(this.guard, this.root, relative, this.identity, token, 'release-owned', expected); }
  async removeDirectory(relative: string, token: string, expected?: GuardIdentity): Promise<void> { await guardedOwnedDirectory(this.guard, this.root, relative, this.identity, token, 'rmdir-owned', expected); }
}

export function validCandidatePath(value: string): boolean {
  return validPortablePath(value);
}

function prepare(candidates: Candidate[]): Prepared[] {
  if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > MAX_ENTRIES) throw new Error('A transaction needs between 1 and 1000 candidate files.');
  const names = new Set<string>();
  let total = 0;
  const result = candidates.map(candidate => {
    if (!candidate || typeof candidate.path !== 'string' || !validCandidatePath(candidate.path)) throw new Error('Candidate has an unsafe relative path.');
    const normalized = portablePathKey(candidate.path);
    if (names.has(normalized)) throw new Error('Candidate paths collide by case or Unicode normalization.');
    names.add(normalized);
    if (candidate.before_sha256 !== null && !/^[0-9a-f]{64}$/.test(candidate.before_sha256)) throw new Error('Candidate has an invalid before fingerprint.');
    if (candidate.after_base64 === null) {
      if (candidate.before_sha256 === null) throw new Error('Candidate cannot be absent both before and after.');
      return { path: candidate.path, before: candidate.before_sha256, after: null, bytes: null };
    }
    if (typeof candidate.after_base64 !== 'string' || candidate.after_base64.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(candidate.after_base64)) throw new Error('Candidate bytes must be canonical bounded base64.');
    const bytes = Buffer.from(candidate.after_base64, 'base64');
    if (bytes.toString('base64') !== candidate.after_base64 || bytes.length > MAX_FILE_BYTES) throw new Error('Candidate bytes are invalid or exceed the per-file limit.');
    total += bytes.length;
    return { path: candidate.path, before: candidate.before_sha256, after: sha256(bytes), bytes };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (total > MAX_TRANSACTION_BYTES) throw new Error('Transaction exceeds its byte budget.');
  return result;
}

function outcome(journal: Journal, status: TransactionOutcome['status'], replayed = false): TransactionOutcome {
  return {
    status, transaction_id: journal.id,
    files: journal.entries.map(file => ({ path: file.path, before_sha256: file.before, after_sha256: file.after })),
    replayed, ...(journal.message ? { message: journal.message } : {}), limitations: [...LIMITATIONS],
  };
}

function checkJournal(journal: Journal, workspace: SecureWorkspace): void {
  if (journal.workspace !== workspace.root || journal.identity.device !== workspace.identity.device || journal.identity.inode !== workspace.identity.inode) throw new Error('WORKSPACE_ROOT_CHANGED: journal does not belong to this workspace identity.');
  if (!['prepared', 'committing', 'completed', 'recovering', 'rolled_back', 'conflict'].includes(journal.phase) || journal.entries.length === 0 || journal.entries.length > MAX_ENTRIES) throw new Error('Invalid transaction journal.');
  const seen = new Set<string>();
  for (const entry of journal.entries) {
    const normalized = typeof entry.path === 'string' ? portablePathKey(entry.path) : '';
    if (typeof entry.path !== 'string' || !validCandidatePath(entry.path) || seen.has(normalized) || (entry.before !== null && !/^[0-9a-f]{64}$/.test(entry.before)) || (entry.after !== null && !/^[0-9a-f]{64}$/.test(entry.after)) || (entry.before === null && entry.after === null) || !['pending', 'writing', 'applied'].includes(entry.state)) throw new Error('Invalid transaction journal entry.');
    seen.add(normalized);
  }
  if (journal.directories !== undefined) {
    if (!Array.isArray(journal.directories) || journal.directories.length > 1000) throw new Error('Invalid transaction directory inventory.');
    const names = new Set<string>();
    for (const directory of journal.directories) {
      if (!directory || !validCandidatePath(directory.path) || names.has(portablePathKey(directory.path)) || !/^[0-9a-f]{64}$/.test(directory.token) || !['planned', 'created', 'released', 'removed'].includes(directory.state)
          || (directory.identity !== undefined && (!/^\d+$/.test(directory.identity.device) || !/^\d+$/.test(directory.identity.inode))) || (['created', 'released'].includes(directory.state) && !directory.identity)) throw new Error('Invalid transaction directory entry.');
      names.add(portablePathKey(directory.path));
    }
  }
  prepareReadPreconditions(journal.read_preconditions ?? []);
}

function prepareReadPreconditions(values: readonly ReadPrecondition[]): ReadPrecondition[] {
  if (!Array.isArray(values) || values.length > 10000) throw new Error('Invalid transaction read preconditions.');
  const names = new Set<string>();
  return values.map(value => {
    if (!value || Object.keys(value).sort().join(',') !== 'path,sha256' || typeof value.path !== 'string' || !validCandidatePath(value.path) || names.has(portablePathKey(value.path)) || value.sha256 !== null && (typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256))) throw new Error('Invalid transaction read preconditions.');
    names.add(portablePathKey(value.path)); return { path: value.path, sha256: value.sha256 };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

/** Exact version-one request encoding, shared with completed-receipt replay. */
export function transactionRequestHash(workspace: string, identity: GuardIdentity, files: readonly { path: string; before: string | null; after: string | null }[], conditions: readonly ReadPrecondition[] = []): string {
  return sha256(JSON.stringify({ workspace, identity, files: files.map(file => ({ path: file.path, before: file.before, after: file.after })), ...(conditions.length ? { read_preconditions: conditions } : {}) }));
}

export class TransactionBroker {
  constructor(private readonly store: JournalStore, private readonly workspace: SecureWorkspace, private readonly verifyExternalPreconditions?: () => Promise<void>) {}
  private transactionOutcome(journal: Journal, status: TransactionOutcome['status'], replayed = false): TransactionOutcome {
    const result = outcome(journal, status, replayed);
    if (this.workspace.metadataModel === 'transactional-ntfs-same-object') result.limitations.push('Windows publishes each file through a committed NTFS transaction while retaining the original file object and its security metadata. TxF is filesystem-dependent and Microsoft warns that it may be unavailable in future Windows releases.');
    if (this.workspace.metadataModel === 'privileged-security-and-stream-capture') result.limitations.push('This Windows filesystem uses captured security descriptors and streams; the existing process token must hold the required security privileges.');
    return result;
  }

  async preview(candidates: Candidate[]): Promise<TransactionOutcome> {
    const prepared = prepare(candidates);
    for (const file of prepared) {
      if (await this.fingerprint(file.path) !== file.before) throw new Error(`STALE_PRECONDITION: ${file.path}`);
    }
    return { status: 'preview', files: prepared.map(file => ({ path: file.path, before_sha256: file.before, after_sha256: file.after })), limitations: [...LIMITATIONS] };
  }

  async apply(candidates: Candidate[], idempotencyKey: string, signal?: AbortSignal, readPreconditions: readonly ReadPrecondition[] = []): Promise<TransactionOutcome> {
    const checkCancellation = () => { if (signal?.aborted) throw new Error('TRANSACTION_CANCELLED'); };
    checkCancellation();
    if (!this.workspace.metadataPreservationVerified) throw new Error('METADATA_PRESERVATION_UNVERIFIED: edit apply is disabled until ACL and extended-attribute preservation is verified.');
    if (typeof idempotencyKey !== 'string' || idempotencyKey.length < 1 || idempotencyKey.length > 256) throw new Error('An idempotency key of at most 256 characters is required.');
    const prepared = prepare(candidates);
    const conditions = prepareReadPreconditions(readPreconditions);
    const requestHash = transactionRequestHash(this.workspace.root, this.workspace.identity, prepared, conditions);
    const id = sha256(`${this.workspace.root}\0${idempotencyKey}`);
    return this.store.withWorkspaceLock(this.workspace.root, async () => {
      checkCancellation();
      const existing = await this.store.load(id);
      if (existing) {
        checkJournal(existing, this.workspace);
        if (existing.request_hash !== requestHash) throw new Error('IDEMPOTENCY_KEY_REUSED: request or original fingerprints differ.');
        checkCancellation(); return this.reconcile(existing, true, signal);
      }
      await this.checkReadPreconditions(conditions, signal);
      const original: (Buffer | null)[] = [];
      const metadata: (GuardMetadata | undefined)[] = [];
      let originalBytes = 0;
      let metadataBytes = 0;
      const directoryPaths = new Map<string, string>();
      for (const file of prepared) {
        checkCancellation();
        if ((file.before === null || file.after === null) && (!this.workspace.create || !this.workspace.remove || !this.workspace.readOptional || !this.workspace.flushParent)) throw new Error('FILE_OPERATIONS_UNAVAILABLE: native creation, removal and durability are required.');
        const bytes = this.workspace.readOptional ? await this.workspace.readOptional(file.path) : await this.workspace.read(file.path);
        if ((bytes === null ? null : sha256(bytes)) !== file.before) throw new Error(`STALE_PRECONDITION: ${file.path}`);
        if (file.after === null && (!this.workspace.metadata || file.before === null)) throw new Error('FILE_METADATA_UNAVAILABLE: deletion recovery requires original metadata.');
        const savedMetadata = file.after === null ? await this.workspace.metadata!(file.path, file.before!) : undefined;
        if (savedMetadata?.preserved_file !== undefined && !this.workspace.releaseMetadata) throw new Error('FILE_METADATA_CLEANUP_UNAVAILABLE');
        metadataBytes += savedMetadata ? Buffer.byteLength(JSON.stringify(savedMetadata)) : 0;
        if (metadataBytes > 2 * 1024 * 1024) throw new Error('Transaction recovery metadata exceeds its byte budget.');
        originalBytes += bytes?.length ?? 0;
        if (originalBytes > MAX_TRANSACTION_BYTES) throw new Error('Transaction originals exceed their byte budget.');
        original.push(bytes); metadata.push(savedMetadata);
        if (file.before === null && this.workspace.missingParents) {
          for (const name of await this.workspace.missingParents(file.path)) {
            const key = portablePathKey(name);
            if (directoryPaths.has(key) && directoryPaths.get(key) !== name) throw new Error('Output parent directories collide by case or Unicode normalization.');
            directoryPaths.set(key, name);
          }
        }
      }
      if (directoryPaths.size > 1000) throw new Error('Transaction exceeds its parent-directory budget.');
      if (directoryPaths.size && (!this.workspace.createDirectory || !this.workspace.releaseDirectory || !this.workspace.removeDirectory)) throw new Error('DIRECTORY_OPERATIONS_UNAVAILABLE');
      const directories: JournalDirectory[] = [...directoryPaths.values()].sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : a > b ? 1 : 0)).map(name => ({ path: name, token: sha256(randomUUID() + randomUUID()), state: 'planned' }));
      const entries: JournalEntry[] = prepared.map((file, index) => ({ path: file.path, before: file.before, after: file.after, state: 'pending', ...(metadata[index] ? { metadata: metadata[index] } : {}) }));
      const journal: Journal = { version: 1, id, request_hash: requestHash, workspace: this.workspace.root, identity: this.workspace.identity, phase: 'prepared', entries, ...(directories.length ? { directories } : {}), ...(conditions.length ? { read_preconditions: conditions } : {}) };
      checkCancellation(); await this.store.create(journal);
      for (let i = 0; i < prepared.length; i++) {
        const before = original[i]; const file = prepared[i];
        if (!file) throw new Error('Transaction asset inventory is inconsistent.');
        if (before !== null && before !== undefined) await this.store.saveAsset(id, i, 'before', before);
        if (file.bytes !== null) await this.store.saveAsset(id, i, 'after', file.bytes);
      }
      try {
        // Recheck after validation, private asset writes and lock acquisition,
        // immediately before the first workspace directory/file mutation.
        await this.checkReadPreconditions(conditions, signal);
        for (const directory of directories) {
          checkCancellation();
          directory.identity = await this.workspace.createDirectory!(directory.path, directory.token);
          directory.state = 'created'; await this.store.save(journal);
        }
        checkCancellation(); journal.phase = 'committing';
        await this.store.save(journal);
        for (let i = 0; i < prepared.length; i++) {
          checkCancellation();
          await this.checkReadPreconditions(conditions, signal, journal.entries.slice(0, i));
          const file = prepared[i]; const entry = journal.entries[i];
          if (!file || !entry) throw new Error('Transaction inventory is inconsistent.');
          entry.state = 'writing';
          await this.store.save(journal);
          checkCancellation();
          if (file.before === null) await this.workspace.create!(file.path, file.bytes!);
          else if (file.after === null) await this.workspace.remove!(file.path, file.before, entry.metadata);
          else await this.workspace.replace(file.path, file.before, file.bytes!);
          await this.checkReadPreconditions(conditions, signal, journal.entries.slice(0, i + 1));
          checkCancellation(); entry.state = 'applied';
          await this.store.save(journal);
        }
        await this.checkReadPreconditions(conditions, signal, journal.entries);
        checkCancellation(); journal.phase = 'completed';
        await this.store.save(journal);
        checkCancellation(); await this.releaseDirectories(journal);
        await this.releaseMetadata(journal);
        return this.transactionOutcome(journal, 'completed');
      } catch (error: unknown) {
        // Retain all journal and asset bytes; the caller can reconcile under a new lock.
        const message = error instanceof Error ? error.message : 'Unknown transaction failure.';
        throw new Error(`TRANSACTION_RECOVERY_REQUIRED: ${message}`);
      }
    });
  }

  async recover(transactionId: string): Promise<TransactionOutcome> {
    if (!this.workspace.metadataPreservationVerified) throw new Error('METADATA_PRESERVATION_UNVERIFIED: recovery is disabled until ACL and extended-attribute preservation is verified.');
    return this.store.withWorkspaceLock(this.workspace.root, async () => {
      const journal = await this.store.load(transactionId);
      if (!journal) throw new Error('Transaction journal not found.');
      checkJournal(journal, this.workspace);
      return this.reconcile(journal, true);
    });
  }

  private async fingerprint(relative: string): Promise<string | null> {
    const bytes = this.workspace.readOptional ? await this.workspace.readOptional(relative) : await this.workspace.read(relative);
    return bytes === null ? null : sha256(bytes);
  }

  private async checkReadPreconditions(conditions: readonly ReadPrecondition[], signal?: AbortSignal, committed?: JournalEntry[]): Promise<void> {
    await this.verifyExternalPreconditions?.();
    for (const condition of conditions) {
      if (signal?.aborted) throw new Error('TRANSACTION_CANCELLED');
      const entry = committed?.find(item => item.path === condition.path);
      if (await this.fingerprint(condition.path) !== (entry ? entry.after : condition.sha256)) throw new Error(`STALE_DEPENDENCY_PRECONDITION: ${condition.path}`);
    }
  }

  private async recoveryReadPreconditions(journal: Journal, signal?: AbortSignal): Promise<boolean> {
    try { await this.checkReadPreconditions(journal.read_preconditions ?? [], signal, journal.entries); return true; }
    catch (error) {
      if (signal?.aborted) throw error;
      journal.phase = 'conflict'; journal.message = error instanceof Error ? error.message : 'Dependency state cannot be revalidated.';
      await this.store.save(journal); return false;
    }
  }

  private async releaseDirectories(journal: Journal): Promise<void> {
    for (const directory of journal.directories ?? []) {
      if (directory.state === 'released' || directory.state === 'removed') continue;
      if (!this.workspace.releaseDirectory || !directory.identity) throw new Error('DIRECTORY_OPERATIONS_UNAVAILABLE');
      await this.workspace.releaseDirectory(directory.path, directory.token, directory.identity);
      directory.state = 'released'; await this.store.save(journal);
    }
  }
  private async releaseMetadata(journal: Journal): Promise<void> {
    for (const entry of journal.entries) if (entry.metadata?.preserved_file !== undefined) { if (!this.workspace.releaseMetadata) throw new Error('FILE_METADATA_CLEANUP_UNAVAILABLE'); await this.workspace.releaseMetadata(entry.path, entry.metadata); }
  }

  private async removeDirectories(journal: Journal): Promise<boolean> {
    for (const directory of [...journal.directories ?? []].reverse()) {
      if (directory.state === 'removed') continue;
      if (!this.workspace.removeDirectory || directory.state === 'released') throw new Error('DIRECTORY_OPERATIONS_UNAVAILABLE');
      try { await this.workspace.removeDirectory(directory.path, directory.token, directory.identity); }
      catch (error) {
        journal.phase = 'conflict'; journal.message = `An owned output directory could not be safely removed: ${directory.path}`;
        await this.store.save(journal); return false;
      }
      directory.state = 'removed'; await this.store.save(journal);
    }
    return true;
  }

  private async reconcile(journal: Journal, replayed: boolean, signal?: AbortSignal): Promise<TransactionOutcome> {
    const checkCancellation = () => { if (signal?.aborted) throw new Error('TRANSACTION_RECOVERY_REQUIRED: TRANSACTION_CANCELLED'); }; checkCancellation();
    if (journal.phase === 'completed') { await this.releaseDirectories(journal); await this.releaseMetadata(journal); return this.transactionOutcome(journal, 'completed', replayed); }
    if (journal.phase === 'rolled_back') { await this.releaseMetadata(journal); return this.transactionOutcome(journal, 'rolled_back', replayed); }
    if (journal.phase === 'conflict') return this.transactionOutcome(journal, 'conflict', replayed);
    if (journal.phase === 'prepared') {
      if (!await this.removeDirectories(journal)) return this.transactionOutcome(journal, 'conflict', replayed);
      journal.phase = 'rolled_back'; journal.message = 'No file replacements were started.';
      await this.store.save(journal);
      await this.releaseMetadata(journal);
      return this.transactionOutcome(journal, 'rolled_back', replayed);
    }
    const current: (string | null)[] = [];
    for (const entry of journal.entries) {
      try { current.push(await this.fingerprint(entry.path)); }
      catch {
        journal.phase = 'conflict'; journal.message = `A file cannot be safely inspected: ${entry.path}`;
        await this.store.save(journal);
        return this.transactionOutcome(journal, 'conflict', replayed);
      }
    }
    for (let i = 0; i < journal.entries.length; i++) {
      const entry = journal.entries[i]; const hash = current[i];
      if (!entry || (hash !== entry.before && hash !== entry.after)) {
        journal.phase = 'conflict'; journal.message = `A file changed outside the transaction: ${entry?.path ?? 'unknown'}`;
        await this.store.save(journal);
        return this.transactionOutcome(journal, 'conflict', replayed);
      }
    }
    if (journal.phase === 'committing' && journal.entries.every((entry, index) => current[index] === entry.after)) {
      if (!await this.recoveryReadPreconditions(journal, signal)) return this.transactionOutcome(journal, 'conflict', replayed);
      // Repeat atomic replacement to establish data and directory durability if
      // the previous process failed after rename but before its flush returned.
      for (let i = 0; i < journal.entries.length; i++) {
        checkCancellation();
        if (!await this.recoveryReadPreconditions(journal, signal)) return this.transactionOutcome(journal, 'conflict', replayed);
        const entry = journal.entries[i]; if (!entry) throw new Error('Invalid transaction entry.');
        if (entry.after === null) { if (!this.workspace.flushParent) throw new Error('FILE_OPERATIONS_UNAVAILABLE'); await this.workspace.flushParent(entry.path); }
        else await this.workspace.replace(entry.path, entry.after, await this.store.loadAsset(journal.id, i, 'after', entry.after));
        if (!await this.recoveryReadPreconditions(journal, signal)) return this.transactionOutcome(journal, 'conflict', replayed);
      }
      journal.phase = 'completed'; await this.store.save(journal);
      await this.releaseDirectories(journal);
      await this.releaseMetadata(journal);
      return this.transactionOutcome(journal, 'completed', replayed);
    }
    journal.phase = 'recovering'; await this.store.save(journal);
    for (let i = journal.entries.length - 1; i >= 0; i--) {
      checkCancellation();
      const entry = journal.entries[i]; if (!entry) throw new Error('Invalid transaction entry.');
      if (current[i] === entry.after && entry.after !== entry.before) {
        if (entry.before === null) { if (!this.workspace.remove || entry.after === null) throw new Error('FILE_OPERATIONS_UNAVAILABLE'); await this.workspace.remove(entry.path, entry.after); }
        else if (entry.after === null) { if (!this.workspace.create || !entry.metadata) throw new Error('FILE_METADATA_UNAVAILABLE'); await this.workspace.create(entry.path, await this.store.loadAsset(journal.id, i, 'before', entry.before), entry.metadata); }
        else await this.workspace.replace(entry.path, entry.after, await this.store.loadAsset(journal.id, i, 'before', entry.before));
      }
    }
    if (!await this.removeDirectories(journal)) return this.transactionOutcome(journal, 'conflict', replayed);
    journal.phase = 'rolled_back'; journal.message = 'Interrupted replacements were reconciled using verified backups.';
    await this.store.save(journal);
    await this.releaseMetadata(journal);
    return this.transactionOutcome(journal, 'rolled_back', replayed);
  }
}
