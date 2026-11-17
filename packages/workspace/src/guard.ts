import { spawn } from 'node:child_process';
import path from 'node:path';
import { AuthorizationError, absolutePathReason, outsideRootsReason } from './authorization.js';

export type GuardEntry = { name: string; kind: 'file' | 'directory' | 'symlink' | 'other'; size: number };
export type GuardIdentity = { device: string; inode: string; grant?: { root: string; relative: string; device: string; inode: string } };
export type GuardMetadata = Record<string, unknown>;

/** Execute only the installed guard, with bounded output and no shell. */
async function guardCall(executable: string, args: string[], maxBytes: number, input?: Buffer, signal?: AbortSignal): Promise<Buffer> {
  if (!path.isAbsolute(executable)) throw new Error('The filesystem guard must have an absolute path.');
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LANG: 'C' }, windowsHide: true });
    const stdout: Buffer[] = [];
    let total = 0;
    let stderr = '';
    let failure: Error | undefined;
    const timeout = setTimeout(() => { failure = new Error('Filesystem guard timed out.'); child.kill('SIGKILL'); }, 30_000);
    const onAbort = () => { failure ??= new Error('WORKER_CANCELLED'); child.kill('SIGKILL'); };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
    child.stdout.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) { failure = new Error('Filesystem guard output exceeded its limit.'); child.kill('SIGKILL'); return; }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => { if (stderr.length < 4096) stderr += chunk.toString('utf8').slice(0, 4096 - stderr.length); });
    child.stdin.on('error', error => { if ((error as NodeJS.ErrnoException).code !== 'EPIPE') failure = error; });
    child.stdin.end(input);
    child.once('error', error => { failure = error; });
    child.once('close', code => {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
      if (failure) return reject(failure);
      if (code !== 0) {
        const error = new Error(`Filesystem guard rejected the request: ${stderr.trim() || `exit ${code}`}`) as Error & { code?: string };
        const line = stderr.split('\n').find(value => value.startsWith('ud-agent-guard-error: '));
        if (line) {
          try {
            const detail = JSON.parse(line.slice('ud-agent-guard-error: '.length)) as { kind?: string };
            const mapped = ({ NotFound: 'ENOENT', AlreadyExists: 'EEXIST', PermissionDenied: 'EACCES', InvalidInput: 'EINVAL', WouldBlock: 'EWOULDBLOCK' } as Record<string, string>)[detail.kind ?? ''];
            if (mapped) error.code = mapped;
          } catch { /* Human-readable failure remains authoritative. */ }
        }
        return reject(error);
      }
      resolve(Buffer.concat(stdout));
    });
  });
}

function identityArgs(identity: GuardIdentity): string[] {
  if (!/^\d+$/.test(identity.device) || !/^\d+$/.test(identity.inode)) throw new Error('Invalid workspace identity.');
  if (identity.grant) {
    if (!path.isAbsolute(identity.grant.root) || !/^\d+$/.test(identity.grant.device) || !/^\d+$/.test(identity.grant.inode)) throw new Error('Invalid grant identity.');
    return ['--workspace', identity.grant.relative, '--root-device', identity.grant.device, '--root-inode', identity.grant.inode, '--workspace-device', identity.device, '--workspace-inode', identity.inode];
  }
  return ['--root-device', identity.device, '--root-inode', identity.inode];
}

function commandRoot(root: string, identity?: GuardIdentity): string {
  return identity?.grant?.root ?? root;
}

/** Bind a requested directory by walking beneath a configured grant in the helper. */
export async function guardedGrant(executable: string, requested: string, grantedRoots: readonly string[], signal?: AbortSignal): Promise<GuardIdentity> {
  if (!path.isAbsolute(requested) || requested.includes('\0')) throw new AuthorizationError(absolutePathReason(grantedRoots));
  const target = path.resolve(requested);
  for (const candidate of grantedRoots) {
    if (!path.isAbsolute(candidate) || candidate.includes('\0')) continue;
    const root = path.resolve(candidate);
    const rel = path.relative(root, target);
    if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) continue;
    const relative = rel || '.';
    const bytes = await guardCall(executable, ['bind', '--root', root, '--workspace', relative], 4096, undefined, signal);
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    if (!parsed || typeof parsed !== 'object') throw new Error('Invalid grant binding.');
    const value = parsed as Record<string, unknown>;
    const decode = (item: unknown): { device: string; inode: string } => {
      if (!item || typeof item !== 'object') throw new Error('Invalid grant binding.');
      const record = item as Record<string, unknown>;
      if (typeof record.device !== 'string' || !/^\d+$/.test(record.device) || typeof record.inode !== 'string' || !/^\d+$/.test(record.inode)) throw new Error('Invalid grant binding.');
      return { device: record.device, inode: record.inode };
    };
    const grant = decode(value.grant); const workspace = decode(value.workspace);
    return { ...workspace, grant: { root, relative, ...grant } };
  }
  throw new AuthorizationError(outsideRootsReason(requested, grantedRoots));
}

export async function guardedIdentity(executable: string, root: string, signal?: AbortSignal): Promise<GuardIdentity> {
  const bytes = await guardCall(executable, ['identity', '--root', root], 1024, undefined, signal);
  const parsed: unknown = JSON.parse(bytes.toString('utf8'));
  if (!parsed || typeof parsed !== 'object') throw new Error('Filesystem guard returned an invalid workspace identity.');
  const value = parsed as Record<string, unknown>;
  if (typeof value.device !== 'string' || !/^\d+$/.test(value.device) || typeof value.inode !== 'string' || !/^\d+$/.test(value.inode)) throw new Error('Filesystem guard returned an invalid workspace identity.');
  return { device: value.device, inode: value.inode };
}

export async function guardedList(executable: string, root: string, relative: string, identity?: GuardIdentity, signal?: AbortSignal): Promise<GuardEntry[]> {
  const bytes = await guardCall(executable, ['list', '--root', commandRoot(root, identity), '--path', relative, ...(identity ? identityArgs(identity) : [])], 8 * 1024 * 1024, undefined, signal);
  const parsed: unknown = JSON.parse(bytes.toString('utf8'));
  if (!Array.isArray(parsed) || parsed.length > 20_000) throw new Error('Filesystem guard returned an invalid directory listing.');
  const names = new Set<string>();
  return parsed.map((item: unknown) => {
    if (!item || typeof item !== 'object') throw new Error('Filesystem guard returned an invalid entry.');
    const entry = item as Record<string, unknown>;
    if (typeof entry.name !== 'string' || entry.name === '' || entry.name === '.' || entry.name === '..' || entry.name.includes('/') || entry.name.includes('\\') || entry.name.includes('\0') || names.has(entry.name)) throw new Error('Filesystem guard returned an unsafe entry name.');
    if (!['file', 'directory', 'symlink', 'other'].includes(entry.kind as string) || !Number.isSafeInteger(entry.size) || (entry.size as number) < 0) throw new Error('Filesystem guard returned an invalid entry.');
    names.add(entry.name);
    return entry as GuardEntry;
  });
}

export async function guardedRead(executable: string, root: string, relative: string, maxBytes: number, identity?: GuardIdentity, signal?: AbortSignal): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 64 * 1024 * 1024) throw new Error('Invalid guard read limit.');
  return guardCall(executable, ['read', '--root', commandRoot(root, identity), '--path', relative, '--max-bytes', String(maxBytes), ...(identity ? identityArgs(identity) : [])], maxBytes, undefined, signal);
}

/** Raw bounded FD stream. Partial output has no authority until helper exit0. */
export async function* guardedReadStream(executable: string, root: string, relative: string, maxBytes: number, identity: GuardIdentity, signal?: AbortSignal): AsyncGenerator<Buffer> {
  if (!path.isAbsolute(executable) || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 20 * 1024 ** 3) throw new Error('Invalid guard stream limit or executable.');
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  const child = spawn(executable, ['read-stream', '--root', commandRoot(root, identity), '--path', relative, '--max-bytes', String(maxBytes), ...identityArgs(identity)], { shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LANG: 'C' }, windowsHide: true });
  let failure: Error | undefined; let stderr = ''; let total = 0;
  const stop = (reason: Error) => { failure ??= reason; child.kill('SIGKILL'); };
  const timer = setTimeout(() => stop(new Error('Filesystem guard stream timed out.')), 120_000);
  const abort = () => stop(new Error('WORKER_CANCELLED'));
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  child.stderr.on('data', (chunk: Buffer) => { if (stderr.length < 4096) stderr += chunk.toString('utf8').slice(0, 4096 - stderr.length); });
  child.on('error', error => { failure ??= error; });
  const closed = new Promise<number | null>(resolve => child.once('close', code => resolve(code)));
  let finished = false;
  try {
    for await (const bytes of child.stdout) {
      const chunk = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes); total += chunk.length;
      if (total > maxBytes) { stop(new Error('Filesystem guard stream exceeded its limit.')); break; }
      if (failure) break;
      yield chunk;
    }
    const code = await closed; finished = true;
    if (failure) throw failure;
    if (code !== 0) throw new Error(`Filesystem guard rejected the stream: ${stderr.trim() || `exit ${code}`}`);
  } finally {
    if (!finished) { stop(new Error('Filesystem guard stream was not consumed.')); child.stdout.destroy(); await closed; }
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
  }
}

export async function guardedReplace(executable: string, root: string, relative: string, identity: GuardIdentity, beforeSha256: string, replacement: Buffer): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(beforeSha256)) throw new Error('Invalid source fingerprint.');
  if (replacement.length > 64 * 1024 * 1024) throw new Error('Replacement exceeds per-file limit.');
  await guardCall(executable, ['replace', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--before-sha256', beforeSha256, '--max-bytes', String(64 * 1024 * 1024)], 4096, replacement);
}

export async function guardedCapabilities(executable: string, root: string, identity: GuardIdentity): Promise<{ metadataPreservation: boolean; creation: boolean; removal: boolean; metadataModel?: string }> {
  const bytes = await guardCall(executable, ['capabilities', '--root', commandRoot(root, identity), ...identityArgs(identity)], 4096);
  const value: unknown = JSON.parse(bytes.toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid native guard capabilities.');
  const record = value as Record<string, unknown>;
  if (record.schema_version !== 1 || typeof record.metadata_preservation !== 'boolean' || typeof record.create_exclusive !== 'boolean' || typeof record.remove_checked !== 'boolean') throw new Error('Invalid native guard capabilities.');
  if (record.metadata_model !== undefined && !['native-metadata-capture', 'transactional-ntfs-same-object', 'privileged-security-and-stream-capture'].includes(record.metadata_model as string)) throw new Error('Invalid native metadata model.');
  return { metadataPreservation: record.metadata_preservation, creation: record.create_exclusive, removal: record.remove_checked, ...(typeof record.metadata_model === 'string' ? { metadataModel: record.metadata_model } : {}) };
}

export async function guardedReadOptional(executable: string, root: string, relative: string, identity: GuardIdentity): Promise<Buffer | null> {
  const parts = relative.split('/'); const leaf = parts.pop();
  let entries: GuardEntry[];
  try { entries = await guardedList(executable, root, parts.join('/') || '.', identity); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  const entry = entries.find(item => item.name === leaf);
  if (!entry) return null;
  if (entry.kind !== 'file') throw new Error('Transaction target is not a regular file.');
  return guardedRead(executable, root, relative, 64 * 1024 * 1024, identity);
}

export async function guardedOwnedDirectory(executable: string, root: string, relative: string, identity: GuardIdentity, token: string, action: 'mkdir-owned' | 'release-owned' | 'rmdir-owned', expected?: GuardIdentity): Promise<GuardIdentity | null> {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('Invalid directory ownership token.');
  const args = [action, '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--owner-token', token];
  if (expected) {
    if (!/^\d+$/.test(expected.device) || !/^\d+$/.test(expected.inode)) throw new Error('Invalid directory ownership identity.');
    args.push('--entry-device', expected.device, '--entry-inode', expected.inode);
  }
  const parsed: unknown = JSON.parse((await guardCall(executable, args, 4096)).toString('utf8'));
  if (parsed === null && action === 'rmdir-owned') return null;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid native directory identity.');
  const value = parsed as Record<string, unknown>;
  if (typeof value.device !== 'string' || !/^\d+$/.test(value.device) || typeof value.inode !== 'string' || !/^\d+$/.test(value.inode)) throw new Error('Invalid native directory identity.');
  return { device: value.device, inode: value.inode };
}

export async function guardedMetadata(executable: string, root: string, relative: string, identity: GuardIdentity, beforeSha256: string): Promise<GuardMetadata> {
  if (!/^[0-9a-f]{64}$/.test(beforeSha256)) throw new Error('Invalid source fingerprint.');
  const bytes = await guardCall(executable, ['metadata', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--before-sha256', beforeSha256, '--max-bytes', String(64 * 1024 * 1024)], 2 * 1024 * 1024);
  const value: unknown = JSON.parse(bytes.toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid native metadata snapshot.');
  return value as GuardMetadata;
}

export async function guardedCreate(executable: string, root: string, relative: string, identity: GuardIdentity, bytes: Buffer, metadata?: GuardMetadata): Promise<void> {
  if (bytes.length > 64 * 1024 * 1024) throw new Error('Creation exceeds per-file limit.');
  let input = bytes;
  if (metadata) {
    const header = Buffer.from(`${JSON.stringify(metadata)}\n`);
    if (header.length > 2 * 1024 * 1024) throw new Error('Metadata snapshot exceeds its limit.');
    input = Buffer.concat([header, bytes]);
  }
  await guardCall(executable, [metadata ? 'restore' : 'create', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--max-bytes', String(64 * 1024 * 1024)], 4096, input);
}

export async function guardedRemove(executable: string, root: string, relative: string, identity: GuardIdentity, beforeSha256: string, metadata?: GuardMetadata): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(beforeSha256)) throw new Error('Invalid source fingerprint.');
  const preserved = metadata?.preserved_file !== undefined; const input = preserved ? Buffer.from(`${JSON.stringify(metadata)}\n`) : undefined;
  if (input && input.length > 2 * 1024 * 1024) throw new Error('Metadata snapshot exceeds its limit.');
  await guardCall(executable, [preserved ? 'remove-preserved' : 'remove', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--before-sha256', beforeSha256, '--max-bytes', String(64 * 1024 * 1024)], 4096, input);
}

export async function guardedReleaseMetadata(executable: string, root: string, relative: string, identity: GuardIdentity, metadata: GuardMetadata): Promise<void> {
  if (metadata.preserved_file === undefined) return;
  const bytes = Buffer.from(`${JSON.stringify(metadata)}\n`); if (bytes.length > 2 * 1024 * 1024) throw new Error('Metadata snapshot exceeds its limit.');
  await guardCall(executable, ['release-metadata', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--max-bytes', String(64 * 1024 * 1024)], 4096, bytes);
}

export async function guardedFlushParent(executable: string, root: string, relative: string, identity: GuardIdentity): Promise<void> {
  await guardCall(executable, ['flush-parent', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity)], 4096);
}

export async function guardedPrivateDirectory(executable: string, root: string, relative: string, identity: GuardIdentity, initialize = false): Promise<void> {
  await guardCall(executable, [initialize ? 'state-private-init' : 'state-private-check', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity)], 4096);
}

export async function guardedPrivateRead(executable: string, root: string, relative: string, maxBytes: number, identity: GuardIdentity): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 64 * 1024 * 1024) throw new Error('Invalid private read limit.');
  return guardCall(executable, ['private-read', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity), '--max-bytes', String(maxBytes)], maxBytes);
}

export async function guardedFlushDirectory(executable: string, root: string, relative: string, identity: GuardIdentity): Promise<void> {
  await guardCall(executable, ['flush-directory', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity)], 4096);
}

/** Kernel ownership ends on pipe EOF/process death; PID files are not locks. */
export async function guardedStateLock(executable: string, root: string, relative: string, identity: GuardIdentity, existingOnly = false): Promise<() => Promise<void>> {
  if (!path.isAbsolute(executable)) throw new Error('The state lock guard must be absolute.');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [existingOnly ? 'state-lock-existing' : 'state-lock', '--root', commandRoot(root, identity), '--path', relative, ...identityArgs(identity)], { shell: false, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows' } : {}), LANG: 'C' } });
    let stdout = ''; let stderr = ''; let acquired = false; let closed = false;
    let finish: ((error?: Error) => void) | undefined;
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('State lock acquisition timed out.')); }, 30_000);
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); if (stderr.length > 4096) child.kill('SIGKILL'); });
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
      if (stdout.length > 1024) { child.kill('SIGKILL'); return; }
      if (!acquired && stdout.endsWith('\n')) {
        try { const value = JSON.parse(stdout); if (value.schema_version !== 1 || value.locked !== true) throw new Error(); }
        catch { child.kill('SIGKILL'); clearTimeout(timeout); reject(new Error('Invalid native state lock response.')); return; }
        acquired = true; clearTimeout(timeout);
        let released: Promise<void> | undefined;
        resolve(() => released ??= new Promise<void>((done, fail) => {
          if (closed) { fail(new Error('Native state lock ended before release.')); return; }
          const ending = setTimeout(() => { child.kill('SIGKILL'); fail(new Error('Native state lock release timed out.')); }, 5000);
          finish = error => { clearTimeout(ending); if (error) fail(error); else done(); };
          child.stdin.end();
        }));
      }
    });
    child.stdin.on('error', () => { /* Close handles the authoritative outcome. */ });
    child.once('error', error => { clearTimeout(timeout); if (!acquired) reject(error); else finish?.(error); });
    child.once('close', code => {
      closed = true; clearTimeout(timeout);
      if (!acquired) {
        const error = new Error(`STATE_LOCKED_OR_UNVERIFIED: ${stderr.trim() || `exit ${code}`}`) as Error & { code?: string };
        const line = stderr.split('\n').find(value => value.startsWith('ud-agent-guard-error: '));
        if (line) { try { const result = JSON.parse(line.slice('ud-agent-guard-error: '.length)); if (result.kind === 'WouldBlock' || [11, 35, 32, 33].includes(result.os_code)) error.code = 'EBUSY'; else if (result.kind === 'NotFound') error.code = 'ENOENT'; } catch { /* Preserve the unverified failure. */ } }
        reject(error);
      }
      else finish?.(code === 0 ? undefined : new Error(`Native state lock failed: ${stderr.trim() || `exit ${code}`}`));
    });
  });
}
