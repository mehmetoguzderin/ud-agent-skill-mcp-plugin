import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, realpath, stat, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import type { Snapshot } from './snapshot.js';
import { validPortablePath } from './portable-path.js';
import { captureGitMetadata, type PrivateGitMetadata } from './git-metadata.js';

function hash(bytes: Buffer): string { return createHash('sha256').update(bytes).digest('hex'); }
async function gitExecutable(): Promise<string> {
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, process.platform === 'win32' ? 'git.exe' : 'git');
    try {
      const resolved = await realpath(candidate), info = await stat(resolved);
      if (!info.isFile() || (process.platform !== 'win32' && ((info.mode & 0o022) !== 0 || (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid())))) continue;
      await access(resolved, process.platform === 'win32' ? constants.F_OK : constants.X_OK); return resolved;
    } catch (error: unknown) { if (!['ENOENT', 'ENOTDIR', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error; }
  }
  throw new Error('GIT_SNAPSHOT_PREREQUISITE_MISSING');
}

/** Git alone expands installation-prefix/named-user spellings, against a
 * single product-authored key. No original config or repository path is used. */
async function expandGitConfigPath(executable: string, directory: string, literal: string, home: string, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (!literal || Buffer.byteLength(literal) > 1024 * 1024 || /[\0\r\n]/.test(literal)) throw new Error('GIT_METADATA_CONFIG_INVALID');
  const config = path.join(directory, `path-expansion-${randomUUID()}.config`);
  const quoted = literal.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\t/g, '\\t').replace(/\x08/g, '\\b');
  await writeFile(config, `[paths]\nvalue = "${quoted}"\n`, { flag: 'wx', mode: 0o600 });
  try {
    const bytes = await new Promise<Buffer>((resolve,reject) => {
      const env: NodeJS.ProcessEnv = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\Windows'}\System32` : '/usr/bin:/bin', HOME: home, LC_ALL:'C', GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_CONFIG_COUNT:'0', GIT_CEILING_DIRECTORIES:directory, GIT_TERMINAL_PROMPT:'0' };
      if (process.env.SystemRoot) env.SystemRoot=process.env.SystemRoot;
      const child = spawn(executable,['--no-pager','--no-optional-locks','config','--no-includes','--file',config,'--null','--path','paths.value'],{ cwd:path.join(directory,'worktree'),env,shell:false,windowsHide:true,stdio:['ignore','pipe','pipe'] });
      const output:Buffer[]=[]; let size=0,stderrSize=0,failure:Error|undefined;
      const stop=(error:Error)=>{failure??=error;child.kill('SIGKILL');};
      const timer=setTimeout(()=>stop(new Error('GIT_SNAPSHOT_TIMEOUT')),30_000),abort=()=>stop(new Error('WORKER_CANCELLED'));
      signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
      child.stdout.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>65536)stop(new Error('GIT_CONFIG_PATH_EXPANSION_TOO_LARGE'));else output.push(chunk);});child.stderr.on('data',(chunk:Buffer)=>{stderrSize+=chunk.length;if(stderrSize>1024*1024)stop(new Error('GIT_SNAPSHOT_TOO_LARGE'));});child.once('error',stop);
      child.once('close',code=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);if(failure)reject(failure);else if(code!==0)reject(new Error('GIT_CONFIG_PATH_EXPANSION_UNAVAILABLE'));else resolve(Buffer.concat(output));});
    });
    if (!bytes.length || bytes.at(-1)!==0 || bytes.subarray(0,-1).includes(0)) throw new Error('GIT_CONFIG_PATH_EXPANSION_INVALID');
    const selected = new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,-1)); if (!path.isAbsolute(selected)) throw new Error('GIT_CONFIG_PATH_EXPANSION_INVALID'); return selected;
  } finally { await rm(config,{force:true}); }
}

async function git(executable: string, metadata: PrivateGitMetadata, args: string[], input?: Buffer, signal?: AbortSignal, optional = false): Promise<Buffer> {
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  const env: NodeJS.ProcessEnv = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\Windows'}\System32` : '/usr/bin:/bin', LC_ALL: 'C', HOME: metadata.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_CONFIG_COUNT: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', GIT_ATTR_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: metadata.directory, GIT_COMMON_DIR: metadata.commonDir };
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ['--no-pager', '--no-optional-locks', '--git-dir', metadata.gitDir, '--work-tree', metadata.workTree, '-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${process.platform === 'win32' ? 'NUL' : '/dev/null'}`, '-c', 'protocol.allow=never', '-c', 'credential.helper=', ...args], { cwd: metadata.workTree, env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks: Buffer[] = []; let size = 0, stderrSize = 0, failed: Error | undefined;
    const stop = (error: Error) => { failed ??= error; child.kill('SIGKILL'); };
    const timer = setTimeout(() => stop(new Error('GIT_SNAPSHOT_TIMEOUT')), 120_000);
    const abort = () => stop(new Error('WORKER_CANCELLED')); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    child.stdout.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 64 * 1024 * 1024) stop(new Error('GIT_SNAPSHOT_TOO_LARGE')); else chunks.push(chunk); });
    child.stderr.on('data', (chunk:Buffer) => { stderrSize+=chunk.length; if(stderrSize>1024*1024)stop(new Error('GIT_SNAPSHOT_TOO_LARGE')); }); child.stdin.on('error', error => { if ((error as NodeJS.ErrnoException).code !== 'EPIPE') stop(error); });
    child.on('error', stop); child.stdin.end(input);
    child.on('close', code => { clearTimeout(timer); signal?.removeEventListener('abort', abort); if (failed) reject(failed); else if (code !== 0 && !(optional && code === 1)) reject(new Error('GIT_BASE_REVISION_UNAVAILABLE')); else resolve(Buffer.concat(chunks)); });
  });
}

function objectBytes(content: Buffer, expected: string, type: string): Buffer {
  const end = content.indexOf(10); if (end < 0) throw new Error('GIT_OBJECT_STREAM_INVALID');
  const header = /^([0-9a-f]+) ([a-z]+) (\d+)$/.exec(content.subarray(0, end).toString('ascii'));
  if (!header || header[1] !== expected || header[2] !== type || !Number.isSafeInteger(Number(header[3]))) throw new Error('GIT_OBJECT_STREAM_INVALID');
  const size = Number(header[3]); if (size > 32 * 1024 * 1024 || end + size + 2 !== content.length || content.at(-1) !== 10) throw new Error('GIT_OBJECT_STREAM_INVALID');
  const bytes = content.subarray(end + 1, end + 1 + size);
  if (createHash(expected.length === 40 ? 'sha1' : 'sha256').update(Buffer.from(`${type} ${size}\0`)).update(bytes).digest('hex') !== expected) throw new Error('GIT_OBJECT_CONTENT_MISMATCH');
  return bytes;
}

/** Capture exact Git object bytes without checkout, hooks, filters, or network. */
export async function appendGitBase(guard: string, workingTree: string, grants: readonly string[], revision: string, snapshot: Snapshot, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (!revision || revision.length > 1024 || /[\0\r\n]/.test(revision)) throw new Error('GIT_BASE_REVISION_INVALID');
  const executable = await gitExecutable();
  const metadata = await captureGitMetadata(guard, workingTree, grants, snapshot.directory, signal, (directory,literal,home)=>expandGitConfigPath(executable,directory,literal,home,signal));
  try {
  const branchBytes = await git(executable, metadata, ['symbolic-ref', '--quiet', 'HEAD'], undefined, signal, true);
  const branchRef = branchBytes.at(-1) === 10 ? branchBytes.subarray(0,-1) : branchBytes;
  const branch = branchRef.subarray(0,11).equals(Buffer.from('refs/heads/')) ? branchRef.subarray(11) : undefined;
  if (branch && [0,10,13].some(byte=>branch.includes(byte))) throw new Error('GIT_METADATA_POINTER_INVALID');
  await metadata.configure(branch);
  const prefix = path.relative(metadata.top, workingTree).split(path.sep).join('/');
  if (prefix === '..' || prefix.startsWith('../') || path.isAbsolute(prefix)) throw new Error('GIT_WORKSPACE_UNVERIFIED');
  const commit = (await git(executable, metadata, ['rev-parse', '--verify', '--end-of-options', `${revision}^{commit}`], undefined, signal)).toString('ascii').trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit)) throw new Error('GIT_OBJECT_IDENTITY_INVALID');
  const commitBytes = objectBytes(await git(executable, metadata, ['cat-file', '--batch'], Buffer.from(commit + '\n'), signal), commit, 'commit');
  const tree = /^tree ([0-9a-f]{40}|[0-9a-f]{64})\n/.exec(commitBytes.toString('latin1'))?.[1];
  if (!tree || tree.length !== commit.length) throw new Error('GIT_OBJECT_IDENTITY_INVALID');
  const files = new Map<string, { oid: string; bytes?: Buffer }>();
  const queue = [{ oid: tree, name: '' }]; let treeCount = 0, treeBytes = 0;
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const item = queue[cursor]!; if (++treeCount > 10_000) throw new Error('GIT_TREE_ENTRY_UNSUPPORTED');
    const bytes = objectBytes(await git(executable, metadata, ['cat-file', '--batch'], Buffer.from(item.oid + '\n'), signal), item.oid, 'tree');
    treeBytes += bytes.length; if (treeBytes > 32 * 1024 * 1024) throw new Error('GIT_BASE_REPORT_TOO_LARGE');
    let at = 0; const names = new Set<string>();
    while (at < bytes.length) {
      const space = bytes.indexOf(32, at), nul = bytes.indexOf(0, space + 1), oidBytes = commit.length / 2;
      if (space < at || nul < space || nul + 1 + oidBytes > bytes.length) throw new Error('GIT_TREE_ENTRY_UNSUPPORTED');
      const mode = bytes.subarray(at, space).toString('ascii'), name = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(space + 1, nul));
      if (!name || name === '.' || name === '..' || /[\/\\\0\r\n]/.test(name) || names.has(name)) throw new Error('GIT_TREE_ENTRY_UNSUPPORTED'); names.add(name);
      const full = item.name ? `${item.name}/${name}` : name, oid = bytes.subarray(nul + 1, nul + 1 + oidBytes).toString('hex'); at = nul + 1 + oidBytes;
      if (mode === '40000') { if (!prefix || full === prefix || full.startsWith(prefix + '/') || prefix.startsWith(full + '/')) queue.push({ oid, name: full }); continue; }
      if (prefix && !full.startsWith(prefix + '/')) continue;
      const relative = prefix ? full.slice(prefix.length + 1) : full;
      if (!relative.endsWith('.conllu')) continue;
      if (!['100644', '100755'].includes(mode) || !validPortablePath(relative) || relative.startsWith('.ud-agent-inputs/') || files.has(relative) || files.size >= 10_000) throw new Error('GIT_TREE_ENTRY_UNSUPPORTED');
      files.set(relative, { oid });
    }
  }
  const orderedFiles = [...files].sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b)));
  const values = orderedFiles.map(([,value])=>value);
  const content = values.length ? await git(executable, metadata, ['cat-file', '--batch'], Buffer.from(values.map(file => file.oid).join('\n') + '\n'), signal) : Buffer.alloc(0);
  let offset = 0, total = 0;
  for (const value of values) {
    const end = content.indexOf(10, offset); if (end < 0) throw new Error('GIT_OBJECT_STREAM_INVALID');
    const header = /^(\w+) blob (\d+)$/.exec(content.subarray(offset, end).toString('ascii'));
    if (!header || header[1] !== value.oid || !Number.isSafeInteger(Number(header[2]))) throw new Error('GIT_OBJECT_STREAM_INVALID');
    const size = Number(header[2]); total += size;
    if (size > 32 * 1024 * 1024 || total > 32 * 1024 * 1024 || end + 1 + size >= content.length || content[end + 1 + size] !== 10) throw new Error('GIT_BASE_REPORT_TOO_LARGE');
    value.bytes = content.subarray(end + 1, end + 1 + size); offset = end + 2 + size;
    const oid = createHash(value.oid.length === 40 ? 'sha1' : 'sha256').update(Buffer.from(`blob ${size}\0`)).update(value.bytes).digest('hex');
    if (oid !== value.oid) throw new Error('GIT_OBJECT_CONTENT_MISMATCH');
  }
  if (offset !== content.length) throw new Error('GIT_OBJECT_STREAM_INVALID');
  await metadata.verify();
  const directory = `.ud-agent-inputs/git-${commit}/tree`, document = `.ud-agent-inputs/git-${commit}/snapshot.json`;
  const receipt: Record<string, { sha256: string; size_bytes: number; blob_oid: string }> = {}, stored: Record<string, { sha256: string; content: string }> = {};
  for (const [name, value] of orderedFiles) {
    const bytes = value.bytes!; const digest = hash(bytes); const location = `${directory}/${name}`;
    await mkdir(path.dirname(path.join(snapshot.directory, ...location.split('/'))), { recursive: true, mode: 0o700 });
    await writeFile(path.join(snapshot.directory, ...location.split('/')), bytes, { flag: 'wx', mode: 0o600 });
    snapshot.files.push({ path: location, sha256: digest, size: bytes.length });
    receipt[name] = { sha256: digest, size_bytes: bytes.length, blob_oid: value.oid };
    stored[name] = { sha256: digest, content: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  }
  await mkdir(path.dirname(path.join(snapshot.directory, ...document.split('/'))), { recursive: true, mode: 0o700 });
  const bytes = Buffer.from(JSON.stringify({ revision, files: stored }));
  if (bytes.length > 64 * 1024 * 1024) throw new Error('GIT_BASE_REPORT_TOO_LARGE');
  await writeFile(path.join(snapshot.directory, ...document.split('/')), bytes, { flag: 'wx', mode: 0o600 });
  snapshot.files.push({ path: document, sha256: hash(bytes), size: bytes.length });
  return { requested_revision: revision, resolved_commit: commit, tree_oid: tree, files: receipt, base_directory_path: directory, base_snapshot_path: document, base_snapshot_sha256: hash(bytes) };
  } finally { await metadata.cleanup(); }
}
