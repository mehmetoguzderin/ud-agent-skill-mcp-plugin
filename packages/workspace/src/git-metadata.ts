import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { guardedGrant, guardedIdentity, guardedList, guardedRead, guardedReadStream, type GuardIdentity } from './guard.js';
import { validatePrivateMidx } from './git-pack.js';
import { gitConfigText, includeConditionMatches, includeTarget, parseGitConfig, parseGitAlternates, quoteGitAlternate, type GitConfigEntry } from './git-config.js';

const MAX_BYTES = 20 * 1024 ** 3;
const decode = (bytes: Buffer) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const safeRelative = (name: string) => name !== '' && !path.isAbsolute(name) && name.split('/').every(part => part !== '' && part !== '.' && part !== '..' && !/[\\:\0\r\n]/.test(part) && (process.platform !== 'win32' || !/[<>"|?*\u0000-\u001f]|[. ]$/.test(part) && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)));
function abort(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('WORKER_CANCELLED'); }
function pointer(bytes: Buffer, kind: 'gitdir' | 'commondir'): string {
  const text = decode(bytes).replace(/[\r\n]+$/, ''); const selected = kind === 'gitdir' ? /^gitdir: (.+)$/.exec(text)?.[1] : text;
  if (!selected || /[\0\r\n]/.test(selected)) throw new Error('GIT_METADATA_POINTER_INVALID'); return selected;
}
function quote(value: string): string { return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\t/g, '\\t').replace(/\x08/g, '\\b') + '"'; }

export type PrivateGitMetadata = {
  top: string; directory: string; gitDir: string; commonDir: string; workTree: string;
  configure(branch?: string | Buffer): Promise<void>; verify(): Promise<void>; cleanup(): Promise<void>;
};
/** No Git process may run until this grant-first capture completes. Original
 * config, metadata pointers and alternates are never given to Git. */
export async function captureGitMetadata(guard: string, workingTree: string, grants: readonly string[], destination: string, signal?: AbortSignal, expandPath?: (directory: string, literal: string, home: string) => Promise<string>): Promise<PrivateGitMetadata> {
  const authorities = new Map<string, GuardIdentity>(); const listings: { root:string; relative:string; identity:GuardIdentity; sha256:string }[] = []; let controlBytes = 0; const controls = new Map<string, { bytes: Buffer; sha256: string }>();
  const identities = async (root: string) => { const known = authorities.get(root); if (known) return known; abort(signal); const id = await guardedGrant(guard, root, grants, signal); authorities.set(root, id); return id; };
  const read = async (file: string, optional = false): Promise<Buffer | undefined> => {
    if (controls.has(file)) return controls.get(file)!.bytes;
    const parent = path.dirname(file);
    try { const id = await identities(parent); const bytes = await guardedRead(guard, parent, path.basename(file), 64 * 1024 * 1024, id, signal); controlBytes += bytes.length; if (controlBytes > 128 * 1024 * 1024) throw new Error('GIT_METADATA_CONTROLS_TOO_LARGE'); controls.set(file, { bytes, sha256: digest(bytes) }); return bytes; }
    catch (error) { if (optional && (error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  };
  let top = path.resolve(workingTree), selected = '';
  for (;;) {
    const id = await identities(top); const entries = await guardedList(guard, top, '.', id, signal); const marker = entries.find(entry => entry.name === '.git');
    if (marker) {
      if (marker.kind === 'directory') selected = path.join(top, '.git');
      else if (marker.kind === 'file') selected = path.resolve(top, pointer((await read(path.join(top, '.git')))!, 'gitdir'));
      else throw new Error('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
      await identities(selected); break;
    }
    const parent = path.dirname(top); if (parent === top) throw new Error('GIT_SNAPSHOT_PREREQUISITE_MISSING');
    // A missing ancestor grant is denied before any discovery/read in it.
    await identities(parent); top = parent;
  }
  const commonPointer = await read(path.join(selected, 'commondir'), true);
  const common = commonPointer ? path.resolve(selected, pointer(commonPointer, 'commondir')) : selected;
  await identities(common);
  const directory = await mkdtemp(path.join(destination, '.git-private-'));
  const workTree = path.join(directory, 'worktree'); await mkdir(workTree, { mode: 0o700 });
  const copied = new Map<string, string>(); let total = 0, entries = 0;
  const configFiles = new Map<string, Buffer>();
  const skip = (relative: string) => /(?:^|\/)config(?:\.worktree)?$/.test(relative) || /(?:^|\/)(?:gitdir|commondir)$/.test(relative) || /(?:^|\/)commit-graph$/.test(relative) || /(?:^|\/)commit-graphs(?:\/|$)/.test(relative) || /(?:^|\/)http-alternates$/.test(relative);
  const copyRoot = async (source: string, objectRoot = false): Promise<string> => {
    const known = copied.get(source); if (known) return known;
    if (copied.size >= 128) throw new Error('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
    const identity = await identities(source), target = path.join(directory, `metadata-${copied.size}`); copied.set(source, target); await mkdir(target, { mode: 0o700 });
    const queue = [''];
    for (let cursor = 0; cursor < queue.length; cursor++) {
      abort(signal); const parent = queue[cursor]!;
      const found = await guardedList(guard, source, parent || '.', identity, signal); listings.push({ root: source, relative: parent || '.', identity, sha256: digest(Buffer.from(JSON.stringify(found))) });
      for (const item of found) {
        if (++entries > 50_000 || item.kind === 'symlink' || item.kind === 'other') throw new Error('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
        const relative = parent ? `${parent}/${item.name}` : item.name;
        if (!safeRelative(relative)) throw new Error('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
        const output = path.join(target, ...relative.split('/'));
        if (item.kind === 'directory') { await mkdir(output, { mode: 0o700 }); queue.push(relative); continue; }
        const config = /(?:^|\/)config(?:\.worktree)?$/.test(relative);
        if (config) { if (relative !== 'config' && relative !== 'config.worktree') continue; const bytes = await read(path.join(source, ...relative.split('/'))); configFiles.set(path.join(source, ...relative.split('/')), bytes!); continue; }
        if (skip(relative)) continue;
        const alternate = relative === (objectRoot ? 'info/alternates' : 'objects/info/alternates');
        if (alternate) {
          const bytes = (await read(path.join(source, ...relative.split('/'))))!; const paths: string[] = [];
          for (const line of parseGitAlternates(bytes)) {
            paths.push(await copyRoot(path.resolve(source, ...(objectRoot ? [] : ['objects']), line), true));
          }
          await writeFile(output, paths.map(quoteGitAlternate).join('\n') + '\n', { flag: 'wx', mode: 0o600 }); continue;
        }
        total += item.size; if (total > MAX_BYTES) throw new Error('GIT_METADATA_UNSAFE_OR_TOO_LARGE');
        const handle = await open(output, 'wx', 0o600); let size = 0; const copiedHash = createHash('sha256');
        try {
          for await (const chunk of guardedReadStream(guard, source, relative, Math.max(1, MAX_BYTES - total + item.size), identity, signal)) { size += chunk.length; copiedHash.update(chunk); if (size > item.size) throw new Error('GIT_METADATA_CHANGED_DURING_SNAPSHOT'); let offset = 0; while (offset < chunk.length) { const result = await handle.write(chunk, offset); if (!result.bytesWritten) throw new Error('GIT_METADATA_COPY_FAILED'); offset += result.bytesWritten; } }
          if (size !== item.size) throw new Error('GIT_METADATA_CHANGED_DURING_SNAPSHOT');
        } finally { await handle.close(); }
        if (/(?:^|\/)(?:HEAD|packed-refs|shallow|tables\.list|multi-pack-index-chain)$/.test(relative) || /(?:^|\/)refs\//.test(relative)) {
          // Small mutable selectors are rechecked after object extraction. The
          // object bodies themselves are independently hashed against their OID.
          const bytes = await read(path.join(source, ...relative.split('/'))); if (bytes && (bytes.length !== size || digest(bytes) !== copiedHash.digest('hex'))) throw new Error('GIT_METADATA_CHANGED_DURING_SNAPSHOT');
        }
        if (item.name === 'multi-pack-index' || /^multi-pack-index-[0-9a-f]+\.midx$/.test(item.name)) await validatePrivateMidx(output);
        if (item.name === 'multi-pack-index-chain') { const bytes = (await read(path.join(source, ...relative.split('/'))))!; for (const line of decode(bytes).split('\n').filter(Boolean)) if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(line)) throw new Error('GIT_PACK_LOOKUP_UNSAFE'); }
        if (/(?:^|\/)tables\.list$/.test(relative)) {
          const bytes = (await read(path.join(source, ...relative.split('/'))))!;
          for (const line of decode(bytes).split('\n').filter(Boolean)) if (!/^[A-Za-z0-9._-]+\.ref$/.test(line) || line.includes('..')) throw new Error('GIT_REFTABLE_LIST_INVALID');
        }
      }
    }
    return target;
  };
  try {
    const gitDir = await copyRoot(selected), commonDir = common === selected ? gitDir : await copyRoot(common);
    if (commonDir !== gitDir) await writeFile(path.join(gitDir, 'commondir'), commonDir + '\n', { mode: 0o600 });
    // Back-pointers to real worktrees are intentionally replaced with a private
    // worktree. Revision queries never discover or open original worktree paths.
    for (const target of copied.values()) await writeFile(path.join(target, 'gitdir'), path.join(workTree, '.git') + '\n', { mode: 0o600 });
    const roots = [path.join(common, 'config'), ...(selected === common ? [] : [path.join(selected, 'config')])];
    const worktreeConfig = path.join(selected, 'config.worktree');
    const parsed = new Map<string, GitConfigEntry[]>();
    const rawEntries = async (file: string): Promise<GitConfigEntry[]> => { const known = parsed.get(file); if (known) return known; const bytes = configFiles.get(file) ?? await read(file, true); const entries = bytes ? parseGitConfig(bytes) : []; parsed.set(file, entries); return entries; };
    const urls = (entries: GitConfigEntry[]) => [...new Set(entries.filter(entry => entry.section === 'remote' && entry.subsection !== undefined && entry.key === 'url' && entry.value !== null).map(entry => entry.value!))].map(value => Buffer.from(value, 'latin1'));
    const home = os.homedir(); const expandedPaths = new Map<string,string>();
    const expand = async (files: string[], branch: string | Buffer | undefined, remoteUrls: readonly (string | Buffer)[], hasConfig: boolean): Promise<GitConfigEntry[]> => {
      const output: GitConfigEntry[] = []; const budget = { remaining: 20_000_000 }; let expanded = 0;
      const visit = async (file: string, depth: number, fromHasConfig: boolean): Promise<void> => {
        if (depth > 10) throw new Error('GIT_CONFIG_INCLUDE_DEPTH');
        for (const entry of await rawEntries(file)) {
          abort(signal); if (++expanded > 50_000) throw new Error('GIT_CONFIG_EXPANSION_TOO_LARGE');
          if (fromHasConfig && entry.section === 'remote' && entry.subsection !== undefined && entry.key === 'url') throw new Error('GIT_CONFIG_HASCONFIG_REMOTE_URL');
          output.push(entry);
          if (entry.key !== 'path' || (entry.section !== 'include' && entry.section !== 'includeif')) continue;
          let include = entry.section === 'include'; let conditionalHasConfig = false;
          if (entry.section === 'includeif' && entry.subsection !== undefined) {
            const condition = Buffer.from(entry.subsection, 'latin1'); conditionalHasConfig = condition.subarray(0,10).toString('ascii') === 'hasconfig:';
            include = (!conditionalHasConfig || hasConfig) && includeConditionMatches(condition, { gitDir: selected, configFile: file, home, ...(branch === undefined ? {} : { branch }), remoteUrls, budget });
          }
          if (include) {
            const literal = entry.value === null ? '' : gitConfigText(entry.value);
            const special = literal.startsWith('%(prefix)') || literal.startsWith('~') && literal !== '~' && !literal.startsWith('~/');
            if (special && expandPath && !expandedPaths.has(literal)) expandedPaths.set(literal, await expandPath(directory,literal,home));
            const target = special && expandedPaths.has(literal) ? path.resolve(expandedPaths.get(literal)!) : includeTarget(entry.value, file, home);
            await visit(target, depth + 1, fromHasConfig || conditionalHasConfig);
          }
        }
      };
      for (const file of files) await visit(file, 0, false); return output;
    };
    const project = async (branch?: string | Buffer) => {
      const initial = await expand(roots, branch, [], false);
      const initialUrls = urls(initial);
      const rootEntries = await expand(roots, branch, initialUrls, true);
      const worktreeSetting = rootEntries.filter(entry => entry.section === 'extensions' && entry.key === 'worktreeconfig').at(-1);
      const enabled = worktreeSetting !== undefined && (worktreeSetting.value === null || /^(?:true|yes|on|1)$/i.test(worktreeSetting.value));
      const files = enabled ? [...roots, worktreeConfig] : roots;
      const preliminary = await expand(files, branch, [], false);
      const remoteUrls = urls(preliminary);
      const all = await expand(files, branch, remoteUrls, true);
      const sections: string[] = ['[core]\n\tbare = true\n\tfsmonitor = false\n\tmultiPackIndex = true\n\tcommitGraph = false\n'];
      let projectedBytes = 0;
      for (const entry of [...rootEntries.filter(entry => entry.section === 'extensions' || entry.section === 'core' && entry.key === 'repositoryformatversion'), ...all.filter(entry => entry.section !== 'extensions' && entry.section !== 'core')]) {
        const safe = entry.section === 'core' && entry.key === 'repositoryformatversion' || entry.section === 'extensions' || entry.section === 'branch' && ['remote', 'merge', 'pushremote'].includes(entry.key) || entry.section === 'remote' && ['fetch', 'push'].includes(entry.key) || entry.section === 'remote' && entry.subsection === undefined && entry.key === 'pushdefault' || entry.section === 'push' && entry.key === 'default';
        if (!safe) continue;
        const subsection = entry.subsection === undefined ? '' : ` ${quote(gitConfigText(entry.subsection))}`;
        const selectedValue = entry.value === null ? 'true' : quote(gitConfigText(entry.value));
        const section = `[${entry.section}${subsection}]\n\t${entry.key} = ${selectedValue}\n`; projectedBytes += Buffer.byteLength(section); if (projectedBytes > 4 * 1024 * 1024) throw new Error('GIT_CONFIG_EXPANSION_TOO_LARGE'); sections.push(section);
      }
      await writeFile(path.join(commonDir, 'config'), sections.join(''), { mode: 0o600 });
      if (enabled) await writeFile(path.join(gitDir, 'config.worktree'), '', { mode: 0o600 });
    };
    // Expands direct/gitdir/hasconfig includes before the first Git invocation;
    // onbranch includes are admitted after the safe private symbolic-ref query.
    await project();
    return { top, directory, gitDir, commonDir, workTree, configure: project, verify: async () => {
      for (const listing of listings) { const actual = await guardedList(guard, listing.root, listing.relative, listing.identity, signal); if (digest(Buffer.from(JSON.stringify(actual))) !== listing.sha256) throw new Error('GIT_METADATA_CHANGED_DURING_SNAPSHOT'); }
      for (const [source, identity] of authorities) { const current = await guardedIdentity(guard, source, signal); if (current.device !== identity.device || current.inode !== identity.inode) throw new Error('GIT_METADATA_IDENTITY_CHANGED'); }
      for (const [file, expected] of controls) { const actual = await guardedRead(guard, path.dirname(file), path.basename(file), 64 * 1024 * 1024, authorities.get(path.dirname(file))!, signal); if (digest(actual) !== expected.sha256) throw new Error('GIT_METADATA_CHANGED_DURING_SNAPSHOT'); }
    }, cleanup: () => rm(directory, { recursive: true, force: true }) };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}
