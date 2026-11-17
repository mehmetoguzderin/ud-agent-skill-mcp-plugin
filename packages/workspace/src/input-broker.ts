import { createHash } from 'node:crypto';
import { lstat, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { captureValidationSnapshot, operationInputPaths } from './snapshot.js';
import type { Snapshot } from './snapshot.js';
import { guardedGrant, guardedRead } from './guard.js';
import { validPortablePath } from './portable-path.js';
import { appendGitBase } from './git-snapshot.js';
import { appendPlanState } from './plan-state.js';

const INTERNAL = '.ud-agent-inputs';
const RULES = ['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'];
export type OperationSnapshot = { snapshot: Snapshot; arguments: Record<string, unknown>; sourceMap: { snapshot_path: string; original_path: string }[]; contextPath?: string; brokerEvidence?: Record<string, unknown> };
export type ContextBundle = { uri: string; manifest: string; files: Record<string, string> };
/** Keeps the literal failure code at its throw site and appends an actionable retry hint. */
function withHint(error: Error, hint: string): Error { error.message = `${error.message}: ${hint}`; return error; }
function digest(bytes: Buffer | string): string { return createHash('sha256').update(bytes).digest('hex'); }
function contains(root: string, target: string): boolean { const relative = path.relative(root, target); return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); }

/** Snapshot every declared input beneath an explicit grant and rewrite worker paths. */
export async function captureOperationSnapshot(guard: string, args: Record<string, unknown>, grants: readonly string[], signal?: AbortSignal, installedContext?: string, operation?: string, contextBundle?: ContextBundle): Promise<OperationSnapshot> {
  if (typeof args.working_tree_path !== 'string' || !path.isAbsolute(args.working_tree_path)) throw new Error('A granted absolute working tree is required.');
  const root = path.resolve(args.working_tree_path);
  const externals = new Map<string, { root: string; paths: string[]; selected: string; prefix: string; context: boolean }>();
  let contextPath: string | undefined;
  const rewrite = async (value: unknown, depth: number, key = ''): Promise<unknown> => {
    if (depth > 16) throw new Error('Operation input nesting exceeds its limit.');
    if (/^(?:output|destination|working_tree)(?:_|$)/.test(key)) return value;
    if (key === 'ud_context_path') {
      if (value === undefined || value === '' || value === installedContext) return '';
      if (typeof value !== 'string' || !value || /^(?:""|'')$/.test(value)) throw withHint(new Error('CONTEXT_INPUT_INVALID'), typeof value === 'string' ? 'ud_context_path is the two-character text "" (quote marks); send an empty string with no characters for the default context.' : 'ud_context_path must be a string; send an empty string for the default context.');
      if (value.startsWith('ud://')) {
        if (!contextBundle || value !== contextBundle.uri) throw new Error('CONTEXT_RESOURCE_NOT_AUTHORIZED');
        const manifest = JSON.parse(contextBundle.manifest) as { rules?: Record<string, string>; context_sha256?: unknown; rule_dir?: unknown };
        if (manifest.rule_dir !== 'rules' || !manifest.rules || Object.keys(contextBundle.files).sort().join(',') !== RULES.join(',') || Object.keys(manifest.rules).sort().join(',') !== RULES.join(',')) throw new Error('CONTEXT_RESOURCE_INVALID');
        const hashes = Object.fromEntries(RULES.map(name => [name, digest(contextBundle.files[name]!)]));
        if (RULES.some(name => hashes[name] !== manifest.rules![name]) || digest(JSON.stringify(hashes)) !== manifest.context_sha256) throw new Error('CONTEXT_RESOURCE_INTEGRITY_FAILED');
        contextPath = `${INTERNAL}/context-${manifest.context_sha256}/context.json`; return contextPath;
      }
      const absolute = path.isAbsolute(value) ? path.resolve(value) : path.resolve(root, value);
      const selected = await addExternal(absolute, true); contextPath = selected; return selected;
    }
    if (typeof value === 'string' && /(?:^|_)paths?$/.test(key)) {
      if (!path.isAbsolute(value)) {
        if (value !== '.' && !validPortablePath(value)) throw new Error('Operation input path is unsafe.');
        if (value === INTERNAL || value.startsWith(`${INTERNAL}/`)) throw new Error('Operation input uses a reserved broker path.');
        return value;
      }
      const absolute = path.resolve(value);
      if (contains(root, absolute)) return path.relative(root, absolute).split(path.sep).join('/') || '.';
      return addExternal(absolute, false);
    }
    if (Array.isArray(value)) {
      if (value.length > 10_000) throw new Error('Operation input selection exceeds its limit.');
      const out = []; for (const item of value) out.push(await rewrite(item, depth + 1, key.endsWith('s') ? key.slice(0, -1) : key)); return out;
    }
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {}; for (const [name, item] of Object.entries(value)) out[name] = await rewrite(item, depth + 1, name); return out;
    }
    return value;
  };
  const addExternal = async (absolute: string, context: boolean): Promise<string> => {
    const cached = externals.get(`${context}:${absolute}`); if (cached) return cached.selected;
    const info = await lstat(absolute);
    if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) throw new Error('Operation input must be an ordinary file or directory.');
    const sourceRoot = info.isDirectory() ? absolute : path.dirname(absolute);
    const identity = await guardedGrant(guard, sourceRoot, grants, signal);
    const prefix = `${INTERNAL}/${digest(`${context}:${absolute}`).slice(0, 24)}`;
    let selected = info.isDirectory() ? prefix : `${prefix}/${path.basename(absolute)}`;
    let paths = [info.isDirectory() ? '.' : path.basename(absolute)];
    if (context && info.isFile()) {
      const bytes = await guardedRead(guard, sourceRoot, path.basename(absolute), 1024 * 1024, identity, signal);
      const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Record<string, unknown>;
      if (typeof manifest.rule_dir !== 'string' || (manifest.rule_dir !== '.' && !validPortablePath(manifest.rule_dir))) throw new Error('CONTEXT_RULE_DIRECTORY_INVALID');
      paths = [...new Set([path.basename(absolute), ...RULES.map(name => manifest.rule_dir === '.' ? name : `${manifest.rule_dir}/${name}`)])];
      if (manifest.repository_checks && typeof manifest.repository_checks === 'object' && !Array.isArray(manifest.repository_checks)) {
        const assets = (manifest.repository_checks as Record<string, unknown>).assets;
        if (assets && typeof assets === 'object' && !Array.isArray(assets)) {
          for (const name of Object.keys(assets)) { if (!validPortablePath(name)) throw new Error('CONTEXT_ASSET_PATH_INVALID'); paths.push(name); }
        }
      }
    }
    if (context && info.isDirectory()) selected = `${prefix}/context.json`;
    if (externals.size >= 128) throw new Error('Operation has too many independent input roots.');
    externals.set(`${context}:${absolute}`, { root: sourceRoot, paths, selected, prefix, context });
    return selected;
  };
  const rewritten = await rewrite(args, 0) as Record<string, unknown>;
  // Reserved prefixes are staged separately, never read from a project tree.
  const primaryPaths = operationInputPaths(rewritten).filter(name => name !== INTERNAL && !name.startsWith(`${INTERNAL}/`));
  const snapshot = await captureValidationSnapshot(guard, root, grants, signal, primaryPaths);
  try {
    if (snapshot.files.some(file => file.path === INTERNAL || file.path.startsWith(`${INTERNAL}/`))) throw new Error('Workspace uses a reserved broker input directory.');
    const sourceMap = snapshot.files.map(file => ({ snapshot_path: file.path, original_path: path.join(root, ...file.path.split('/')) }));
    if (contextBundle && contextPath?.startsWith(`${INTERNAL}/context-`)) {
      const prefix = path.posix.dirname(contextPath);
      for (const [name, content] of [['context.json', contextBundle.manifest], ...RULES.map(name => [`rules/${name}`, contextBundle.files[name]!])] as [string, string][]) {
        const relative = `${prefix}/${name}`, bytes = Buffer.from(content);
        if (bytes.toString('utf8') !== content || bytes.length > 64 * 1024 * 1024) throw new Error('CONTEXT_RESOURCE_INVALID');
        const target = path.join(snapshot.directory, ...relative.split('/'));
        await mkdir(path.dirname(target), { recursive: true, mode: 0o700 }); await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
        snapshot.files.push({ path: relative, sha256: digest(bytes), size: bytes.length });
        sourceMap.push({ snapshot_path: relative, original_path: contextBundle.uri });
      }
    }
    for (const entry of externals.values()) {
      sourceMap.push({ snapshot_path: entry.prefix, original_path: entry.root });
      const captured = await captureValidationSnapshot(guard, entry.root, grants, signal, entry.paths, false);
      try {
        for (const file of captured.files) {
          const relative = `${entry.prefix}/${file.path}`;
          const bytes = await guardedRead(guard, captured.directory, file.path, 64 * 1024 * 1024, captured.snapshot_identity, signal);
          if (digest(bytes) !== file.sha256) throw new Error('OPERATION_INPUT_CHANGED');
          const target = path.join(snapshot.directory, ...relative.split('/'));
          await mkdir(path.dirname(target), { recursive: true, mode: 0o700 }); await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
          snapshot.files.push({ ...file, path: relative }); sourceMap.push({ snapshot_path: relative, original_path: path.join(entry.root, ...file.path.split('/')) });
        }
        if (entry.context) {
          const contextFile = entry.selected.slice(entry.prefix.length + 1);
          const existing = captured.files.find(file => file.path === contextFile);
          if (!existing) {
            const rules = Object.fromEntries(RULES.map(name => { const file = captured.files.find(item => item.path === name); if (!file) throw withHint(new Error('CONTEXT_RULES_INCOMPLETE'), 'ud_context_path has no UD rule files; retry with ud_context_path empty (no value) for the default context.'); return [name, file.sha256]; }));
            const bytes = Buffer.from(`${JSON.stringify({ schema_version: 1, rule_dir: '.', rules, context_sha256: digest(JSON.stringify(rules)) })}\n`);
            await writeFile(path.join(snapshot.directory, ...entry.selected.split('/')), bytes, { flag: 'wx', mode: 0o600 });
            snapshot.files.push({ path: entry.selected, sha256: digest(bytes), size: bytes.length });
          }
        }
      } finally { await captured.cleanup(); }
    }
    const planState = operation === 'plan_apply' ? await appendPlanState(guard, root, rewritten, snapshot, signal) : undefined;
    for (const file of snapshot.files) if (!file.path.startsWith(`${INTERNAL}/`) && !sourceMap.some(item => item.snapshot_path === file.path)) sourceMap.push({ snapshot_path: file.path, original_path: path.join(root, ...file.path.split('/')) });
    const gitBase = (operation === 'changes_review' || operation === 'treebank_review') && typeof args.base_revision === 'string' ? await appendGitBase(guard, root, grants, args.base_revision, snapshot, signal) : undefined;
    snapshot.files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    // Framing and the Python receiver hash this exact field order. Inputs
    // appended from Git or context resources must use the same canonical form
    // as native workspace files before their aggregate identity is frozen.
    snapshot.files = snapshot.files.map(file => ({ path: file.path, size: file.size, sha256: file.sha256 }));
    if (snapshot.files.length > 10_000 || snapshot.files.reduce((sum, file) => sum + file.size, 0) > 512 * 1024 * 1024) throw new Error('Operation snapshot exceeds its bounds.');
    snapshot.sha256 = digest(JSON.stringify(snapshot.files));
    return { snapshot, arguments: rewritten, sourceMap, ...(contextPath === undefined ? {} : { contextPath }), ...(gitBase === undefined && planState === undefined ? {} : { brokerEvidence: { schema_version: 1, snapshot_sha256: snapshot.sha256, ...(gitBase === undefined ? {} : { git_base: gitBase }), ...(planState === undefined ? {} : { plan_state: planState }) } }) };
  } catch (error) { await snapshot.cleanup(); throw error; }
}
