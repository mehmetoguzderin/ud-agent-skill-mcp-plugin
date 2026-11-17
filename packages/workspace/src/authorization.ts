import { lstat, realpath, stat } from 'node:fs/promises';
import path from 'node:path';

export class AuthorizationError extends Error {
  readonly code = 'WORKSPACE_NOT_AUTHORIZED';
}

/** Actionable for small models: name the single host-granted workspace to retry with. */
export function absolutePathReason(grantedRoots: readonly string[]): string {
  const roots = grantedRoots.filter(root => path.isAbsolute(root) && !root.includes('\0'));
  return roots.length === 1 ? `Workspace must be an absolute host path; retry with working_tree_path "${path.resolve(roots[0]!)}".` : 'Workspace must be an absolute host path.';
}

/** The single granted root, if exactly one is configured (the only safe retry suggestion). */
function singleRoot(grantedRoots: readonly string[]): string | undefined {
  const roots = grantedRoots.filter(root => path.isAbsolute(root) && !root.includes('\0'));
  return roots.length === 1 ? path.resolve(roots[0]!) : undefined;
}

/** A file or a missing path given as the workspace: say which argument holds what, and name the grant. */
export function workspaceArgumentReason(problem: string, grantedRoots: readonly string[]): string {
  const root = singleRoot(grantedRoots);
  return `${problem}; working_tree_path is the folder and file_paths names files inside it${root ? `: retry with working_tree_path "${root}"` : ''}.`;
}

/** Outside every grant: name the path and, with one grant, the folder to use and how the other paths relate to it. */
export function outsideRootsReason(target: string, grantedRoots: readonly string[]): string {
  const root = singleRoot(grantedRoots);
  return root ? `Workspace is outside the configured authorized roots: "${target}" is not inside "${root}". Use working_tree_path "${root}" and give the other paths relative to it (inside that folder); a placeholder such as "/" is not a path.` : 'Workspace is outside the configured authorized roots.';
}

function contains(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

/** A regular file given as working_tree_path, inside a granted root, with file_paths empty or naming that
 * file, has one meaning: its folder is the workspace and the file is selected. Returns the corrected arguments
 * and a note, or undefined when the input is not exactly that case. Authorization still runs on the result. */
export async function workspaceFileArguments(args: Record<string, unknown>, grantedRoots: readonly string[]): Promise<{ args: Record<string, unknown>; note: string } | undefined> {
  const target = args.working_tree_path, files = args.file_paths;
  // Without file_paths, a reference object (tree_ref, token_ref.tree_ref, ...) naming that same file keeps the scope exact.
  // Otherwise (e.g. gold_file_paths/prediction_file_paths), other relative path arguments inside that folder do.
  const refs = files === undefined ? (referencedFiles(args).length ? referencedFiles(args) : otherPathArguments(args)) : undefined;
  if (typeof target !== 'string' || !path.isAbsolute(target) || target.includes('\0')) return undefined;
  if (refs === undefined && (!Array.isArray(files) || files.some(file => typeof file !== 'string'))) return undefined;
  let info;
  try { info = await lstat(target); } catch { return undefined; }
  if (!info.isFile()) return undefined;
  const folder = path.dirname(path.resolve(target)), name = path.basename(target);
  if (refs !== undefined) {
    const sameFile = referencedFiles(args).length > 0;
    if (!refs.length || !refs.every(file => sameFile ? path.resolve(folder, file) === path.join(folder, name) : !path.isAbsolute(file) && contains(folder, path.resolve(folder, file)))) return undefined;
  } else if (!(files as string[]).every(file => path.resolve(folder, file) === path.join(folder, name))) return undefined;
  let canonical: string;
  try { canonical = await realpath(folder); } catch { return undefined; }
  for (const root of grantedRoots) {
    if (!path.isAbsolute(root) || root.includes('\0')) continue;
    let canonicalRoot: string;
    try { canonicalRoot = await realpath(root); } catch { continue; }
    if (contains(canonicalRoot, canonical)) {
      if (refs !== undefined) return { args: { ...args, working_tree_path: folder }, note: referencedFiles(args).length ? `working_tree_path named a file; used its folder "${folder}" as working_tree_path (the references name "${name}").` : `working_tree_path named a file; used its folder "${folder}" as working_tree_path (the other path arguments are relative to it).` };
      return { args: { ...args, working_tree_path: folder, file_paths: [name] }, note: `working_tree_path named a file; used its folder "${folder}" as working_tree_path with file_paths ["${name}"].` };
    }
  }
  return undefined;
}

/** file_path values of reference objects (keys ending in _ref, nested), e.g. token_ref.tree_ref.file_path. */
function referencedFiles(args: Record<string, unknown>): string[] {
  const found: string[] = [];
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || !value || typeof value !== 'object' || Array.isArray(value)) return;
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (key === 'file_path' && typeof item === 'string') found.push(item);
      else if (/_ref$/.test(key)) visit(item, depth + 1);
    }
  };
  for (const [key, item] of Object.entries(args)) if (/_ref$/.test(key)) visit(item, 0);
  return found;
}

/** Relative values of other path arguments (keys ending in _path/_paths), excluding the workspace, context and outputs. */
function otherPathArguments(args: Record<string, unknown>): string[] {
  const found: string[] = [];
  for (const [key, value] of Object.entries(args)) {
    if (!/(?:^|_)paths?$/.test(key) || /^(?:working_tree|ud_context|output|destination)(?:_|$)/.test(key)) continue;
    for (const item of Array.isArray(value) ? value : [value]) if (typeof item === 'string' && item) found.push(item);
  }
  return found;
}

/**
 * A relative working_tree_path ("." , "./", "sub", "a.conllu") under exactly one granted root is resolved inside
 * that root; anything that would leave it, or several roots, keeps the normal rejection.
 */
export async function relativeWorkspaceArguments(args: Record<string, unknown>, grantedRoots: readonly string[]): Promise<{ args: Record<string, unknown>; note: string } | undefined> {
  const value = args.working_tree_path;
  if (typeof value !== 'string' || !value || value.includes('\0') || grantedRoots.length !== 1) return undefined;
  const root = grantedRoots[0]!;
  if (!path.isAbsolute(root) || root.includes('\0')) return undefined;
  if (path.isAbsolute(value)) {
    // "/treebank" for the grant ".../treebank": only when that absolute path does not exist, so no real folder is redirected.
    if (path.resolve(value) !== path.resolve('/', path.basename(root)) || path.resolve(value) === path.resolve(root)) return undefined;
    try { await lstat(value); return undefined; } catch { /* absent: read it as the grant's name */ }
    return { args: { ...args, working_tree_path: path.resolve(root) }, note: `working_tree_path "${value}" does not exist; it names the granted workspace folder, so used "${path.resolve(root)}".` };
  }
  // The grant's own name ("treebank", "./treebank") or its absolute path missing the leading slash ("tmp/x/treebank") mean the grant.
  const trimmed = path.normalize(value).replace(path.sep === '\\' ? /\\+$/ : /\/+$/, '');
  const name = path.basename(root);
  let target = trimmed === name || path.resolve('/', trimmed) === path.resolve(root) ? path.resolve(root) : path.resolve(root, value);
  // "treebank/gold.conllu" repeats the grant's name in front of a path inside it; use the inside path when the literal one is absent.
  if (target !== path.resolve(root) && trimmed.startsWith(`${name}${path.sep}`)) {
    try { await lstat(target); } catch { target = path.resolve(root, trimmed.slice(name.length + 1)); }
  }
  let canonicalRoot: string, canonical: string;
  try { canonicalRoot = await realpath(root); canonical = await realpath(target); } catch { return undefined; }
  if (canonical !== canonicalRoot && !contains(canonicalRoot, canonical)) return undefined;
  return { args: { ...args, working_tree_path: target }, note: `working_tree_path "${value}" was relative; resolved it inside the granted workspace as "${target}".` };
}

/**
 * File arguments (keys ending in _path/_paths, other than the workspace, context and outputs) are relative to
 * working_tree_path. An absolute value inside it becomes that relative name; an absolute value that does not exist
 * but whose file name exists directly in the workspace (a missed folder level) becomes that name. Others are kept.
 */
export async function absoluteFileArguments(args: Record<string, unknown>): Promise<{ args: Record<string, unknown>; note: string } | undefined> {
  const root = args.working_tree_path;
  if (typeof root !== 'string' || !path.isAbsolute(root) || root.includes('\0')) return undefined;
  const changed: string[] = [], next: Record<string, unknown> = { ...args };
  const fix = async (value: unknown): Promise<unknown> => {
    if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) return value;
    const resolved = path.resolve(value);
    if (resolved !== path.resolve(root) && contains(path.resolve(root), resolved)) { changed.push(`"${value}" → "${path.relative(root, resolved)}"`); return path.relative(root, resolved); }
    try { await lstat(resolved); return value; } catch { /* absent: maybe a missed folder level */ }
    try { if ((await stat(path.join(root, path.basename(resolved)))).isFile()) { changed.push(`"${value}" → "${path.basename(resolved)}"`); return path.basename(resolved); } } catch { /* keep */ }
    return value;
  };
  for (const [key, value] of Object.entries(args)) {
    if (!/(?:^|_)paths?$/.test(key) || /^(?:working_tree|ud_context|output|destination)(?:_|$)/.test(key)) continue;
    next[key] = Array.isArray(value) ? await Promise.all(value.map(fix)) : await fix(value);
  }
  return changed.length ? { args: next, note: `file paths are relative to working_tree_path; used ${changed.join(', ')}.` } : undefined;
}

/**
 * XML tool-call formats carry strings verbatim, so an empty value is often written as the two characters "" or ''.
 * Neither can name a context file; read them as the empty string (installed default) and say so.
 */
export function quotedEmptyContextArguments(args: Record<string, unknown>): { args: Record<string, unknown>; note: string } | undefined {
  // Placeholder words and the workspace folder itself are not context selections either.
  if (typeof args.ud_context_path === 'string' && /^(?:empty|none|null|default|\{\}|\[\]|\/|\.)$/i.test(args.ud_context_path.trim())) return { args: { ...args, ud_context_path: '' }, note: `ud_context_path was the placeholder "${args.ud_context_path}"; used the installed default context (empty string).` };
  if (typeof args.ud_context_path === 'string' && typeof args.working_tree_path === 'string' && args.ud_context_path.replace(/\/+$/, '') === args.working_tree_path.replace(/\/+$/, '')) return { args: { ...args, ud_context_path: '' }, note: 'ud_context_path repeated working_tree_path; used the installed default context (empty string).' };
  // A CoNLL-U data file is never a rules context either (contexts are context.json bundles or ud:// resources).
  if (typeof args.ud_context_path === 'string' && /\.conllu$/i.test(args.ud_context_path)) return { args: { ...args, ud_context_path: '' }, note: `ud_context_path named the data file "${args.ud_context_path}", which cannot be a rules context; used the installed default context (empty string).` };
  // Whitespace around the quotes (` ""`) or only whitespace is the same empty selection.
  if (typeof args.ud_context_path !== 'string' || !/^\s*(?:""|'')?\s*$/.test(args.ud_context_path) || args.ud_context_path === '') return undefined;
  return { args: { ...args, ud_context_path: '' }, note: `ud_context_path was the quote characters ${args.ud_context_path}; used the installed default context (empty string).` };
}

/** A path argument cannot grant access. Roots come from trusted launch configuration. */
export async function authorizeWorkspace(target: string, grantedRoots: readonly string[]): Promise<string> {
  if (!path.isAbsolute(target) || target.includes('\0')) throw new AuthorizationError(absolutePathReason(grantedRoots));
  let targetInfo;
  try { targetInfo = await lstat(target); }
  catch (error: unknown) {
    // The error code stays ENOENT; only the message gains the retry argument.
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') (error as Error).message = workspaceArgumentReason((error as Error).message, grantedRoots);
    throw error;
  }
  if (targetInfo.isSymbolicLink()) throw new AuthorizationError('A symbolic link cannot be the workspace root.');
  const canonical = await realpath(target);
  if (!(await stat(canonical)).isDirectory()) throw new AuthorizationError(workspaceArgumentReason('Workspace is not a directory', grantedRoots));
  for (const root of grantedRoots) {
    if (!path.isAbsolute(root) || root.includes('\0')) continue;
    let canonicalRoot: string;
    try { canonicalRoot = await realpath(root); }
    catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    if (contains(canonicalRoot, canonical)) return canonical;
  }
  throw new AuthorizationError(outsideRootsReason(target, grantedRoots));
}

/** Parsed from trusted process/host configuration, never from a request argument. */
export function parseGrantedRoots(value: string | undefined): string[] {
  if (value === undefined || value === '') return [];
  let parsed: unknown;
  try { parsed = JSON.parse(value); }
  catch { throw new AuthorizationError('UD_AGENT_ALLOWED_ROOTS must contain valid JSON.'); }
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'string' || !path.isAbsolute(item))) {
    throw new AuthorizationError('UD_AGENT_ALLOWED_ROOTS must be a JSON array of absolute paths.');
  }
  return parsed as string[];
}
