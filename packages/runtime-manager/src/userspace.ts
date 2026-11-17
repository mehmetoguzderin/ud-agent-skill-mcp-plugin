import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, link, lstat, mkdir, mkdtemp, open, readFile, readdir, readlink, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { assetRepairRecords, repairOwnedAssetPack } from './asset-repair.js';
import type { Host } from './profiles.js';
import { loadNativeGuardReceipt, readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import { coreAssetRoot, coreDescriptor, prepareCoreAssets, readCoreDescriptor } from './userspace-core.js';
import { runCommand } from './command.js';
import { acquireManagedPythonArchive, acquireVerifiedUv, acquireVendorUv, acquireRenderArchive, acquireMicrosoftEdgeMsi, acquireGoogleBrowserArchive, UvAcquisitionUnavailable, validateManagedPythonDownload, validateUvDownload, validateUvVendorDownload } from './userspace-download.js';
import type { ManagedPythonDownload, UvDownload, UvVendorDownload } from './userspace-download.js';
import { acquirePerlVendorArchive, validatePerlVendorRecipe } from './userspace-perl-runtime.js';
import type { PerlVendorRecipe } from './userspace-perl-runtime.js';
import { durableWrite, fsyncDirectory, JournalStore, openStateAuthority } from '../../workspace/src/journal.js';
import { guardedCreate, guardedIdentity, guardedPrivateRead, guardedStateLock } from '../../workspace/src/guard.js';
const stateGuard = new AsyncLocalStorage<string>();
const maintenanceAuthority = new AsyncLocalStorage<{ state: string; markerSha256: string }>();
const setupCancellation = new AsyncLocalStorage<AbortSignal | undefined>();
function checkSetupCancellation(): void { if (setupCancellation.getStore()?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED'); }
const setupFetch: typeof fetch = (input, options) => { const signal = setupCancellation.getStore(); return fetch(input, signal ? { ...options, signal: options?.signal ? AbortSignal.any([signal, options.signal]) : signal } : options); };
async function stateAuthority(directory: string, initialize = false) {
  if (process.platform !== 'win32') return undefined;
  const guard = stateGuard.getStore();
  if (!guard) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
  return openStateAuthority(directory, guard, initialize);
}
async function syncState(directory: string): Promise<void> { await fsyncDirectory(directory, await stateAuthority(directory)); }
async function stateBytes(file: string): Promise<Buffer> {
  if (process.platform !== 'win32') return readBoundedReceiptBytes(file);
  const native = await stateAuthority(path.dirname(file));
  if (!native) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
  return guardedPrivateRead(native.guard, native.root, path.basename(file), 1024 * 1024, native.identity);
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const issued = new WeakMap<object, { sourceRoot: string; stateRoot: string; manifest: string; environment: string; fingerprint: string }>();
type Entry = { path: string; sha256: string; size: number };
type PerlLoader = { executable: string; libraryDirs: string[] };
type DeferredPerl = { recipe: string; definition: PerlVendorRecipe; relocatedLibraryDirs?: string[] };
type Pack = { coreArchive?: string; assetRoot: string; guardPath: string; guardSha256: string; digest: string; host: Host; files: Entry[]; packs: ('core' | 'render')[]; worker: string; upstream: string; context: string; bootstrap: string; guard: string; requirements: string; wheels: string; uv?: string; uvDownload?: UvDownload; uvVendorDownload?: UvVendorDownload; pythonDownload?: ManagedPythonDownload; perl?: { executable: string; libraryDirs: string[]; loader?: PerlLoader; deferredRuntime?: DeferredPerl }; render?: { manifest: string }; lazyRender?: { url: string; sha256: string; size: number; manifest: string } };
export type UserspaceExecution = Readonly<{ python: string; workerPath: string; upstreamPath: string; contextPath: string; bootstrap: string; guard: string; manifestSha256: string; packs: readonly ('core' | 'render')[]; isolation: 'userspace'; perl?: string; perlLibraryPaths?: readonly string[]; perlLoader?: Readonly<{ executable: string; libraryPaths: readonly string[] }>; renderManifest?: string; renderReady?: boolean; contextAssetRoot?: string }>;

function sha256(bytes: Buffer | string): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function safeRelative(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes('\0') && !value.includes(':') && !value.startsWith('/') && value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

/** Versions before uv 0.7 lack part of the isolated managed-Python workflow. */
export function isCompatibleUvVersion(output: string): boolean {
  const match = /^uv (\d+)\.(\d+)\.(\d+)(?:\s|$)/.exec(output);
  if (!match) return false;
  const major = Number(match[1]); const minor = Number(match[2]);
  return Number.isSafeInteger(major) && Number.isSafeInteger(minor) && (major > 0 || minor >= 7);
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid userspace receipt.');
  return value as Record<string, unknown>;
}

/** A product-owned location; this never creates or changes a directory. */
export function userspaceStateRoot(host: Host = { platform: process.platform, arch: process.arch }, env: NodeJS.ProcessEnv = process.env): string {
  const api = host.platform === 'win32' ? path.win32 : path.posix;
  const home = host.platform === 'win32' ? env.USERPROFILE : env.HOME;
  if (host.platform === 'win32') {
    if (!env.LOCALAPPDATA || !api.isAbsolute(env.LOCALAPPDATA)) throw new Error('LOCALAPPDATA is required for userspace state.');
    return api.join(env.LOCALAPPDATA, 'ud-agent', 'data', 'userspace');
  }
  if (!home || !api.isAbsolute(home)) throw new Error('An absolute home directory is required for userspace state.');
  if (host.platform === 'darwin') return api.join(home, 'Library', 'Application Support', 'ud-agent', 'userspace');
  if (host.platform === 'linux') {
    const data = env.XDG_DATA_HOME && api.isAbsolute(env.XDG_DATA_HOME) ? env.XDG_DATA_HOME : api.join(home, '.local', 'share');
    return api.join(data, 'ud-agent', 'userspace');
  }
  throw new Error('Unsupported userspace platform.');
}

async function ownedDirectory(dir: string, create = false): Promise<string> {
  if (!path.isAbsolute(dir)) throw new Error('Userspace state directory must be absolute.');
  if (create) checkSetupCancellation();
  if (create) await mkdir(dir, { recursive: true, mode: 0o700 });
  const info = await lstat(dir);
  if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && info.uid !== process.getuid())))) throw new Error('Userspace state directory is not private and user-owned.');
  if (process.platform === 'win32') await stateAuthority(dir, create);
  return realpath(dir);
}

async function checkedPath(root: string, relative: string, type: 'file' | 'directory'): Promise<string> {
  if (!safeRelative(relative)) throw new Error('Invalid userspace asset path.');
  let current = root;
  const parts = relative.split('/');
  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink() || (index < parts.length - 1 ? !info.isDirectory() : type === 'file' ? !info.isFile() : !info.isDirectory())) throw new Error('Userspace asset path contains a link or unexpected file.');
  }
  return current;
}

/** Verify the manifest binding and each installed product asset before use. */
async function loadPack(sourceRoot: string, host: Host, stateRoot = userspaceStateRoot(host)): Promise<Pack> {
  if (!path.isAbsolute(sourceRoot) || !['darwin', 'linux', 'win32'].includes(host.platform) || !['x64', 'arm64'].includes(host.arch)) throw new Error('Unsupported userspace platform or product path.');
  const productRoot = await realpath(sourceRoot);
  const rootLock = record(JSON.parse((await readBoundedReceiptBytes(await checkedPath(productRoot, 'runtime/runtime.lock.json', 'file'))).toString('utf8')));
  if (rootLock.schema_version !== 1 || rootLock.product_version !== '0.1.0-beta.1' || rootLock.state !== 'frozen' || typeof rootLock.userspace_sha256 !== 'string' || !DIGEST.test(rootLock.userspace_sha256)) throw new Error('USERSPACE_RECEIPT_NOT_FROZEN');
  // Six closed native inventories include thousands of Perl/browser assets.
  const bytes = await readBoundedReceiptBytes(await checkedPath(productRoot, 'runtime/userspace.lock.json', 'file'), 32 * 1024 * 1024);
  if (sha256(bytes) !== rootLock.userspace_sha256) throw new Error('USERSPACE_RECEIPT_MISMATCH');
  const manifest = record(JSON.parse(bytes.toString('utf8')));
  if (manifest.schema_version !== 1 || manifest.product_version !== '0.1.0-beta.1' || manifest.state !== 'frozen') throw new Error('USERSPACE_RECEIPT_NOT_FROZEN');
  const platforms = record(manifest.platforms);
  const item = record(platforms[`${host.platform}/${host.arch}`]);
  const root = await coreAssetRoot(productRoot, stateRoot, item, host);
  const nativeGuard = coreDescriptor(item, host) ? await loadNativeGuardReceipt(productRoot, host) : undefined;
  const installedGuard = nativeGuard?.guard;
  try {
  const uvDownload = item.uv_download === undefined ? undefined : validateUvDownload(item.uv_download);
  const uvVendorDownload = item.uv_vendor_download === undefined ? undefined : validateUvVendorDownload(item.uv_vendor_download, host);
  if (uvVendorDownload && (uvDownload || item.uv !== undefined)) throw new Error('The userspace pack declares conflicting uv sources.');
  const pythonDownload = item.python_download === undefined ? undefined : validateManagedPythonDownload(item.python_download, host);
  if (uvDownload && !uvDownload.url.endsWith(`/uv-${host.platform}-${host.arch}${host.platform === 'win32' ? '.exe' : ''}`)) throw new Error('The uv download receipt targets a different host.');
  const paths = ['worker', 'upstream', 'context', 'bootstrap', 'guard', 'requirements', 'wheels'] as const;
  if (paths.some(key => !safeRelative(item[key])) || (item.uv !== undefined && !safeRelative(item.uv)) || !Array.isArray(item.files) || item.files.length < 1 || item.files.length > 20_000 || !Array.isArray(item.packs) || !item.packs.includes('core') || item.packs.some(pack => pack !== 'core' && pack !== 'render') || new Set(item.packs).size !== item.packs.length) throw new Error('Invalid userspace platform receipt.');
  const perl = item.perl === undefined ? undefined : record(item.perl);
  if ((manifest.format_revision === 2 && !perl) || (perl && (Object.keys(perl).some(key => !['executable', 'library_dirs', 'loader', 'deferred_runtime'].includes(key)) || !safeRelative(perl.executable) || !Array.isArray(perl.library_dirs) || perl.library_dirs.length < 1 || perl.library_dirs.length > 32 || perl.library_dirs.some(name => !safeRelative(name))))) throw new Error('USERSPACE_PRIVATE_PERL_REQUIRED');
  const deferredPerl = perl?.deferred_runtime === undefined ? undefined : record(perl.deferred_runtime);
  if (deferredPerl && (host.platform !== 'win32' || Object.keys(deferredPerl).sort().join(',') !== 'provider,recipe' || deferredPerl.provider !== 'conda-vc-runtime' || !safeRelative(deferredPerl.recipe))) throw new Error('USERSPACE_PERL_VENDOR_RECIPE_INVALID');
  const perlLoader = perl?.loader === undefined ? undefined : record(perl.loader);
  if (perlLoader && (host.platform !== 'linux' || Object.keys(perlLoader).sort().join(',') !== 'executable,library_dirs' || !safeRelative(perlLoader.executable) || !Array.isArray(perlLoader.library_dirs) || perlLoader.library_dirs.length < 1 || perlLoader.library_dirs.length > 64 || new Set(perlLoader.library_dirs).size !== perlLoader.library_dirs.length || perlLoader.library_dirs.some(name => !safeRelative(name)))) throw new Error('USERSPACE_PRIVATE_PERL_LOADER_INVALID');
  const render = item.render === undefined ? undefined : record(item.render);
  if (render && (Object.keys(render).join(',') !== 'manifest' || !safeRelative(render.manifest) || !item.packs.includes('render'))) throw new Error('Invalid userspace render receipt.');
  const lazy = item.lazy_render === undefined ? undefined : record(item.lazy_render);
  if (lazy && (render || Object.keys(lazy).sort().join(',') !== 'manifest,sha256,size,url' || lazy.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-render-${host.platform}-${host.arch}.tar.gz` || typeof lazy.sha256 !== 'string' || !DIGEST.test(lazy.sha256) || !Number.isSafeInteger(lazy.size) || (lazy.size as number) < 1 || (lazy.size as number) > 2 * 1024 ** 3 || !safeRelative(lazy.manifest))) throw new Error('Invalid userspace lazy render receipt.');
  const files: Entry[] = []; const names = new Set<string>(); let total = 0;
  for (const value of item.files) {
    const file = record(value);
    if (!safeRelative(file.path) || typeof file.sha256 !== 'string' || !DIGEST.test(file.sha256) || !Number.isSafeInteger(file.size) || (file.size as number) < 0 || (file.size as number) > 128 * 1024 * 1024 || names.has(file.path)) throw new Error('Invalid userspace asset receipt.');
    names.add(file.path); total += file.size as number;
    if (total > 2 * 1024 * 1024 * 1024) throw new Error('Userspace assets exceed the size limit.');
    files.push({ path: file.path, sha256: file.sha256, size: file.size as number });
  }
  // Bound IO concurrency while still hashing every listed byte on every check.
  // No ambient caches or saved verification flags are trusted here.
  let cursor = 0;
  const verification = await Promise.allSettled(Array.from({ length: Math.min(16, files.length) }, async () => {
    for (;;) {
      const file = files[cursor++]; if (!file) return;
      const resolved = await checkedPath(root, file.path, 'file');
      if ((await stat(resolved)).size !== file.size) throw new Error('Userspace asset size does not match its receipt.');
      await verifyArchive(resolved, file.sha256);
    }
  }));
  for (const result of verification) if (result.status === 'rejected') throw result.reason;
  let perlVendor: DeferredPerl | undefined;
  if (deferredPerl && perl) {
    const name = deferredPerl.recipe as string;
    const fileByPath = new Map(files.map(file => [file.path, file]));
    const recipeReceipt = fileByPath.get(name);
    if (!recipeReceipt) throw new Error('USERSPACE_PERL_VENDOR_RECIPE_UNLISTED');
    const recipeBytes = await readBoundedReceiptBytes(await checkedPath(root, name, 'file'), 4 * 1024 ** 2);
    if (recipeBytes.length !== recipeReceipt.size || sha256(recipeBytes) !== recipeReceipt.sha256) throw new Error('USERSPACE_PERL_VENDOR_RECIPE_MISMATCH');
    const definition = validatePerlVendorRecipe(JSON.parse(recipeBytes.toString('utf8')), host);
    const directory = path.posix.dirname(name);
    for (const row of definition.base_files) {
      const source = path.posix.join(directory, row.source), entry = fileByPath.get(source);
      if (!entry || entry.sha256 !== `sha256:${row.sha256}` || entry.size !== row.size_bytes) throw new Error('USERSPACE_PERL_VENDOR_BASE_UNLISTED');
    }
    perlVendor = { recipe: name, definition };
    if (definition.supplier) {
      if (!safeRelative(directory) || perl.executable !== path.posix.join(directory, definition.executable) || names.has(perl.executable as string)) throw new Error('USERSPACE_PERL_SUPPLIER_EXECUTABLE_INVALID');
      const installed = [...definition.base_files, ...definition.files, ...definition.supplier.files];
      perlVendor.relocatedLibraryDirs = (perl.library_dirs as string[]).map(library => {
        const relative = path.posix.relative(directory, library);
        if (!safeRelative(relative) || !installed.some(file => file.path.startsWith(relative + '/'))) throw new Error('USERSPACE_PERL_SUPPLIER_LIBRARY_INVALID');
        return 'deferred-perl/' + relative;
      });
    }
  }
  for (const key of ['context', 'bootstrap', 'guard', 'requirements'] as const) if (!names.has(item[key] as string)) throw new Error(`Userspace ${key} is missing from the receipt.`);
  for (const key of ['worker', 'upstream', 'wheels'] as const) {
    const directory = item[key] as string;
    await checkedPath(root, directory, 'directory');
    if (key !== 'wheels' && !files.some(file => file.path.startsWith(directory + '/'))) throw new Error(`Userspace ${key} is empty.`);
  }
  if (item.uv !== undefined && !names.has(item.uv as string)) throw new Error('Bundled uv is missing from the receipt.');
  if (perl && !perlVendor?.definition.supplier) {
    if (!names.has(perl.executable as string)) throw new Error('Private Perl executable is missing from the receipt.');
    const executable = await checkedPath(root, perl.executable as string, 'file');
    if (process.platform !== 'win32' && ((await lstat(executable)).mode & 0o111) === 0) throw new Error('Private Perl is not executable.');
    for (const name of perl.library_dirs as string[]) {
      await checkedPath(root, name, 'directory');
      if (!files.some(file => file.path.startsWith(name + '/'))) throw new Error('Private Perl library is empty.');
    }
  }
  if (perlLoader) {
    if (!names.has(perlLoader.executable as string)) throw new Error('Private Perl loader is missing from the receipt.');
    const executable = await checkedPath(root, perlLoader.executable as string, 'file');
    if (((await lstat(executable)).mode & 0o111) === 0) throw new Error('Private Perl loader is not executable.');
    for (const name of perlLoader.library_dirs as string[]) {
      await checkedPath(root, name, 'directory');
      if (!files.some(file => file.path.startsWith(name + '/'))) throw new Error('Private Perl native library directory is empty.');
    }
  }
  if (render && !names.has(render.manifest as string)) throw new Error('Render manifest is missing from the receipt.');
  // Reject unlisted Python modules and wheels, even when every listed file is
  // correct: otherwise Python's importer could load an unverified extra file.
  async function inventory(directory: string): Promise<void> {
    const queue = [directory]; let count = 0;
    while (queue.length) {
      const relative = queue.shift(); if (!relative) break;
      const absolute = await checkedPath(root, relative, 'directory');
      for (const name of await readdir(absolute)) {
        if (++count > 20_000) throw new Error('Userspace asset inventory exceeds its limit.');
        const child = `${relative}/${name}`; const info = await lstat(path.join(absolute, name));
        if (info.isSymbolicLink()) throw new Error('Userspace assets cannot contain symbolic links.');
        if (info.isDirectory()) queue.push(child);
        else if (!info.isFile() || !names.has(child)) throw new Error('Userspace assets contain an unlisted file.');
      }
    }
  }
  const perlRoots = perlVendor?.definition.supplier ? [path.posix.dirname(perlVendor.recipe)]
    : perl ? [...perl.library_dirs as string[], path.posix.dirname(perl.executable as string)] : [];
  const roots = [...new Set([item.worker as string, item.upstream as string, item.wheels as string, path.posix.dirname(item.context as string), ...perlRoots, ...(perlLoader ? [...perlLoader.library_dirs as string[], path.posix.dirname(perlLoader.executable as string)] : []), ...(render ? [path.posix.dirname(render.manifest as string)] : [])])];
  for (const directory of roots.filter(selected => !roots.some(parent => parent !== selected && selected.startsWith(parent + '/')))) await inventory(directory);
  const context = record(JSON.parse(await readFile(await checkedPath(root, item.context as string, 'file'), 'utf8')));
  const rules = record(context.rules);
  const requiredRules = ['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'];
  if (!safeRelative(context.rule_dir) || Object.keys(rules).sort().join(',') !== requiredRules.join(',') || requiredRules.some(name => typeof rules[name] !== 'string' || !/^[0-9a-f]{64}$/.test(rules[name] as string))) throw new Error('Userspace rule context is incomplete.');
  for (const name of requiredRules) {
    const location = `${path.posix.dirname(item.context as string)}/${context.rule_dir}/${name}`;
    const entry = files.find(file => file.path === location);
    if (!entry || entry.sha256 !== `sha256:${rules[name]}`) throw new Error('Userspace rule context does not match its receipt.');
  }
  const contextHash = sha256(JSON.stringify(Object.fromEntries(requiredRules.map(name => [name, rules[name]])))).slice(7);
  if (context.context_sha256 !== contextHash) throw new Error('Userspace rule context fingerprint does not match.');
  const requirements = (await readFile(await checkedPath(root, item.requirements as string, 'file'), 'utf8')).split(/\r?\n/).filter(Boolean);
  if (requirements.some(line => !/^[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*(?: --hash=sha256:[0-9a-f]{64})+$/.test(line))) throw new Error('Userspace requirements must contain only exact hash-locked packages.');
  return { ...(perl ? { perl: { executable: perl.executable as string, libraryDirs: perl.library_dirs as string[], ...(perlVendor ? { deferredRuntime: perlVendor } : {}), ...(perlLoader ? { loader: { executable: perlLoader.executable as string, libraryDirs: perlLoader.library_dirs as string[] } } : {}) } } : {}), ...(render ? { render: { manifest: render.manifest as string } } : {}), ...(lazy ? { lazyRender: lazy as { url: string; sha256: string; size: number; manifest: string } } : {}), ...(coreDescriptor(item, host) ? { coreArchive: coreDescriptor(item, host)!.sha256 } : {}), assetRoot: root, guardPath: installedGuard ?? await checkedPath(root, item.guard as string, 'file'), guardSha256: nativeGuard?.guardSha256 ?? files.find(file => file.path === item.guard)!.sha256, digest: sha256(bytes), host, files, packs: [...item.packs] as ('core' | 'render')[], worker: item.worker as string, upstream: item.upstream as string, context: item.context as string, bootstrap: item.bootstrap as string, guard: item.guard as string, requirements: item.requirements as string, wheels: item.wheels as string, ...(item.uv === undefined ? {} : { uv: item.uv as string }), ...(uvDownload === undefined ? {} : { uvDownload }), ...(uvVendorDownload === undefined ? {} : { uvVendorDownload }), ...(pythonDownload === undefined ? {} : { pythonDownload }) };
  } catch (error) { if (installedGuard && (error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('USERSPACE_CORE_INTEGRITY_FAILED: cached inventory member is missing.', { cause: error }); throw error; }
}

/** Inspect immutable product inputs without preparing or mutating userspace. */
export async function verifyUserspacePack(sourceRoot: string, host: Host = { platform: process.platform, arch: process.arch }, stateRoot = userspaceStateRoot(host)): Promise<{ manifestSha256: string; packs: readonly ('core' | 'render')[]; guard: string; guardSha256: string }> {
  const pack = await loadPack(sourceRoot, host, stateRoot);
  const guard = pack.guardPath;
  const receipt = pack.files.find(file => file.path === pack.guard);
  if (!receipt) throw new Error('Userspace guard receipt is missing.');
  const info = await lstat(guard);
  if (process.platform !== 'win32' && (info.mode & 0o111) === 0) throw new Error('Userspace guard is not executable.');
  return { manifestSha256: pack.digest, packs: Object.freeze([...pack.packs]), guard, guardSha256: pack.guardSha256 };
}

async function command(executable: string, args: string[], home: string, timeoutMs = 120_000, managedInstall = false): Promise<{ code: number; stdout: string }> {
  checkSetupCancellation(); const cancellation = setupCancellation.getStore();
  if (!path.isAbsolute(executable) || args.some(arg => arg.includes('\0'))) throw new Error('Invalid userspace command.');
  await ownedDirectory(path.join(home, 'uv-cache'), true);
  const env: NodeJS.ProcessEnv = { HOME: home, USERPROFILE: home, PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', LANG: 'C', UV_NO_CONFIG: '1', UV_NO_PROJECT: '1', UV_NO_ENV_FILE: '1', UV_OFFLINE: '1', UV_PYTHON_DOWNLOADS: managedInstall ? 'manual' : 'never', UV_PYTHON_INSTALL_BIN: '0', UV_CACHE_DIR: path.join(home, 'uv-cache'), UV_PYTHON_INSTALL_DIR: path.join(home, 'pythons'), PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1', PIP_CONFIG_FILE: process.platform === 'win32' ? 'NUL' : '/dev/null', PIP_NO_INDEX: '1', PIP_DISABLE_PIP_VERSION_CHECK: '1' };
  if (process.env.SystemRoot !== undefined) env.SystemRoot = process.env.SystemRoot;
  let launchedExecutable = executable; let launchedArguments = args;
  if (process.platform === 'win32' || process.platform === 'linux') {
    const guard = stateGuard.getStore(); if (!guard) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
    const handle = await open(executable, constants.O_RDONLY); let executableSha256: string;
    try {
      const before = await handle.stat({ bigint: true }); if (!before.isFile() || before.size < 1n || before.size > 256n * 1024n * 1024n) throw new Error('USERSPACE_EXECUTABLE_INVALID');
      const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true });
      if (BigInt(bytes.length) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) throw new Error('USERSPACE_EXECUTABLE_CHANGED');
      executableSha256 = sha256(bytes).slice(7);
    } finally { await handle.close(); }
    launchedExecutable = guard; launchedArguments = ['contained-setup', '--executable', executable, '--executable-sha256', executableSha256, '--arguments-json', JSON.stringify(args), '--staging', home];
  }
  checkSetupCancellation();
  return new Promise((resolve, reject) => {
    // Pipe stdin even for setup: the Windows native wrapper requires three
    // explicit inherited handles, and EOF is the only input to these commands.
    const child = spawn(launchedExecutable, launchedArguments, { cwd: home, env, shell: false, windowsHide: true, detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.on('error', () => { /* Exit/close reports authoritative failure. */ }); if (process.platform !== 'linux') child.stdin.end();
    let output = ''; let size = 0; let failure: Error | undefined;
    let forced: NodeJS.Timeout | undefined;
    const stop = (error: Error) => { failure ??= error; if (process.platform === 'linux') { child.stdin.end(); child.kill('SIGTERM'); forced ??= setTimeout(() => child.kill('SIGKILL'), 35_000); } else if (process.platform !== 'win32' && child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } } else child.kill('SIGKILL'); };
    const abort = () => stop(new Error('USERSPACE_SETUP_CANCELLED')); cancellation?.addEventListener('abort', abort, { once: true }); if (cancellation?.aborted) abort();
    const timer = setTimeout(() => stop(new Error('USERSPACE_SETUP_TIMEOUT')), timeoutMs);
    const capture = (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) stop(new Error('USERSPACE_SETUP_OUTPUT_LIMIT')); else output += chunk.toString('utf8'); };
    child.stdout.on('data', capture); child.stderr.on('data', capture); child.once('error', error => { failure = error; });
    child.once('close', (code, signal) => { clearTimeout(timer); clearTimeout(forced); child.stdin.end(); cancellation?.removeEventListener('abort', abort); if (failure) reject(failure); else if (signal || code === null) reject(new Error('USERSPACE_SETUP_TERMINATED')); else resolve({ code, stdout: output }); });
  });
}

async function findProgram(name: string, searchPath: string): Promise<string | undefined> {
  for (const dir of searchPath.split(path.delimiter)) {
    if (!path.isAbsolute(dir)) continue;
    const candidate = path.join(dir, name + (process.platform === 'win32' ? '.exe' : ''));
    try {
      const resolved = await realpath(candidate); const info = await stat(resolved);
      if (!info.isFile() || (process.platform !== 'win32' && ((info.mode & 0o022) !== 0 || (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid())))) continue;
      await access(resolved, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
      return resolved;
    } catch { /* Continue with the next absolute PATH entry. */ }
  }
  return undefined;
}

async function findPython(searchPath: string, home: string): Promise<{ executable: string; version: string } | undefined> {
  const seen = new Set<string>();
  for (const name of ['python3.15', 'python3.14', 'python3', 'python']) {
    const executable = await findProgram(name, searchPath);
    if (!executable || seen.has(executable)) continue;
    seen.add(executable);
    try {
      const result = await command(executable, ['-I', '-c', 'import sys; print("%s.%s.%s" % sys.version_info[:3])'], home, 10_000);
      const version = result.stdout.trim();
      if (result.code === 0 && /^3\.(?:14|15)\.\d+$/.test(version)) return { executable, version };
    } catch { /* Try the next available interpreter. */ }
  }
  return undefined;
}

async function findManagedPython(uv: string, home: string, requested: string): Promise<{ executable: string; version: string; managedPath: string } | undefined> {
  const result = await command(uv, ['python', 'find', '--managed-python', '--system', '--no-python-downloads', requested], home, 10_000);
  if (result.code !== 0) return undefined;
  const output = result.stdout.trim().split(/\r?\n/).find(line => path.isAbsolute(line));
  if (!output) return undefined;
  const managedRoot = await realpath(path.join(home, 'pythons')); const executable = await realpath(output);
  const relative = path.relative(managedRoot, executable);
  const [distribution] = relative.split(path.sep);
  if (!distribution || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative) || !/^[A-Za-z0-9._+-]+$/.test(distribution)) throw new Error('Managed Python is outside its product-owned directory.');
  const version = await command(executable, ['-I', '-B', '-c', 'import sys; print("%s.%s.%s" % sys.version_info[:3])'], home, 10_000);
  if (version.code !== 0 || !/^3\.(?:14|15)\.\d+$/.test(version.stdout.trim()) || !version.stdout.trim().startsWith(requested)) throw new Error('Managed Python version does not match its request.');
  return { executable, version: version.stdout.trim(), managedPath: `pythons/${distribution}` };
}

async function installManagedPython(uv: string, state: string, receipt: ManagedPythonDownload, network: 'bootstrap_only' | 'offline'): Promise<{ executable: string; version: string; managedPath: string } | undefined> {
  let acquired;
  try { acquired = await acquireManagedPythonArchive({ url: receipt.url, version: receipt.version, sha256: receipt.sha256, size: receipt.size }, state, { platform: process.platform, arch: process.arch }, network, setupFetch); }
  catch (error: unknown) { checkSetupCancellation(); if (error instanceof UvAcquisitionUnavailable) return undefined; throw error; }
  if (!acquired) return undefined;
  const [major, minor, patch] = receipt.version.split('.').map(Number);
  const key = `cpython-${receipt.version}-${receipt.os}-${receipt.arch}-${receipt.libc}`;
  const metadata = { [key]: { name: 'cpython', arch: { family: receipt.arch, variant: null }, os: receipt.os, libc: receipt.libc, major, minor, patch, prerelease: '', url: receipt.url, sha256: receipt.sha256.slice(7), variant: null } };
  const file = path.join(state, `.python-metadata-${randomUUID()}.json`);
  try {
    const installations = path.join(state, 'pythons');
    await mkdir(installations, { recursive: true, mode: 0o700 });
    await ownedDirectory(installations);
    await writeFile(file, JSON.stringify(metadata) + '\n', { flag: 'wx', mode: 0o600 });
    // uv receives only a previously hash-verified local archive; offline mode
    // prevents any provider fallback or automatic network download.
    const result = await command(uv, ['python', 'install', receipt.version, '--offline', '--install-dir', installations, '--mirror', pathToFileURL(acquired.mirror).href, '--python-downloads-json-url', file], state, 120_000, true);
    if (result.code !== 0) throw new Error('USERSPACE_MANAGED_PYTHON_INSTALL_FAILED');
    const python = await findManagedPython(uv, state, receipt.version);
    if (!python) throw new Error('USERSPACE_MANAGED_PYTHON_NOT_FOUND');
    return python;
  } finally { await rm(file, { force: true }); }
}

async function treeFingerprint(root: string): Promise<string> {
  const entries: string[] = [];
  async function hashRegular(file: string): Promise<string> {
    const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.size > 128n * 1024n * 1024n) throw new Error('Userspace environment file exceeds its limit.');
      const hash = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let position = 0;
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        position += bytesRead;
        if (BigInt(position) > before.size) throw new Error('Userspace environment changed during verification.');
        hash.update(buffer.subarray(0, bytesRead));
      }
      const after = await handle.stat({ bigint: true });
      if (BigInt(position) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('Userspace environment changed during verification.');
      return `sha256:${hash.digest('hex')}`;
    } finally { await handle.close(); }
  }
  async function visit(directory: string, relative: string): Promise<void> {
    for (const name of (await readdir(directory)).sort()) {
      if (++count > 100_000) throw new Error('Userspace environment inventory exceeds its limit.');
      const file = path.join(directory, name); const rel = relative ? `${relative}/${name}` : name; const info = await lstat(file);
      if (info.isDirectory()) { entries.push(`d\0${rel}\0${info.mode & 0o777}`); await visit(file, rel); }
      else if (info.isSymbolicLink()) {
        const target = await realpath(file); const relativeTarget = path.relative(root, target);
        const inside = relativeTarget !== '..' && !relativeTarget.startsWith('..' + path.sep) && !path.isAbsolute(relativeTarget);
        if (!inside && !/^(?:bin\/python(?:3(?:\.\d+)?)?|Scripts\/python(?:3(?:\.\d+)?)?\.exe)$/.test(rel)) throw new Error('Userspace environment link escapes the environment.');
        const targetInfo = await stat(target);
        if (!inside && (!targetInfo.isFile() || targetInfo.size > 128 * 1024 * 1024)) throw new Error('Userspace interpreter link is invalid.');
        entries.push(`l\0${rel}\0${await readlink(file)}${inside ? '' : '\0' + await hashRegular(target)}`);
      }
      else if (info.isFile()) {
        if (info.size > 128 * 1024 * 1024) throw new Error('Userspace environment file exceeds its limit.');
        entries.push(`f\0${rel}\0${info.mode & 0o777}\0${await hashRegular(file)}`);
      } else throw new Error('Userspace environment contains a special file.');
    }
  }
  let count = 0; await visit(root, ''); return sha256(entries.join('\n'));
}

type RenderProbe = { schema_version: 1; revision: 1; manifest_sha256: string; environment_fingerprint: string; browser_manifest_sha256: string; guard_sha256: string; outputs: { png: { sha256: string; size_bytes: number }; pdf: { sha256: string; size_bytes: number } } };
type Marker = { render_probe?: RenderProbe; core_archive?: string; schema_version: 1; manifest: string; environment: string; fingerprint: string; python_version: string; installer: 'uv' | 'venv'; platform?: string; arch?: string; abi?: string; managed_python?: { path: string; fingerprint: string } };
function marker(value: unknown): Marker {
  const data = record(value);
  if (data.schema_version !== 1 || typeof data.manifest !== 'string' || !DIGEST.test(data.manifest) || typeof data.environment !== 'string' || !/^env-[0-9a-f-]{36}$/.test(data.environment) || typeof data.fingerprint !== 'string' || !DIGEST.test(data.fingerprint) || typeof data.python_version !== 'string' || !/^3\.(?:14|15)\.\d+$/.test(data.python_version) || !['uv', 'venv'].includes(String(data.installer))) throw new Error('Invalid userspace environment marker.');
  if (data.core_archive !== undefined && (typeof data.core_archive !== 'string' || !DIGEST.test(data.core_archive))) throw new Error('Invalid userspace core marker.');
  if (data.managed_python !== undefined) {
    const managed = record(data.managed_python);
    if (typeof managed.path !== 'string' || !/^pythons\/[A-Za-z0-9._+-]+$/.test(managed.path) || typeof managed.fingerprint !== 'string' || !DIGEST.test(managed.fingerprint)) throw new Error('Invalid managed Python marker.');
  }
  if (data.platform !== undefined || data.arch !== undefined || data.abi !== undefined) {
    if (!['darwin', 'linux', 'win32'].includes(String(data.platform)) || !['arm64', 'x64'].includes(String(data.arch)) || (data.abi !== 'cp314' && data.abi !== 'cp315') || data.abi !== `cp${data.python_version.split('.').slice(0, 2).join('')}`) throw new Error('Invalid userspace platform or ABI marker.');
  }
  if (data.render_probe !== undefined) {
    const probe = record(data.render_probe), outputs = record(probe.outputs);
    if (probe.schema_version !== 1 || probe.revision !== 1 || Object.keys(probe).sort().join(',') !== 'browser_manifest_sha256,environment_fingerprint,guard_sha256,manifest_sha256,outputs,revision,schema_version' || ['manifest_sha256','environment_fingerprint','browser_manifest_sha256','guard_sha256'].some(key => typeof probe[key] !== 'string' || !DIGEST.test(probe[key] as string)) || Object.keys(outputs).sort().join(',') !== 'pdf,png') throw new Error('USERSPACE_RENDER_PROBE_RECORD_INVALID');
    for (const format of ['png','pdf']) { const output = record(outputs[format]); if (Object.keys(output).sort().join(',') !== 'sha256,size_bytes' || typeof output.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(output.sha256) || !Number.isSafeInteger(output.size_bytes) || (output.size_bytes as number) < 100 || (output.size_bytes as number) > 64 * 1024 * 1024) throw new Error('USERSPACE_RENDER_PROBE_RECORD_INVALID'); }
  }
  return data as Marker;
}

async function verifyRenderManifest(python: string, worker: string, manifest: string, installationRoot?: string): Promise<void> {
  const script = 'import os,sys; sys.path.insert(0,sys.argv[1]); os.environ["UD_AGENT_RENDER_MANIFEST"]=sys.argv[2]; from ud_agent.render_browser import verified_renderer; verified_renderer(installation_root=sys.argv[3]) if len(sys.argv)>3 else verified_renderer()';
  const checked = await runCommand(python, ['-I', '-B', '-c', script, worker, manifest, ...(installationRoot ? [installationRoot] : [])], { timeoutMs: 120_000, maxOutputBytes: 1024 * 1024, ...(setupCancellation.getStore() ? { signal: setupCancellation.getStore()! } : {}) });
  if (checked.code !== 0) throw new Error('USERSPACE_RENDER_INTEGRITY_FAILED');
}

async function resolveLazyRender(pack: Pack, state: string, python: string, worker: string): Promise<string | undefined> {
  if (!pack.lazyRender) return undefined;
  const directory = path.join(state, 'renders', pack.lazyRender.sha256.slice(7));
  try { await ownedDirectory(directory); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  const manifest = await checkedPath(directory, pack.lazyRender.manifest, 'file');
  await verifyRenderManifest(python, worker, manifest);
  return manifest;
}

async function materializeDeferredRender(pack: Pack, capability: UserspaceExecution, source: string, state: string, directory: string, manifest: string, host: Host, network: 'bootstrap_only' | 'offline', installationRoot: string): Promise<boolean> {
  const receipt = record(JSON.parse((await readBoundedReceiptBytes(await checkedPath(directory, manifest, 'file'))).toString('utf8')));
  if (receipt.deferred_browser === undefined) return false;
  const deferred = record(receipt.deferred_browser);
  const edge = deferred.provider === 'microsoft-edge', google = deferred.provider === 'google-chrome-for-testing';
  if ((!edge && !google) || Object.keys(deferred).sort().join(',') !== (edge ? 'decoder,directory,provider,recipe' : 'directory,provider,recipe') || !safeRelative(deferred.recipe) || !safeRelative(deferred.directory) || edge && (host.platform !== 'win32' || host.arch !== 'arm64' || !safeRelative(deferred.decoder))) throw new Error('USERSPACE_RENDER_DEFERRED_BROWSER_INVALID');
  const parent = path.posix.dirname(manifest), relative = (name: string) => parent === '.' ? name : `${parent}/${name}`;
  const recipe = record(JSON.parse((await readBoundedReceiptBytes(await checkedPath(directory, relative(deferred.recipe), 'file'))).toString('utf8')));
  if (edge) await checkedPath(directory, relative(deferred.decoder as string), 'file');
  if (recipe.schema_version !== 1 || recipe.provider !== deferred.provider || recipe.platform !== `${host.platform}/${host.arch}`) throw new Error('USERSPACE_RENDER_VENDOR_RECEIPT_INVALID');
  const archive = record(recipe.archive);
  if (Object.keys(archive).sort().join(',') !== 'sha256,size_bytes,url' || typeof archive.url !== 'string' || typeof archive.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(archive.sha256) || !Number.isSafeInteger(archive.size_bytes)) throw new Error('USERSPACE_RENDER_VENDOR_RECEIPT_INVALID');
  const module = `${pack.worker}/ud_agent/${edge ? 'windows_browser' : 'vendor_browser'}.py`;
  if (!pack.files.some(file => file.path === module)) throw new Error('USERSPACE_RENDER_EXTRACTOR_NOT_VERIFIED');
  const extractor = await checkedPath(source, module, 'file');
  await ownedDirectory(path.join(state, 'render-vendor-cache'), true);
  const descriptor = { url: archive.url, sha256: `sha256:${archive.sha256}`, size: archive.size_bytes as number };
  const payload = await (edge ? acquireMicrosoftEdgeMsi : acquireGoogleBrowserArchive)(descriptor, state, host, network, setupFetch);
  if (!payload) throw new Error('USERSPACE_RENDER_VENDOR_OFFLINE_CACHE_MISSING');
  checkSetupCancellation();
  const selectedManifest = await checkedPath(directory, manifest, 'file');
  const result = await command(capability.python, ['-I', '-B', extractor, '--pack-dir', path.dirname(selectedManifest), ...(edge ? ['--msi', payload, '--decoder', deferred.decoder as string] : ['--archive', payload, '--installation-dir', path.join(installationRoot, parent)]), '--recipe', deferred.recipe, '--output-dir', deferred.directory, '--manifest', path.posix.basename(manifest)], state, 600_000);
  if (result.code !== 0) throw new Error('USERSPACE_RENDER_VENDOR_MATERIALIZATION_FAILED');
  checkSetupCancellation();
  const completed = record(JSON.parse((await readBoundedReceiptBytes(await checkedPath(directory, manifest, 'file'))).toString('utf8')));
  if (completed.deferred_browser !== undefined) throw new Error('USERSPACE_RENDER_VENDOR_MATERIALIZATION_INCOMPLETE');
  return google && host.platform === 'linux';
}

/** Prepare optional browser bytes once, without changing the core environment. */
export async function prepareUserspaceRender(capability: UserspaceExecution, network: 'bootstrap_only' | 'offline' = 'bootstrap_only', signal?: AbortSignal): Promise<UserspaceExecution> {
  return setupCancellation.run(signal ?? setupCancellation.getStore(), async () => { checkSetupCancellation();
  const binding = issued.get(capability);
  if (!binding) throw new Error('USERSPACE_AUTHORITY_REQUIRED');
  await verifyUserspaceExecution(capability);
  if (capability.packs.includes('render')) return ensureUserspaceRenderProbe(capability, signal);
  const host = { platform: process.platform, arch: process.arch };
  const pack = await loadPack(binding.sourceRoot, host, binding.stateRoot);
  if (!pack.lazyRender) throw new Error('USERSPACE_RENDER_PACK_REQUIRED');
  return stateGuard.run(capability.guard, async () => {
    const release = await acquireUserspaceLease(capability);
    try {
    const journal = await JournalStore.open(binding.stateRoot, capability.guard);
    return journal.withWorkspaceLock('userspace-render', async () => {
      const ready = await resolveUserspaceExecution(binding.sourceRoot, binding.stateRoot, host);
      if (ready.packs.includes('render')) return ensureUserspaceRenderProbe(ready, signal);
      const receipt = pack.lazyRender!;
      const archive = await acquireRenderArchive(receipt, binding.stateRoot, host, network, setupFetch);
      if (!archive) throw new Error('USERSPACE_RENDER_OFFLINE_CACHE_MISSING');
      const parent = await ownedDirectory(path.join(binding.stateRoot, 'renders'), true);
      const temporary = await mkdtemp(path.join(parent, '.install-'));
      const destination = path.join(parent, receipt.sha256.slice(7));
      try {
        const extractor = await checkedPath(pack.assetRoot, `${pack.worker}/ud_agent/runtime_assets.py`, 'file');
        if (!pack.files.some(file => file.path === `${pack.worker}/ud_agent/runtime_assets.py`)) throw new Error('USERSPACE_RENDER_EXTRACTOR_NOT_VERIFIED');
        const extracted = await command(capability.python, ['-I', '-B', extractor, archive, receipt.sha256, String(receipt.size), temporary, receipt.manifest], binding.stateRoot, 300_000);
        if (extracted.code !== 0) throw new Error('USERSPACE_RENDER_EXTRACTION_FAILED');
        const projectedRoot = await materializeDeferredRender(pack, capability, pack.assetRoot, binding.stateRoot, temporary, receipt.manifest, host, network, destination);
        await verifyRenderManifest(capability.python, capability.workerPath, await checkedPath(temporary, receipt.manifest, 'file'), projectedRoot ? path.join(destination, path.posix.dirname(receipt.manifest)) : undefined);
        checkSetupCancellation(); await rename(temporary, destination);
        await syncState(parent);
        const result = await resolveUserspaceExecution(binding.sourceRoot, binding.stateRoot, host);
        if (!result.packs.includes('render')) throw new Error('USERSPACE_RENDER_PREPARATION_FAILED');
        return ensureUserspaceRenderProbe(result, signal);
      } catch (error) {
        await rm(temporary, { recursive: true, force: true });
        throw error;
      }
    });
    } finally { await release(); }
  });
  });
}


async function ensureUserspaceRenderProbe(capability: UserspaceExecution, signal?: AbortSignal): Promise<UserspaceExecution> {
  const binding = issued.get(capability); if (!binding || !capability.renderManifest) throw new Error('USERSPACE_RENDER_PACK_REQUIRED');
  return stateGuard.run(capability.guard, async () => {
    const release = await acquireUserspaceLease(capability);
    try {
      const store = await JournalStore.open(binding.stateRoot, capability.guard);
      const deadline = Date.now() + 300_000;
      for (;;) {
      if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED');
      let entered = false;
      try { return await store.withWorkspaceLock('userspace-render-probe', async () => {
        entered = true;
        const fresh = await resolveUserspaceExecution(binding.sourceRoot, binding.stateRoot);
        if (fresh.renderReady === true) return fresh;
        if (!fresh.renderManifest) throw new Error('USERSPACE_RENDER_PACK_REQUIRED');
        const pack = await loadPack(binding.sourceRoot, { platform: process.platform, arch: process.arch }, binding.stateRoot);
        const parent = await ownedDirectory(path.join(binding.stateRoot, 'uv-cache'), true), directory = await mkdtemp(path.join(parent, 'render-probe-'));
        try {
          const { runUserspaceValidation } = await import('../../coordinator/src/userspace-worker.js');
          const { RENDER_PROBE_SENTENCE, verifyRenderProbe } = await import('../../coordinator/src/render-probe.js');
          const outputs = {} as RenderProbe['outputs'];
          for (const format of ['png', 'pdf'] as const) {
            if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED');
            const result = await runUserspaceValidation(fresh, { operation: 'sentence_render', arguments: { working_tree_path: directory, sentence_conllu: RENDER_PROBE_SENTENCE, output_format: format, output_path: path.join(directory, 'probe.' + format), ud_context_path: '' }, allowedRoots: [directory], ...(signal ? { signal } : {}) });
            outputs[format] = verifyRenderProbe(result.result, format);
          }
          const index = path.join(binding.stateRoot, `current-${pack.digest.slice(7)}.json`), current = marker(JSON.parse((await stateBytes(index)).toString('utf8')));
          if (current.fingerprint !== binding.fingerprint || current.environment !== path.basename(binding.environment)) throw new Error('USERSPACE_AUTHORITY_CHANGED');
          const proof: RenderProbe = { schema_version: 1, revision: 1, manifest_sha256: pack.digest, environment_fingerprint: current.fingerprint, browser_manifest_sha256: sha256(await readBoundedReceiptBytes(fresh.renderManifest)), guard_sha256: pack.guardSha256, outputs };
          await durableWrite(index, Buffer.from(JSON.stringify({ ...current, render_probe: proof })), await stateAuthority(binding.stateRoot));
          return resolveUserspaceExecution(binding.sourceRoot, binding.stateRoot);
        } finally { await rm(directory, { recursive: true, force: true }); }
      }); } catch (error) {
        // A concurrent probe owns this kernel lock. Wait for its durable proof,
        // without adopting stale directory locks or retrying execution errors.
        if (entered || !(error instanceof Error) || error.message !== 'WORKSPACE_LOCKED_OR_STALE: the native workspace lock is held.') throw error;
        if (Date.now() >= deadline) throw new Error('USERSPACE_RENDER_PROBE_BUSY');
        await new Promise<void>((resolve, reject) => {
          const cancelled = () => { clearTimeout(timer); signal?.removeEventListener('abort', cancelled); reject(new Error('USERSPACE_SETUP_CANCELLED')); };
          const timer = setTimeout(() => { signal?.removeEventListener('abort', cancelled); resolve(); }, 250);
          signal?.addEventListener('abort', cancelled, { once: true });
          if (signal?.aborted) cancelled();
        });
      }
      }
    } finally { await release(); }
  });
}

/** Mint a capability only for a frozen product pack and intact private environment. */
export async function resolveUserspaceExecution(sourceRoot: string, stateRoot = userspaceStateRoot(), host: Host = { platform: process.platform, arch: process.arch }): Promise<UserspaceExecution> {
  const source = await realpath(sourceRoot); const pack = await loadPack(source, host, stateRoot);
  return stateGuard.run(pack.guardPath, async () => {
  const state = await ownedDirectory(stateRoot);
  const index = path.join(state, `current-${pack.digest.slice(7)}.json`);
  const item = marker(JSON.parse((await stateBytes(index)).toString('utf8')));
  if (item.manifest !== pack.digest) throw new Error('Userspace environment belongs to a different release.');
  const environment = await checkedPath(state, item.environment, 'directory');
  if (await treeFingerprint(environment) !== item.fingerprint) throw new Error('USERSPACE_ENVIRONMENT_CHANGED');
  if (item.managed_python && await treeFingerprint(await checkedPath(state, item.managed_python.path, 'directory')) !== item.managed_python.fingerprint) throw new Error('USERSPACE_MANAGED_PYTHON_CHANGED');
  const python = path.join(environment, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  if (!(await stat(python)).isFile()) throw new Error('Userspace Python executable is unavailable.');
  if (item.platform !== undefined) {
    if (item.platform !== host.platform || item.arch !== host.arch) throw new Error('USERSPACE_PLATFORM_CHANGED');
  } else {
    // Prior local development markers lacked platform identity. Check the
    // interpreter itself, without writing state, before reusing them.
    const script = 'import json,platform,sys; print(json.dumps({"version":"%s.%s.%s" % sys.version_info[:3],"platform":sys.platform,"arch":platform.machine()}))';
    const result = await runCommand(python, ['-I', '-B', '-c', script], { timeoutMs: 10_000, maxOutputBytes: 4096 });
    if (result.code !== 0) throw new Error('Legacy userspace interpreter inspection failed.');
    const observed = record(JSON.parse(result.stdout.toString('utf8')));
    const arch = typeof observed.arch === 'string' ? observed.arch.toLowerCase() : '';
    if (observed.version !== item.python_version || observed.platform !== host.platform || !(host.arch === 'arm64' ? ['arm64', 'aarch64'].includes(arch) : ['x86_64', 'amd64'].includes(arch))) throw new Error('USERSPACE_PLATFORM_CHANGED');
  }
  const lazyManifest = pack.lazyRender ? await resolveLazyRender(pack, state, python, await checkedPath(pack.assetRoot, pack.worker, 'directory')) : undefined;
  const perl = pack.perl;
  const deferred = perl?.deferredRuntime;
  const perlRuntime = perl ? {
    perl: deferred ? await checkedPath(environment, 'deferred-perl/' + deferred.definition.executable, 'file') : await checkedPath(pack.assetRoot, perl.executable, 'file'),
    perlLibraryPaths: Object.freeze(await Promise.all((deferred?.relocatedLibraryDirs ?? perl.libraryDirs)
      .map(name => checkedPath(deferred?.relocatedLibraryDirs ? environment : pack.assetRoot, name, 'directory')))),
    ...(perl.loader ? { perlLoader: Object.freeze({ executable: await checkedPath(pack.assetRoot, perl.loader.executable, 'file'), libraryPaths: Object.freeze(await Promise.all(perl.loader.libraryDirs.map(name => checkedPath(pack.assetRoot, name, 'directory')))) }) } : {}),
  } : {};
  const capability: UserspaceExecution = Object.freeze({ ...(lazyManifest ? { renderManifest: lazyManifest } : {}), ...perlRuntime, ...(pack.render ? { renderManifest: await checkedPath(pack.assetRoot, pack.render.manifest, 'file') } : {}), contextAssetRoot: path.dirname(await checkedPath(pack.assetRoot, pack.context, 'file')), python, workerPath: await checkedPath(pack.assetRoot, pack.worker, 'directory'), upstreamPath: await checkedPath(pack.assetRoot, pack.upstream, 'directory'), contextPath: await checkedPath(pack.assetRoot, pack.context, 'file'), bootstrap: await checkedPath(pack.assetRoot, pack.bootstrap, 'file'), guard: pack.guardPath, manifestSha256: pack.digest, packs: Object.freeze([...pack.packs, ...(lazyManifest && !pack.packs.includes('render') ? ['render' as const] : [])]), isolation: 'userspace' });
  const renderIdentity = capability.renderManifest ? { schema_version: 1 as const, revision: 1 as const, manifest_sha256: pack.digest, environment_fingerprint: item.fingerprint, browser_manifest_sha256: sha256(await readBoundedReceiptBytes(capability.renderManifest)), guard_sha256: pack.guardSha256 } : undefined;
  const renderReady = renderIdentity && item.render_probe ? Object.entries(renderIdentity).every(([key, value]) => item.render_probe![key as keyof RenderProbe] === value) : false;
  const admitted = capability.renderManifest ? Object.freeze({ ...capability, renderReady }) : capability;
  issued.set(admitted, { sourceRoot: source, stateRoot: state, manifest: pack.digest, environment, fingerprint: item.fingerprint });
  return admitted;
  });
}

/** Capabilities cannot be fabricated, serialized or reused after changing files. */
export async function verifyUserspaceExecution(capability: unknown): Promise<void> {
  if (!capability || typeof capability !== 'object') throw new Error('USERSPACE_AUTHORITY_REQUIRED');
  const binding = issued.get(capability);
  if (!binding) throw new Error('USERSPACE_AUTHORITY_REQUIRED');
  const fresh = await resolveUserspaceExecution(binding.sourceRoot, binding.stateRoot);
  const other = issued.get(fresh);
  if (!other || other.manifest !== binding.manifest || other.environment !== binding.environment || other.fingerprint !== binding.fingerprint) throw new Error('USERSPACE_AUTHORITY_CHANGED');
}

async function maintenanceActive(state: string): Promise<boolean> {
  for (const name of ['.maintenance.lock', '.recovery.lock']) {
    try {
      await lstat(path.join(state, name));
      const authority = maintenanceAuthority.getStore();
      if (name === '.maintenance.lock' && authority?.state === state) { const bytes = await stateBytes(path.join(state, name)); if (`sha256:${createHash('sha256').update(bytes).digest('hex')}` !== authority.markerSha256) throw new Error('USERSPACE_MAINTENANCE_OWNERSHIP_CHANGED'); continue; }
      return true;
    }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  return false;
}

async function withUserspaceMaintenance<T>(state: string, guard: string, action: () => Promise<T>, heldSetupGate?: string): Promise<T> {
  if (maintenanceAuthority.getStore()?.state === state) return action();
  const release = await guardedStateLock(guard, state, '.userspace-maintenance.native', await guardedIdentity(guard, state));
  let owned: string | undefined; let ownerSha256: string | undefined;
  try {
    for (const name of ['.maintenance.lock', '.recovery.lock']) { const file = path.join(state, name); try { await lstat(file); if (await ownerIsAlive(file, '.userspace-maintenance.native')) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS'); await rm(file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
    owned = await claim(state, '.maintenance.lock', '.userspace-maintenance.native');
    ownerSha256 = `sha256:${createHash('sha256').update(await stateBytes(owned)).digest('hex')}`;
    for (const name of (await readdir(state)).filter(value => /^\.(?:setup-[0-9a-f]{64}\.lock|lease-[0-9a-f-]{36})$/.test(value))) { const file = path.join(state, name); if (await ownerIsAlive(file, heldSetupGate)) throw new Error('USERSPACE_RUNTIME_IN_USE'); await rm(file); }
    return await maintenanceAuthority.run({ state, markerSha256: ownerSha256 }, action);
  } finally { try { if (owned) { if (ownerSha256 !== `sha256:${createHash('sha256').update(await stateBytes(owned)).digest('hex')}`) throw new Error('USERSPACE_MAINTENANCE_OWNERSHIP_CHANGED'); await rm(owned); } await syncState(state); } finally { await release(); } }
}

/** Publish a complete owner record atomically; an empty/crashed file is never treated as a stale lease. */
async function claim(state: string, name: string, kernelLock?: string): Promise<string> {
  const temporary = path.join(state, `.owner-${randomUUID()}.tmp`); const target = path.join(state, name);
  const contents = Buffer.from(JSON.stringify({ schema_version: 1, pid: process.pid, ...(kernelLock ? { kernel_lock: kernelLock } : {}) }) + '\n');
  const helper = stateGuard.getStore();
  if (helper) { await guardedCreate(helper, state, name, await guardedIdentity(helper, state), contents); return target; }
  try {
    const file = await open(temporary, 'wx', 0o600);
    try { await file.writeFile(contents); await file.sync(); } finally { await file.close(); }
    await link(temporary, target);
    return target;
  } finally { await rm(temporary, { force: true }); await syncState(state); }
}

async function ownerIsAlive(file: string, heldGate?: string): Promise<boolean> {
  const value = record(JSON.parse((await stateBytes(file)).toString('utf8')));
  if (value.schema_version !== 1 || !Number.isSafeInteger(value.pid) || (value.pid as number) <= 0 || (value.pid as number) > 2_147_483_647) throw new Error('USERSPACE_OWNER_RECORD_INVALID');
  if (value.kernel_lock !== undefined) {
    if (typeof value.kernel_lock !== 'string' || !/^\.(?:lease-[0-9a-f-]{36}|setup-[0-9a-f]{64}|userspace-maintenance)\.native$/.test(value.kernel_lock)) throw new Error('USERSPACE_OWNER_RECORD_INVALID');
    const name = path.basename(file); const expected = name.startsWith('.lease-') ? `${name}.native` : name.startsWith('.setup-') ? name.replace(/\.lock$/, '.native') : ['.maintenance.lock', '.recovery.lock'].includes(name) ? '.userspace-maintenance.native' : undefined;
    if (value.kernel_lock !== expected) throw new Error('USERSPACE_OWNER_RECORD_INVALID');
    const helper = stateGuard.getStore(); if (!helper) throw new Error('USERSPACE_RECOVERY_GUARD_REQUIRED');
    if (heldGate === value.kernel_lock) return false;
    const state = path.dirname(file); await lstat(path.join(state, value.kernel_lock));
    try { const release = await guardedStateLock(helper, state, value.kernel_lock, await guardedIdentity(helper, state)); await release(); return false; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') return true; throw error; }
  }
  try { process.kill(value.pid as number, 0); return true; }
  catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    // Access denial or unsupported process queries are not proof of death.
    return true;
  }
}

/** A worker lease excludes owned-runtime removal until the job is finished. */
export async function acquireUserspaceLease(capability: UserspaceExecution): Promise<() => Promise<void>> {
  const binding = issued.get(capability);
  if (!binding) throw new Error('USERSPACE_AUTHORITY_REQUIRED');
  return stateGuard.run(capability.guard, async () => {
  if (await maintenanceActive(binding.stateRoot)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS');
  const name = `.lease-${randomUUID()}`; const kernelLock = `${name}.native`;
  const unlock = await guardedStateLock(capability.guard, binding.stateRoot, kernelLock, await guardedIdentity(capability.guard, binding.stateRoot));
  let lease: string | undefined;
  try {
    lease = await claim(binding.stateRoot, name, kernelLock);
    if (await maintenanceActive(binding.stateRoot)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS');
    await verifyUserspaceExecution(capability);
  } catch (error: unknown) { if (lease) await rm(lease, { force: true }); await unlock(); throw error; }
  const leaseFile = lease;
  let released = false;
  return async () => stateGuard.run(capability.guard, async () => { if (!released) { try { await rm(leaseFile, { force: true }); await syncState(binding.stateRoot); released = true; } finally { await unlock(); } await rm(path.join(binding.stateRoot, kernelLock), { force: true }); await syncState(binding.stateRoot); } });
  });
}

/** Remove only product-owned cache or indexed environments; never global data. */
export async function cleanUserspaceState(stateRoot = userspaceStateRoot(), action: 'cache' | 'owned-runtime', dryRun: boolean, guard?: string): Promise<{ paths: string[]; dry_run: boolean }> {
  return stateGuard.run(guard ?? stateGuard.getStore() ?? '', async () => {
  if (!['cache', 'owned-runtime'].includes(action) || typeof dryRun !== 'boolean') throw new Error('Invalid userspace cleanup request.');
  let state: string;
  try { state = await ownedDirectory(stateRoot); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { paths: [], dry_run: dryRun }; throw error; }
  const gateGuard = stateGuard.getStore();
  let releaseGate: (() => Promise<void>) | undefined;
  if (!dryRun && gateGuard) { try { releaseGate = await guardedStateLock(gateGuard, state, '.userspace-maintenance.native', await guardedIdentity(gateGuard, state)); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS'); throw error; } }
  try {
  async function inventory(): Promise<string[]> {
    const names = await readdir(state);
    const paths: string[] = [];
    for (const name of names.filter(value => /^\.(?:setup-[0-9a-f]{64}\.lock|lease-[0-9a-f-]{36})$/.test(value))) {
      const entry = await lstat(path.join(state, name));
      if (!entry.isFile() || entry.isSymbolicLink()) throw new Error('USERSPACE_OWNER_RECORD_INVALID');
      if (await ownerIsAlive(path.join(state, name))) throw new Error('USERSPACE_RUNTIME_IN_USE');
      paths.push(name);
      if (name.startsWith('.lease-')) { try { const native = await lstat(path.join(state, `${name}.native`)); if (!native.isFile() || native.isSymbolicLink()) throw new Error('USERSPACE_OWNER_RECORD_INVALID'); paths.push(`${name}.native`); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
    }
    if (action === 'cache') {
      for (const name of ['uv-cache', 'python-mirror', 'render-cache', 'render-vendor-cache', 'perl-vendor-cache', 'core-cache']) {
        try { await ownedDirectory(path.join(state, name)); paths.push(name); }
        catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      }
    } else {
      const environments = new Set<string>();
      for (const name of names.filter(value => /^current-[0-9a-f]{64}\.json$/.test(value))) {
        const file = path.join(state, name); const data = marker(JSON.parse((await stateBytes(file)).toString('utf8')));
        if (name !== `current-${data.manifest.slice(7)}.json` || environments.has(data.environment)) throw new Error('Invalid userspace cleanup inventory.');
        environments.add(data.environment);
        try { await ownedDirectory(path.join(state, data.environment)); paths.push(data.environment); }
        catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
        paths.push(name);
      }
      for (const name of names.filter(value => /^repair-(?:[0-9a-f]{64}|history-[0-9a-f-]{36})\.json$/.test(value))) { const value = record(JSON.parse((await stateBytes(path.join(state, name))).toString('utf8'))); const saved = repairJournal(value, value.manifest as string); if (!['completed', 'rolled_back'].includes(saved.phase)) throw new Error('USERSPACE_REPAIR_RECOVERY_REQUIRED'); if (await exists(path.join(state, saved.quarantine))) { await ownedDirectory(path.join(state, saved.quarantine)); paths.push(saved.quarantine); } paths.push(name); }
      if (gateGuard) for (const saved of await assetRepairRecords(state, gateGuard)) { if (saved.record.phase === 'building') throw new Error('ASSET_REPAIR_RECOVERY_REQUIRED'); if (await exists(path.join(state, saved.record.quarantine))) { await ownedDirectory(path.join(state, saved.record.quarantine)); paths.push(saved.record.quarantine); } paths.push(saved.file); }
      for (const name of ['pythons', 'tools', 'uv-cache', 'python-mirror', 'render-cache', 'render-vendor-cache', 'perl-vendor-cache', 'renders', 'core-cache', 'corepacks']) {
        try { await ownedDirectory(path.join(state, name)); paths.push(name); }
        catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      }
    }
    return [...new Set(paths)];
  }
  const maintenance = path.join(state, '.maintenance.lock');
  const recovery = path.join(state, '.recovery.lock');
  if (dryRun) {
    let staleRecovery = false;
    try { await lstat(recovery); if (await ownerIsAlive(recovery)) throw new Error('USERSPACE_RECOVERY_IN_PROGRESS'); staleRecovery = true; }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    let stale = false;
    try { await lstat(maintenance); if (await ownerIsAlive(maintenance)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS'); stale = true; }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    return { paths: [...(staleRecovery ? ['.recovery.lock'] : []), ...(stale ? ['.maintenance.lock'] : []), ...await inventory()], dry_run: true };
  }
  try {
    await lstat(recovery);
    if (await ownerIsAlive(recovery, releaseGate ? '.userspace-maintenance.native' : undefined)) throw new Error('USERSPACE_RECOVERY_IN_PROGRESS');
    if (!releaseGate) throw new Error('USERSPACE_RECOVERY_GUARD_REQUIRED');
    await rm(recovery);
    await syncState(state);
  } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  let lock: string;
  try { lock = await claim(state, '.maintenance.lock', releaseGate ? '.userspace-maintenance.native' : undefined); }
  catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    let held: string;
    try { held = await claim(state, '.recovery.lock', releaseGate ? '.userspace-maintenance.native' : undefined); }
    catch (recoveryError: unknown) { if ((recoveryError as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('USERSPACE_RECOVERY_IN_PROGRESS'); throw recoveryError; }
    try {
      if (await ownerIsAlive(maintenance, releaseGate ? '.userspace-maintenance.native' : undefined)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS');
      await rm(maintenance, { force: true });
    } finally { await rm(held, { force: true }); }
    try { lock = await claim(state, '.maintenance.lock', releaseGate ? '.userspace-maintenance.native' : undefined); }
    catch (retryError: unknown) { if ((retryError as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS'); throw retryError; }
  }
  try {
    try { await lstat(recovery); throw new Error('USERSPACE_RECOVERY_IN_PROGRESS'); }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const paths = await inventory();
    for (const relative of paths) await rm(path.join(state, relative), { recursive: relative.startsWith('env-') || relative.startsWith('quarantine-') || ['uv-cache', 'python-mirror', 'render-cache', 'render-vendor-cache', 'perl-vendor-cache', 'renders', 'pythons', 'tools', 'core-cache', 'corepacks'].includes(relative), force: true });
    return { paths, dry_run: false };
  } finally { await rm(lock, { force: true }); await syncState(state); }
  } finally { await releaseGate?.(); }
  });
}

/** Prepare from a verified offline wheelhouse; no user/global environment is modified. */
export async function prepareUserspace(sourceRoot: string, stateRoot = userspaceStateRoot(), searchPath = process.env.PATH ?? '', host: Host = { platform: process.platform, arch: process.arch }, network: 'bootstrap_only' | 'offline' = 'bootstrap_only', signal?: AbortSignal): Promise<{ installer: 'uv' | 'venv'; reused: boolean; capability: UserspaceExecution }> {
  return setupCancellation.run(signal ?? setupCancellation.getStore(), async () => { checkSetupCancellation();
  if (host.platform !== process.platform || host.arch !== process.arch) throw new Error('Userspace preparation requires the native host platform.');
  const source = await realpath(sourceRoot); await prepareCoreAssets(source, stateRoot, host, network, setupFetch, setupCancellation.getStore()); const pack = await loadPack(source, host, stateRoot);
  return stateGuard.run(pack.guardPath, async () => {
  const state = await ownedDirectory(stateRoot, true);
  if (await maintenanceActive(state)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS');
  try { const capability = await resolveUserspaceExecution(source, state, host); const data = marker(JSON.parse((await stateBytes(path.join(state, `current-${pack.digest.slice(7)}.json`))).toString('utf8'))); return { installer: data.installer, reused: true, capability }; }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  let lock: string;
  const helper = stateGuard.getStore();
  let unlockSetup: (() => Promise<void>) | undefined;
  if (helper) { try { unlockSetup = await guardedStateLock(helper, state, `.setup-${pack.digest.slice(7)}.native`, await guardedIdentity(helper, state)); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') throw new Error('USERSPACE_SETUP_IN_PROGRESS_OR_RECOVERY_REQUIRED'); throw error; } }
  try {
    const name = `.setup-${pack.digest.slice(7)}.lock`;
    try { lock = await claim(state, name, unlockSetup ? `.setup-${pack.digest.slice(7)}.native` : undefined); }
    catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (!unlockSetup || await ownerIsAlive(path.join(state, name), `.setup-${pack.digest.slice(7)}.native`)) throw new Error('USERSPACE_SETUP_IN_PROGRESS_OR_RECOVERY_REQUIRED');
      await rm(path.join(state, name)); await syncState(state);
      lock = await claim(state, name, `.setup-${pack.digest.slice(7)}.native`);
    }
  } catch (error) { await unlockSetup?.(); throw error; }
  let environment: string | undefined;
  try {
    if (await maintenanceActive(state)) throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS');
    try { const capability = await resolveUserspaceExecution(source, state, host); const data = marker(JSON.parse((await stateBytes(path.join(state, `current-${pack.digest.slice(7)}.json`))).toString('utf8'))); return { installer: data.installer, reused: true, capability }; }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    let uv = await findProgram('uv', searchPath);
    if (uv) {
      try { const result = await command(uv, ['--version'], state, 10_000); if (result.code !== 0 || !isCompatibleUvVersion(result.stdout)) uv = undefined; }
      catch { uv = undefined; }
    }
    if (!uv && pack.uv) {
      uv = await checkedPath(pack.assetRoot, pack.uv, 'file');
      const result = await command(uv, ['--version'], state, 10_000);
      if (result.code !== 0 || !isCompatibleUvVersion(result.stdout)) throw new Error('The verified bundled uv is not compatible.');
    }
    if (!uv && (pack.uvDownload || pack.uvVendorDownload)) {
      try {
        uv = pack.uvVendorDownload
          ? await acquireVendorUv(pack.uvVendorDownload, state, host, network, setupFetch)
          : await acquireVerifiedUv(pack.uvDownload!, state, network, setupFetch);
      }
      catch (error: unknown) { checkSetupCancellation(); if (!(error instanceof UvAcquisitionUnavailable)) throw error; }
      if (uv) {
        const result = await command(uv, ['--version'], state, 10_000);
        if (result.code !== 0 || !isCompatibleUvVersion(result.stdout)) throw new Error('The verified downloaded uv is not compatible.');
      }
    }
    let python: { executable: string; version: string; managedPath?: string } | undefined = await findPython(searchPath, state);
    if (!python && uv) {
      for (const version of ['3.15', '3.14']) {
        python = await findManagedPython(uv, state, version);
        if (python) break;
      }
      if (!python && pack.pythonDownload) python = await installManagedPython(uv, state, pack.pythonDownload, network);
    }
    checkSetupCancellation(); if (!python) throw new Error('USERSPACE_COMPATIBLE_PYTHON_REQUIRED');
    environment = await mkdtemp(path.join(state, 'env-'));
    // mkdtemp's suffix is not portable enough to authenticate the environment name.
    const final = path.join(state, `env-${randomUUID()}`); await rename(environment, final); environment = final; await ownedDirectory(final, true); await syncState(state);
    const create = uv ? await command(uv, ['venv', '--python', python.executable, '--no-python-downloads', environment], state) : await command(python.executable, ['-I', '-m', 'venv', '--copies', environment], state);
    if (create.code !== 0) throw new Error('USERSPACE_VENV_CREATION_FAILED');
    const envPython = path.join(environment, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
    const requirements = await checkedPath(pack.assetRoot, pack.requirements, 'file'); const wheels = await checkedPath(pack.assetRoot, pack.wheels, 'directory');
    const install = uv ? await command(uv, ['pip', 'install', '--python', envPython, '--no-index', '--no-deps', '--find-links', wheels, '--require-hashes', '-r', requirements], state) : await command(envPython, ['-I', '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check', '--no-index', '--no-deps', '--find-links', wheels, '--require-hashes', '-r', requirements], state);
    if (install.code !== 0) throw new Error('USERSPACE_DEPENDENCY_INSTALL_FAILED');
    const worker = await checkedPath(pack.assetRoot, pack.worker, 'directory'); const upstream = await checkedPath(pack.assetRoot, pack.upstream, 'directory');
    const probe = await command(envPython, ['-I', '-B', '-c', 'import sys; sys.path[:0] = sys.argv[1:]; import ud_agent.worker, udtools, udapi, regex', worker, upstream], state);
    if (probe.code !== 0) throw new Error('USERSPACE_DEPENDENCY_PROBE_FAILED', { cause: new Error(`dependency probe exited ${probe.code}: ${probe.stdout.slice(0, 4096)}`) });
    if (pack.perl?.deferredRuntime) {
      const selected = pack.perl.deferredRuntime;
      const cache = await ownedDirectory(path.join(state, 'perl-vendor-cache'), true);
      const signal = setupCancellation.getStore();
      const options = { temporaryRoot: environment, ...(signal ? { signal } : {}) };
      const archive = await acquirePerlVendorArchive(selected.definition, cache, network, setupFetch, options);
      const supplier = selected.definition.supplier;
      const supplierArgs = supplier ? ['--supplier-archive', await acquirePerlVendorArchive(supplier, cache, network, setupFetch, options)] : [];
      const recipe = await checkedPath(pack.assetRoot, selected.recipe, 'file');
      const extractor = await checkedPath(pack.assetRoot, pack.worker + '/ud_agent/vendor_runtime.py', 'file');
      const materialized = await command(envPython, ['-I', '-B', extractor, '--recipe', recipe, '--archive', archive, ...supplierArgs, '--source-root', path.dirname(recipe), '--output-dir', path.join(environment, 'deferred-perl')], state);
      if (materialized.code !== 0) throw new Error('USERSPACE_PERL_VENDOR_MATERIALIZATION_FAILED', { cause: new Error(materialized.stdout.slice(0, 4096)) });
      await checkedPath(environment, 'deferred-perl/' + selected.definition.executable, 'file');
      for (const name of selected.relocatedLibraryDirs ?? []) await checkedPath(environment, name, 'directory');
    }
    const fingerprint = await treeFingerprint(environment);
    const managed = python.managedPath ? { path: python.managedPath, fingerprint: await treeFingerprint(await checkedPath(state, python.managedPath, 'directory')) } : undefined;
    const data: Marker = { ...(pack.coreArchive ? { core_archive: pack.coreArchive } : {}), schema_version: 1, manifest: pack.digest, environment: path.basename(environment), fingerprint, python_version: python.version, installer: uv ? 'uv' : 'venv', platform: host.platform, arch: host.arch, abi: `cp${python.version.split('.').slice(0, 2).join('')}`, ...(managed === undefined ? {} : { managed_python: managed }) };
    checkSetupCancellation(); await durableWrite(path.join(state, `current-${pack.digest.slice(7)}.json`), Buffer.from(JSON.stringify(data) + '\n'), await stateAuthority(state));
    environment = undefined;
    const capability = await resolveUserspaceExecution(source, state, host);
    try { await withUserspaceMaintenance(state, capability.guard, () => pruneUserspaceState(state, `current-${pack.digest.slice(7)}.json`), `.setup-${pack.digest.slice(7)}.native`); }
    catch (error) { if (!(error instanceof Error) || !/^(?:USERSPACE_RUNTIME_IN_USE|STATE_LOCKED_OR_UNVERIFIED:|USERSPACE_MAINTENANCE_IN_PROGRESS)/.test(error.message)) throw error; }
    return { installer: data.installer, reused: false, capability };
  } finally {
    try { if (environment) await rm(environment, { recursive: true, force: true }); await rm(lock, { force: true }); }
    finally { await unlockSetup?.(); }
  }
  });
  });
}

type RepairMove = { from: string; to: string; device: string; inode: string };
type RepairJournal = { schema_version: 1; manifest: string; quarantine: string; phase: 'building' | 'completed' | 'rolled_back' | 'conflict'; previous_usable: boolean; moves: RepairMove[] };
function repairJournal(value: unknown, manifest: string): RepairJournal {
  const item = record(value);
  if (item.schema_version !== 1 || typeof item.manifest !== 'string' || !DIGEST.test(item.manifest) || item.manifest !== manifest || typeof item.quarantine !== 'string' || !/^quarantine-[0-9a-f-]{36}$/.test(item.quarantine) || !['building', 'completed', 'rolled_back', 'conflict'].includes(String(item.phase)) || typeof item.previous_usable !== 'boolean' || !Array.isArray(item.moves) || item.moves.length > 16) throw new Error('USERSPACE_REPAIR_JOURNAL_INVALID');
  const seen = new Set<string>(); const destinations = new Set<string>();
  for (const raw of item.moves) { const move = record(raw); if (typeof move.from !== 'string' || !/^(?:current-[0-9a-f]{64}\.json|env-[0-9a-f-]{36}|tools|uv-cache|python-mirror|render-cache|render-vendor-cache|perl-vendor-cache|renders\/[0-9a-f]{64}|pythons\/[A-Za-z0-9._+-]+)$/.test(move.from) || typeof move.to !== 'string' || !/^item-[0-9]{1,2}$/.test(move.to) || typeof move.device !== 'string' || !/^\d+$/.test(move.device) || typeof move.inode !== 'string' || !/^\d+$/.test(move.inode) || seen.has(move.from) || destinations.has(move.to)) throw new Error('USERSPACE_REPAIR_JOURNAL_INVALID'); seen.add(move.from); destinations.add(move.to); }
  return item as RepairJournal;
}
async function exists(file: string): Promise<boolean> { try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
async function moveIdentity(file: string, move: RepairMove): Promise<void> { const info = await lstat(file, { bigint: true }); if (info.isSymbolicLink() || info.dev.toString() !== move.device || info.ino.toString() !== move.inode) throw new Error('USERSPACE_REPAIR_IDENTITY_CHANGED'); }

/** Explicit repair never treats a corrupt product receipt as fallback authority. */
export async function repairUserspace(sourceRoot: string, stateRoot = userspaceStateRoot(), searchPath = process.env.PATH ?? '', host: Host = { platform: process.platform, arch: process.arch }, network: 'bootstrap_only' | 'offline' = 'bootstrap_only', signal?: AbortSignal): Promise<{ installer: 'uv' | 'venv'; reused: boolean; capability: UserspaceExecution; repaired: boolean; quarantine?: string; retention: { removed: string[]; cache_bytes: number } }> {
  return setupCancellation.run(signal ?? setupCancellation.getStore(), async () => { checkSetupCancellation();
  const source = await realpath(sourceRoot); const core = await readCoreDescriptor(source, host); let coreRepair: { repaired: boolean; quarantine?: string } = { repaired: false };
  if (core) {
    const helper = await loadNativeGuardReceipt(source, host);
    coreRepair = await stateGuard.run(helper.guard, async () => { const state = await ownedDirectory(stateRoot, true); return withUserspaceMaintenance(state, helper.guard, () => repairOwnedAssetPack(state, helper.guard, 'core', core, async () => { await loadPack(source, host, state); }, () => prepareCoreAssets(source, state, host, network, setupFetch, setupCancellation.getStore(), async () => { const held = maintenanceAuthority.getStore(); if (!held || held.state !== state || sha256(await stateBytes(path.join(state, '.maintenance.lock'))) !== held.markerSha256) throw new Error('USERSPACE_MAINTENANCE_OWNERSHIP_CHANGED'); }), setupCancellation.getStore())); });
  }
  const pack = await loadPack(source, host, stateRoot); const guard = pack.guardPath;
  const repaired = await stateGuard.run(guard, async () => {
    const state = await ownedDirectory(stateRoot, true);
    return withUserspaceMaintenance(state, guard, async () => {
      const indexName = `current-${pack.digest.slice(7)}.json`; const index = path.join(state, indexName); const journalPath = path.join(state, `repair-${pack.digest.slice(7)}.json`);
      let journal: RepairJournal | undefined; let previousJournalBytes: Buffer | undefined;
      try { const bytes = await stateBytes(journalPath); const previous = repairJournal(JSON.parse(bytes.toString('utf8')), pack.digest); if (previous.phase === 'building') journal = previous; else if (previous.phase === 'conflict') throw new Error('USERSPACE_REPAIR_RECOVERY_REQUIRED'); else previousJournalBytes = bytes; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      let ready: UserspaceExecution | undefined; try { ready = await resolveUserspaceExecution(source, state, host); } catch { /* The verified product pack is intact; inspect owned state below. */ }
      if (ready) {
        const data = marker(JSON.parse((await stateBytes(index)).toString('utf8')));
        if (journal) { journal.phase = 'completed'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(journal)}\n`), await stateAuthority(state)); }
        return { capability: ready, installer: data.installer, reused: true, repaired: journal !== undefined, ...(journal ? { quarantine: journal.quarantine } : {}), retention: await pruneUserspaceState(state, indexName) };
      }
      if (!journal) {
        if (previousJournalBytes) await durableWrite(path.join(state, `repair-history-${randomUUID()}.json`), previousJournalBytes, await stateAuthority(state));
        const quarantine = `quarantine-${randomUUID()}`; await ownedDirectory(path.join(state, quarantine), true);
        const moves: RepairMove[] = []; let old: Marker | undefined; let previousUsable = false;
        if (await exists(index)) { try { old = marker(JSON.parse((await stateBytes(index)).toString('utf8'))); if (old.manifest !== pack.digest) throw new Error('USERSPACE_REPAIR_WRONG_RELEASE'); } catch (error) { if (error instanceof Error && error.message === 'USERSPACE_REPAIR_WRONG_RELEASE') throw error; } }
        const add = async (relative: string) => { const file = path.join(state, ...relative.split('/')); if (!await exists(file)) return; const info = await lstat(file, { bigint: true }); if (info.isSymbolicLink() || !info.isDirectory() && !info.isFile() || typeof process.getuid === 'function' && info.uid !== BigInt(process.getuid())) throw new Error('USERSPACE_REPAIR_UNOWNED_PATH'); moves.push({ from: relative, to: `item-${moves.length}`, device: info.dev.toString(), inode: info.ino.toString() }); };
        await add(indexName);
        if (old) {
          const environment = path.join(state, old.environment);
          if (await exists(environment)) { try { previousUsable = await treeFingerprint(await ownedDirectory(environment)) === old.fingerprint; } catch { previousUsable = false; } await add(old.environment); }
          if (old.managed_python) { try { if (await treeFingerprint(await checkedPath(state, old.managed_python.path, 'directory')) !== old.managed_python.fingerprint) await add(old.managed_python.path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') await add(old.managed_python.path); } }
        }
        // Offline preparation must still be able to verify and use preseeded
        // acquisition bytes. Online repair can replace these cache directories.
        if (network === 'bootstrap_only') {
          for (const name of ['tools', 'uv-cache', 'python-mirror', 'render-cache', 'render-vendor-cache']) await add(name);
        }
        if (pack.lazyRender) await add(`renders/${pack.lazyRender.sha256.slice(7)}`);
        journal = { schema_version: 1, manifest: pack.digest, quarantine, phase: 'building', previous_usable: previousUsable, moves };
        await durableWrite(journalPath, Buffer.from(`${JSON.stringify(journal)}\n`), await stateAuthority(state));
      }
      const saved = journal; const quarantineRoot = await ownedDirectory(path.join(state, saved.quarantine));
      for (const move of saved.moves) {
        checkSetupCancellation();
        const from = path.join(state, ...move.from.split('/')); const to = path.join(quarantineRoot, move.to); const a = await exists(from); const b = await exists(to);
        if (a && !b) { await moveIdentity(from, move); await rename(from, to); await syncState(path.dirname(from)); await syncState(quarantineRoot); }
        else if (!a && b) await moveIdentity(to, move);
        else throw new Error('USERSPACE_REPAIR_RECOVERY_CONFLICT');
      }
      try {
        const prepared = await prepareUserspace(source, state, searchPath, host, network);
        saved.phase = 'completed'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), await stateAuthority(state));
        return { ...prepared, repaired: true, quarantine: saved.quarantine, retention: await pruneUserspaceState(state, indexName) };
      } catch (failure) {
        try {
          for (const [position, move] of [...saved.moves].reverse().entries()) {
            const from = path.join(state, ...move.from.split('/')); const to = path.join(quarantineRoot, move.to); await moveIdentity(to, move);
            if (await exists(from)) { const info = await lstat(from); if (info.isSymbolicLink() || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('USERSPACE_REPAIR_RECOVERY_CONFLICT'); await rename(from, path.join(quarantineRoot, `failed-${position}`)); }
            await rename(to, from); await syncState(path.dirname(from));
          }
          saved.phase = 'rolled_back'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), await stateAuthority(state));
        } catch { saved.phase = 'conflict'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), await stateAuthority(state)); throw new Error('USERSPACE_REPAIR_RECOVERY_REQUIRED'); }
        const error = new Error(`USERSPACE_REPAIR_FAILED: ${failure instanceof Error ? failure.message : 'runtime preparation failed'}`) as Error & { repair?: unknown };
        error.repair = { previous_state_restored: true, previous_usable: saved.previous_usable, quarantine: saved.quarantine }; throw error;
      }
    });
  });
  return { ...repaired, repaired: repaired.repaired || coreRepair.repaired, ...(repaired.quarantine ? {} : coreRepair.quarantine ? { quarantine: coreRepair.quarantine } : {}) };
  });
}

/** Bounded cache retention touches only recognized product-owned state. */
async function pruneUserspaceState(state: string, currentIndex: string, maxCacheBytes = 2 * 1024 ** 3, maxEnvironments = 2): Promise<{ removed: string[]; cache_bytes: number }> {
  const removed: string[] = []; let inventoryCount = 0;
  const size = async (file: string, depth = 0): Promise<number> => { if (++inventoryCount > 100000 || depth > 64) throw new Error('USERSPACE_RETENTION_INVENTORY_LIMIT'); const info = await lstat(file); if (typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('USERSPACE_RETENTION_UNOWNED_PATH'); if (info.isSymbolicLink()) return info.size; if (info.isFile()) return info.size; if (!info.isDirectory()) throw new Error('USERSPACE_RETENTION_SPECIAL_FILE'); let total = 0; for (const name of await readdir(file)) total += await size(path.join(file, name), depth + 1); return total; };
  const caches: { path: string; size: number; modified: number }[] = [];
  for (const name of ['uv-cache', 'python-mirror', 'render-cache', 'render-vendor-cache', 'perl-vendor-cache', 'core-cache']) { const directory = path.join(state, name); if (!await exists(directory)) continue; await ownedDirectory(directory); for (const child of await readdir(directory)) { const file = path.join(directory, child); const info = await lstat(file); caches.push({ path: path.join(name, child), size: await size(file), modified: info.mtimeMs }); } }
  let cacheBytes = caches.reduce((total, item) => total + item.size, 0);
  for (const item of caches.sort((a, b) => a.modified - b.modified || (a.path < b.path ? -1 : 1))) { if (cacheBytes <= maxCacheBytes) break; await rm(path.join(state, item.path), { recursive: true, force: true }); cacheBytes -= item.size; removed.push(item.path); }
  const indexes: { name: string; data: Marker; modified: number }[] = [];
  for (const name of (await readdir(state)).filter(name => /^current-[0-9a-f]{64}\.json$/.test(name))) { const info = await lstat(path.join(state, name)); const data = marker(JSON.parse((await stateBytes(path.join(state, name))).toString('utf8'))); if (name !== `current-${data.manifest.slice(7)}.json`) throw new Error('USERSPACE_RETENTION_INDEX_INVALID'); indexes.push({ name, data, modified: info.mtimeMs }); }
  const retained = indexes.sort((a, b) => a.name === currentIndex ? -1 : b.name === currentIndex ? 1 : b.modified - a.modified); const keep = new Set(retained.slice(0, maxEnvironments).map(item => item.data.environment));
  for (const item of retained.slice(maxEnvironments)) { if (!keep.has(item.data.environment)) { const directory = path.join(state, item.data.environment); if (await exists(directory)) { await ownedDirectory(directory); await rm(directory, { recursive: true, force: true }); removed.push(item.data.environment); } } await rm(path.join(state, item.name)); removed.push(item.name); }
  const corePacks = path.join(state, 'corepacks');
  if (await exists(corePacks)) { await ownedDirectory(corePacks); const needed = new Set(retained.slice(0, maxEnvironments).map(item => item.data.core_archive?.slice(7)).filter((value): value is string => value !== undefined)); for (const name of await readdir(corePacks)) { if (!/^[0-9a-f]{64}$/.test(name) || needed.has(name)) continue; await ownedDirectory(path.join(corePacks, name)); await rm(path.join(corePacks, name), { recursive: true }); removed.push(`corepacks/${name}`); } }
  const quarantines = new Map<string, { device: string; inode: string; modified: number }>();
  const histories = new Map<string, string[]>();
  for (const name of (await readdir(state)).filter(name => /^repair-(?:[0-9a-f]{64}|history-[0-9a-f-]{36})\.json$/.test(name))) { const value = record(JSON.parse((await stateBytes(path.join(state, name))).toString('utf8'))); const journal = repairJournal(value, value.manifest as string); if (journal.phase !== 'completed' && journal.phase !== 'rolled_back') continue; if (name.startsWith('repair-history-')) histories.set(journal.quarantine, [...histories.get(journal.quarantine) ?? [], name]); const directory = path.join(state, journal.quarantine); if (!await exists(directory)) continue; const info = await lstat(directory, { bigint: true }); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('USERSPACE_RETENTION_QUARANTINE_INVALID'); quarantines.set(journal.quarantine, { device: info.dev.toString(), inode: info.ino.toString(), modified: Number(info.mtimeMs) }); }
  const helper = stateGuard.getStore();
  if (helper) for (const saved of await assetRepairRecords(state, helper)) { if (saved.record.phase === 'building') continue; const directory = path.join(state, saved.record.quarantine); if (!await exists(directory)) continue; const info = await lstat(directory, { bigint: true }); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('USERSPACE_RETENTION_QUARANTINE_INVALID'); quarantines.set(saved.record.quarantine, { device: info.dev.toString(), inode: info.ino.toString(), modified: Number(info.mtimeMs) }); if (saved.file.startsWith('asset-repair-history-')) histories.set(saved.record.quarantine, [...histories.get(saved.record.quarantine) ?? [], saved.file]); }
  for (const [name, identity] of [...quarantines].sort((a, b) => b[1].modified - a[1].modified).slice(2)) { await moveIdentity(path.join(state, name), { from: '', to: '', device: identity.device, inode: identity.inode }); await rm(path.join(state, name), { recursive: true, force: true }); for (const history of histories.get(name) ?? []) await rm(path.join(state, history)); removed.push(name); }
  await syncState(state); return { removed, cache_bytes: cacheBytes };
}
