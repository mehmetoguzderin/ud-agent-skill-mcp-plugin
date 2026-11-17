import { constants } from 'node:fs';
import { access, lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { applyEdits, modify, parse as parseJson, printParseErrorCode } from 'jsonc-parser';
import type { ParseError } from 'jsonc-parser';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { parseDocument } from 'yaml';
import { discoverWorkspace } from '../../workspace/src/discovery.js';
import { GuardedWorkspace, TransactionBroker, validCandidatePath } from '../../workspace/src/transactions.js';
import type { Candidate } from '../../workspace/src/transactions.js';
import { boundedRead, durableWrite, fsyncDirectory, JournalStore, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedReadOptional, guardedStateLock } from '../../workspace/src/guard.js';
import { resolveProductGuard } from './docker-authority.js';
import { userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { configureSpecialHost, specialHostProfile } from './connect-special.js';

type Host = { file: string; format: 'json' | 'toml' | 'yaml' | 'deepseek' | 'openclaw'; key: string; skills: string; user?: boolean; stdio?: boolean; workflow?: boolean; base?: string; manualSkills?: boolean };
const HOSTS: Record<string, Host> = {
  codex: { file: '.codex/config.toml', format: 'toml', key: 'mcp_servers', skills: '.agents/skills' },
  'codex-global': { file: '.codex/config.toml', format: 'toml', key: 'mcp_servers', skills: '.agents/skills', user: true },
  'claude-code': { file: '.mcp.json', format: 'json', key: 'mcpServers', skills: '.claude/skills' },
  grok: { file: '.grok/config.toml', format: 'toml', key: 'mcp_servers', skills: '.grok/skills' },
  kimi: { file: '.kimi-code/mcp.json', format: 'json', key: 'mcpServers', skills: '.agents/skills' },
  qwen: { file: '.qwen/settings.json', format: 'json', key: 'mcpServers', skills: '.qwen/skills' },
  pi: { file: '.pi/mcp.json', format: 'json', key: 'mcpServers', skills: '.agents/skills' },
  gemini: { file: '.gemini/settings.json', format: 'json', key: 'mcpServers', skills: '.gemini/skills' },
  cursor: { file: '.cursor/mcp.json', format: 'json', key: 'mcpServers', skills: '.cursor/skills' },
  copilot: { file: '.mcp.json', format: 'json', key: 'mcpServers', skills: '.github/skills', stdio: true },
  vscode: { file: '.vscode/mcp.json', format: 'json', key: 'servers', skills: '.github/skills', stdio: true },
  hermes: { file: '.hermes/config.yaml', format: 'yaml', key: 'mcp_servers', skills: '.hermes/skills', user: true },
  'mini-swe-agent': { file: '.ud-agent/mini-swe-agent.json', format: 'json', key: 'coordinators', skills: '.agents/skills', workflow: true },
};
const ALIASES: Record<string, string> = { 'chatgpt-desktop': 'codex-global', 'grok-build': 'grok', 'kimi-code': 'kimi', 'qwen-code': 'qwen', 'github-copilot': 'copilot', 'vscode-copilot': 'vscode', claude: 'claude-code', 'pi-harness': 'pi' };
const SKILLS = ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release'];
type Entry = { command: string; args: string[]; type?: string };
/** Workspace-relative skill folders that `connect` writes for project hosts (e.g. .agents/skills). */
export function projectSkillDirectories(): string[] {
  return [...new Set(Object.values(HOSTS).filter(host => !host.user).map(host => host.skills))];
}

type Receipt = { version: 1; host: string; workspace: string; base?: string; entry: Entry; skills: { path: string; sha256: string }[] };
function connectionReceipt(value: unknown, host: string, workspace: string, base: string): Receipt {
  const receipt = object(value), entry = object(receipt.entry);
  if (receipt.version !== 1 || receipt.host !== host || receipt.workspace !== workspace || typeof entry.command !== 'string' || !entry.command || entry.command.includes('\0') || !Array.isArray(entry.args) || entry.args.length > 256 || entry.args.some(arg => typeof arg !== 'string' || arg.includes('\0')) || entry.type !== undefined && entry.type !== 'stdio' || !Array.isArray(receipt.skills) || receipt.skills.length > 501) throw new Error('Connection ownership receipt is invalid.');
  if (receipt.base !== undefined && receipt.base !== base) throw new Error('Connection profile location changed. Review its existing registration before reconnecting.');
  const seen = new Set<string>();
  for (const value of receipt.skills) {
    const file = object(value);
    if (typeof file.path !== 'string' || !validCandidatePath(file.path) || seen.has(file.path) || typeof file.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(file.sha256)) throw new Error('Connection ownership receipt is invalid.');
    seen.add(file.path);
  }
  return receipt as Receipt;
}

/** Reconcile the exact prior intent before recalculating any configuration. */
async function recoverConnection(store: JournalStore, secure: GuardedWorkspace, intentFile: string, receiptFile: string, host: string, workspace: string, guard: string): Promise<void> {
  const native = await openStateAuthority(store.root, guard);
  let intent: Record<string, unknown>;
  try { intent = object(JSON.parse((await boundedRead(intentFile, 1024 * 1024, native)).toString('utf8'))); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  const identity = object(intent.identity);
  if (intent.schema_version !== 1 || intent.host !== host || intent.workspace !== workspace || intent.base !== secure.root || identity.device !== secure.identity.device || identity.inode !== secure.identity.inode || typeof intent.transaction_id !== 'string' || !/^[0-9a-f]{64}$/.test(intent.transaction_id) || !Array.isArray(intent.expected) || intent.expected.length < 1 || intent.expected.length > 1000) throw new Error('CONNECTION_RECOVERY_INTENT_INVALID');
  const receipt = connectionReceipt(intent.receipt, host, workspace, secure.root);
  const expected = new Map<string, string | null>();
  for (const raw of intent.expected) {
    const item = object(raw);
    if (typeof item.path !== 'string' || !validCandidatePath(item.path) || expected.has(item.path) || item.after !== null && (typeof item.after !== 'string' || !/^[0-9a-f]{64}$/.test(item.after))) throw new Error('CONNECTION_RECOVERY_INTENT_INVALID');
    expected.set(item.path, item.after as string | null);
  }
  const journal = await store.load(intent.transaction_id);
  if (journal) {
    if (journal.entries.length !== expected.size || journal.entries.some(file => !expected.has(file.path) || expected.get(file.path) !== file.after)) throw new Error('CONNECTION_RECOVERY_MANIFEST_MISMATCH');
    const recovered = await new TransactionBroker(store, secure).recover(intent.transaction_id);
    if (recovered.status === 'completed') {
      for (const [name, hash] of expected) { const bytes = await secure.readOptional(name); if ((bytes === null ? null : sha256(bytes)) !== hash) throw new Error('CONNECTION_RECOVERY_OUTPUT_CHANGED'); }
      for (const item of receipt.skills) { const bytes = await secure.readOptional(item.path); if (bytes === null || sha256(bytes) !== item.sha256) throw new Error('CONNECTION_RECOVERY_OUTPUT_CHANGED'); }
      await durableWrite(receiptFile, Buffer.from(JSON.stringify(receipt)), native);
    } else if (recovered.status !== 'rolled_back') throw new Error('CONNECTION_RECOVERY_CONFLICT');
  }
  await rm(intentFile); await fsyncDirectory(store.root, native);
}
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Host configuration must contain an object.'); return value as Record<string, unknown>; }
async function read(file: string): Promise<Buffer | null> {
  let handle;
  try { handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  try { const info = await handle.stat(); if (!info.isFile() || info.size > 4 * 1024 * 1024) throw new Error('Host configuration must be a bounded ordinary file.'); return await handle.readFile(); }
  finally { await handle.close(); }
}
function configuration(text: string, format: Host['format'], key: string, entry?: Entry): { current: unknown; next: string } {
  if (format === 'deepseek' || format === 'openclaw') return configureSpecialHost(text, format, entry);
  if (format === 'yaml') {
    const document = parseDocument(text || '{}', { uniqueKeys: true });
    if (document.errors.length || document.warnings.length) throw new Error('Host YAML configuration is invalid or ambiguous.');
    const parsed = object(document.toJSON()); const current = parsed[key] === undefined ? undefined : object(parsed[key]).ud;
    if (entry) document.setIn([key, 'ud'], entry); else document.deleteIn([key, 'ud']);
    return { current, next: String(document) };
  }
  if (format === 'toml') {
    const document = parseToml(text); const parent = document[key] === undefined ? {} : object(document[key]); const current = parent.ud;
    const lines = text.split(/(?<=\n)/), kept: string[] = []; let owned = false, found = false;
    for (const line of lines) {
      if (/^\s*\[/.test(line)) {
        owned = false;
        if (/^\s*\[(?!\[).*\]\s*(?:#.*)?$/.test(line.trimEnd())) {
          const probe = parseToml(`${line.trimEnd()}\n__ud_connection_probe = 1\n`);
          const keys: string[] = []; let cursor: unknown = probe;
          while (cursor && typeof cursor === 'object' && !Array.isArray(cursor)) {
            const names = Object.keys(cursor); if (names.length !== 1 || names[0] === '__ud_connection_probe') break;
            keys.push(names[0]!); cursor = (cursor as Record<string, unknown>)[names[0]!];
          }
          owned = keys[0] === key && keys[1] === 'ud'; found ||= owned;
        }
      }
      if (!owned) kept.push(line);
    }
    if (current !== undefined && !found) throw new Error('This TOML uses an inline ud table. Manage that entry in the host, then reconnect; unrelated settings will be preserved.');
    const prefix = kept.join('').trimEnd();
    return { current, next: prefix + (prefix ? '\n\n' : '') + (entry ? stringifyToml({ [key]: { ud: entry } }) : '') };
  }
  const errors: ParseError[] = [], document = object(parseJson(text || '{}', errors, { allowTrailingComma: true }));
  if (errors.length) throw new Error(`Host JSON configuration is invalid: ${printParseErrorCode(errors[0]!.error)}`);
  const current = document[key] === undefined ? undefined : object(document[key]).ud;
  return { current, next: applyEdits(text || '{}', modify(text || '{}', [key, 'ud'], entry, { formattingOptions: { insertSpaces: true, tabSize: 2 } })) + (text.endsWith('\n') ? '' : '\n') };
}
async function launcher(sourceRoot: string, workspace: string): Promise<Entry> {
  const native = path.join(sourceRoot, 'bin', process.platform === 'win32' ? 'ud-agent.exe' : 'ud-agent');
  try { const info = await lstat(native); if (info.isFile() && !info.isSymbolicLink()) { await access(native, process.platform === 'win32' ? constants.F_OK : constants.X_OK); return { command: native, args: ['mcp', '--allow-root', workspace] }; } }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const bundled = path.join(sourceRoot, 'lib/coordinator.mjs');
  if (await read(bundled)) return { command: process.execPath, args: [bundled, 'mcp', '--allow-root', workspace] };
  throw new Error('Install a published native archive or npm package before connecting a host.');
}

export async function connectHost(hostName: string, options: { sourceRoot: string; workingTree?: string; cwd?: string; home?: string; stateRoot?: string; guard?: string; check?: boolean; remove?: boolean; dryRun?: boolean; noSkills?: boolean; launch?: Entry; platform?: NodeJS.Platform; appData?: string; xdgConfigHome?: string }): Promise<Record<string, unknown>> {
  const host = ALIASES[hostName] ?? hostName, home = options.home ?? os.homedir();
  const platform = options.platform ?? process.platform;
  const desktop: Host | undefined = host !== 'claude-desktop' ? undefined : platform === 'darwin'
    ? { file: 'Library/Application Support/Claude/claude_desktop_config.json', format: 'json', key: 'mcpServers', skills: '.ud-agent/claude-desktop-skills', user: true, manualSkills: true }
    : platform === 'win32' || platform === 'linux'
      ? { file: 'Claude/claude_desktop_config.json', format: 'json', key: 'mcpServers', skills: 'Claude/ud-agent-skills', user: true, manualSkills: true, base: platform === 'win32' ? options.appData ?? process.env.APPDATA ?? path.join(home, 'AppData/Roaming') : options.xdgConfigHome ?? process.env.XDG_CONFIG_HOME ?? path.join(home, '.config') }
      : undefined;
  const profile: Host | undefined = HOSTS[host] ?? specialHostProfile(host) ?? desktop;
  if (!profile) {
    const routes: Record<string, string> = { 'chatgpt-desktop': 'Use ChatGPT Desktop Plugins to install the published UD plugin, then open your treebank folder.', cowork: 'Use Cowork Plugins to install ud-agent-skill-mcp-plugin from its owned marketplace.', 'claude-desktop': 'Open the published platform MCPB bundle in Claude Desktop and choose your treebank folder.', deepseek: 'Install the official DeepSeek Harness MCP-client plugin, then use the UD host configuration in the published plugin package.', openclaw: 'Use openclaw mcp add with the published coordinator; see README OpenClaw for the host-managed route.', 'mini-swe-agent': 'Use the installed ud-agent CLI from the agent shell and the six published standalone skills.' };
    if (!routes[host]) throw new Error(`Unknown host: ${hostName}. Supported hosts: ${[...Object.keys(HOSTS), ...Object.keys(routes)].join(', ')}.`);
    return { status: 'host_managed_install', host, next: routes[host], readme_section: host, changed: [] };
  }
  const workspace = options.workingTree ? await realpath(path.resolve(options.workingTree)) : await discoverWorkspace(options.cwd ?? process.cwd(), home);
  if (!workspace) throw new Error('Open your treebank folder in a terminal and try again, or choose it with --working-tree PATH. Home and filesystem roots are not inferred as workspaces.');
  const info = await lstat(workspace); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Choose an ordinary workspace directory.');
  if (profile.base !== undefined && (!path.isAbsolute(profile.base) || profile.base.includes('\0'))) throw new Error('Host configuration directory must be an absolute user-profile path.');
  const base = profile.base ? await realpath(profile.base) : profile.user ? await realpath(home) : workspace;
  const guard = options.guard ?? (await resolveProductGuard(options.sourceRoot, { platform: process.platform, arch: process.arch })).guard;
  const state = options.stateRoot ?? `${userspaceStateRoot()}-connections`, receiptName = `${sha256(`${host}\0${workspace}`)}.json`;
  const intentFile = path.join(state, `.connect-${receiptName}`);
  let unlock: (() => Promise<void>) | undefined, store: JournalStore | undefined, secure: GuardedWorkspace | undefined;
  if (!options.check && !options.dryRun) {
    await mkdir(state, { recursive: true, mode: 0o700 }); store = await JournalStore.open(state, guard);
    unlock = await guardedStateLock(guard, store.root, `.connect-${sha256(`${host}\0${workspace}`)}.native`, await guardedIdentity(guard, store.root));
  }
  try {
  if (options.check || options.dryRun) {
    try { await lstat(intentFile); return { status: 'recovery_required', host, workspace, changed: [], next: 'Run connect for this host again to reconcile its interrupted installation.' }; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  if (store) { secure = await GuardedWorkspace.open(base, guard, [base]); await recoverConnection(store, secure, intentFile, path.join(state, receiptName), host, workspace, guard); }
  const destination = path.join(base, ...profile.file.split('/')), before = await read(destination), oldText = before?.toString('utf8') ?? '';
  const entry = { ...(options.launch ?? await launcher(options.sourceRoot, workspace)), ...(profile.stdio ? { type: 'stdio' } : {}) };
  let receipt: Receipt | undefined;
  try { await lstat(state); const native = await openStateAuthority(state, guard); receipt = connectionReceipt(JSON.parse((await boundedRead(path.join(state, receiptName), 1024 * 1024, native)).toString('utf8')), host, workspace, base); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const desired = configuration(oldText, profile.format, profile.key, options.remove ? undefined : entry);
  if (desired.current !== undefined && JSON.stringify(desired.current) !== JSON.stringify(receipt?.entry ?? entry)) throw new Error('The ud server entry was changed or belongs to another installation. Review it in your host before replacing it.');
  if (options.check) return { status: JSON.stringify(desired.current) === JSON.stringify(entry) ? 'connected' : 'not_connected', host, workspace, configuration: destination, changed: [], skills: receipt?.skills ?? [] };
  if (options.remove && !receipt && desired.current === undefined) return { status: 'not_connected', host, workspace, changed: [] };
  const candidates: Candidate[] = [];
  if (desired.next !== oldText && !(options.remove && before === null)) candidates.push({ path: profile.file, before_sha256: before === null ? null : sha256(before), after_base64: Buffer.from(desired.next).toString('base64') });
  const skillFiles: { path: string; sha256: string }[] = options.noSkills && !options.remove ? [...(receipt?.skills ?? [])] : [];
  if (options.remove) {
    const identity = receipt?.skills.length ? secure?.identity ?? await guardedIdentity(guard, base) : undefined;
    for (const owned of receipt?.skills ?? []) {
      if (!SKILLS.some(skill => owned.path.startsWith(`${profile.skills}/${skill}/`)) && !(profile.workflow && owned.path === '.ud-agent/WORKFLOW.md')) throw new Error('Connection ownership receipt contains an out-of-scope file.');
      const original = secure ? await secure.readOptional(owned.path) : await guardedReadOptional(guard, base, owned.path, identity!);
      if (original && sha256(original) === owned.sha256) candidates.push({ path: owned.path, before_sha256: owned.sha256, after_base64: null });
    }
  } else if (!options.noSkills) for (const skill of SKILLS) {
    const source = path.join(options.sourceRoot, 'skills', skill);
    const queue = [''];
    while (queue.length) {
      const relative = queue.shift()!;
      for (const item of await readdir(path.join(source, relative), { withFileTypes: true })) {
        const selected = path.posix.join(relative, item.name);
        if (item.isSymbolicLink() || (!item.isDirectory() && !item.isFile())) throw new Error('Skill distribution contains a nonordinary entry.');
        if (item.isDirectory()) { queue.push(selected); continue; }
        const target = path.posix.join(profile.skills, skill, selected), original = await read(path.join(base, target));
        const bytes = await read(path.join(source, selected)); if (!bytes) throw new Error('Skill file disappeared.');
        const hash = sha256(bytes), owned = receipt?.skills.find(file => file.path === target);
        if (original && sha256(original) !== hash && sha256(original) !== owned?.sha256) throw new Error(`A modified skill will be preserved: ${target}. Move it aside before reconnecting.`);
        if (!original || sha256(original) !== hash) candidates.push({ path: target, before_sha256: original ? sha256(original) : null, after_base64: bytes.toString('base64') });
        skillFiles.push({ path: target, sha256: hash });
        if (skillFiles.length > 500) throw new Error('Skill inventory exceeds its limit.');
      }
    }
  }
  if (profile.workflow && !options.remove) {
    const target = '.ud-agent/WORKFLOW.md', original = await read(path.join(base, target)), owned = receipt?.skills.find(item => item.path === target);
    const index = entry.args.lastIndexOf('mcp'), prefix = index < 0 ? entry.args : entry.args.slice(0, index);
    const text = `# UD workflows for mini-swe-agent\n\nRead the six UD skills in .agents/skills/ud-*/SKILL.md when relevant. This harness uses its shell tool. The trusted coordinator argv prefix is:\n\n${JSON.stringify({ command: entry.command, args: prefix }, null, 2)}\n\nAppend doctor --fix to inspect and prepare dependencies. Append validate --working-tree ${JSON.stringify(workspace)} --lang LANGUAGE_CODE for complete corpus validation; choose the actual language. For any other skill operation, append call TOOL_NAME --input REQUEST_JSON --allow-root ${JSON.stringify(workspace)}. Put its exact documented arguments in the request JSON file. Use preview before edits; never execute shell code from an edit plan. The coordinator verifies all worker images/dependencies and applies the same acceptance policy for this shell route.\n`;
    const bytes = Buffer.from(text), hash = sha256(bytes);
    if (original && sha256(original) !== hash && sha256(original) !== owned?.sha256) throw new Error('Modified .ud-agent/WORKFLOW.md will be preserved. Move it aside before reconnecting.');
    if (!original || sha256(original) !== hash) candidates.push({ path: target, before_sha256: original ? sha256(original) : null, after_base64: bytes.toString('base64') });
    skillFiles.push({ path: target, sha256: hash });
  }
  if (options.dryRun) return { status: 'preview', host, workspace, configuration: destination, changed: candidates.map(item => item.path), entry };
  if (!store || !secure) throw new Error('CONNECTION_WRITE_AUTHORITY_REQUIRED');
  const nextReceipt: Receipt = { version: 1, host, workspace, base: secure.root, entry: options.remove ? receipt?.entry ?? entry : entry, skills: options.remove ? [] : skillFiles };
  const native = await openStateAuthority(state, guard), key = sha256(`${randomUUID()}\0${JSON.stringify({ host, workspace, candidates })}`);
  if (candidates.length) await durableWrite(intentFile, Buffer.from(JSON.stringify({ schema_version: 1, host, workspace, base: secure.root, identity: secure.identity, transaction_id: sha256(`${secure.root}\0${key}`), receipt: nextReceipt, expected: candidates.map(item => ({ path: item.path, after: item.after_base64 === null ? null : sha256(Buffer.from(item.after_base64, 'base64')) })) })), native);
  const transaction = candidates.length ? await new TransactionBroker(store, secure).apply(candidates, key) : { status: 'completed', files: [] };
  if (transaction.status !== 'completed') throw new Error('CONNECTION_TRANSACTION_INCOMPLETE');
  await durableWrite(path.join(state, receiptName), Buffer.from(JSON.stringify(nextReceipt)), native);
  if (candidates.length) { await rm(intentFile); await fsyncDirectory(state, native); }
  return { status: options.remove ? 'disconnected' : 'connected', host, workspace, configuration: destination, changed: candidates.map(item => item.path), transaction, skills: options.remove ? [] : SKILLS.filter(skill => skillFiles.some(file => file.path.startsWith(`${profile.skills}/${skill}/`))), ...(profile.manualSkills && !options.remove && skillFiles.length > 0 ? { skill_activation: { mode: 'manual_upload', directory: path.join(base, profile.skills), instructions: 'ZIP each staged skill folder, then use Claude Customize > Skills > Create skill > Upload a skill and enable it. The local MCP registration is separate.' } } : {}), next: options.remove ? 'Restart your host to unload UD.' : profile.workflow ? 'Ask mini-swe-agent to read .ud-agent/WORKFLOW.md and validate this treebank.' : 'Restart your host, open this workspace, and ask: Validate this treebank with UD.', first_request: profile.workflow ? 'The shell workflow uses doctor --fix and the installed coordinator CLI.' : 'The first UD request prepares and verifies the selected runtime automatically.' };
  } finally { await unlock?.(); }
}
