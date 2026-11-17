/** MIT. Actual desktop identities stay distinct from related CLIs. */
import path from 'node:path';
import { existsSync, readFileSync, mkdirSync, writeFileSync, copyFileSync, readdirSync, symlinkSync, unlinkSync, lstatSync, readlinkSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { runOwned, startOwned } from './process.mjs';
import { privateEnvironment } from './preparation.mjs';
import { createCoordinatorBridge } from './coordinator-bridge.mjs';
import { selectedDockerEnvironment } from './container.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

export const DESKTOP_SURFACES = Object.freeze({
  'chatgpt-desktop': { app: '/Applications/ChatGPT.app', surface: 'ChatGPT Desktop', profile: 'native-app-profile', provider: 'custom-provider-capability-probe-required' },
  'codex-desktop': { app: '/Applications/Codex.app', surface: 'Codex Desktop', profile: 'native-app-profile', provider: 'responses' },
  'claude-desktop': { app: '/Applications/Claude.app', surface: 'Claude Desktop chat', profile: 'native-third-party-profile', provider: 'messages-experimental' },
  cursor: { app: '/Applications/Cursor.app', surface: 'Cursor IDE agent', profile: 'electron-user-data-dir', provider: 'private-direct-routing-unverified' },
  'vscode-copilot': { app: '/Applications/Visual Studio Code.app', surface: 'VS Code Copilot agent', profile: 'electron-user-data-dir', provider: 'custom-endpoint' },
  'codex-ide': { app: '/Applications/Visual Studio Code.app', surface: 'Codex IDE extension', profile: 'electron-user-data-dir', provider: 'responses' },
  'claude-cowork': { app: '/Applications/Claude.app', surface: 'Claude Cowork', profile: 'native-third-party-profile', provider: 'native-third-party-capability-probe-required' },
});
const bundles = { 'chatgpt-desktop': 'com.openai.chat', 'codex-desktop': 'com.openai.codex', 'vscode-copilot': 'com.microsoft.VSCode', 'codex-ide': 'com.microsoft.VSCode' };
export async function desktopContentIdentity(directory) {
  const tree = createHash('sha256'); let files = 0, bytes = 0;
  async function visit(relative) {
    const file = path.join(directory, relative), stat = lstatSync(file);
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(file), resolved = path.resolve(path.dirname(file), target);
      if (resolved !== directory && !resolved.startsWith(directory + path.sep)) throw new Error('DESKTOP_IDENTITY_LINK_ESCAPES_BUNDLE');
      tree.update(JSON.stringify([relative, 'link', target]) + '\n'); return;
    }
    if (stat.isDirectory()) { for (const name of readdirSync(file).sort()) await visit(path.join(relative, name)); return; }
    if (!stat.isFile()) throw new Error('DESKTOP_IDENTITY_SPECIAL_FILE');
    const hash = createHash('sha256'); for await (const chunk of createReadStream(file)) hash.update(chunk);
    tree.update(JSON.stringify([relative, stat.mode & 0o777, stat.size, hash.digest('hex')]) + '\n'); files++; bytes += stat.size;
  }
  await visit(''); return { sha256: tree.digest('hex'), files, bytes, method: 'sorted-content-tree-v1' };
}
export async function inspectDesktop(id, { runner = runOwned, appPaths } = {}) {
  const surface = DESKTOP_SURFACES[id];
  if (!surface) throw new Error('DESKTOP_SURFACE_UNKNOWN');
  let app = appPaths?.[id] ?? surface.app;
  if (id === 'codex-desktop' && !existsSync(app) && existsSync('/Applications/ChatGPT.app')) app = '/Applications/ChatGPT.app';
  const info = path.join(app, 'Contents/Info.plist');
  if (!existsSync(info)) return { ...surface, installed: false, status: 'interface unsupported', reason: 'The actual desktop application is absent. A related CLI cannot certify this surface.' };
  const result = { ...surface, app, installed: true, info_plist_sha256: sha256(readFileSync(info)), status: 'interface unsupported', execution_location: 'native-macos' };
  try {
    result.bundle_id = (await runner('/usr/bin/plutil', ['-extract', 'CFBundleIdentifier', 'raw', info], { timeout: 5000 })).stdout.trim();
    result.version = (await runner('/usr/bin/plutil', ['-extract', 'CFBundleShortVersionString', 'raw', info], { timeout: 5000 })).stdout.trim();
    result.bundle_executable = (await runner('/usr/bin/plutil', ['-extract', 'CFBundleExecutable', 'raw', info], { timeout: 5000 })).stdout.trim();
  } catch (error) { result.identity_error = error.message; }
  if (bundles[id] && result.bundle_id !== bundles[id]) return { ...result, installed: false, observed_bundle_id: result.bundle_id, reason: `The application filename identifies a different product (${result.bundle_id ?? 'unverified'}); it cannot certify ${surface.surface}.` };
  if (id === 'vscode-copilot' || id === 'codex-ide') {
    const resources = path.join(app, 'Contents/Resources/app');
    const extension = id === 'vscode-copilot' ? path.join(resources, 'extensions/copilot') : findCodexExtension();
    const packageFile = extension && path.join(extension, 'package.json');
    if (!packageFile || !existsSync(packageFile)) return { ...result, reason: 'The actual native extension is absent.' };
    const metadata = JSON.parse(readFileSync(packageFile, 'utf8'));
    const main = path.resolve(extension, metadata.main + (path.extname(metadata.main) ? '' : '.js'));
    const files = [info, path.join(resources, 'package.json'), path.join(resources, 'out/vs/workbench/workbench.desktop.main.js'), packageFile, main];
    result.extension = { id: `${metadata.publisher}.${metadata.name}`, version: metadata.version, directory: extension };
    result.identity_files = files.map(file => ({ path: file, sha256: sha256(readFileSync(file)) }));
    result.application_closure = await desktopContentIdentity(app);
    if (!extension.startsWith(app + path.sep)) result.extension_closure = await desktopContentIdentity(extension);
    result.client_identity = sha256(JSON.stringify([result.application_closure, result.extension_closure ?? null, result.extension.id]));
    result.identity_scope = 'complete-application-and-selected-extension-content';
    if (!/^[\w.-]+$/.test(result.bundle_executable ?? '')) return { ...result, reason: 'Application executable identity is unverified.' };
    result.executable = path.join(app, 'Contents/MacOS', result.bundle_executable);
    result.driver_available = id === 'vscode-copilot';
    result.skill_mechanism = id === 'vscode-copilot' ? 'native-agent-skills' : 'native-codex-skills';
  }
  result.reason = id === 'cursor'
    ? 'The actual Cursor agent must prove direct private-provider routing. A cloud relay or public tunnel does not satisfy the local-only campaign.'
    : 'Actual surface installed; isolated UI launch, exact provider routing, fresh conversation, event capture, cancellation and cleanup have no verified automation driver.';
  return result;
}
function findCodexExtension() {
  const directory = path.join(process.env.HOME ?? '', '.vscode/extensions');
  if (!existsSync(directory)) return undefined;
  const matches = readdirSync(directory).filter(name => /^openai\.chatgpt-[\w.-]+-darwin-arm64$/.test(name));
  // Multiple installed versions require an explicit selection, not a lexical guess.
  return matches.length === 1 ? path.join(directory, matches[0]) : undefined;
}

/** Short aliases are owned pointers only; all data stays in the private profile. */
export function createDesktopProfileAliases(root, profile, userData) {
  if (![root, profile, userData].every(path.isAbsolute) || !profile.startsWith(root + path.sep) || !userData.startsWith(profile + path.sep)) throw new Error('DESKTOP_PRIVATE_ROOT_REQUIRED');
  const aliasRoot = path.join(root, '.artifacts/ui'), identity = sha256(profile).slice(0, 8);
  const userDataAlias = path.join(aliasRoot, 'v' + identity), temporaryAlias = path.join(aliasRoot, 't' + identity), temporary = path.join(profile, 'tmp');
  if (Buffer.byteLength(path.join(userDataAlias, '1.14-main.sock')) > 103) throw new Error('DESKTOP_PROFILE_SOCKET_PATH_TOO_LONG');
  if (Buffer.byteLength(path.join(temporaryAlias, 'mcp-XXXXXX/mcp.sock')) > 103) throw new Error('DESKTOP_TEMP_SOCKET_PATH_TOO_LONG');
  mkdirSync(aliasRoot, { recursive: true, mode: 0o700 }); mkdirSync(temporary, { mode: 0o700 });
  const aliases = [];
  const remember = (alias, target) => { symlinkSync(target, alias); const info = lstatSync(alias); aliases.push({ path: alias, target, uid: info.uid, device: info.dev, inode: info.ino }); };
  const verify = row => { const info = lstatSync(row.path); return info.isSymbolicLink() && info.uid === row.uid && info.dev === row.device && info.ino === row.inode && readlinkSync(row.path) === row.target; };
  try { remember(userDataAlias, userData); remember(temporaryAlias, temporary); }
  catch (error) { for (const row of aliases) if (verify(row)) unlinkSync(row.path); throw error; }
  let closed = false;
  return { userDataAlias, temporaryAlias, temporary, identities: aliases,
    cleanup(releaseVerified) {
      if (closed) return { verified: true, removed: aliases.map(row => row.path) };
      if (releaseVerified !== true) return { verified: false, retained: aliases, reason: 'DESKTOP_PROCESS_RELEASE_UNVERIFIED' };
      try { if (!aliases.every(verify)) return { verified: false, retained: aliases, reason: 'DESKTOP_PROFILE_ALIAS_IDENTITY_CHANGED' }; }
      catch (error) { return { verified: false, retained: aliases, reason: 'DESKTOP_PROFILE_ALIAS_IDENTITY_UNVERIFIED', error: error.message }; }
      for (const row of aliases) unlinkSync(row.path);
      closed = true; return { verified: true, removed: aliases.map(row => row.path) };
    } };
}

export function configureDesktopProfile({ profile, model, endpoint, prompt, image, skillsEnabled }) {
  const url = new URL(endpoint);
  if (url.hostname !== '127.0.0.1' || url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/') throw new Error('DESKTOP_PRIVATE_PROVIDER_REQUIRED');
  const userData = path.join(profile, 'vscode'), user = path.join(userData, 'User'), driver = path.join(profile, 'driver');
  mkdirSync(user, { recursive: true, mode: 0o700 }); mkdirSync(driver, { recursive: true, mode: 0o700 });
  const write = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 });
  write(path.join(user, 'settings.json'), {
    'telemetry.telemetryLevel': 'off', 'update.mode': 'none', 'extensions.autoUpdate': false, 'extensions.autoCheckUpdates': false,
    'workbench.startupEditor': 'none', 'workbench.enableExperiments': false, 'security.workspace.trust.enabled': false,
    'chat.agent.enabled': true, 'chat.useAgentSkills': skillsEnabled, 'chat.useCustomizationsInParentRepositories': false,
    'chat.agentHost.byokModels.enabled': false,
    'chat.defaultToCopilotHarness': false, 'chat.editor.preferCopilotHarness': false,
    'chat.tools.global.autoApprove': true, 'chat.tools.terminal.enableAutoApprove': true, 'chat.mcp.autostart': 'newAndOutdated',
    'chat.byokUtilityModelDefault': 'mainAgent', 'chat.agent.maxRequests': 10, 'chat.agent.autoFix': false,
    'github.copilot.enable': { '*': false }, 'github.copilot.chat.codesearch.enabled': false,
  });
  write(path.join(user, 'chatLanguageModels.json'), [{ vendor: 'customendpoint', name: 'UD local evaluation', apiKey: 'local-eval-only', apiType: 'chat-completions', models: [{
    id: model, name: model, url: endpoint + '/v1/chat/completions', apiType: 'chat-completions', toolCalling: true, vision: true,
    maxInputTokens: 15872, maxOutputTokens: 512, contextWindow: 16384, thinking: false, streaming: true,
    statefulResponses: false, zeroDataRetentionEnabled: true, modelOptions: { temperature: null, top_p: null },
  }] }]);
  write(path.join(driver, 'package.json'), { name: 'ud-local-eval-native-ui-driver', publisher: 'ud-local-eval', version: '1.0.0', engines: { vscode: '^1.146.0' }, activationEvents: ['onStartupFinished'], main: './extension.cjs' });
  copyFileSync(new URL('./vscode-driver.cjs', import.meta.url), path.join(driver, 'extension.cjs'));
  const spec = { model, prompt, ...(image ? { image } : {}), events: path.join(profile, 'desktop-events.jsonl'), result: path.join(profile, 'desktop-result.json'), transcript: path.join(profile, 'native-chat.json') };
  const configuration = path.join(profile, 'desktop-driver.json'); write(configuration, spec);
  return { userData, driver, configuration, spec };
}

export function desktopTranscript(profile) {
  const file = path.join(profile, 'native-chat.json'), resultFile = path.join(profile, 'desktop-result.json'), eventsFile = path.join(profile, 'desktop-events.jsonl');
  const events = existsSync(eventsFile) ? readFileSync(eventsFile, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
  if (!existsSync(resultFile) || !existsSync(file)) return { events, finalAnswer: '' };
  const result = JSON.parse(readFileSync(resultFile, 'utf8')), transcript = JSON.parse(readFileSync(file, 'utf8'));
  if (result.status !== 'completed' || !Array.isArray(transcript.requests) || transcript.requests.length !== 1) return { events, finalAnswer: '', transcript };
  const request = transcript.requests[0];
  if (!Array.isArray(request.response) || request.result?.errorDetails || result.response?.errorDetails || request.isCanceled) return { events, finalAnswer: '', transcript };
  const finalAnswer = request.response.filter(part => typeof part.value === 'string' && !part.kind || part.kind === 'markdownContent').map(part => part.value ?? part.content?.value ?? '').join('');
  return { events, finalAnswer, transcript };
}

/** Actual application process, private profile, one native command, owned cleanup. */
export async function startDesktop({ root, harness, model, endpoint, taskRoot, profile, prompt, image, skillsEnabled, budgetEnvironment,
  hostBudgetEnvironment = budgetEnvironment, signal, installation, beforeStart, beforeLaunch, allowUnverified = false, record = () => {} }) {
  if (!DESKTOP_SURFACES[harness.id]) throw new Error('DESKTOP_SURFACE_UNKNOWN');
  if (process.platform !== 'darwin' || harness.id !== 'vscode-copilot' || !harness.driver_available) throw new Error(`DESKTOP_NATIVE_LIFECYCLE_UNVERIFIED:${harness.id}`);
  if (!allowUnverified && harness.status !== 'mechanically-admitted') throw new Error('DESKTOP_NATIVE_ROUTE_NOT_ADMITTED');
  for (const directory of [installation, taskRoot, profile]) if (!path.isAbsolute(directory) || !directory.startsWith(root + path.sep)) throw new Error('DESKTOP_PRIVATE_ROOT_REQUIRED');
  mkdirSync(profile, { recursive: true, mode: 0o700 });
  const configured = configureDesktopProfile({ profile, model, endpoint, prompt, image, skillsEnabled });
  // Short names cover both Electron IPC and Copilot's internal MCP socket.
  const aliases = createDesktopProfileAliases(root, profile, configured.userData);
  const env = { ...privateEnvironment(root, profile), TMPDIR: aliases.temporaryAlias, TMP: aliases.temporaryAlias, TEMP: aliases.temporaryAlias, UD_EVAL_DESKTOP_DRIVER: configured.configuration };
  record({ type: 'desktop.profile_aliases', aliases: aliases.identities });
  let bridge, owned;
  try {
  bridge = await createCoordinatorBridge({ coordinator: path.join(installation, 'dist/packages/coordinator/src/entry.js'), taskRoot,
    environment: { ...env, ...hostBudgetEnvironment, ...selectedDockerEnvironment() }, temporaryInputRoot: path.join(profile, 'tmp'), signal, record });
  const bin = path.join(profile, 'bin'); mkdirSync(bin, { mode: 0o700 });
  const shim = path.join(bin, 'coordinator-stdio.mjs'); copyFileSync(new URL('./coordinator-stdio.mjs', import.meta.url), shim);
  writeFileSync(path.join(bin, 'coordinator-capability.json'), JSON.stringify({ url: bridge.url, token: bridge.token }), { mode: 0o600, flag: 'wx' });
  env.UD_EVAL_COORDINATOR_BRIDGE = JSON.stringify({ url: bridge.url, token: bridge.token });
  env.PATH = `${bin}:${env.PATH}`;
  writeFileSync(path.join(bin, 'ud-agent'), '#!/usr/bin/env node\nimport ' + JSON.stringify(pathToFileURL(shim).href) + ';\n', { mode: 0o700 });
  const { connectHost } = await import(pathToFileURL(path.join(installation, 'dist/packages/coordinator/src/connect.js')).href);
  await connectHost('vscode', { sourceRoot: installation, workingTree: taskRoot, home: profile, stateRoot: path.join(profile, 'connections'), noSkills: !skillsEnabled,
    launch: { command: process.execPath, args: [shim, 'mcp', '--allow-root', taskRoot] } });
  const allowed = [installation, taskRoot, profile, harness.extension.directory], ownerHome = process.env.HOME;
  const protectedRoots = [...new Set([root, ...(ownerHome && path.isAbsolute(ownerHome) ? [ownerHome] : [])])];
  const policy = '(version 1) (allow default)' + protectedRoots.map(directory =>
    ` (deny file-read-data (require-all (subpath ${JSON.stringify(directory)}) ${allowed.map(allow => `(require-not (subpath ${JSON.stringify(allow)}))`).join(' ')}))`
    + ` (deny file-write* (require-all (subpath ${JSON.stringify(directory)}) ${[taskRoot, profile].map(allow => `(require-not (subpath ${JSON.stringify(allow)}))`).join(' ')}))`).join('')
    + ` (deny file-write*) (allow file-write* (subpath ${JSON.stringify(taskRoot)}) (subpath ${JSON.stringify(profile)})) (allow file-write-data (literal "/dev/null"))`
    + ' (deny network-outbound) (allow network-outbound (remote ip "localhost:*"))'
    + ` (allow network-outbound (remote unix-socket (subpath ${JSON.stringify(profile)})))`
    + ` (allow network-outbound (remote unix-socket (subpath ${JSON.stringify(aliases.temporaryAlias)})))`;
  const args = ['--user-data-dir', aliases.userDataAlias, '--extensions-dir', path.join(profile, 'extensions'), '--extensionDevelopmentPath=' + configured.driver,
    '--extensionDevelopmentPath=' + harness.extension.directory,
    '--no-sandbox', '--skip-welcome', '--skip-release-notes', '--disable-workspace-trust', '--disable-updates', '--disable-telemetry', '--disable-crash-reporter', '--new-window', taskRoot];
  await beforeStart?.();
  await beforeLaunch?.();
  owned = startOwned('/usr/bin/sandbox-exec', ['-p', policy, harness.executable, ...args], { cwd: taskRoot, env, signal, timeout: 90_000, log: path.join(profile, 'native-process.jsonl') });
  owned.child.stdin.end();
  record({ type: 'desktop.launch', application: harness.app, identity: harness.client_identity, profile: configured.userData });
  let poll;
  const finish = new Promise(resolve => { poll = setInterval(() => { if (existsSync(configured.spec.result)) { clearInterval(poll); resolve(owned.stop('native-ui-completed')); } }, 100); });
  let reconciliation;
  const reconcile = (application, coordinator) => reconciliation ??= (async () => {
    coordinator ??= await bridge.stop();
    const released = application.cleanupVerified === true && coordinator.cleanupVerified === true;
    const aliasCleanup = aliases.cleanup(released);
    record({ type: 'desktop.profile_alias_cleanup', ...aliasCleanup });
    return { ...application, coordinator_cleanup: coordinator, alias_cleanup: aliasCleanup, cleanupVerified: released && aliasCleanup.verified === true };
  })();
  const stop = async reason => { const started = Date.now(); const [application, coordinator] = await Promise.all([owned.stop(reason), bridge.stop()]); const result = await reconcile(application, coordinator); return { ...result, cleanupVerified: result.cleanupVerified === true && Date.now() - started <= 5000 }; };
  const done = Promise.race([owned.done, finish]).then(result => reconcile(result)).finally(() => clearInterval(poll));
  return { ...owned, stop, done, events: () => desktopTranscript(profile).events, finalAnswer: () => desktopTranscript(profile).finalAnswer,
    identity: { execution_location: 'native-macos', runtime_location: 'native-macos', surface: harness.surface, application: harness.app,
      extension: harness.extension, client_identity: harness.client_identity, skill_mechanism: 'native-agent-skills' } };
  } catch (error) {
    const [application, coordinator] = await Promise.allSettled([owned?.stop('desktop-start-failed'), bridge?.stop()]);
    const verified = (!owned || application.status === 'fulfilled' && application.value.cleanupVerified === true) && (!bridge || coordinator.status === 'fulfilled' && coordinator.value.cleanupVerified === true);
    const aliasCleanup = aliases.cleanup(verified); record({ type: 'desktop.profile_alias_cleanup', ...aliasCleanup });
    if (!aliasCleanup.verified) error.cleanup_error = aliasCleanup.reason;
    throw error;
  }
}
