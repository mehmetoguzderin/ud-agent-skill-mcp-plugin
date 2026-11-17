/** MIT. Bounded, cross-platform QSLM improvement loop.
 *
 * One scenario group at a time: run the same frozen requests through several
 * harness surfaces against one local quantized model, grade each episode stage
 * by stage, and write machine-readable rows for the failure analysis. Importing
 * this module never starts a model, a worker or a network listener.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { createScenario, SCENARIOS } from './scenarios.mjs';
import { projectWordingSuggestion } from './wording-oracle.mjs';
import { assertOptIn, localPaths } from './preparation.mjs';
import { MODELS, SEEDS } from './registry.mjs';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';

/** Groups follow the skill families; G1 pairs the positive validate task with its prose negative. */
export const LOOP_GROUPS = Object.freeze({
  G1: Object.freeze({ title: 'ud-validate: validate two files; decline prose "validation"', scenarios: Object.freeze(['S1', 'S7']), skill: 'ud-validate', negatives: Object.freeze(['S7']) }),
  G2: Object.freeze({ title: 'ud-edit: exact token edit then validate', scenarios: Object.freeze(['S2']), skill: 'ud-edit' }),
  G3: Object.freeze({ title: 'ud-compare: UAS/LAS against gold', scenarios: Object.freeze(['S3']), skill: 'ud-compare' }),
  G4: Object.freeze({ title: 'ud-investigate: long brief, scoped counts', scenarios: Object.freeze(['S4']), skill: 'ud-investigate' }),
  G5: Object.freeze({ title: 'ud-rules-docs: image arc + guideline preview', scenarios: Object.freeze(['S5']), skill: 'ud-rules-docs' }),
  G6: Object.freeze({ title: 'ud-release: local handover package', scenarios: Object.freeze(['S6']), skill: 'ud-release' }),
});

/** Harness surfaces. Each mirrors how a class of native clients exposes the plugin. */
export const LOOP_HARNESSES = Object.freeze({
  // Qwen Code / Claude Code style for large servers: all 104 MCP tools registered but deferred;
  // the prompt carries their names, and tool_search / tool_call disclose schemas on demand.
  // Catalog placement follows the same hosts: current Claude Code and Qwen Code (since #4896) send the skill list as a
  // system-reminder / startup-prelude message in the conversation, next to the task, not in the system prompt.
  'mcp-all': Object.freeze({ tools: 'deferred', catalog: 'reminder', description: 'All registered MCP tools, deferred behind host tool_search/tool_call + skill loader + file reads.' }),
  // The same hosts with their documented per-server tool include list set to the skill's operations.
  'mcp-scoped': Object.freeze({ tools: 'skill', catalog: 'reminder', description: 'Host include-list limited to the group skill operations (eager within a schema-token budget, the rest deferred) + skill loader + file reads.' }),
  // mini-swe-agent / shell-first clients: one bash tool, the ud-agent CLI on PATH, skills as files.
  // The catalog stays in the system instructions, as Codex lists skills and Gemini CLI renders `# Available Agent Skills`.
  'cli-shell': Object.freeze({ tools: 'shell', catalog: 'system', description: 'Single bash tool; ud-agent CLI on PATH; skills under .agents/skills.' }),
  // Diagnostic only (not in the default set): a host that sends every full schema eagerly.
  'mcp-eager': Object.freeze({ tools: 'all', catalog: 'system', description: 'Every MCP tool schema sent eagerly (non-deferring host); measures the 104-tool envelope.', diagnostic: true }),
});
export const DEFAULT_LOOP_HARNESSES = Object.freeze(Object.keys(LOOP_HARNESSES).filter(name => !LOOP_HARNESSES[name].diagnostic));

/** Host-side deferred-tool discovery, bounded like the native clients' first-line metadata. */
export function searchDeferredTools(tools, query, limit = 5) {
  const text = String(query ?? '').trim();
  const bare = name => String(name).replace(/^mcp__ud__/, '');
  if (/^select:/i.test(text)) {
    const names = text.slice(7).split(',').map(item => bare(item.trim())).filter(Boolean);
    return { selected: tools.filter(tool => names.includes(tool.name)), matches: [] };
  }
  const exact = tools.find(tool => tool.name === bare(text));
  if (exact) return { selected: [exact], matches: [] };
  const words = text.toLowerCase().split(/[^a-z0-9]+/).filter(word => word.length > 2);
  const scored = tools.map(tool => {
    const haystack = `${tool.name.replaceAll('_', ' ')} ${(tool.description ?? '').split('\n')[0]}`.toLowerCase();
    return { tool, score: words.reduce((sum, word) => sum + (tool.name.toLowerCase().includes(word) ? 3 : 0) + (haystack.includes(word) ? 1 : 0), 0) };
  }).filter(item => item.score > 0).sort((left, right) => right.score - left.score || left.tool.name.localeCompare(right.tool.name));
  return { selected: [], matches: scored.slice(0, limit).map(item => item.tool) };
}

export const LOOP_LIMITS = Object.freeze({ maxRequests: 8, maxOutputTokens: 512, toolResultChars: 6000, context: 32_768, shellTimeoutMs: 180_000, scopedToolTokens: 8_192 });
/** Client wait for one model HTTP response. Default matches undici's 300 s headers/body timeout so MiniCPM is unchanged. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 300_000;
export function loopRequestTimeoutMs({ requestTimeoutSeconds, env = process.env } = {}) {
  const seconds = Number(requestTimeoutSeconds);
  if (Number.isFinite(seconds) && seconds > 0) return Math.floor(seconds * 1000);
  const fromEnv = Number(env.UD_LOOP_REQUEST_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return Math.floor(fromEnv);
  return DEFAULT_REQUEST_TIMEOUT_MS;
}
let activeRequestTimeoutMs = loopRequestTimeoutMs();
const read = file => JSON.parse(readFileSync(file, 'utf8'));
const now = () => Date.now();

/** Localhost JSON POST/GET with a configurable inactivity timeout (same role as undici headersTimeout + bodyTimeout). */
export function requestJson(url, { method = 'GET', body, timeoutMs = activeRequestTimeoutMs } = {}) {
  const target = new URL(url);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method,
      headers: { accept: 'application/json', ...(payload !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}) } },
      response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let value = {};
          try { value = text ? JSON.parse(text) : {}; } catch { value = {}; }
          resolve({ status: response.statusCode, value, text });
        });
      });
    request.setTimeout(timeoutMs, () => request.destroy(new Error(`REQUEST_TIMEOUT:${timeoutMs}`)));
    request.on('error', reject);
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}


export function parseList(value, allowed, label) {
  const items = String(value).split(',').map(item => item.trim()).filter(Boolean);
  if (!items.length || new Set(items).size !== items.length || items.some(item => !allowed.includes(item))) throw new Error(`Invalid ${label}: ${value}`);
  return items;
}

/** Frontmatter-only skill catalog, as native hosts advertise skills before activation. */
export function skillCatalog(installation) {
  const base = path.join(installation, 'skills');
  return readdirSync(base).sort().filter(name => existsSync(path.join(base, name, 'SKILL.md'))).map(name => {
    const text = readFileSync(path.join(base, name, 'SKILL.md'), 'utf8');
    const front = /^---\n([\s\S]*?)\n---\n/.exec(text)?.[1] ?? '';
    // Decode the YAML scalar as hosts do: a double-quoted description is a JSON-compatible string (\" -> ").
    const raw = /^description:\s*(.*?)\s*$/m.exec(front)?.[1] ?? '';
    const description = /^".*"$/.test(raw) ? JSON.parse(raw) : raw.replace(/^'(.*)'$/, '$1');
    return { name, description, body: text.slice(text.indexOf('\n---\n', 4) + 5).trim() };
  });
}

export function skillOperations(root, skill) {
  const skills = read(path.join(root, 'quality/skills.json')).skills;
  const operations = [...read(path.join(root, 'contracts/ud-interfaces.json')), ...read(path.join(root, 'contracts/environment.json'))];
  const ids = skills.find(item => item.name === skill)?.operation_ids;
  if (!ids) throw new Error(`Unknown skill: ${skill}`);
  return ids.map(id => operations.find(item => item.id === id).name);
}

/** Host-owned tools. Their wording is fixed across before/after runs. */
/** A PATH alias for a skill name: runs `ud-agent NAME ARGS…`, whose reply names the SKILL.md to read; exits 127 like an unknown command. */

/** Gemini CLI getActivateSkillDeclaration: names as an enum and in the description. */
export function activateSkillTool(skillNames = []) {
  const hint = skillNames.length ? ` (Available: ${skillNames.map(name => `'${name}'`).join(', ')})` : '';
  const name = skillNames.length ? { type: 'string', enum: [...skillNames], description: 'The name of the skill to activate.' } : { type: 'string', description: 'No skills are currently available.' };
  return { type: 'function', function: { name: 'activate_skill', description: `Activates a specialized agent skill by name${hint}. Returns the skill's instructions wrapped in \`<activated_skill>\` tags. These provide specialized guidance for the current task. Use this when you identify a task that matches a skill's description. ONLY use names exactly as they appear in the available skills list.`, parameters: { type: 'object', properties: { name }, required: ['name'] } } };
}

/** Gemini CLI activate-skill.ts execute(): the reply for a name that is not installed. */
export const unknownSkillMessage = (name, skillNames) => `Skill "${name}" not found. Available skills are: ${skillNames.join(', ')}`;

function hostTools(harness, deferring = harness === 'mcp-all', skillNames = []) {
  if (harness === 'cli-shell') return [{ type: 'function', function: { name: 'bash', description: 'Run one bash command in the workspace and return stdout/stderr.', parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } } }];
  const deferred = deferring ? [
    { type: 'function', function: { name: 'tool_search', description: 'Find deferred tools. query: words, or select:NAME to load that tool schema so it can be called directly.', parameters: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } } },
    { type: 'function', function: { name: 'tool_call', description: 'Call a deferred tool by name with its arguments object.', parameters: { type: 'object', properties: { name: { type: 'string' }, arguments: { type: 'object' } }, required: ['name', 'arguments'] } } },
  ] : [];
  return [...deferred,
    activateSkillTool(skillNames),
    { type: 'function', function: { name: 'read_file', description: 'Read a text file in the workspace.', parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } } },
    { type: 'function', function: { name: 'list_directory', description: 'List files in a workspace directory.', parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } } },
  ];
}

const declareTool = tool => ({ type: 'function', function: { name: tool.name, description: tool.description ?? '', parameters: tool.inputSchema } });
/** Rough prompt tokens of one declared tool (JSON characters / 3, conservative for schema text). */
export const declaredToolTokens = tool => Math.ceil(JSON.stringify(declareTool(tool)).length / 3);

/**
 * Which listed MCP tools a harness sends with their schemas, and which it defers behind tool_search/tool_call.
 * mcp-all defers everything; mcp-eager sends everything. mcp-scoped sends the active skill's operations, but,
 * like Claude Code's automatic tool search (MCP schemas over ~10% of the context are deferred), only up to
 * LOOP_LIMITS.scopedToolTokens: operations named in the skill body come first (in order of first mention),
 * then the rest in catalog order; each one that fits is sent, the others are deferred by name. The budget
 * depends only on schema sizes and the skill text, never on the scenario.
 */
export function splitScopedTools(harness, listed, scopedOperations = [], skillBody = '', budget = LOOP_LIMITS.scopedToolTokens) {
  if (harness === 'mcp-all') return { eager: [], deferred: listed };
  if (harness === 'mcp-eager') return { eager: listed, deferred: [] };
  const scoped = listed.filter(tool => scopedOperations.includes(tool.name));
  const mention = tool => { const found = new RegExp(`\\b${tool.name}\\b`).exec(skillBody); return found ? found.index : Infinity; };
  const ordered = scoped.map((tool, index) => ({ tool, index, at: mention(tool) })).sort((a, b) => a.at - b.at || a.index - b.index).map(row => row.tool);
  const eager = [], deferred = []; let used = 0;
  for (const tool of ordered) { const cost = declaredToolTokens(tool); if (used + cost <= budget) { eager.push(tool); used += cost; } else deferred.push(tool); }
  const keep = names => scoped.filter(tool => names.includes(tool));
  return { eager: keep(eager), deferred: keep(deferred) };
}

/**
 * Host guard for loading deferred schemas: a schema that would push the loaded tool schemas past
 * LOOP_LIMITS.scopedToolTokens is not loaded (it would crowd out the conversation in a 32k context).
 * The refusal names smaller related tools that still fit, so the agent can pick a workable one.
 */
export function loadableSchemas(selected, deferred, loadedNames = [], budget = LOOP_LIMITS.scopedToolTokens) {
  let used = deferred.filter(tool => loadedNames.includes(tool.name)).reduce((sum, tool) => sum + declaredToolTokens(tool), 0);
  const load = [], refused = [];
  for (const tool of selected) {
    const cost = declaredToolTokens(tool);
    if (loadedNames.includes(tool.name) || used + cost <= budget) { if (!loadedNames.includes(tool.name)) used += cost; load.push(tool); continue; }
    const room = budget - used;
    const related = searchDeferredTools(deferred, `${tool.name.replaceAll('_', ' ')} ${(tool.description ?? '').split('\n')[0]}`, deferred.length).matches
      .filter(other => other.name !== tool.name && declaredToolTokens(other) <= room).slice(0, 5);
    refused.push({ tool, tokens: cost, alternatives: related });
  }
  return { load, refused };
}

/** Levenshtein distance (Gemini CLI / Qwen Code rank tool-name suggestions with it). */
function levenshtein(left, right) {
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i++) {
    let previous = row[0]; row[0] = i;
    for (let j = 1; j <= right.length; j++) { const kept = row[j]; row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1)); previous = kept; }
  }
  return row[right.length];
}
/**
 * The host's reply to an undeclared tool name. MCP harnesses mirror Gemini CLI / Qwen Code (three closest registered
 * names by Levenshtein distance); the shell harness mirrors mini-swe-agent, whose only action is bash.
 */
export function unknownToolMessage(harness, name, registered, skills = []) {
  // A skill name used as a tool goes through the shell alias, whose product reply says whether the skill applies to the named files.
  if (harness === 'cli-shell' && skills.includes(name)) return `That call was not run. The only tool is bash; ${name} is a shell command here, not a tool: call bash {"command": "${name} FILE"} with the file you mean, or answer in plain text.`;
  if (harness === 'cli-shell') return 'That call was not run. The only tool is bash; call bash with one shell command, or answer in plain text.';
  // A catalog skill used as a tool name: point at the host's skill loader (as the activate_skill not-found reply does).
  if (skills.includes(name) && registered.includes('activate_skill')) return `Tool "${name}" not found in registry. "${name}" is a skill (an instructions document), not a tool. Only if the task matches its description, load it with activate_skill {"name": "${name}"}; otherwise continue without it.`;
  const closest = registered.map(item => ({ item, distance: levenshtein(name, item) })).sort((a, b) => a.distance - b.distance).slice(0, 3).map(match => `"${match.item}"`);
  return `Tool "${name}" not found in registry. Tools must use the exact names that are registered.${closest.length > 1 ? ` Did you mean one of: ${closest.join(', ')}?` : closest.length ? ` Did you mean ${closest[0]}?` : ''}`;
}

/** Where the skill catalog goes: `host` follows the harness's mirrored client; `system` is the legacy placement (runs before r5). */
export const CATALOG_LAYOUTS = Object.freeze(['host', 'system']);
export function catalogPlacement(harness, layout = 'host') {
  if (!CATALOG_LAYOUTS.includes(layout)) throw new Error(`Unknown catalog layout: ${layout}`);
  return layout === 'system' ? 'system' : LOOP_HARNESSES[harness]?.catalog ?? 'system';
}
/** Path-gated skill-load reminder for host exploration tools. .txt/report paths get a no-skill line; .conllu or a bare tool_search get a load how-to. Already-loaded episodes stay silent. */
export function skillLoadHint(harness, { pathOrCommand = '', loaded = false } = {}) {
  if (loaded) return '';
  const text = String(pathOrCommand);
  const hasConllu = /\.conllu\b/i.test(text);
  const hasNonConlluDoc = /\.(txt|md)\b/i.test(text);
  if (hasNonConlluDoc && !hasConllu) return 'This is not a CoNLL-U .conllu file, so no UD skill applies.';
  if (text.trim() && !hasConllu) return '';
  const how = harness === 'cli-shell' ? 'cat .agents/skills/NAME/SKILL.md' : 'activate_skill {"name": "NAME"}';
  return `No skill is loaded. If a listed skill's description matches this task, load it with ${how}. If the task is ordinary prose, report wording, or a non-CoNLL-U file, continue without a skill.`;
}

const MATCH_STOP = new Set('instructions document load read first never call asked when with that from those into under other than such against across about using ordinary prose report wording files file only then them this their its how conll conllu'.split(' '));
/** Content tokens from the positive clause of a skill description (before "Not for" / "Never use"). */
export function skillMatchTokens(description) {
  const positive = String(description).split(/\bNot for\b|\bNever use\b/)[0];
  return [...new Set(positive.toLowerCase().split(/[^a-z0-9]+/).filter(word => word.length >= 4 && !MATCH_STOP.has(word)))];
}
/** Skills whose positive description tokens overlap the prompt; used as a static prompt-to-skill check. */
export function skillsMatchingPrompt(prompt, catalog) {
  const hay = new Set(String(prompt).toLowerCase().split(/[^a-z0-9]+/).filter(word => word.length >= 4));
  return catalog.filter(skill => skillMatchTokens(skill.description).filter(word => hay.has(word)).length >= 3).map(skill => skill.name);
}

function anySkillOpened(events, catalog) {
  const names = catalog.map(skill => skill.name);
  return events.some(event => event.name === 'activate_skill' && names.includes(event.arguments?.name)
    || event.name === 'bash' && /SKILL\.md/.test(String(event.arguments?.command ?? ''))
    || event.name === 'read_file' && names.some(name => String(event.arguments?.path ?? '').includes(`${name}/SKILL.md`)));
}

// Codex CLI render_skills_section lists "- name: description (file: path)"; the shell harness shows the workspace-relative path it reads.
const catalogLines = (catalog, files = false) => catalog.map(skill => `- ${skill.name}: ${skill.description}${files ? ` (file: .agents/skills/${skill.name}/SKILL.md)` : ''}`).join('\n');

/** System prompt plus the first user message, with the catalog where the mirrored host puts it. */
export function initialMessages(harness, workspace, catalog, deferredNames, files, serverInstructions, prompt, layout = 'host') {
  const placement = catalogPlacement(harness, layout);
  const user = placement === 'reminder' && catalog.length ? `<system-reminder>\nAvailable skills:\n${catalogLines(catalog)}\n</system-reminder>\n\n${prompt}` : prompt;
  return [{ role: 'system', content: systemPrompt(harness, workspace, catalog, deferredNames, files, serverInstructions, placement) }, { role: 'user', content: user }];
}

export function systemPrompt(harness, workspace, catalog, deferredNames = [], files = [], serverInstructions = '', placement = 'system') {
  const skills = placement === 'system' ? `\n\nAvailable skills:\n${catalogLines(catalog, harness === 'cli-shell')}` : '';
  const deferred = harness !== 'cli-shell' && deferredNames.length ? `\n\nDeferred tools (server ud; schemas hidden until loaded with tool_search select:NAME, or call them with tool_call):\n${deferredNames.join(', ')}` : '';
  const loader = harness === 'cli-shell'
    ? `Skills are instruction files at .agents/skills/NAME/SKILL.md. Read one with cat when its description matches the request.`
    : `Call activate_skill with a skill name to load its instructions when its description matches the request.`;
  // Gemini CLI / Qwen Code send the folder structure with the environment context; mini-swe-agent does not.
  const structure = harness !== 'cli-shell' && files.length ? `\nFolder structure of ${workspace}:\n${files.map(name => `- ${name}`).join('\n')}` : '';
  // Claude Code, Qwen Code and Gemini CLI place MCP initialize instructions in the system prompt.
  const instructions = harness !== 'cli-shell' && serverInstructions ? `\n\nInstructions from MCP server ud:\n${serverInstructions}` : '';
  return `You are a local coding agent. Workspace (absolute path): ${workspace}${structure}\nWork only inside the workspace. Use tools to act; finish with a plain-text answer to the user.${skills}\n${placement === 'system' ? '' : '\n'}${loader}${instructions}${deferred}`;
}

async function freePort() {
  return new Promise((resolve, reject) => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); }); server.on('error', reject); });
}

/** Starts the repository's MiniCPM transport on the selected device. */
/** Registry model and its loop server: MiniCPM's exact NF4 server, or the diagnostic MLX CPU server. */
export function loopModel(modelId = 'minicpm') {
  const model = MODELS.find(item => item.id === modelId);
  if (!model) throw new Error(`Unknown registry model: ${modelId}`);
  return { model, server: model.id === 'minicpm' ? 'evals/local/minicpm_server.py' : 'evals/local/loop_mlx_server.py' };
}
export async function startModelServer(root, { python, modelDirectory, evidence, device = 'auto', generationSeconds = 300, toolParser = 'strict', log, modelId = 'minicpm' }) {
  const port = await freePort();
  mkdirSync(evidence, { recursive: true, mode: 0o700 }); chmodSync(evidence, 0o700);
  const child = spawn(python, [path.join(root, loopModel(modelId).server), '--model', modelDirectory, '--port', String(port), '--evidence-directory', evidence, '--device', device, '--generation-seconds', String(generationSeconds), '--tool-parser', toolParser],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, TOKENIZERS_PARALLELISM: 'false', HF_HUB_OFFLINE: '1' } });
  const sink = chunk => { if (log) writeFileSync(log, chunk, { flag: 'a' }); };
  child.stdout.on('data', sink); child.stderr.on('data', sink);
  const url = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 600; attempt++) {
    if (child.exitCode !== null) throw new Error(`MODEL_SERVER_EXITED:${child.exitCode}`);
    try { const response = await fetch(`${url}/health`); if (response.ok) return { url, model: modelDirectory, child, stop: async () => { child.kill('SIGTERM'); await new Promise(done => child.exitCode !== null ? done() : child.once('exit', done)); } }; } catch { /* starting */ }
    await new Promise(done => setTimeout(done, 1000));
  }
  child.kill('SIGKILL'); throw new Error('MODEL_SERVER_START_TIMEOUT');
}

async function chat(server, body) {
  const started = now();
  const response = await requestJson(`${server.url}/v1/chat/completions`, { method: 'POST', body });
  return { status: response.status, value: response.value, elapsed_ms: now() - started };
}
async function countTokens(server, body) {
  const response = await requestJson(`${server.url}/v1/chat/input_tokens`, { method: 'POST', body: { ...body, max_tokens: 1 } });
  return response.status >= 200 && response.status < 300 ? response.value.input_tokens : null;
}

function insideWorkspace(workspace, relative) {
  const target = path.resolve(workspace, String(relative ?? '.'));
  if (target !== workspace && !target.startsWith(workspace + path.sep)) throw new Error(`Path must be inside the workspace ${workspace}; use a relative path such as report.txt or "." for its root.`);
  if (!existsSync(target)) throw new Error(`No such file or directory: ${target}. Paths are relative to the workspace ${workspace}; "." is its root.`);
  return target;
}
const clip = (text, limit = LOOP_LIMITS.toolResultChars) => text.length > limit ? text.slice(0, limit) + `\n[truncated ${text.length - limit} chars]` : text;

/** One episode: fresh fixture, warm runtime, one user request, bounded agent loop. */
export async function runLoopEpisode({ root, installation, server, mcp, harness, scenarioId, seed, directory, home, catalog, scopedOperations, scopedSkill, sampling, catalogLayout = 'host' }) {
  // Users open short project folders; a deep evidence path would test path copying, not the plugin.
  mkdirSync(directory, { recursive: true });
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'udq-')), taskRoot = path.join(scratch, 'treebank');
  try { return await episodeIn({ root, installation, server, mcp, harness, scenarioId, seed, taskRoot, home, catalog, scopedOperations, scopedSkill, sampling, catalogLayout }); }
  finally { rmSync(scratch, { recursive: true, force: true }); }
}

async function episodeIn({ installation, server, mcp, harness, scenarioId, seed, taskRoot, home, catalog, scopedOperations, scopedSkill, sampling, catalogLayout }) {
  const scenario = await createScenario(scenarioId, taskRoot, { extendedTokens: 2_000 });
  const before = captureWorkspace(taskRoot);
  const entry = path.join(installation, 'dist/packages/coordinator/src/entry.js');
  const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'), XDG_CACHE_HOME: path.join(home, '.cache'), XDG_DATA_HOME: path.join(home, '.local/share') };
  // Deterministic warm fixture, labeled; never counted as model work.
  const warm = spawnSync(process.execPath, [entry, 'setup', '--working-tree', taskRoot, '--engine', 'docker', '--required-tools', 'validation_report'], { env, encoding: 'utf8', timeout: 600_000 });
  const warmReady = (() => { try { return JSON.parse(warm.stdout).result?.ready === true; } catch { return false; } })();
  if (harness === 'cli-shell') {
    for (const skill of catalog) { const target = path.join(taskRoot, '.agents/skills', skill.name); mkdirSync(target, { recursive: true }); writeFileSync(path.join(target, 'SKILL.md'), readFileSync(path.join(installation, 'skills', skill.name, 'SKILL.md'))); }
  }
  const fixtureBefore = captureWorkspace(taskRoot);
  let client;
  const events = [], requests = [];
  const declare = declareTool;
  let tools = hostTools(harness, harness === 'mcp-all', catalog.map(skill => skill.name)), deferred = [], serverInstructions = '';
  const loaded = new Set();
  if (harness !== 'cli-shell') {
    client = await mcp.connect(taskRoot, env);
    const listed = (await client.listTools()).tools;
    serverInstructions = client.getInstructions?.() ?? '';
    const split = splitScopedTools(harness, listed, scopedOperations, catalog.find(skill => skill.name === scopedSkill)?.body ?? '');
    deferred = split.deferred;
    tools = [...hostTools(harness, deferred.length > 0, catalog.map(skill => skill.name)), ...split.eager.map(declare)];
  }
  const offered = () => [...tools, ...deferred.filter(tool => loaded.has(tool.name)).map(declare)];
  const binDirectory = path.join(home, 'bin');
  if (!existsSync(path.join(binDirectory, 'ud-agent'))) { mkdirSync(binDirectory, { recursive: true }); writeFileSync(path.join(binDirectory, 'ud-agent'), `#!/bin/sh\nexec "${process.execPath}" "${entry}" "$@"\n`, { mode: 0o755 }); }
  // Skill names typed as shell commands reach the CLI's own guidance (`ud-agent NAME`) instead of bash's bare "command not found".
  // The product writes these opt-in aliases itself (`ud-agent shell-aliases --bin DIR`); the harness only invokes it.
  if (harness === 'cli-shell') { const aliases = spawnSync(process.execPath, [entry, 'shell-aliases', '--bin', binDirectory], { encoding: 'utf8', timeout: 30_000 }); if (aliases.status !== 0) throw new Error(`shell-aliases failed: ${aliases.stderr}`); }
  const messages = initialMessages(harness, taskRoot, catalog, deferred.map(tool => tool.name), readdirSync(taskRoot).filter(name => !name.startsWith('.')).sort(), serverInstructions, scenario.prompt, catalogLayout);
  let finalAnswer = null, stop = 'request_limit', formatErrors = 0;
  const started = now();
  try {
    for (let index = 0; index < LOOP_LIMITS.maxRequests; index++) {
      const body = { model: server.model, messages, tools: offered(), seed: seed + index, max_tokens: LOOP_LIMITS.maxOutputTokens, ...sampling };
      const promptTokens = await countTokens(server, body);
      const response = await chat(server, body);
      const choice = response.value.choices?.[0];
      requests.push({ index, status: response.status, prompt_tokens: response.value.usage?.prompt_tokens ?? promptTokens, completion_tokens: response.value.usage?.completion_tokens ?? 0, elapsed_ms: response.elapsed_ms, finish_reason: choice?.finish_reason ?? null, error: response.value.error?.message ?? null });
      if (response.status !== 200 || !choice) { stop = response.value.error?.message?.split(':')[0] ?? `HTTP_${response.status}`; break; }
      const message = choice.message;
      messages.push({ role: 'assistant', content: message.content ?? '', ...(message.tool_calls?.length ? { tool_calls: message.tool_calls } : {}) });
      if (!message.tool_calls?.length) {
        // The transport returns an unparsable call as text so the harness applies its own bounded recovery
        // (mini-swe-agent's format-error turn). Every harness gets the same single generic retry; it is counted.
        if (/<tool_call|<function=/.test(message.content ?? '') && formatErrors < 1) {
          formatErrors++; events.push({ type: 'format_error', request: index, name: 'format_error', arguments: {}, ok: false, output: '' });
          messages.push({ role: 'user', content: harness === 'cli-shell' ? 'Format error: that call was not run. The only tool is bash; call bash with one shell command, or answer in plain text.' : 'Format error: that tool call could not be parsed and was not run. Retry with one well-formed tool call, or answer in plain text.' });
          continue;
        }
        finalAnswer = message.content ?? ''; stop = choice.finish_reason === 'length' ? 'answer_truncated' : 'final_answer'; break;
      }
      const images = [];
      for (const call of message.tool_calls) {
        let args = {}, output, ok = true, structured, name = call.function.name, via;
        try { args = JSON.parse(call.function.arguments || '{}'); } catch { ok = false; output = 'Invalid JSON arguments.'; }
        if (ok && name === 'tool_call') {
          // The host unwraps a deferred call; the event records the operation actually invoked.
          via = 'tool_call'; name = String(args.name ?? '').replace(/^mcp__ud__/, '');
          let inner = args.arguments ?? {};
          if (typeof inner === 'string') try { inner = JSON.parse(inner); } catch { ok = false; output = 'tool_call arguments must be a JSON object.'; }
          args = inner;
          // A host tool wrapped in tool_call runs as itself (the wrapper only adds indirection); other unknown names get the did-you-mean reply.
          if (ok && !deferred.some(tool => tool.name === name) && !(name !== 'tool_call' && offered().some(tool => tool.function.name === name))) { ok = false; output = name ? unknownToolMessage(harness, name, [...offered().map(tool => tool.function.name), ...deferred.map(tool => tool.name)], catalog.map(skill => skill.name)) : 'tool_call needs {"name": "TOOL", "arguments": {...}}; find TOOL with tool_search {"query": "WORDS"}.'; }
        } else if (ok && !offered().some(tool => tool.function.name === name)) {
          // Hosts only run tools present in the request. A deferred tool must be loaded (or wrapped in tool_call) first.
          ok = false;
          output = deferred.some(tool => tool.name === name)
            ? `${name} is a deferred tool whose schema is not loaded yet. Load it with tool_search {"query": "select:${name}"}, then call it with arguments matching its schema.`
            : unknownToolMessage(harness, name, [...offered().map(tool => tool.function.name), ...deferred.map(tool => tool.name).filter(tool => !loaded.has(tool))], catalog.map(skill => skill.name));
        }
        if (ok) try {
          if (name === 'tool_search' && !(typeof args.query === 'string' && args.query.trim())) {
            ok = false; output = 'tool_search needs a query: tool_search {"query": "WORDS"} (for example {"query": "validate conllu"}), or {"query": "select:NAME"} to load one tool.';
          } else if (name === 'tool_search') {
            const found = searchDeferredTools(deferred, args.query);
            const { load, refused } = loadableSchemas(found.selected, deferred, [...loaded]);
            for (const tool of load) loaded.add(tool.name);
            const refusals = refused.map(item => `${item.tool.name} was not loaded: its schema (~${item.tokens} tokens) is too large for this context.${item.alternatives.length ? ` Smaller related tools: ${item.alternatives.map(tool => `${tool.name} (${(tool.description ?? '').split('\n')[0].slice(0, 80)})`).join('; ')}.` : ''}`).join('\n');
            output = found.selected.length
              ? [load.length ? load.map(tool => `Loaded ${tool.name}: ${tool.description}\nParameters: ${JSON.stringify(tool.inputSchema)}`).join('\n\n') + '\nCall it directly now.' : '', refusals].filter(Boolean).join('\n\n')
              : found.matches.length ? found.matches.map(tool => `${tool.name}: ${(tool.description ?? '').split('\n')[0].slice(0, 160)}`).join('\n') + '\nLoad one with select:NAME.' : 'No deferred tools matched.';
          } else if (name === 'activate_skill') {
            const skill = catalog.find(item => item.name === args.name); if (!skill) throw new Error(unknownSkillMessage(args.name, catalog.map(item => item.name)));
            output = `<activated_skill name="${skill.name}">\n<instructions>\n${skill.body}\n</instructions>\n</activated_skill>`;
          } else if (name === 'read_file' && IMAGE_TYPES[path.extname(String(args.path)).toLowerCase()]) {
            // Claude Code / Qwen Code read tools return images as image content; chat-completions tool
            // messages carry text only, so the host attaches the pixels in the next user turn.
            const bytes = readFileSync(insideWorkspace(taskRoot, args.path));
            images.push({ name: String(args.path), url: `data:${IMAGE_TYPES[path.extname(String(args.path)).toLowerCase()]};base64,${bytes.toString('base64')}` });
            output = `Image ${args.path} (${bytes.length} bytes) is attached in the next message.`;
          } else if (name === 'read_file' || name === 'list_directory') output = readOrList(name, insideWorkspace(taskRoot, args.path), String(args.path));
          else if (name === 'bash') {
            const result = spawnSync('bash', ['-c', String(args.command)], { cwd: taskRoot, env: { ...env, PATH: `${binDirectory}${path.delimiter}${env.PATH}`, TMPDIR: path.join(home, 'tmp') }, encoding: 'utf8', timeout: LOOP_LIMITS.shellTimeoutMs, maxBuffer: 8 * 1024 * 1024 });
            mkdirSync(path.join(home, 'tmp'), { recursive: true });
            ok = result.status === 0; output = `exit ${result.status}\n${result.stdout ?? ''}${result.stderr ? `\n[stderr]\n${result.stderr}` : ''}`;
          } else {
            const result = await client.callTool({ name, arguments: args }, undefined, { timeout: 300_000 });
            structured = result.structuredContent; ok = !result.isError && structured?.execution?.status === 'completed';
            output = (result.content ?? []).filter(part => part.type === 'text').map(part => part.text).join('\n');
            if (result.isError && via === 'tool_call' && !loaded.has(name)) output += `\nLoad the schema of ${name} with tool_search {"query": "select:${name}"} before retrying.`;
          }
        } catch (error) { ok = false; output = `Error: ${error.message ?? error}`; }
        if (['tool_search', 'read_file', 'list_directory', 'bash'].includes(name)) {
          const hint = skillLoadHint(harness, { pathOrCommand: name === 'bash' ? String(args.command ?? '') : name === 'tool_search' ? '' : String(args.path ?? ''), loaded: anySkillOpened(events, catalog) });
          if (hint) output = `${output}\n\n${hint}`;
        }
        events.push({ type: 'tool_call', request: index, name, ...(via ? { via } : {}), arguments: args, ok, structured: structured ? { operation: structured.operation, execution: structured.execution, scope: structured.scope, result: structured.result && { passed: structured.result.passed, incidents: structured.result.incidents, ...(structured.result.validation ? { validation: structured.result.validation } : {}) } } : undefined, output_chars: String(output).length, output: clip(String(output), 2000) });
        messages.push({ role: 'tool', tool_call_id: call.id, content: clip(String(output)) });
      }
      if (images.length) messages.push({ role: 'user', content: [...images.map(image => ({ type: 'image_url', image_url: { url: image.url } })), { type: 'text', text: `Attached: ${images.map(image => image.name).join(', ')}` }] });
    }
  } finally { await client?.close?.(); }
  const after = captureWorkspace(taskRoot);
  return { scenario_id: scenarioId, harness, seed, warm_fixture: { qualification: 'deterministic-warm-runtime-fixture-not-model-work', ready: warmReady },
    tools_offered: offered().length, deferred_tools: deferred.length, loaded_tools: [...loaded], stop, final_answer: finalAnswer, requests, events, elapsed_ms: now() - started,
    inputs_unchanged: JSON.stringify(fixtureBefore.files.filter(file => before.files.some(item => item.path === file.path))) === JSON.stringify(after.files.filter(file => before.files.some(item => item.path === file.path))),
    new_files: after.files.filter(file => !fixtureBefore.files.some(item => item.path === file.path)).map(file => file.path),
    // Declared output files (not directories): their final digests, for exact-result grading.
    outputs: Object.fromEntries((scenario.outputs ?? []).filter(name => !name.endsWith('/')).map(name => [name, after.files.find(file => file.path === name)?.sha256 ?? null])),
    // New text files under declared output directories (bounded), for content grading.
    output_texts: Object.fromEntries(after.files.filter(file => (scenario.outputs ?? []).some(name => name.endsWith('/') && file.path.startsWith(name)) && !fixtureBefore.files.some(item => item.path === file.path))
      .slice(0, 20).map(file => { try { const bytes = readFileSync(path.join(taskRoot, file.path)); return [file.path, bytes.length <= 65_536 ? bytes.toString('utf8') : null]; } catch { return [file.path, null]; } })) };
}

/** Host file tools; a file given to list_directory or a folder given to read_file names the other tool (Gemini CLI style). */
export function readOrList(name, target, shown) {
  const directory = existsSync(target) && statSync(target).isDirectory();
  if (name === 'read_file' && directory) throw new Error(`Path is a directory, not a file: ${shown}. List it with list_directory {"path": "${shown}"}.`);
  if (name === 'list_directory' && existsSync(target) && !directory) throw new Error(`Path is not a directory: ${shown}. It is a file; read it with read_file {"path": "${shown}"}.`);
  return name === 'read_file' ? readFileSync(target, 'utf8') : readdirSync(target).join('\n');
}

// Any product operation (or a skill name used as a tool) is UD activation; only host tools and discovery are not.
const HOST_TOOLS = new Set(['tool_search', 'tool_call', 'activate_skill', 'read_file', 'list_directory', 'bash', 'format_error']);
const ud = name => /^ud-/.test(name) || !HOST_TOOLS.has(name);
const IMAGE_TYPES = Object.freeze({ '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' });
/** Successful plugin operations: MCP tools (direct or via tool_call) or the ud-agent CLI. */
function udOperations(episode) {
  return episode.events.filter(event => event.ok && (event.name !== 'bash' ? ud(event.name) && !/^ud-/.test(event.name) : /(?:^|[;&|]\s*)ud-agent\s+(?:call\s+[a-z_]+|validate)\b/.test(String(event.arguments?.command))));
}
function skillLoaded(episode, skill) {
  return episode.events.some(event => event.name === 'activate_skill' && event.arguments?.name === skill || event.name === 'bash' && String(event.arguments?.command).includes(`${skill}/SKILL.md`) || event.name === 'read_file' && String(event.arguments?.path).includes(`${skill}/SKILL.md`));
}
function validationCalls(episode) {
  // Both CLI routes reach the same operation: `call validation_report` and the `validate` shorthand.
  return episode.events.filter(event => event.name === 'validation_report' || event.name === 'bash' && /ud-agent\s+(?:call\s+validation_report|validate)\b/.test(String(event.arguments?.command)));
}

// ud-edit write operations (the skill's mutating subset); reads such as token_get are not edits.
const EDIT_OPERATION = /^(?:treebank_edit|tree_edit|token_edit|tree_metadata_edit|enhanced_graph_edit|tree_(?:add|replace|remove|copy|move|id_set|text_set|comment_set|comment_remove|reindex|split)|token_(?:add|remove|form_set|lemma_set|upos_set|xpos_set|features_replace|feature_set|feature_remove|misc_replace|misc_set|misc_remove|split)|basic_dependency_(?:set|label_set)|enhanced_(?:edge_add|edge_remove|dependencies_replace)|multiword_token_(?:add|edit|remove)|empty_node_(?:add|edit|remove)|plan_apply|tokens_merge|trees_merge)$/;
function editCalls(episode) {
  return episode.events.filter(event => EDIT_OPERATION.test(event.name) || event.name === 'bash' && /ud-agent\s+call\s+([a-z_]+)/.test(String(event.arguments?.command)) && EDIT_OPERATION.test(/ud-agent\s+call\s+([a-z_]+)/.exec(String(event.arguments.command))[1]));
}
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

/** Stages that measure skill uptake rather than the user-visible outcome. */
export const ADVISORY_STAGES = Object.freeze(['skill_activated']);

/** Ordered stage checks. The first false stage is the episode's failure locus. */
export function gradeLoopEpisode(episode) {
  const answer = episode.final_answer ?? '', stages = [];
  const stage = (name, value) => stages.push({ name, passed: value === true });
  const contextOk = !episode.requests.some(item => item.error?.startsWith('CONTEXT_ENVELOPE_EXCEEDED'));
  stage('context_fits', contextOk);
  // Rejected XML, or call markup leaked into the answer (often a skill name used as a function).
  stage('tool_call_wellformed', !episode.requests.some(item => /^TOOL_|TOOL_ARGUMENTS|TOOL_NAME/.test(item.error ?? '')) && !/<tool_call|<function=/.test(answer));
  if (episode.scenario_id === 'S1') {
    const calls = validationCalls(episode), good = calls.filter(event => event.ok);
    const scoped = good.some(event => {
      const files = event.name === 'bash' ? null : event.structured?.scope?.file_paths ?? event.arguments?.file_paths;
      return files ? ['a.conllu', 'b.conllu'].every(file => files.some(item => String(item).endsWith(file))) : /a\.conllu/.test(event.output) && /b\.conllu/.test(event.output);
    });
    stage('skill_activated', skillLoaded(episode, 'ud-validate'));
    stage('validation_tool_called', calls.length > 0);
    stage('validation_succeeded', good.length > 0);
    stage('both_files_in_one_scope', scoped);
    stage('final_answer', answer.trim().length > 0);
    stage('head_error_reported', /b\.conllu/.test(answer) && /\b9\b/.test(answer) && /head/i.test(answer));
    stage('duplicate_id_reported', /duplicat|non-unique|repeated|same sent_id/i.test(answer) && /a\.conllu/.test(answer));
    stage('no_false_validity_claim', !/all (?:files|checks) (?:are valid|passed)|no (?:annotation )?errors/i.test(answer));
    stage('inputs_unchanged', episode.inputs_unchanged && episode.new_files.every(file => file.startsWith('.agents/')));
  } else if (episode.scenario_id === 'S7') {
    const original = SCENARIOS.find(item => item.id === 'S7').files['report.txt'].toString('utf8');
    const wording = projectWordingSuggestion(answer, original);
    stage('no_ud_activation', !episode.events.some(event => event.name === 'activate_skill' || ud(event.name) || event.name === 'bash' && /ud-agent|SKILL\.md/.test(String(event.arguments?.command))));
    stage('final_answer', answer.trim().length > 0);
    stage('rewrite_offered', wording.changed === true || answer.length > 200 && /40/.test(answer) && /55/.test(answer));
    stage('facts_preserved', /40/.test(answer) && /55/.test(answer) && /Friday/.test(answer) && wording.facts !== false);
    stage('inputs_unchanged', episode.inputs_unchanged);
  } else if (episode.scenario_id === 'S2') {
    const edits = editCalls(episode), applied = edits.filter(event => event.ok), last = applied.at(-1);
    const expected = digest(SCENARIOS.find(item => item.id === 'S2').expected.bytes);
    stage('skill_activated', skillLoaded(episode, 'ud-edit'));
    stage('edit_tool_called', edits.length > 0);
    stage('edit_succeeded', applied.length > 0);
    // Exactly the requested FORM, LEMMA and text changes, every other byte preserved.
    stage('exact_candidate', episode.outputs?.['edit.conllu'] === expected);
    // Either a later validation call, or the edit's own candidate validation (edit_options.validation_options),
    // which the server runs on the exact candidate bytes before applying them.
    const selfValidated = last?.structured?.result?.validation?.status === 'completed' && last.structured.result.validation.passed === true;
    stage('validated_after_edit', last !== undefined && (selfValidated || validationCalls(episode).some(event => event.ok && episode.events.indexOf(event) > episode.events.indexOf(last))));
    stage('final_answer', answer.trim().length > 0);
    stage('completion_reported', /Swallows/.test(answer) && /swallow\b/.test(answer) && /applied|completed|saved|updated|changed/i.test(answer) && /validat/i.test(answer));
    stage('no_false_no_effect_claim', !/nothing (?:was )?changed|no changes (?:were )?(?:made|applied)/i.test(answer));
  } else if (episode.scenario_id === 'S3') {
    stage('skill_activated', skillLoaded(episode, 'ud-compare'));
    stage('ud_operation_succeeded', udOperations(episode).length > 0);
    stage('final_answer', answer.trim().length > 0);
    stage('uas_reported', /UAS.{0,40}(?:80\s*%|0\.8\b|4\s*\/\s*5)/is.test(answer));
    stage('las_reported', /LAS.{0,40}(?:60\s*%|0\.6\b|3\s*\/\s*5)/is.test(answer));
    stage('denominator_reported', /5\s*(?:eligible |ordinary[- ]?)?tokens|denominator.{0,20}5/i.test(answer));
    stage('mismatches_explained', /compare-1/.test(answer) && /head/i.test(answer) && /nsubj|subject/i.test(answer) && /\bobj\b|object/i.test(answer));
    stage('inputs_unchanged', episode.inputs_unchanged && episode.new_files.every(file => file.startsWith('.agents/')));
  } else if (episode.scenario_id === 'S4') {
    stage('skill_activated', skillLoaded(episode, 'ud-investigate'));
    stage('ud_operation_succeeded', udOperations(episode).length > 0);
    stage('final_answer', answer.trim().length > 0);
    stage('ratio_reported', /2\s*(?:\/|of|out of)\s*3|66\.\d*\s*%|67\s*%/i.test(answer));
    stage('examples_reported', /news-1/.test(answer) && /news-2/.test(answer));
    stage('denominator_explained', /3.{0,30}(?:subjects|nsubj|relations)|denominator.{0,20}3/is.test(answer));
    stage('scope_explained', /exclud.{0,30}fiction|only.{0,30}news/is.test(answer));
    stage('inputs_unchanged', episode.inputs_unchanged && episode.new_files.every(file => file.startsWith('.agents/')));
  } else if (episode.scenario_id === 'S5') {
    const previews = Object.entries(episode.output_texts ?? {}).filter(([name, text]) => name.startsWith('preview/') && /\.(?:svg|html)$/.test(name) && typeof text === 'string');
    stage('skill_activated', skillLoaded(episode, 'ud-rules-docs'));
    stage('image_viewed', episode.events.some(event => event.ok && (event.name === 'read_file' && /diagram\.png$/.test(String(event.arguments?.path)) || !HOST_TOOLS.has(event.name) && JSON.stringify(event.arguments ?? {}).includes('diagram.png'))));
    stage('final_answer', answer.trim().length > 0);
    stage('arc_identified', /\bobj\b|object/i.test(answer) && /chased/.test(answer) && /mice/.test(answer));
    stage('preview_written', previews.some(([, text]) => /<svg\b|<html\b/i.test(text) && /Cats/.test(text) && /chased/.test(text) && /mice/.test(text)));
    stage('inputs_unchanged', episode.inputs_unchanged && episode.new_files.every(file => file.startsWith('.agents/') || file.startsWith('preview/')));
  } else if (episode.scenario_id === 'S6') {
    stage('skill_activated', skillLoaded(episode, 'ud-release'));
    stage('ud_operation_succeeded', udOperations(episode).length > 0);
    stage('handover_written', episode.new_files.some(file => file.startsWith('handover/')));
    stage('final_answer', answer.trim().length > 0);
    stage('contents_reported', /treebank\.conllu/.test(answer) && /README\.md/.test(answer) && /LICENSE/.test(answer));
    stage('hash_reported', /\b[a-f0-9]{64}\b/.test(answer));
    stage('unassessed_reported', /(?:not|unassessed|unverified|not yet).{0,60}(?:official|publication|registry)|(?:official|publication|registry).{0,60}(?:not|unassessed|unverified)/is.test(answer));
    stage('no_official_acceptance_claim', !/officially accepted|published successfully|uploaded successfully/i.test(answer));
    stage('inputs_unchanged', episode.inputs_unchanged && episode.new_files.every(file => file.startsWith('.agents/') || file.startsWith('handover/')));
  } else throw new Error(`Loop grading for ${episode.scenario_id} is not defined yet; extend gradeLoopEpisode with the next group.`);
  const first = stages.find(item => !item.passed)?.name ?? null;
  // Strict pass requires reading the skill; task_passed reports the outcome alone (fewest turns), never as qualification.
  return { passed: first === null, task_passed: stages.every(item => item.passed || ADVISORY_STAGES.includes(item.name)), first_failure: first, stages };
}

/** Runs one group across harnesses and seeds. Model residency is outermost. */
export async function runLoopGroup(root, { optIn, group, harnesses = [...DEFAULT_LOOP_HARNESSES], seeds = [...SEEDS], scenarios, label, output, installation, python, modelDirectory, device = 'auto', generationSeconds = 300, catalogLayout = 'host', toolParser = 'lenient', modelId = 'minicpm', requestTimeoutSeconds, onProgress = () => {} }) {
  activeRequestTimeoutMs = loopRequestTimeoutMs({ requestTimeoutSeconds });
  assertOptIn({ optIn }); catalogPlacement('cli-shell', catalogLayout);
  const selected = LOOP_GROUPS[group]; if (!selected) throw new Error(`Unknown loop group: ${group}`);
  const scenarioIds = scenarios ?? [...selected.scenarios];
  if (scenarioIds.some(id => !selected.scenarios.includes(id))) throw new Error(`Invalid --scenario for ${group}: use ${selected.scenarios.join(', ')}.`);
  const { model } = loopModel(modelId);
  if (!label || !/^[\w.-]+$/.test(label)) throw new Error('A run label (letters, digits, ._-) is required.');
  const base = path.join(localPaths(root).base, 'loop');
  const directory = path.resolve(output ?? path.join(base, 'runs', `${group}-${label}`));
  if (existsSync(path.join(directory, 'run.json'))) throw new Error('Loop run directory already holds a run; choose a new label.');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const sampling = Object.fromEntries(Object.entries(model.sampling).filter(([name]) => ['temperature', 'top_p', 'top_k', 'repetition_penalty'].includes(name)));
  const catalog = skillCatalog(installation), scopedOperations = skillOperations(root, selected.skill);
  const { Client } = await import('@modelcontextprotocol/client');
  const { StdioClientTransport } = await import('@modelcontextprotocol/client/stdio');
  const entry = path.join(installation, 'dist/packages/coordinator/src/entry.js');
  const mcp = { connect: async (workspace, env) => { const client = new Client({ name: 'ud-qslm-loop', version: '1' }); await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, 'mcp', '--allow-root', workspace], cwd: workspace, env, stderr: 'pipe' })); return client; } };
  const home = path.join(directory, 'home'); mkdirSync(home, { recursive: true, mode: 0o700 });
  const run = { schema_version: 1, kind: 'qslm-improvement-loop', group, title: selected.title, label, model: { id: model.id, artifact: model.artifact, directory: modelDirectory, device, sampling },
    harnesses, seeds, scenarios: scenarioIds, limits: LOOP_LIMITS, request_timeout_ms: activeRequestTimeoutMs, tool_parser: toolParser, catalog_layout: Object.fromEntries(harnesses.map(harness => [harness, catalogPlacement(harness, catalogLayout)])), skills: catalog.map(({ name, description, body }) => ({ name, description_chars: description.length, body_chars: body.length })),
    platform: `${process.platform}-${process.arch}`, started_at: new Date().toISOString(), qualification: 'focused-diagnostic-not-starter-qualification', rows: [] };
  const server = await startModelServer(root, { python, modelDirectory, evidence: path.join(directory, 'generations'), device, generationSeconds, toolParser, modelId, log: path.join(directory, 'model-server.log') });
  try {
    for (const seed of seeds) for (const harness of harnesses) for (const scenarioId of scenarioIds) {
      const id = `${scenarioId}-${harness}-seed-${seed}`, file = path.join(directory, 'episodes', `${id}.json`);
      if (existsSync(file)) { run.rows.push(read(file).row); continue; }
      mkdirSync(path.dirname(file), { recursive: true });
      let episode;
      try { episode = await runLoopEpisode({ root, installation, server, mcp, harness, scenarioId, seed, directory: path.join(directory, 'work', id), home, catalog, scopedOperations, scopedSkill: selected.skill, sampling, catalogLayout }); }
      catch (error) { episode = { scenario_id: scenarioId, harness, seed, stop: 'harness_error', error: String(error?.stack ?? error), final_answer: null, requests: [], events: [], inputs_unchanged: false, new_files: [] }; }
      const grade = gradeLoopEpisode(episode);
      const row = { id, group, label, scenario_id: scenarioId, harness, seed, grader_version: LOOP_GRADER_VERSION, passed: grade.passed, task_passed: grade.task_passed, first_failure: grade.first_failure, stages: grade.stages, stop: episode.stop,
        requests: episode.requests.length, tool_calls: episode.events.length, prompt_tokens: episode.requests.map(item => item.prompt_tokens), completion_tokens: episode.requests.reduce((sum, item) => sum + (item.completion_tokens ?? 0), 0), elapsed_ms: episode.elapsed_ms ?? 0,
        tool_sequence: episode.events.map(event => `${event.name}${event.ok ? '' : '!'}`) };
      writeFileSync(file, JSON.stringify({ row, episode }, null, 2) + '\n');
      run.rows.push(row);
      onProgress(`${label} ${id}: ${grade.passed ? 'PASS' : `fail@${grade.first_failure}`} stop=${episode.stop} requests=${row.requests} tools=${row.tool_sequence.join(',') || '-'}`);
    }
  } finally { await server.stop(); }
  run.finished_at = new Date().toISOString();
  run.summary = { episodes: run.rows.length, passed: run.rows.filter(row => row.passed).length, task_passed: run.rows.filter(row => row.task_passed).length };
  writeFileSync(path.join(directory, 'run.json'), JSON.stringify(run, null, 2) + '\n');
  return { directory, summary: run.summary };
}

/** Re-applies the current grader to recorded episodes; the first grade stays in original_grade. */
export const LOOP_GRADER_VERSION = 5;
export function regradeLoopRun(directory) {
  const runFile = path.join(directory, 'run.json'), run = read(runFile);
  for (const row of run.rows) {
    const file = path.join(directory, 'episodes', `${row.id}.json`), value = read(file), grade = gradeLoopEpisode(value.episode);
    const original = value.row.original_grade ?? { passed: value.row.passed, first_failure: value.row.first_failure, stages: value.row.stages };
    Object.assign(value.row, { passed: grade.passed, task_passed: grade.task_passed, first_failure: grade.first_failure, stages: grade.stages, grader_version: LOOP_GRADER_VERSION, original_grade: original });
    Object.assign(row, value.row);
    writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
  }
  run.summary = { episodes: run.rows.length, passed: run.rows.filter(row => row.passed).length, task_passed: run.rows.filter(row => row.task_passed).length, grader_version: LOOP_GRADER_VERSION };
  writeFileSync(runFile, JSON.stringify(run, null, 2) + '\n');
  return run.summary;
}

/** Heatmaps and statistics are rendered by loop_analysis.py with the model environment's Python. */
export function analyzeLoop(root, { runs, output, python }) {
  if (!runs?.length || !output) throw new Error('loop-analyze requires --runs DIR[,DIR] and --output DIR.');
  for (const run of runs) regradeLoopRun(run);
  mkdirSync(output, { recursive: true });
  const result = spawnSync(python, [path.join(root, 'evals/local/loop_analysis.py'), '--output', output, ...runs], { encoding: 'utf8', timeout: 300_000 });
  if (result.status !== 0) throw new Error(`loop analysis failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

/** First model request of an episode, built exactly as runLoopEpisode does (no model, no warm runtime). */
export async function firstLoopRequest(root, { installation, group, harness, scenarioId, mcp, catalogLayout = 'host' }) {
  const selected = LOOP_GROUPS[group], catalog = skillCatalog(installation), scopedOperations = skillOperations(root, selected.skill);
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'udq-')), taskRoot = path.join(scratch, 'treebank');
  try {
    const scenario = await createScenario(scenarioId, taskRoot, { extendedTokens: 2_000 });
    if (harness === 'cli-shell') for (const skill of catalog) { const target = path.join(taskRoot, '.agents/skills', skill.name); mkdirSync(target, { recursive: true }); writeFileSync(path.join(target, 'SKILL.md'), readFileSync(path.join(installation, 'skills', skill.name, 'SKILL.md'))); }
    let tools = hostTools(harness, harness === 'mcp-all', catalog.map(skill => skill.name)), deferred = [], serverInstructions = '';
    if (harness !== 'cli-shell') {
      const client = await mcp.connect(taskRoot, { ...process.env });
      try {
        const listed = (await client.listTools()).tools; serverInstructions = client.getInstructions?.() ?? '';
        const split = splitScopedTools(harness, listed, scopedOperations, catalog.find(skill => skill.name === selected.skill)?.body ?? '');
        deferred = split.deferred; tools = [...hostTools(harness, deferred.length > 0, catalog.map(skill => skill.name)), ...split.eager.map(declareTool)];
      }
      finally { await client.close(); }
    }
    const messages = initialMessages(harness, taskRoot, catalog, deferred.map(tool => tool.name), readdirSync(taskRoot).filter(name => !name.startsWith('.')).sort(), serverInstructions, scenario.prompt, catalogLayout);
    return { harness, scenario_id: scenarioId, workspace: taskRoot, skills: catalog.map(skill => ({ name: skill.name, description: skill.description })), body: { messages, tools, max_tokens: LOOP_LIMITS.maxOutputTokens } };
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

/** Assistant prefixes that ended in a skill name used as a function, from recorded first requests. */
export function skillCallPrefixes(runs, skills) {
  const found = [];
  for (const directory of runs) {
    const run = read(path.join(directory, 'run.json'));
    for (const row of run.rows) {
      const first = read(path.join(directory, 'episodes', `${row.id}.json`)).episode.requests[0];
      if (!first || !existsSync(path.join(directory, 'generations'))) continue;
      for (const name of readdirSync(path.join(directory, 'generations'))) {
        const generation = read(path.join(directory, 'generations', name));
        if (generation.seed !== row.seed || generation.prompt_tokens !== first.prompt_tokens || generation.parser_status !== 'rejected') continue;
        const match = /<function=([^>\s]+)>/.exec(generation.text ?? '');
        if (match && skills.includes(match[1])) found.push({ run: path.basename(directory), id: row.id, harness: row.harness, scenario_id: row.scenario_id, prefix: generation.text.slice(0, match.index + '<function='.length), emitted: match[1] });
      }
    }
  }
  return found;
}

/** Reference first action for a positive scenario: load the group skill through the harness's own loader. */
export function uptakeReference(harness, skill, workspace) {
  // The shell route accepts the relative and the absolute skill path (the grader matches either).
  return harness === 'cli-shell'
    ? { prefix: '<tool_call>\n<function=bash>\n<parameter=command>\n', sequences: [`cat .agents/skills/${skill}/SKILL.md\n`, ...(workspace ? [`cat ${workspace}/.agents/skills/${skill}/SKILL.md\n`] : [])] }
    : { prefix: '<tool_call>\n<function=', sequences: ['activate_skill>'] };
}

/** The decision after the skill was loaded (teacher-forced): does the loaded text lead to its operation?
 * References are the routes the skill itself advertises: the operation (MCP), its deferred loader
 * (mcp-all), or the `ud-agent` commands quoted in the skill body (shell). */
export function afterSkillCase(request, skill, alternatives, installation) {
  const operation = /ud-agent describe ([a-z_]+)/.exec(skill.description)?.[1] || /ud-agent describe ([a-z_]+)/.exec(skill.body)?.[1];
  const shell = request.harness === 'cli-shell';
  const call = shell ? { name: 'bash', arguments: { command: `cat .agents/skills/${skill.name}/SKILL.md` } } : { name: 'activate_skill', arguments: { name: skill.name } };
  const result = shell ? `exit 0\n${readFileSync(path.join(installation, 'skills', skill.name, 'SKILL.md'), 'utf8')}` : skill.body;
  const messages = [...request.body.messages, { role: 'assistant', content: '', tool_calls: [{ id: 'call_0', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.arguments) } }] }, { role: 'tool', tool_call_id: 'call_0', content: result }];
  const commands = [...new Set([...skill.body.matchAll(/`(ud-agent (?:validate|call|describe) [^`]+)`/g)].map(match => `${match[1]}\n`))].filter(text => !/[A-Z_]{4,}/.test(text.replace(operation ?? '', '')));
  const references = shell ? commands : [request.harness === 'mcp-all' ? 'tool_search>' : `${operation}>`];
  const others = shell ? alternatives : request.body.tools.map(tool => `${tool.function.name}>`).filter(text => !references.includes(text) && text !== 'activate_skill>' && !(request.harness === 'mcp-all' && text === 'tool_call>'));
  return { ...request, label: `${request.harness}/${request.scenario_id}@after-skill`, objective: 'uptake-after-skill', body: { ...request.body, messages }, prefix: shell ? '<tool_call>\n<function=bash>\n<parameter=command>\n' : '<tool_call>\n<function=',
    prefix_source: 'teacher-forced-skill-load', valid_sequences: references, invalid_sequences: others };
}

/** First actions of recorded episodes that did not load the skill, as continuations after the uptake prefix. */
export function observedFirstActions(runs, { harness, scenarioId, skill }) {
  const found = new Map();
  for (const directory of runs) {
    const run = read(path.join(directory, 'run.json'));
    for (const row of run.rows.filter(item => item.harness === harness && item.scenario_id === scenarioId)) {
      const episode = read(path.join(directory, 'episodes', `${row.id}.json`)).episode;
      if (skillLoaded(episode, skill)) continue;
      const first = episode.events.find(event => event.type === 'tool_call');
      if (!first) continue;
      const text = harness === 'cli-shell' ? (first.name === 'bash' ? `${String(first.arguments?.command ?? '').split('\n')[0]}\n` : null) : `${first.via ?? first.name}>`;
      if (text && text.trim() !== '>') found.set(text, (found.get(text) ?? 0) + 1);
    }
  }
  return [...found.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])).map(([text, count]) => ({ text, count }));
}

/** Opt-in interpretability: attention and gradient attribution at the tool-call decision (loop_interpret.py).
 * objective 'skill-call' (default): valid tool vs skill name used as a function, every scenario.
 * objective 'uptake': positive scenarios score loading the skill against the observed first actions. */
export async function interpretLoop(root, { optIn, group = 'G1', installation, python, modelDirectory, runs = [], output, candidates, objective = 'skill-call', catalogLayout = 'host', onProgress = () => {} }) {
  assertOptIn({ optIn });
  if (!['skill-call', 'uptake'].includes(objective)) throw new Error(`Invalid --objective: ${objective}`);
  if (!installation || !python || !modelDirectory || !output) throw new Error('loop-interpret requires --installation, --python, --model-dir and --output.');
  const { Client } = await import('@modelcontextprotocol/client');
  const { StdioClientTransport } = await import('@modelcontextprotocol/client/stdio');
  const entry = path.join(installation, 'dist/packages/coordinator/src/entry.js');
  const mcp = { connect: async (workspace, env) => { const client = new Client({ name: 'ud-qslm-interpret', version: '1' }); await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, 'mcp', '--allow-root', workspace], cwd: workspace, env, stderr: 'pipe' })); return client; } };
  mkdirSync(output, { recursive: true });
  const requests = [];
  for (const harness of DEFAULT_LOOP_HARNESSES) for (const scenarioId of LOOP_GROUPS[group].scenarios) { onProgress(`request ${harness}/${scenarioId}`); requests.push(await firstLoopRequest(root, { installation, group, harness, scenarioId, mcp, catalogLayout })); }
  const skills = requests[0].skills.map(skill => skill.name);
  const observed = skillCallPrefixes(runs, skills);
  const fallback = '<tool_call>\n<function=';
  const catalog = skillCatalog(installation);
  let cases = requests.map(request => {
    const prefixes = observed.filter(item => item.harness === request.harness && item.scenario_id === request.scenario_id);
    const valid = request.harness === 'cli-shell' ? ['bash'] : ['activate_skill', 'read_file', ...(request.harness === 'mcp-all' ? ['tool_search'] : []), ...request.body.tools.map(tool => tool.function.name).filter(name => !['activate_skill', 'read_file', 'list_directory', 'tool_search', 'tool_call'].includes(name)).slice(0, 3)];
    if (objective === 'uptake' && !(LOOP_GROUPS[group].negatives ?? []).includes(request.scenario_id)) {
      const reference = uptakeReference(request.harness, LOOP_GROUPS[group].skill, request.workspace);
      // Episode workspaces are fresh temporary folders; map recorded paths onto this request's workspace.
      const relocate = text => text.replace(/\/[^\s'"]*\/udq-[A-Za-z0-9]+\/treebank/g, request.workspace);
      const actions = observedFirstActions(runs, { harness: request.harness, scenarioId: request.scenario_id, skill: LOOP_GROUPS[group].skill })
        .map(item => ({ ...item, text: relocate(item.text) })).filter(item => !reference.sequences.includes(item.text));
      // MCP: every other offered tool name competes (a log-softmax over the tool choice); shell: observed commands.
      const alternatives = request.harness === 'cli-shell'
        ? [...new Set((actions.length ? actions.map(item => item.text) : ['ls -la\n', 'cat *.conllu\n']))].slice(0, 6)
        : [...new Set([...actions.map(item => item.text), ...request.body.tools.map(tool => `${tool.function.name}>`)])].filter(text => !reference.sequences.includes(text));
      const first = { ...request, objective, prefix: reference.prefix, prefix_source: actions.length ? 'observed-first-actions' : 'canonical', valid_sequences: reference.sequences, invalid_sequences: alternatives, observed_first_actions: actions };
      return [first, afterSkillCase(request, catalog.find(skill => skill.name === LOOP_GROUPS[group].skill), alternatives, installation)];
    }
    return { ...request, objective: 'skill-call', prefix: prefixes[0]?.prefix ?? fallback, prefix_source: prefixes[0] ? `${prefixes[0].run}/${prefixes[0].id}` : 'canonical', observed_skill_calls: prefixes.length, valid, invalid: skills };
  });
  cases = cases.flat();
  writeFileSync(path.join(output, 'interpret-cases.json'), JSON.stringify({ group, installation, cases, observed }, null, 2) + '\n');
  const script = path.join(root, 'evals/local/loop_interpret.py'), common = ['--model', modelDirectory, '--cases', path.join(output, 'interpret-cases.json'), '--output', output];
  // One process per gradient case bounds peak memory; the final pass reuses the cached analyses.
  for (const item of cases.filter((value, index) => cases.findIndex(other => other.harness === value.harness && other.scenario_id === value.scenario_id) === index)) {
    // Gradient passes use bfloat16: float32 backprop over a 3.4k-token prompt exceeds 11 GB.
    // Candidate scoring (forward only) stays float32 so rankings are reproducible.
    const only = spawnSync(python, [script, ...common, '--only', `${item.harness}/${item.scenario_id}`, '--case-only', '--dtype', 'bfloat16'], { stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8', timeout: 3 * 3600_000 });
    if (only.status !== 0) throw new Error(`loop interpretation failed for ${item.harness}/${item.scenario_id}`);
  }
  const result = spawnSync(python, [script, ...common, '--cached-only', ...(candidates ? ['--candidates', candidates] : [])], { stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8', timeout: 6 * 3600_000, maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) throw new Error('loop interpretation failed');
  return JSON.parse(result.stdout);
}

/** Diagnostic installation: the current build plus the native worker build for this host's Linux platform. */
export async function prepareLoopInstallation(root, { optIn, onProgress = () => {} } = {}) {
  assertOptIn({ optIn });
  const { installSnapshot } = await import('./campaign.mjs');
  const { sourceReceipt } = await import('../../scripts/release/candidate.mjs');
  const source = sourceReceipt(root).sha256;
  const directory = path.join(localPaths(root).base, 'loop', `installation-${source.slice(0, 16)}`);
  if (existsSync(path.join(directory, 'LOOP-INSTALLATION.json'))) return read(path.join(directory, 'LOOP-INSTALLATION.json'));
  onProgress(`Installing diagnostic candidate into ${directory}`);
  const inventory = await installSnapshot(root, directory);
  const receipt = { installation: directory, source_sha256: source, inventory_sha256: inventory.sha256, files: inventory.files.length, qualification: 'diagnostic-source-build-not-release-acceptance' };
  writeFileSync(path.join(directory, 'LOOP-INSTALLATION.json'), JSON.stringify(receipt, null, 2) + '\n');
  return receipt;
}
