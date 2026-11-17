/** MIT. Native client configuration only; each client retains its own agent loop. */
import { mkdirSync, readFileSync, writeFileSync, copyFileSync, symlinkSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { parse, stringify } from 'yaml';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { CLIENT_LOCK } from './native-clients.mjs';

export const NATIVE_RECIPES = Object.freeze({
  'codex-cli': { connect: 'codex', protocol: 'responses', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true },
  'claude-code': { connect: 'claude-code', protocol: 'messages', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true, qualification: 'non-Claude-provider-interoperability-experimental' },
  'gemini-cli': { connect: 'gemini', protocol: 'gemini', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true },
  'qwen-code': { connect: 'qwen', protocol: 'chat', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true },
  'mini-swe-agent': { connect: 'mini-swe-agent', protocol: 'chat', skillMechanism: 'registered-shell-workflow-catalog', events: 'trajectory', canRun: true, requiresContainer: true },
  'hermes-agent': { connect: 'hermes', protocol: 'chat', skillMechanism: 'native-user-skill-discovery', events: 'oneshot', canRun: true },
  'deepseek-harness': { connect: 'deepseek', protocol: 'chat', skillMechanism: 'native-plugin-skills', events: 'native-session', canRun: true },
  'grok-build': { connect: 'grok', protocol: 'chat', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true,
    reason: 'Pinned Grok Build 1.0.77 automatic titles use the selected local model, but initial-title disabling, attributable native title completion, and compatibility with the single-request budget remain unverified. Fresh native conformance is required.' },
  pi: { connect: 'pi', protocol: 'chat', skillMechanism: 'native-progressive-skill-discovery', events: 'jsonl', canRun: true, qualification: 'MCP-registration-requires-native-extension-conformance' },
  openclaw: { connect: 'openclaw', protocol: 'chat', skillMechanism: 'native-progressive-skill-discovery', events: 'json', canRun: true },
  'kimi-code': { connect: 'kimi', protocol: 'chat', skillMechanism: 'native-project-discovery', events: 'jsonl', canRun: true },
});

export function nativeArguments(id, { model, endpoint, taskRoot, output, prompt, image, config, session, isolatedContainer = false }) {
  if (!NATIVE_RECIPES[id]) throw new Error('NATIVE_RECIPE_UNSUPPORTED');
  if (id === 'codex-cli') return ['exec', '--skip-git-repo-check', '--ephemeral', '--json', '--sandbox', isolatedContainer ? 'danger-full-access' : 'workspace-write', '-C', taskRoot, '-o', output,
    '-c', 'model_provider="ud_local_eval"', '-c', 'model_providers.ud_local_eval.name="UD local evaluation"', '-c', `model_providers.ud_local_eval.base_url=${JSON.stringify(endpoint + '/v1')}`,
    '-c', 'model_providers.ud_local_eval.wire_api="responses"', '-c', 'model_reasoning_summary="none"', '-c', 'model_providers.ud_local_eval.requires_openai_auth=false', '-c', 'model_providers.ud_local_eval.supports_websockets=false', '-m', model, ...(image ? ['--image', image] : []), '--', prompt];
  if (image) throw new Error('NATIVE_IMAGE_ATTACHMENT_UNVERIFIED');
  if (id === 'claude-code') return ['--print', '--verbose', '--output-format', 'stream-json', '--permission-mode', 'bypassPermissions', '--max-turns', '10', '--model', model, prompt];
  if (id === 'gemini-cli') return ['--prompt', prompt, '--output-format', 'stream-json', '--approval-mode', 'yolo', '--skip-trust', '--model', model];
  if (id === 'qwen-code') return ['--prompt', prompt, '--output-format', 'stream-json', '--approval-mode', 'yolo', '--auth-type', 'openai', '--openai-base-url', endpoint + '/v1', '--openai-api-key', 'local-eval-only', '--advisor', 'off', '--max-session-turns', '10', '--max-tool-calls', '12', '--max-wall-time', '90s', '--model', model];
  if (id === 'mini-swe-agent') return ['--task', prompt, '--model', `openai/${model}`, '--config', config, '--agent-class', 'default', '--environment-class', 'local', '--output', output, '--exit-immediately', '--yolo', '--cost-limit', '0'];
  if (id === 'hermes-agent') return ['chat', '--query', prompt, '--model', model, '--provider', 'custom', '--quiet', '--cli', '--yolo', '--max-turns', '10'];
  if (id === 'deepseek-harness') return ['--profile', 'headless', '--json', '--permission-mode', 'workspace-write', '--approval-policy', 'never', prompt];
  if (id === 'grok-build') return ['--single', prompt, '--output-format', 'streaming-json', '--always-approve', '--max-turns', '10', '--no-subagents', '--disable-web-search', '--no-plan', '--model', model];
  if (id === 'pi') return ['--print', '--mode', 'json', '--offline', '--thinking', 'off', '--provider', 'ud-local-eval', '--model', model, '--session', output + '.session.jsonl', prompt];
  if (id === 'openclaw') return ['agent', '--local', '--agent', 'main', '--session-id', session, '--message', prompt, '--json', '--thinking', 'off', '--timeout', '85'];
  return ['--output-format', 'stream-json', '--model', 'ud-local-eval', '--prompt', prompt];
}

function write(file, value) {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
}

/** Metadata/path catalog only. No skill is preselected and no full instructions
 * are injected. mini-swe has no native skill loader; this distinction is reported. */
export function shellSkillCatalog(installation, taskRoot) {
  const names = ['ud-validate', 'ud-edit', 'ud-compare', 'ud-investigate', 'ud-rules-docs', 'ud-release'];
  return 'Installed optional workflow skills (read a skill only when relevant):\n' + names.map(name => {
    const text = readFileSync(path.join(installation, 'skills', name, 'SKILL.md'), 'utf8');
    const metadata = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
    if (!metadata) throw new Error('SKILL_METADATA_INVALID');
    const parsed = parse(metadata[1]);
    return `- ${parsed.name}: ${parsed.description} File: ${path.join(taskRoot, '.agents/skills', name, 'SKILL.md')}`;
  }).join('\n') + '\nThe installed ud-agent executable exposes the coordinator CLI; use ud-agent --help for its interface.\n';
}

export function configureNativeProfile(id, { profile, taskRoot, installation, model, endpoint, env, skillsEnabled, clientDirectory, output, modelContextCapacity, studyVariant }) {
  if (studyVariant !== undefined && !['current', 'task-neutral', 'task-neutral-actionable'].includes(studyVariant)) throw new Error('STUDY_NATIVE_VARIANT_UNKNOWN');
  const protocol = NATIVE_RECIPES[id]?.protocol;
  if (!protocol) throw new Error('NATIVE_RECIPE_UNSUPPORTED');
  const settings = { model, endpoint, contextWindow: 16384, maxTokens: 512, reasoning: false };
  const result = { env: { ...env, OPENAI_BASE_URL: endpoint + '/v1', OPENAI_API_KEY: 'local-eval-only', OPENAI_MODEL: model,
    ANTHROPIC_BASE_URL: endpoint, ANTHROPIC_AUTH_TOKEN: 'local-eval-only', ANTHROPIC_MODEL: model,
    GOOGLE_GEMINI_BASE_URL: endpoint, GEMINI_API_KEY: 'local-eval-only', GEMINI_MODEL: model,
    CODEX_HOME: path.join(profile, '.codex'), CLAUDE_CONFIG_DIR: path.join(profile, '.claude'),
    DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    QWEN_CODE_DISABLE_AUTO_UPDATE: '1', MSWEA_CONFIGURED: 'true', MSWEA_COST_TRACKING: 'ignore_errors' } };
  if (id === 'codex-cli') write(path.join(profile, '.codex/config.toml'), `web_search = "disabled"\n[features]\nmulti_agent = false\n[projects.${JSON.stringify(taskRoot)}]\ntrust_level = "trusted"\n`);
  if (id === 'qwen-code') write(path.join(profile, '.qwen/settings.json'), { $version: 4, security: { auth: { selectedType: 'openai' } },
    model: { name: model, maxSessionTurns: 10 }, telemetry: { enabled: false },
    memory: { enableManagedAutoMemory: false, enableManagedAutoDream: false, enableAutoSkill: false, enableTeamMemory: false, enableTeamMemorySync: false },
    modelProviders: { openai: [{ id: model, baseUrl: endpoint + '/v1', envKey: 'OPENAI_API_KEY', generationConfig: { maxRetries: 0, timeout: 85_000, samplingParams: { max_tokens: 512 } } }] } });
  if (id === 'gemini-cli') write(path.join(profile, '.gemini/settings.json'), { security: { auth: { selectedType: 'gemini-api-key' } }, telemetry: { enabled: false } });
  if (id === 'mini-swe-agent') {
    if (!clientDirectory) throw new Error('MINISWE_PINNED_CONFIG_REQUIRED');
    const source = path.join(clientDirectory, 'venv/lib/python3.12/site-packages/minisweagent/config/mini.yaml');
    const config = parse(readFileSync(source, 'utf8'));
    // Supported task framing for ordinary workflows: the pinned repair template
    // otherwise asks read-only comparisons to create a reproduction and edit
    // source. Preserve the native system, tools, loop and submission marker.
    // Explicit historical study "current" conditions retain the old framing.
    if (studyVariant !== 'current') config.agent.instance_template = '{{task}}\n\nUse the bash tool to perform the requested task. Each command runs in a fresh subshell. Read relevant installed instructions and use the available interfaces. Preserve the requested scope and file permissions. When finished, submit your factual final answer by running a separate command that prints COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT followed by that answer. After submission you cannot continue.\n';
    // The native inclusive threshold counts the initial format failure: two
    // consecutive failures permit one correction, while step_limit caps calls.
    config.agent = { ...config.agent, step_limit: 10, cost_limit: 0, wall_time_limit_seconds: 90, max_consecutive_format_errors: 2, output_path: output };
    if (skillsEnabled) config.agent.system_template += '\n' + shellSkillCatalog(installation, taskRoot);
    config.environment = { ...config.environment, cwd: taskRoot, timeout: 25 };
    config.model = { ...config.model, model_name: `openai/${model}`, cost_tracking: 'ignore_errors',
      model_kwargs: { api_base: endpoint + '/v1', api_key: 'local-eval-only', max_tokens: 512, timeout: 85, num_retries: 0, drop_params: false } };
    // PyYAML reads the client's YAML 1.1 schema: quote strings such as "off"
    // so serialization cannot silently turn a native environment value boolean.
    result.config = path.join(profile, 'mini.yaml'); write(result.config, stringify(config, { defaultStringType: 'QUOTE_DOUBLE' }));
  }
  if (id === 'hermes-agent') {
    if (!Number.isSafeInteger(modelContextCapacity) || modelContextCapacity < 64_000) throw new Error('HERMES_NATIVE_MINIMUM_CONTEXT_CAPACITY_64000');
    result.env.HERMES_HOME = path.join(profile, '.hermes');
    result.env.HERMES_DISABLE_LAZY_INSTALLS = '1'; result.env.HERMES_DEFER_AGENT_STARTUP = '1';
    result.env.UD_LOCAL_HERMES_OBSERVATIONS = path.join(profile, 'native-hermes.jsonl');
    const observer = path.join(profile, '.hermes/plugins/ud-local-observer');
    write(path.join(observer, 'plugin.yaml'), stringify({ name: 'ud-local-observer', version: '1.0.0', description: 'Passive local evaluation lifecycle observer', hooks: ['post_tool_call', 'post_llm_call'] }));
    write(path.join(observer, '__init__.py'), readFileSync(new URL('./hermes-observer.py', import.meta.url), 'utf8'));
    // The native auto vision router probes unrelated server metadata and then
    // considers other providers. Bind its supported direct endpoint override
    // to the same admitted model, without asserting an image capability.
    write(path.join(profile, '.hermes/config.yaml'), stringify({ model: { default: model, provider: 'custom', base_url: endpoint + '/v1', context_length: modelContextCapacity }, auxiliary: { vision: { provider: 'custom', model, base_url: endpoint + '/v1', api_key: 'local-eval-only' } }, plugins: { enabled: ['ud-local-observer'] }, max_turns: 10, mcp_discovery_timeout: 10, compression: { enabled: false } }));
  }
  if (id === 'deepseek-harness') {
    result.env.DSH_HOME = path.join(profile, '.dsh');
    write(path.join(profile, '.dsh/cordis.patch.yml'), stringify([
      { id: 'llm-pi-ai', config: { providers: { 'ud-local-eval': { api: 'openai-completions', baseURL: endpoint + '/v1', apiKeyEnv: 'OPENAI_API_KEY', retryPolicy: { mode: 'normal', maxRetries: 0 }, models: [{ id: model, name: model, contextWindow: 32768, maxTokens: 512, reasoningEfforts: false }] } } } },
      { id: 'agent-default-model', config: { provider: 'ud-local-eval', model } }, { id: 'session-title-llm', disabled: true },
    ]));
    if (clientDirectory) symlinkSync(path.join(clientDirectory, 'node_modules'), path.join(profile, '.dsh/node_modules'));
  }
  if (id === 'grok-build') {
    result.env.GROK_HOME = path.join(profile, '.grok');
    result.env.GROK_MODELS_BASE_URL = endpoint + '/v1'; result.env.XAI_API_KEY = 'local-eval-only';
    // Grok resolves model-list and inference credentials separately; its native
    // daemon does not inherit the global key. The documented per-model key
    // keeps the isolated local route independent of interactive login state.
    // The pinned client resolves its initial session title independently of
    // models.default. Keep that native request on the same admitted model;
    // ordinary gateway request and tool accounting still applies.
    write(path.join(profile, '.grok/config.toml'), stringifyToml({ models: { default: model, session_summary: model }, model: { [model]: {
      model, base_url: endpoint + '/v1', api_backend: 'chat_completions', api_key: 'local-eval-only', max_completion_tokens: 512,
      ...(Number.isSafeInteger(modelContextCapacity) && modelContextCapacity > 0 ? { context_window: modelContextCapacity } : {}),
    } } }));
  }
  if (id === 'pi') write(path.join(profile, '.pi/agent/models.json'), { providers: { 'ud-local-eval': { api: 'openai-completions', baseUrl: endpoint + '/v1', apiKey: 'local-eval-only', models: [{ id: model, name: model, reasoning: false, input: ['text', 'image'], contextWindow: 32768, maxTokens: 512, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } });
  if (id === 'openclaw') {
    result.env.OPENCLAW_STATE_DIR = path.join(profile, '.openclaw');
    // Use the granted working tree without creating first-run persona/bootstrap
    // files there. Existing project context and native skill discovery remain.
    write(path.join(profile, '.openclaw/openclaw.json'), { models: { mode: 'replace', providers: { 'ud-local-eval': { baseUrl: endpoint + '/v1', apiKey: 'local-eval-only', api: 'openai-completions', models: [{ id: model, name: model, contextWindow: 32768, maxTokens: 512, reasoning: false, input: ['text', 'image'] }] } } }, agents: { defaults: { workspace: taskRoot, skipBootstrap: true, model: { primary: `ud-local-eval/${model}` } } } });
  }
  if (id === 'kimi-code') {
    result.env.KIMI_CODE_HOME = path.join(profile, '.kimi-code');
    result.env.KIMI_CODE_TRUST_WORKSPACE = '1';
    write(path.join(profile, '.kimi-code/config.toml'), `default_model = "ud-local-eval"\n[thinking]\nenabled = false\n[loop_control]\nmax_steps_per_turn = 10\nmax_attempts_per_step = 2\n[providers.ud-local-eval]\ntype = "openai"\nbase_url = ${JSON.stringify(endpoint + '/v1')}\napi_key = "local-eval-only"\n[models.ud-local-eval]\nprovider = "ud-local-eval"\nmodel = ${JSON.stringify(model)}\nmax_context_size = 32768\n`);
  }
  return result;
}

/** Native configuration variants are frozen before scoring. DeepSeek's shipped
 * headless profile consumes the same registered server as its web profile. */
export function finalizeNativeProfile(id, { profile, taskRoot, skillsEnabled }) {
  if (id === 'qwen-code') {
    // The pinned Qwen 0.27.2 settings loader writes missing $version metadata
    // on startup. Finish that mechanical configuration before the task snapshot.
    const file = path.join(taskRoot, '.qwen/settings.json');
    write(file, { ...JSON.parse(readFileSync(file, 'utf8')), $version: 4 });
  }
  if (id === 'mini-swe-agent' && !skillsEnabled) unlinkSync(path.join(taskRoot, '.ud-agent/WORKFLOW.md'));
  if (id === 'deepseek-harness') {
    const target = path.join(profile, '.dsh/profiles/headless/cordis.patch.yml');
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    copyFileSync(path.join(profile, '.dsh/profiles/web/cordis.patch.yml'), target);
  }
  if (id === 'pi') {
    const target = path.join(taskRoot, '.pi/extensions/ud-mcp.js');
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 }); copyFileSync(new URL('./pi-mcp-extension.mjs', import.meta.url), target);
  }
  if (id === 'gemini-cli') {
    const file = path.join(profile, '.gemini/settings.json');
    write(file, { ...JSON.parse(readFileSync(file, 'utf8')), mcpServers: JSON.parse(readFileSync(path.join(taskRoot, '.gemini/settings.json'), 'utf8')).mcpServers });
  }
  if (id === 'codex-cli') {
    const file = path.join(profile, '.codex/config.toml');
    const config = parseToml(readFileSync(file, 'utf8') + '\n' + readFileSync(path.join(taskRoot, '.codex/config.toml'), 'utf8'));
    // Codex 0.167.1 otherwise admits optional MCP servers after a one-second
    // grace; fast sessions can finish without ever exposing the UD catalog.
    // Require the registered live connection instead of certifying that state.
    if (!config.mcp_servers?.ud) throw new Error('CODEX_UD_REGISTRATION_MISSING');
    Object.assign(config.mcp_servers.ud, { required: true, startup_timeout_sec: 20, startup_readiness: 'connection' });
    write(file, stringifyToml(config));
  }
}

export const nativeClientPin = id => CLIENT_LOCK.clients.find(client => client.id === id);
