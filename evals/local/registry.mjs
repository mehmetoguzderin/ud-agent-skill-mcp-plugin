/** Frozen starter coverage. Importing this module never installs or invokes a model. */
import { readFileSync } from 'node:fs';
import path from 'node:path';

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export const SEEDS = freeze([17, 23, 47]);
export const MODELS = freeze([
  { id: 'minicpm', artifact: 'openbmb/MiniCPM-V-4.7-1B-int4', runtime: 'exact-artifact-feasibility-required', quantization: 'bitsandbytes-nf4',
    sampling: { temperature: 0.7, top_p: 0.95, top_k: 100, repetition_penalty: 1.03, presence_penalty: 0 },
    defaults_to_freeze: ['min_p', 'thinking', 'seed_behavior'], substitution_allowed: false },
  { id: 'lfm3', artifact: 'LiquidAI/LFM3-VL-2B-MLX-5bit', runtime: 'mlx-vlm', minimum_runtime_version: '0.7.11', quantization: 'mlx-5bit',
    sampling: { temperature: 0.1, top_p: 1, top_k: 50, repetition_penalty: 1.1 },
    defaults_to_freeze: ['presence_penalty', 'min_p', 'thinking', 'seed_behavior'], substitution_allowed: false },
  { id: 'bonsai', artifact: 'prism-ml/Ternary-Bonsai-2-2B-mlx-2bit', runtime: 'mlx-vlm', minimum_runtime_version: '0.7.8', quantization: 'mlx-2bit',
    sampling: { temperature: 0.7, top_p: 0.8, top_k: 20, min_p: 0, repetition_penalty: 1, presence_penalty: 1.5, presence_context_size: 64 },
    defaults_to_freeze: ['thinking', 'seed_behavior'], substitution_allowed: false },
]);

function harness(id, name, scenario, location, protocol, variants) {
  return { id, name, scenario_id: scenario, execution_location: location, provider_protocol: protocol,
    native_execution: 'unverified', variants: variants.map(([variant, scope, mechanism]) => ({ id: variant, scope, mechanism, evidence_status: 'untested' })) };
}

/** These are distinct native surfaces, even when their registration is shared. */
export const HARNESSES = freeze([
  harness('chatgpt-desktop', 'ChatGPT Desktop', 'S1', 'native-macos', 'capability-probe-required', [['plugin', 'user', 'native-plugin'], ['direct-mcp', 'user', 'mcp-and-skills']]),
  harness('codex-desktop', 'Codex Desktop', 'S1', 'native-macos', 'responses', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills'], ['global', 'user', 'mcp-and-skills']]),
  harness('gemini-cli', 'Gemini CLI', 'S1', 'arm64-container', 'gemini', [['extension', 'user', 'native-extension'], ['project', 'project', 'mcp-and-skills']]),
  harness('codex-cli', 'Codex CLI', 'S2', 'arm64-container', 'responses', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills'], ['global', 'user', 'mcp-and-skills']]),
  harness('claude-code', 'Claude Code', 'S2', 'arm64-container', 'anthropic-messages-experimental', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills']]),
  harness('qwen-code', 'Qwen Code', 'S2', 'arm64-container', 'openai-chat-completions', [['extension', 'user', 'native-extension'], ['project', 'project', 'mcp-and-skills']]),
  harness('mini-swe-agent', 'mini-swe-agent', 'S3', 'arm64-container', 'provider-adapter', [['project-cli', 'project', 'native-shell-and-skills']]),
  harness('hermes-agent', 'Hermes Agent', 'S3', 'arm64-container', 'provider-adapter', [['local', 'user', 'mcp-and-skills'], ['gateway', 'gateway', 'mcp-and-skills']]),
  harness('deepseek-harness', 'DeepSeek Harness', 'S3', 'arm64-container', 'capability-probe-required', [['native-mcp-plugin', 'project', 'native-plugin-and-skills']]),
  harness('grok-build', 'Grok Build', 'S4', 'arm64-container', 'capability-probe-required', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills']]),
  harness('pi', 'Pi', 'S4', 'arm64-container', 'provider-adapter', [['project', 'project', 'mcp-and-skills']]),
  harness('openclaw', 'OpenClaw', 'S4', 'arm64-container', 'provider-adapter', [['bundle', 'user', 'native-plugin'], ['direct', 'user', 'mcp-and-skills'], ['acp', 'remote', 'native-runtime-projection']]),
  harness('claude-desktop', 'Claude Desktop', 'S5', 'native-macos', 'anthropic-messages-capability-probe-required', [['mcpb-and-skills', 'user', 'extension-and-separate-skills'], ['direct-and-skills', 'user', 'mcp-and-separate-skills']]),
  harness('cursor', 'Cursor', 'S5', 'native-macos', 'backend-routing-capability-probe-required', [['project', 'project', 'mcp-and-skills'], ['global', 'user', 'mcp-and-skills']]),
  harness('vscode-copilot', 'VS Code GitHub Copilot', 'S5', 'native-macos', 'custom-provider-capability-probe-required', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills'], ['copilot-global', 'user', 'mcp-and-skills'], ['legacy-project', 'project', 'legacy-mcp-and-skills']]),
  harness('codex-ide', 'Codex IDE extension', 'S6', 'native-macos', 'responses', [['shared-mcp', 'user', 'mcp-and-skills'], ['project', 'project', 'mcp-and-skills']]),
  harness('claude-cowork', 'Claude Cowork', 'S6', 'native-macos', 'capability-probe-required', [['plugin', 'user', 'native-plugin']]),
  harness('kimi-code', 'Kimi Code', 'S6', 'arm64-container', 'provider-adapter', [['plugin', 'user', 'native-plugin'], ['project', 'project', 'mcp-and-skills']]),
]);

const CONTROL_CELLS = new Set(['codex-cli/S2', 'mini-swe-agent/S3']);

function row(snapshot, model, seed, host, scenario, skillsEnabled) {
  const cell = `${model.id}/${host.id}/${scenario}/seed-${seed}/${skillsEnabled ? 'skills' : 'skills-disabled'}`;
  const id = `${snapshot}/${cell}`;
  return { id, row_id: id, cell_id: cell, snapshot, model_id: model.id, model_artifact: model.artifact,
    harness_id: host.id, scenario_id: scenario, seed, skills_enabled: skillsEnabled,
    kind: skillsEnabled ? 'starter' : 'skill-disabled-control' };
}

/** Model residency is outermost; each seed visits every harness before the next seed. */
export function buildMatrix({ controls = false, snapshot = 'baseline' } = {}) {
  if (typeof controls !== 'boolean' || !['baseline', 'candidate'].includes(snapshot)) throw new Error('Invalid local evaluation matrix options.');
  const rows = [];
  for (const model of MODELS) for (const seed of SEEDS) for (const host of HARNESSES) {
    rows.push(row(snapshot, model, seed, host, host.scenario_id, true));
    if (host.id === 'qwen-code') rows.push(row(snapshot, model, seed, host, 'S7', true));
    if (controls && snapshot === 'baseline' && CONTROL_CELLS.has(`${host.id}/${host.scenario_id}`)) rows.push(row(snapshot, model, seed, host, host.scenario_id, false));
  }
  return rows;
}

/** Predetermined selection, deliberately retaining a selected failed or blocked row. */
export function referenceRows({ snapshot = 'baseline' } = {}) {
  const matrix = buildMatrix({ snapshot });
  return ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7'].map((scenario, index) => {
    const host = scenario === 'S7' ? 'qwen-code' : HARNESSES.find(item => item.scenario_id === scenario).id;
    return matrix.find(item => item.scenario_id === scenario && item.harness_id === host && item.model_id === MODELS[index % MODELS.length].id && item.seed === SEEDS[0]);
  });
}

/** Catalog mapping is structural evidence only; it never implies model execution. */
export function operationCoverage(root) {
  const read = name => JSON.parse(readFileSync(path.join(root, name), 'utf8'));
  const operations = [...read('contracts/ud-interfaces.json'), ...read('contracts/environment.json')];
  const skills = read('quality/skills.json').skills;
  const ids = new Set(), names = new Set();
  return operations.map(operation => {
    if (ids.has(operation.id) || names.has(operation.name)) throw new Error('Duplicate public operation in local evaluation coverage.');
    ids.add(operation.id); names.add(operation.name);
    const input = `contracts/schema/operations/${operation.name}.input.schema.json`;
    const output = operation.output_schema ?? `contracts/schema/results/${operation.name}.schema.json`;
    if (read(input).title !== operation.name || read(output).properties?.operation?.const !== operation.name) throw new Error(`Operation schema identity differs: ${operation.name}`);
    return { operation_id: operation.id, operation: operation.name,
      skill_families: skills.filter(skill => skill.operation_ids.includes(operation.id)).map(skill => skill.name),
      cli: { command: 'ud-agent', arguments: ['call', operation.name, '--input', 'REQUEST_JSON', '--allow-root', 'WORKSPACE'] },
      mcp: { tool: operation.name, input_schema: input, output_schema: output },
      other_advertised_apis: [], prerequisite_capability: operation.runtime_pack,
      evidence: { structural: 'catalogued', deterministic_execution: 'not_run', native_model_execution: 'not_run' } };
  });
}
