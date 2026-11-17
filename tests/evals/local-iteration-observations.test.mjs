/** Descriptive iteration observations use inert captured events only. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { observeIterationEpisode } from '../../evals/local/iteration-observations.mjs';

const description = 'UD editing: inspect the authorized token setter; excludes ordinary report wording.';
const schema = { type: 'object', properties: { form: { type: 'string' } }, required: ['form'] };
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(action) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-iteration-observe-'));
  try {
    const put = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, value); };
    put('skills/ud-edit/SKILL.md', `---\nname: ud-edit\ndescription: ${JSON.stringify(description)}\n---\n\nUse the installed operation schema.\n`);
    put('contracts/ud-interfaces.json', JSON.stringify([{ id: '001', name: 'token_form_set' }]));
    put('contracts/environment.json', '[]');
    put('contracts/schema/operations/token_form_set.input.schema.json', JSON.stringify(schema));
    return action(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const row = { scenario_id: 'S2' };
const request = (id, text = `ud-edit: ${description}`, extra = {}) => ({ type: 'provider_request', id, body: { messages: [{ role: 'system', content: text }], ...extra } });
const observe = (installation, result) => observeIterationEpisode('/unused-current-source', installation, row, result);

test('missing installed metadata, requests and independent grades remain unknown without changing outcome', () => {
  const input = { outcome: 'model_blocked', reason: 'No admitted model', metrics: { counters: null } }, before = structuredClone(input);
  const observed = observe('/nonexistent-installation', input);
  assert.deepEqual(input, before); assert.equal(observed.outcome, 'model_blocked');
  assert.deepEqual(observed.stages, Object.fromEntries(['exposure', 'activation', 'discovery', 'valid_call', 'dispatch', 'interpretation', 'verified_completion'].map(name => [name, null])));
  assert.equal(observed.diagnostic_metrics.ud_operations, null); assert.equal(observed.diagnostic_metrics.captured_provider_requests, null);
});

test('exposure requires exact YAML-decoded metadata in the first native request, not names or later exposure', () => fixture(installation => {
  assert.equal(observe(installation, { events: [request('entry', 'ud-edit'), request('later')] }).stages.exposure, false);
  assert.equal(observe(installation, { events: [request('entry')] }).stages.exposure, true);
  assert.equal(observe(installation, { events: [{ type: 'upstream_request', body: request('entry').body }] }).stages.exposure, null);
  assert.equal(observe(installation, { events: [request('entry', '', { tools: [{ name: 'ud-edit', description }] })] }).stages.exposure, true);
}));

test('a describe proposal is not discovery; actual canonical schema declaration or successful output is', () => fixture(installation => {
  const call = { id: 'describe', name: 'bash', arguments: { command: 'ud-agent describe token_form_set' } };
  const input = { observations: { complete: true }, metrics: { counters: { ud_operations: 0 } }, events: [request('entry'), { type: 'native_calls_admitted', calls: [call] }] };
  const proposed = observe(installation, input);
  assert.equal(proposed.stages.discovery, false); assert.equal(proposed.stages.valid_call, null); assert.equal(proposed.stages.dispatch, false);
  const output = `token_form_set (001): Change a token form\nInput schema: ${hash(schema)}; output schema: ${'a'.repeat(64)}.\n`;
  const completed = observe(installation, { ...input, events: [...input.events, { type: 'native_result_observed', id: 'describe', failed: false }, request('continuation', '', { messages: [{ role: 'tool', tool_call_id: 'describe', content: JSON.stringify({ returncode: 0, output }) }] })] });
  assert.equal(completed.stages.discovery, true);
  const declared = observe(installation, { events: [request('entry', '', { tools: [{ type: 'function', function: { name: 'mcp__ud__token_form_set', parameters: schema } }] })] });
  assert.equal(declared.stages.discovery, true);
  const failed = observe(installation, { ...input, events: [...input.events, request('continuation', '', { messages: [{ role: 'tool', tool_call_id: 'describe', content: JSON.stringify({ returncode: 1, output }) }] })] });
  assert.equal(failed.stages.discovery, false);
}));

test('schema receipts bind installed bytes and require an observed successful tool result', () => fixture(installation => {
  const body = { kind: 'installed-operation-description', name: 'token_form_set', input_schema_sha256: hash(schema) };
  const input = content => ({ events: [request('entry'), request('next', '', { messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'schema', content }] }] })] });
  assert.equal(observe(installation, input(JSON.stringify(body))).stages.discovery, true);
  assert.equal(observe(installation, input(JSON.stringify({ ...body, input_schema_sha256: 'f'.repeat(64) }))).stages.discovery, null);
  assert.equal(observe(installation, { events: [request('entry', JSON.stringify(body))] }).stages.discovery, null);
}));

test('real UD events or counters establish dispatch; optional activation cannot override independent completion', () => fixture(installation => {
  const input = { outcome: 'passed', observations: { skill_activation: false }, verification: { status: 'passed', checks: [] }, events: [request('entry', 'No UD metadata'), { type: 'operation_start', operation_id: 'op', name: 'token_form_set' }], metrics: { counters: { ud_operations: 1 } } };
  const observed = observe(installation, input);
  assert.equal(observed.outcome, 'passed'); assert.equal(observed.stages.activation, false); assert.equal(observed.stages.exposure, false);
  assert.equal(observed.stages.valid_call, true); assert.equal(observed.stages.dispatch, true); assert.equal(observed.stages.verified_completion, true);
  assert.equal(observed.diagnostic_metrics.activation_optional, true); assert.equal(observed.diagnostic_metrics.first_failure, null);
  assert.equal(observe(installation, { metrics: { counters: { ud_operations: 1 } } }).stages.dispatch, true);
}));

test('interpretation uses independent final-answer checks and preserves incomplete grading', () => fixture(installation => {
  const incomplete = observe(installation, { observations: { final_answer_verified: true }, verification: { status: 'incomplete', checks: [{ name: 'accurate_final_edit', status: 'incomplete' }] } });
  assert.equal(incomplete.stages.interpretation, null); assert.equal(incomplete.stages.verified_completion, null);
  const failed = observe(installation, { verification: { status: 'failed', checks: [{ name: 'accurate_final_edit', status: 'failed' }] } });
  assert.equal(failed.stages.interpretation, false); assert.equal(failed.stages.verified_completion, false);
  assert.equal(failed.diagnostic_metrics.first_failure.source, 'independent-grade');
}));

test('identical attempts retain recovery uncertainty and existing measured counters without mutations', () => fixture(installation => {
  const first = { id: 'one', name: 'bash', arguments: { command: 'ud-agent --help', timeout: 3 } }, second = { id: 'two', name: 'bash', arguments: { timeout: 3, command: 'ud-agent --help' } };
  const input = { events: [{ type: 'native_calls_admitted', calls: [first] }, { type: 'response_loss' }, { type: 'native_calls_admitted', calls: [second] }, { type: 'native_calls_admitted', calls: [second] }], metrics: { counters: { inference: 2, tools: 2, ud_operations: 0, input: 41, output: null }, total_elapsed_ms: 130, context: { observed: true } } };
  const before = structuredClone(input), output = observe(installation, input);
  assert.deepEqual(input, before); assert.equal(output.diagnostic_metrics.identical_tool_attempts, 1);
  assert.equal(output.diagnostic_metrics.repeated_exact_calls[0].classification, 'possible-required-response-loss-recovery');
  assert.equal(output.diagnostic_metrics.redundant_identical_tool_attempts, null);
  assert.equal(output.diagnostic_metrics.generated_tokens, null); assert.equal(output.diagnostic_metrics.inference_requests, 2); assert.equal(output.diagnostic_metrics.total_elapsed_ms, 130);
}));
