// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parse } from 'yaml';
import { configureNativeProfile } from '../../evals/local/native-recipes.mjs';
import { validateCoordinatorArguments } from '../../evals/local/coordinator-bridge.mjs';

test('counterfactual discovery commands cross the transparent bridge without gaining workspace authority', () => {
  const root = '/private/task';
  for (const args of [['tools', '--query', 'prediction', '--json'], ['describe', 'treebank_edit', '--path', '/$defs/batch_token_form_set']]) assert.deepEqual(validateCoordinatorArguments(args, root), args);
  assert.throws(() => validateCoordinatorArguments(['describe', 'treebank_edit', '--allow-root', '/private/other'], root), /GRANT_FORBIDDEN/);
  assert.throws(() => validateCoordinatorArguments(['uninstall', '--owned-runtime'], root), /COMMAND_FORBIDDEN/);
});

test('diagnostic neutral framing changes task framing while preserving the native loop and limits', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-study-native-'));
  try {
    const clientDirectory = path.join(directory, 'client');
    const source = path.join(clientDirectory, 'venv/lib/python3.12/site-packages/minisweagent/config/mini.yaml');
    mkdirSync(path.dirname(source), { recursive: true });
    writeFileSync(source, 'agent:\n  system_template: Native system\n  instance_template: "Please solve this issue {{task}} by editing source"\n  action_observation_template: "{{output}}"\nenvironment:\n  env: {}\nmodel: {}\n');
    const input = { taskRoot: directory, model: 'inert', endpoint: 'http://127.0.0.1:9', env: {}, skillsEnabled: false, clientDirectory, output: path.join(directory, 'trajectory.json') };
    const current = configureNativeProfile('mini-swe-agent', { ...input, profile: path.join(directory, 'current'), studyVariant: 'current' });
    const neutral = configureNativeProfile('mini-swe-agent', { ...input, profile: path.join(directory, 'neutral'), studyVariant: 'task-neutral' });
    const a = parse(readFileSync(current.config, 'utf8')), b = parse(readFileSync(neutral.config, 'utf8'));
    assert.equal(a.agent.instance_template, 'Please solve this issue {{task}} by editing source');
    assert.notEqual(a.agent.instance_template, b.agent.instance_template);
    assert.ok(b.agent.instance_template.startsWith('{{task}}'));
    assert.equal(b.agent.action_observation_template, a.agent.action_observation_template);
    assert.equal(b.agent.system_template, a.agent.system_template);
    assert.equal(b.agent.step_limit, 10);
    assert.equal(b.agent.wall_time_limit_seconds, 90);
    assert.deepEqual(b.model, a.model);
    assert.throws(() => configureNativeProfile('mini-swe-agent', { ...input, profile: directory, studyVariant: 'unknown' }), /VARIANT_UNKNOWN/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
