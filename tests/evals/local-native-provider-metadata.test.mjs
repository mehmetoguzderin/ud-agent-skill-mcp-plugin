// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { configureNativeProfile } from '../../evals/local/native-recipes.mjs';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';
import { createGateway } from '../../evals/local/gateway.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

test('native provider profiles bind auxiliary and daemon clients to the selected local model', async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-provider-profile-')));
  const model = 'local/model.with-dots', endpoint = 'http://127.0.0.1:19999';
  const options = { model, endpoint, taskRoot: path.join(directory, 'task'), env: {}, modelContextCapacity: 65536 };
  try {
    const hermes = path.join(directory, 'hermes');
    configureNativeProfile('hermes-agent', { ...options, profile: hermes });
    const config = parseYaml(await readFile(path.join(hermes, '.hermes/config.yaml'), 'utf8'));
    assert.deepEqual(config.auxiliary.vision, { provider: 'custom', model, base_url: endpoint + '/v1', api_key: 'local-eval-only' });
    assert.equal(config.model.context_length, 65536);
    assert.equal(config.model.supports_vision, undefined, 'Routing configuration must not invent an image capability');
    const grok = path.join(directory, 'grok');
    const configured = configureNativeProfile('grok-build', { ...options, profile: grok });
    assert.equal(configured.env.GROK_HOME, path.join(grok, '.grok'));
    const native = parseToml(await readFile(path.join(configured.env.GROK_HOME, 'config.toml'), 'utf8'));
    assert.equal(native.models.default, model);
    assert.equal(native.models.session_summary, model, 'Native automatic titles must use the admitted model instead of the independent hosted default');
    assert.deepEqual(Object.keys(native.model), [model], 'Model IDs must survive TOML quoting as one exact key');
    assert.equal(native.model[model].model, model);
    assert.equal(native.model[model].base_url, endpoint + '/v1');
    assert.equal(native.model[model].api_backend, 'chat_completions');
    assert.equal(native.model[model].api_key, 'local-eval-only', 'Inference must not depend on credentials stripped by the native daemon');
    assert.equal(native.model[model].context_window, options.modelContextCapacity);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

posixTest('negative native metadata discovery does not count as inference or advertise a foreign server', async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-provider-metadata-')));
  const model = 'local/model', records = [];
  let tokenizations = 0;
  const budget = await createBudgetAuthority({ directory });
  const gateway = await createGateway({ upstream: 'http://127.0.0.1:1', model, budget,
    tokenize: () => { tokenizations++; throw new Error('METADATA_MUST_NOT_TOKENIZE'); }, record: value => records.push(value) });
  try {
    const counters = budget.snapshot().counters;
    const paths = ['/', '/api/v1/models', '/api/tags', '/v1/props', '/props', '/version', `/v1/models/${model}`, `/v1/models/${encodeURIComponent(model)}`];
    for (const route of paths) {
      const response = await fetch(gateway.url + route);
      assert.equal(response.status, 404);
      const body = await response.json();
      assert.equal(body.models, undefined); assert.equal(body.context_length, undefined);
    }
    assert.equal(budget.snapshot().stopped, null);
    assert.deepEqual(budget.snapshot().counters, counters);
    assert.equal(tokenizations, 0);
    assert.deepEqual(records.map(({ type, path: route, status, inference }) => ({ type, path: route, status, inference })),
      paths.map(route => ({ type: 'provider_metadata_probe', path: route, status: 404, inference: false })));
    const response = await fetch(gateway.url + '/api/v1/unknown?api_key=private-query', { headers: { authorization: 'Bearer private-header' } });
    assert.equal(response.status, 422);
    assert.equal(budget.snapshot().stopped, 'PROVIDER_ROUTE_UNSUPPORTED', 'Unknown routes remain failures');
    const rejection = records.at(-1);
    assert.equal(rejection.method, 'GET'); assert.equal(rejection.pathname, '/api/v1/unknown');
    assert.equal(rejection.headers, undefined); assert.doesNotMatch(JSON.stringify(rejection), /private-query|private-header|api_key/);
  } finally { await gateway.close(); await budget.close(); await rm(directory, { recursive: true, force: true }); }
});
