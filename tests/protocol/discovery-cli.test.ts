/** Installed discovery works without a worker, writable home, or executable PATH. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { buildSync } from 'esbuild';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

test('installed discovery exposes all authoritative identities and schemas without setup or workspace effects', () => {
  const source = process.cwd(), folder = mkdtempSync(path.join(os.tmpdir(), 'ud-discovery-cli-'));
  try {
    cpSync(path.join(source, 'contracts'), path.join(folder, 'contracts'), { recursive: true });
    const home = path.join(folder, 'home'); mkdirSync(home);
    const entry = path.join(folder, 'coordinator.mjs');
    buildSync({ entryPoints: [path.join(source, 'packages/coordinator/src/entry.ts')], outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node24',
      mainFields: ['module', 'main'], banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' } });
    const env = { HOME: home, USERPROFILE: home, LOCALAPPDATA: home, XDG_DATA_HOME: home, PATH: path.join(home, 'no-executables'), LANG: 'C.UTF-8', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
    const run = (...args: string[]) => spawnSync(process.execPath, [entry, ...args], { env, cwd: home, encoding: 'utf8', timeout: 10_000 });
    const catalog = run('tools', '--json'); assert.equal(catalog.status, 0, catalog.stderr);
    const operations = JSON.parse(catalog.stdout).operations;
    const contracts = [...JSON.parse(readFileSync(path.join(source, 'contracts/ud-interfaces.json'), 'utf8')), ...JSON.parse(readFileSync(path.join(source, 'contracts/environment.json'), 'utf8'))];
    assert.equal(operations.length, 104); assert.deepEqual(operations.map((item: {id: string; name: string}) => [item.id, item.name]), contracts.map(item => [item.id, item.name]));
    for (const name of ['predictions_evaluate', 'treebank_edit', 'check_ud_environment']) {
      const result = run('describe', name, '--json'); assert.equal(result.status, 0, result.stderr); const description = JSON.parse(result.stdout);
      assert.equal(description.name, name); assert.deepEqual(description.input_schema, JSON.parse(readFileSync(path.join(source, 'contracts/schema/operations', `${name}.input.schema.json`), 'utf8')));
      assert.deepEqual(description.output_schema, JSON.parse(readFileSync(path.join(source, 'contracts/schema/results', `${name}.schema.json`), 'utf8')));
      assert.deepEqual(description.access, contracts.find(item => item.name === name).access ?? null);
    }
    const filtered = run('tools', '--query', 'gold', '--json'); assert.equal(filtered.status, 0, filtered.stderr);
    assert.ok(JSON.parse(filtered.stdout).operations.some((item: {name: string}) => item.name === 'predictions_evaluate'));
    const exact = run('tools', '--query', 'predictions_evaluate', '--json'); assert.equal(JSON.parse(exact.stdout).operations[0].name, 'predictions_evaluate');
    const fragmentCall = run('describe', 'treebank_edit', '--path', '/$defs/batch_token_form_set', '--json'); assert.equal(fragmentCall.status, 0, fragmentCall.stderr); assert.ok(JSON.parse(fragmentCall.stdout).fragment.required.includes('form'));
    const text = run('describe', 'predictions_evaluate'); assert.equal(text.status, 0, text.stderr); assert.ok(text.stdout.includes('gold_file_paths'));
    // A shell agent copies the second line: the dedicated command, not a guessed executable named after the tool.
    const validate = run('describe', 'validation_report'); assert.equal(validate.status, 0, validate.stderr); assert.equal(validate.stdout.split('\n')[1], 'Run: ud-agent validate --working-tree "$PWD" --lang LANGUAGE_CODE (checks every .conllu file in that folder; e.g. --lang en)');
    assert.ok(!text.stdout.includes('Run: '), 'Only operations with a dedicated command get a Run line.');
    for (const args of [['describe', '../../secret'], ['describe'], ['tools', 'unexpected'], ['tools', '--query', 'gold', '--query', 'other'], ['describe', 'treebank_edit', '--allow-root', home]]) {
      const invalid = run(...args); assert.equal(invalid.status, 1); assert.ok(invalid.stderr);
    }
    const missingLanguage = run('validate', '--working-tree', home); assert.equal(missingLanguage.status, 1); assert.match(missingLanguage.stderr, /validate requires --lang .*e\.g\. --lang en\./);
    // Named .conllu files are accepted as the file selection (reaching the next check); prose files get the no-UD route.
    const named = run('validate', '--working-tree', home, 'a.conllu', 'b.conllu'); assert.equal(named.status, 1); assert.match(named.stderr, /validate requires --lang/);
    const prose = run('validate', '--working-tree', home, 'report.txt', '--lang', 'en'); assert.equal(prose.status, 1);
    assert.match(prose.stderr, /validate checks CoNLL-U \.conllu files only; report\.txt is not CoNLL-U\. For prose or report wording, read the file and answer without ud-agent\./);
    assert.deepEqual(readdirSync(home), [], 'Discovery must not create runtime state, journals, caches or workspace files.');
  } finally { rmSync(folder, { recursive: true, force: true }); }
}, 30_000);

test('large authoritative schemas have bounded discovery projections and exact safe pointer access', async () => {
  const { describeOperation, formatOperationDescription, schemaFragment } = await import('../../packages/coordinator/src/discovery.js');
  const root = process.cwd(), schema = JSON.parse(readFileSync(path.join(root, 'contracts/schema/operations/treebank_edit.input.schema.json'), 'utf8'));
  assert.ok(JSON.stringify(schema).length > 80000, 'Use the actual large installed schema as the regression.');
  const description = describeOperation(root, 'treebank_edit'), rendered = formatOperationDescription(description);
  assert.ok(Buffer.byteLength(rendered) <= 4096, `Discovery projection unexpectedly expands to ${Buffer.byteLength(rendered)} bytes`);
  assert.ok(rendered.includes('not the complete schema')); assert.ok(rendered.includes('edit_batch')); assert.ok(rendered.includes('/$defs/NAME'));
  assert.deepEqual(description.input_schema, schema);
  const fragment = describeOperation(root, 'treebank_edit', '/$defs/batch_token_form_set');
  assert.deepEqual(fragment.fragment, schema.$defs.batch_token_form_set);
  assert.equal(fragment.fragment_sha256, createHash('sha256').update(JSON.stringify(schema.$defs.batch_token_form_set)).digest('hex'));
  assert.deepEqual(schemaFragment({ properties: { 'a/b': { const: 'escaped' }, '~literal': { type: 'string' } } }, '/properties/a~1b'), { const: 'escaped' });
  assert.deepEqual(schemaFragment({ properties: { '~literal': { type: 'string' } } }, '/properties/~0literal'), { type: 'string' });
  assert.equal(schemaFragment({ required: ['first', 'second'] }, '/required/0'), 'first');
  assert.equal(schemaFragment({ required: ['first', 'second'] }, '/required/1'), 'second');
  for (const pointer of ['/required/length', '/required/01', '/required/-1', '/required/2', '/required/-', '/required/1.0', '/required/9007199254740992']) assert.throws(() => schemaFragment({ required: ['first', 'second'] }, pointer), /pointer/);
  for (const pointer of ['#/$defs/edit_batch', '/missing', '/__proto__', '/constructor/prototype', '/bad~2escape', 'relative', '/' + 'x'.repeat(2049)]) assert.throws(() => schemaFragment(schema, pointer), /pointer/);
  const contracts = [...JSON.parse(readFileSync(path.join(root, 'contracts/ud-interfaces.json'), 'utf8')), ...JSON.parse(readFileSync(path.join(root, 'contracts/environment.json'), 'utf8'))];
  for (const contract of contracts) {
    const operation = describeOperation(root, contract.name);
    assert.deepEqual(operation.input_schema, JSON.parse(readFileSync(path.join(root, 'contracts/schema/operations', contract.name + '.input.schema.json'), 'utf8')));
    assert.deepEqual(operation.output_schema, JSON.parse(readFileSync(path.join(root, 'contracts/schema/results', contract.name + '.schema.json'), 'utf8')));
  }
});
