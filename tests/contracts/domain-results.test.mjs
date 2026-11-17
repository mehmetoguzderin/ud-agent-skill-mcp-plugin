import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';

const root = process.cwd();
const catalog = JSON.parse(readFileSync(path.join(root, 'contracts/ud-interfaces.json'), 'utf8'));
const contracts = JSON.parse(readFileSync(path.join(root, 'contracts/result-shapes.json'), 'utf8'));
const inputs = JSON.parse(readFileSync(path.join(root, 'contracts/input-shapes.json'), 'utf8'));
let results;

beforeAll(() => {
  const local = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const python = process.env.UD_AGENT_PYTHON ?? (existsSync(local) ? local : process.platform === 'win32' ? 'python' : 'python3');
  const run = spawnSync(python, ['tests/domain/worker/operation_cases.py'], {
    cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, PYTHONPATH: path.join(root, 'workers/ud/src'), PYTHONDONTWRITEBYTECODE: '1' },
  });
  expect(run.error, run.stderr).toBeUndefined();
  expect(run.status, run.stderr).toBe(0);
  const records = JSON.parse(run.stdout);
  expect(records).toHaveLength(102);
  results = new Map(records.map(record => [record.operation, record]));
  expect(results.size).toBe(102);
}, 65_000);

describe('independently authored domain result contracts', () => {
  it('covers exactly the 102 preserved application operations', () => {
    expect(Object.keys(contracts.operations).sort()).toEqual(catalog.map(item => item.name).sort());
  });
  for (const operation of catalog) {
    it(`${operation.id} ${operation.name} accepts actual expected behavior and rejects a missing semantic field`, () => {
      const record = results.get(operation.name);
      expect(record).toBeDefined();
      const schema = JSON.parse(JSON.stringify({ $defs: contracts.definitions, ...contracts.operations[operation.name] }).replaceAll('#/definitions/', '#/$defs/'));
      const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
      expect(validate(record.result), JSON.stringify(validate.errors)).toBe(true);
      const missing = structuredClone(record.result);
      delete missing[record.negative_field];
      expect(validate(missing), `missing ${record.negative_field} was accepted`).toBe(false);
    });
  }
});

describe('independently authored domain input contracts', () => {
  const schemaFor = operation => JSON.parse(JSON.stringify({
    $defs: inputs.definitions, type: 'object', additionalProperties: false,
    properties: inputs.operations[operation.name],
    required: operation.parameters.filter(parameter => parameter.required).map(parameter => parameter.name),
  }).replaceAll('#/definitions/', '#/$defs/'));
  it('covers every preserved parameter of every domain signature', () => {
    expect(Object.keys(inputs.operations).sort()).toEqual(catalog.map(item => item.name).sort());
    for (const operation of catalog) expect(Object.keys(inputs.operations[operation.name]).sort()).toEqual(operation.parameters.map(parameter => parameter.name).sort());
  });
  for (const operation of catalog) {
    it(`${operation.id} ${operation.name} accepts executed inputs and rejects malformed semantic arguments`, () => {
      const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schemaFor(operation));
      const args = results.get(operation.name).arguments;
      expect(validate(args), JSON.stringify(validate.errors)).toBe(true);
      const key = operation.parameters.find(parameter => parameter.name !== 'working_tree_path' && parameter.name !== 'ud_context_path' && Object.hasOwn(args, parameter.name)).name;
      expect(validate({ ...args, [key]: false }), `invalid ${key} was accepted`).toBe(false);
    });
  }
  it('preserves token identity aliases and explicit empty attribute replacements', () => {
    const operation = catalog.find(item => item.name === 'token_edit');
    const validate = new Ajv2020({ strict: true }).compile(schemaFor(operation));
    const original = results.get(operation.name).arguments;
    for (const name of ['token_id', 'word_id', 'id']) {
      expect(validate({ ...original, token_ref: { tree_ref: original.token_ref.tree_ref, [name]: '1' }, token_patch: { feats: null, misc: [] } })).toBe(true);
      expect(validate({ ...original, token_ref: { ...original.token_ref.tree_ref, [name]: '1' }, token_patch: { feats: null, misc: [] } })).toBe(true);
    }
    expect(validate({ ...original, token_patch: { unsupported_column: 'x' } })).toBe(false);
  });
  it('validates nested batch actions and temporary sentence identities', () => {
    const operation = catalog.find(item => item.name === 'treebank_edit');
    const validate = new Ajv2020({ strict: true }).compile(schemaFor(operation));
    const original = results.get(operation.name).arguments;
    const args = { ...original, edit_batch: [{ operation: 'tree_copy', temporary_id: '$copy', arguments: { tree_ref: { file_path: 'a.conllu', sent_id: 'a' }, target_file_path: 'b.conllu', insertion_point: 'end', new_sent_id: 'copy' } }, { operation: 'token_lemma_set', arguments: { token_ref: { tree_ref: { temporary_id: '$copy' }, token_id: '1' }, lemma: 'changed' } }] };
    expect(validate(args), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...args, edit_batch: [{ operation: 'unregistered-operation', arguments: {} }] })).toBe(false);
  });
  it('accepts host validation controls for plan application', () => {
    const operation = catalog.find(item => item.name === 'plan_apply');
    const validate = new Ajv2020({ strict: true }).compile(schemaFor(operation));
    const original = results.get(operation.name).arguments;
    expect(validate({ ...original, options: { mode: 'apply', validation_options: { language_code: 'en', level: 2 }, ud_context_path: 'context' } }), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...original, options: { validation_options: { language_code: false } } })).toBe(false);
  });
  it('accepts generated repair actions with optional additional input fingerprints', () => {
    const schema = JSON.parse(JSON.stringify({ $defs: inputs.definitions, $ref: '#/definitions/constrained_plan' }).replaceAll('#/definitions/', '#/$defs/'));
    const validate = new Ajv2020({ strict: true }).compile(schema);
    const action = { id: 'fix', type: 'replace_file', file_path: 'a.conllu', before_sha256: 'a'.repeat(64), after_sha256: 'b'.repeat(64), content: 'replacement\n', depends_on: [] };
    expect(validate({ schema_version: 'ud-plan-v1', actions: [action] }), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ actions: [action] })).toBe(false);
    expect(validate({ schema_version: 'ud-plan-v1', actions: [{ ...action, input_fingerprints: { 'a.conllu': 'wrong' } }] })).toBe(false);
  });
});
