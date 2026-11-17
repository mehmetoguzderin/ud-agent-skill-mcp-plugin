import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import { spawnSync } from 'node:child_process';
import { canonicalSkillFiles, connectedSkillFiles, skillInventory } from '../../scripts/generate/skill-files.mjs';
import { loadDistributionIdentity } from '../../scripts/release/host-adapters.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const root = process.cwd();
function fixture(run) {
  const folder = mkdtempSync(path.join(os.tmpdir(), 'ud-skills-'));
  try {
    writableFixtureCopy(path.join(root, 'skills'), path.join(folder, 'skills'), folder);
    mkdirSync(path.join(folder, 'quality')); writableFixtureCopy(path.join(root, 'quality/skills.json'), path.join(folder, 'quality/skills.json'), folder);
    return run(folder);
  } finally { rmSync(folder, { recursive: true, force: true }); }
}

test('all six standalone skills contain the designed references and resolvable local resources', () => {
  const files = canonicalSkillFiles(root), inventory = skillInventory(root);
  const required = {
    'ud-validate': ['checks', 'setup', 'results'], 'ud-edit': ['transactions', 'ids', 'structural-maps'],
    'ud-investigate': ['profiles', 'heuristics', 'parallel-data'], 'ud-compare': ['evaluation', 'overlap', 'change-review'],
    'ud-rules-docs': ['rules', 'metadata', 'rendering'], 'ud-release': ['readiness', 'packaging', 'handover'],
  };
  assert.deepEqual(inventory.map(item => item.name).sort(), Object.keys(required).sort());
  for (const [skill, names] of Object.entries(required)) for (const name of names) {
    assert.ok(files.has(`${skill}/references/${name}.md`), `missing ${skill}/${name}`);
    assert.ok(inventory.find(item => item.name === skill).required_files.includes(`references/${name}.md`));
  }
  assert.ok(files.has('ud-validate/assets/request-examples.json'));
  const connected = connectedSkillFiles(root, loadDistributionIdentity(root));
  for (const [name, bytes] of connected) {
    assert.deepEqual(readFileSync(path.join(root, 'packaging/grok/ud-agent-skill-mcp-plugin/skills', name)), bytes, name);
    if (name.endsWith('/SKILL.md')) assert.deepEqual(files.get(name), bytes, 'canonical shared connection is stale');
  }
});

test('validation request examples satisfy real public schemas without adding tools', () => {
  const examples = JSON.parse(readFileSync(path.join(root, 'skills/ud-validate/assets/request-examples.json')));
  const names = new Set();
  assert.equal(examples.schema_version, 1); assert.ok(examples.requests.length > 0);
  for (const example of examples.requests) {
    assert.ok(!names.has(example.id)); names.add(example.id);
    const validate = new Ajv({ strict: true }).compile(JSON.parse(readFileSync(path.join(root, 'contracts/schema/operations', example.operation + '.input.schema.json'))));
    assert.equal(validate(example.arguments), true, `${example.id}: ${JSON.stringify(validate.errors)}`);
  }
});

test('complete structural example satisfies the public schema and real worker preview without changing source bytes', () => {
  const example = JSON.parse(readFileSync(path.join(root, 'skills/ud-edit/assets/token-split.json')));
  const validate = new Ajv({ strict: true }).compile(JSON.parse(readFileSync(path.join(root, 'contracts/schema/operations/token_split.input.schema.json'))));
  assert.equal(validate(example.request.arguments), true, JSON.stringify(validate.errors));
  const python = process.env.UD_AGENT_PYTHON ?? path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const script = 'import json,sys,tempfile\nfrom pathlib import Path\nfrom ud_agent.wire import process\nx=json.load(sys.stdin)\nwith tempfile.TemporaryDirectory() as d:\n p=Path(d)/"sample.conllu";p.write_bytes(x["source_conllu"].encode());a=x["request"]["arguments"];a["working_tree_path"]=d;r=process({"operation":"token_split","arguments":a});print(json.dumps({"response":r,"after":p.read_bytes().decode()}))\n';
  const executed = spawnSync(python, ['-c', script], { input: JSON.stringify(example), encoding: 'utf8', timeout: 15000, env: { ...process.env, PYTHONPATH: path.join(root, 'workers/ud/src'), PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(executed.status, 0, executed.stderr);
  const observed = JSON.parse(executed.stdout);
  assert.equal(observed.response.ok, true, executed.stdout);
  assert.equal(observed.response.result.status, 'candidate');
  assert.equal(observed.response.result.changes[0].content, example.expected_candidate_conllu);
  assert.equal(observed.after, example.source_conllu);
});

test('required supporting content cannot disappear behind a valid SKILL.md', () => fixture(folder => {
  rmSync(path.join(folder, 'skills/ud-edit/references/structural-maps.md'));
  assert.throws(() => canonicalSkillFiles(folder), /Required skill resource is missing/);
}));

test('standalone skills reject references to a sibling skill or missing local asset', () => fixture(folder => {
  const file = path.join(folder, 'skills/ud-edit/references/ids.md');
  for (const target of ['../../ud-validate/SKILL.md', 'missing.md']) {
    writeFileSync(file, `[read](${target})\n`);
    assert.throws(() => canonicalSkillFiles(folder), /outside its standalone folder/);
  }
}));

test('skill extraction never follows an authoring symlink or adds an undeclared seventh skill', () => fixture(folder => {
  const link = path.join(folder, 'skills/ud-edit/references/linked.md');
  symlinkSync(path.join(folder, 'skills/ud-validate/SKILL.md'), link);
  assert.throws(() => canonicalSkillFiles(folder), /symlink/); rmSync(link);
  mkdirSync(path.join(folder, 'skills/foreign'));
  assert.throws(() => canonicalSkillFiles(folder), /adds or omits/);
}));
