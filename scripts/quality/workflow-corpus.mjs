/** Shared authored workflow inputs; these do not invoke a model. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import { safeRelative } from '../release/candidate.mjs';
import { skillInventory } from '../generate/skill-files.mjs';

export function loadWorkflowCorpus(root) {
  const corpus = JSON.parse(readFileSync(path.join(root, 'evals/cases/workflows.json'), 'utf8'));
  const skills = new Set(skillInventory(root).map(item => item.name));
  if (corpus.schema_version !== 1 || !Array.isArray(corpus.routing_cases) || !corpus.routing_cases.length || !Array.isArray(corpus.replay_cases) || !corpus.replay_cases.length) throw new Error('Workflow corpus is empty or invalid.');
  const ids = new Set(), ajv = new Ajv({ strict: true });
  for (const item of [...corpus.routing_cases, ...corpus.replay_cases]) {
    if (!item || typeof item.id !== 'string' || !/^[a-z0-9-]+$/.test(item.id) || ids.has(item.id) || typeof item.prompt !== 'string' || !item.prompt) throw new Error('Workflow case identity is duplicate or invalid.');
    ids.add(item.id);
  }
  for (const skill of skills) for (const kind of ['explicit', 'natural', 'negative', 'competition']) {
    if (!corpus.routing_cases.some(item => item.id.startsWith(skill + '-') && item.kind === kind)) throw new Error(`Workflow routing scenario missing: ${skill}/${kind}`);
  }
  for (const item of corpus.routing_cases) {
    if (!['explicit', 'natural', 'negative', 'competition'].includes(item.kind) || (item.expected_skill !== null && !skills.has(item.expected_skill)) || (item.kind === 'negative' && item.expected_skill !== null) || (item.kind === 'competition' && (!skills.has(item.competing_skill) || item.competing_skill === item.expected_skill))) throw new Error('Workflow routing expectation is invalid.');
  }
  for (const item of corpus.replay_cases) {
    if (!skills.has(item.skill) || !item.files || typeof item.files !== 'object' || Array.isArray(item.files) || !Object.keys(item.files).length || !Array.isArray(item.steps) || !item.steps.length || !Array.isArray(item.allowed_writes) || !item.expected_files || typeof item.expected_files !== 'object') throw new Error(`Workflow replay is invalid: ${item.id}`);
    for (const [name, content] of Object.entries(item.files)) { safeRelative(name); if (typeof content !== 'string') throw new Error('Workflow fixture must contain exact UTF-8 bytes.'); }
    for (const name of item.allowed_writes) safeRelative(name);
    for (const [name, content] of Object.entries(item.expected_files)) { safeRelative(name); if (!item.allowed_writes.includes(name) || typeof content !== 'string') throw new Error('Workflow output is not independently authorized.'); }
    if (new Set(item.allowed_writes).size !== item.allowed_writes.length) throw new Error('Duplicate workflow write permission.');
    for (const step of item.steps) {
      if (typeof step.operation !== 'string' || !/^[a-z][a-z0-9_]+$/.test(step.operation)) throw new Error('Workflow operation is invalid.');
      const schema = JSON.parse(readFileSync(path.join(root, 'contracts/schema/operations', step.operation + '.input.schema.json')));
      const validate = ajv.compile(schema);
      if (!validate(substituteWorkflow(step.arguments, '/example/workspace'))) throw new Error(`Workflow arguments violate ${step.operation}: ${JSON.stringify(validate.errors)}`);
      if (!step.expected || !['completed', 'rejected', 'incomplete'].includes(step.expected.execution_status) || !Array.isArray(step.expected.assertions) || !step.expected.assertions.length || step.expected.assertions.some(item => typeof item.pointer !== 'string' || !item.pointer.startsWith('/') || !Object.hasOwn(item, 'value'))) throw new Error('Workflow has no independent result expectation.');
    }
  }
  for (const skill of skills) if (!corpus.replay_cases.some(item => item.skill === skill)) throw new Error(`Workflow replay skill omitted: ${skill}`);
  for (const filename of Object.values(corpus.shared_regressions ?? {})) { safeRelative(filename); readFileSync(path.join(root, filename)); }
  return corpus;
}

export function substituteWorkflow(value, workspace) {
  if (typeof value === 'string') return value.replaceAll('${WORKSPACE}', workspace);
  if (Array.isArray(value)) return value.map(item => substituteWorkflow(item, workspace));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substituteWorkflow(item, workspace)]));
  return value;
}
