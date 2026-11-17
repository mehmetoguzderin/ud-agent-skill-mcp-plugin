/** Exact pre-outcome schedule identity, shared by orchestration and Stryker. */
import { createHash } from 'node:crypto';
import { canonicalJson } from '../release/http-transports.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const insist = (value, message) => { if (!value) throw new Error('Frozen mutation plan: ' + message); };
const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function mutationPlanIdentity(plan, backend) {
  insist(plan?.scope_complete === true, 'complete source scope is required');
  const inventory = plan.inventory ?? plan.mutants;
  insist(Array.isArray(inventory) && inventory.length > 0 && (plan.scheduled ?? inventory.length) === inventory.length, 'empty or incomplete definitions');
  const ids = new Set(), definitions = new Set();
  const mutants = inventory.map(item => {
    insist(item?.definition && hash(canonicalJson(item.definition)) === item.definition_sha256, 'definition hash differs');
    const id = backend === 'typescript' ? item.file + '#' + item.definition_sha256 : item.id;
    const key = item.file + '\0' + item.definition_sha256;
    insist(typeof id === 'string' && !ids.has(id) && !definitions.has(key), 'duplicate definition'); ids.add(id); definitions.add(key);
    return { id, file: item.file, source_sha256: item.source_sha256, definition_sha256: item.definition_sha256 };
  }).sort((a, b) => order(a.id, b.id));
  let tests = plan.tests;
  if (tests && !Array.isArray(tests) && typeof tests === 'object') tests = Object.entries(tests).map(([source, source_sha256]) => ({ source, source_sha256 }));
  else if (Array.isArray(tests)) tests = tests.map(item => ({ ...Object.fromEntries(['source', 'source_sha256', 'name', 'occurrence'].filter(key => Object.hasOwn(item, key)).map(key => [key, item[key]])), ...(Object.hasOwn(item, 'name') ? {} : { id: item.id.replace(/^mutants\//, '') }) }));
  insist(Array.isArray(tests) && tests.length > 0 && new Set(tests.map(canonicalJson)).size === tests.length, 'empty or duplicate test discovery');
  for (const item of [...mutants, ...tests]) insist(typeof (item.file ?? item.source) === 'string' && /^[a-f0-9]{64}$/.test(item.source_sha256 ?? ''), 'source identity is missing');
  tests.sort((a, b) => order(canonicalJson(a), canonicalJson(b)));
  insist(/^[a-f0-9]{64}$/.test(plan.source_tree_sha256 ?? ''), 'source tree identity is missing');
  return { schema_version: 1, backend, tool: plan.tool, source_tree_sha256: plan.source_tree_sha256, mutants, tests, ...(Object.hasOwn(plan, 'case_inventory') ? { case_inventory: plan.case_inventory } : {}) };
}

export function verifyFrozenMutationPlan(plan, frozen, backend) {
  const actual = mutationPlanIdentity(plan, backend);
  insist(canonicalJson(actual) === canonicalJson(frozen), 'regenerated definitions or tests differ from discovery');
  return actual;
}
