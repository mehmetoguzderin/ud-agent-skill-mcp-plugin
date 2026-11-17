/** Reconcile the reviewed bounded corpus; never imply whole-language coverage. */
import { createHash } from 'node:crypto';
import { canonicalJson } from '../release/http-transports.mjs';

export const BOUNDED_POLICY = 'bounded-reviewed-v1';
export const BOUNDED_LANGUAGES = Object.freeze(['typescript', 'python', 'rust', 'perl']);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const insist = (value, message) => { if (!value) throw new Error(message); };
const relative = value => typeof value === 'string' && value.length > 0 && !/[\\\0:]/.test(value) && !value.startsWith('/') && value.normalize('NFC') === value && value.split('/').every(part => part && part !== '.' && part !== '..');
const fingerprint = (hashes, name) => hashes instanceof Map ? hashes.get(name) : hashes?.[name];
const bounded = value => value?.profile === 'bounded' && value.policy === BOUNDED_POLICY && value.qualification === 'bounded-reviewed-corpus' && value.exhaustive === false;
const clean = (execution, status) => execution?.status === status && execution.timed_out === false && !execution.cancelled && !(execution.owned_descendants_cancelled ?? []).length;

export function boundedFaultDefinitions(manifest, readSource, sourceHashes) {
  insist(manifest?.schema_version === 1 && bounded(manifest) && Array.isArray(manifest.cases) && manifest.cases.length === 18, 'Bounded mutation policy must declare its exact 18 cases.');
  insist(typeof readSource === 'function', 'Bounded mutations require actual source bytes.');
  const ids = new Set(), languages = new Set();
  const inventory = manifest.cases.map(item => {
    insist(item && /^[A-Za-z0-9_-]{1,128}$/.test(item.id ?? '') && !ids.has(item.id) && relative(item.file) && ['vitest', 'pytest', 'rust'].includes(item.runner) && !item.unavailable && typeof item.test === 'string' && relative(item.test.split('::')[0]) && typeof item.assertion === 'string' && item.assertion.length > 0 && typeof item.category === 'string' && /^[a-z][a-z-]*$/.test(item.category), 'Invalid or duplicate bounded fault definition.');
    const language = item.file.endsWith('.py') ? 'python' : /\.(?:pl|pm)$/.test(item.file) ? 'perl' : item.file.endsWith('.rs') ? 'rust' : /\.[cm]?[jt]sx?$/.test(item.file) ? 'typescript' : 'data';
    insist(item.language === language && ['typescript', 'python', 'rust', 'perl', 'data'].includes(language) && (language === 'rust') === (item.runner === 'rust'), 'Bounded fault language or runner differs from its source.');
    ids.add(item.id); languages.add(language);
    const bytes = readSource(item.file), find = Buffer.from(item.find ?? ''), replacement = Buffer.from(item.replace ?? '');
    insist(Buffer.isBuffer(bytes) && bytes.length <= 16 * 1024 ** 2 && find.length > 0 && !find.equals(replacement), 'Bounded fault is empty or does not change source bytes.');
    const start = bytes.indexOf(find);
    insist(start >= 0 && bytes.indexOf(find, start + 1) < 0, 'Bounded fault anchor is missing or ambiguous.');
    const source_sha256 = hash(bytes);
    insist(source_sha256 === fingerprint(sourceHashes, item.file), 'Bounded fault source is stale.');
    const definition = { tool: 'fault-canary', version: '1.0.0', operator: item.id, file: item.file, language, category: item.category, start, end: start + find.length, original_hex: find.toString('hex'), replacement_hex: replacement.toString('hex'), runner: item.runner, test: item.test, assertion: item.assertion };
    return { id: item.id, file: item.file, source_sha256, definition, definition_sha256: hash(canonicalJson(definition)) };
  });
  insist(BOUNDED_LANGUAGES.every(language => languages.has(language)), 'Bounded corpus omitted a required language.');
  return inventory;
}

export function assessBoundedFaults({ manifest, plan, report, sourceSha256, sourceHashes, readSource }) {
  const result = { total: 0, killed: 0, per_language: Object.fromEntries(BOUNDED_LANGUAGES.map(language => [language, { scheduled: 0, killed: 0 }])), errors: [], profile: 'bounded', policy: BOUNDED_POLICY, qualification: 'bounded-reviewed-corpus', exhaustive: false };
  try {
    const expected = boundedFaultDefinitions(manifest, readSource, sourceHashes);
    result.total = expected.length;
    for (const item of expected) (result.per_language[item.definition.language] ??= { scheduled: 0, killed: 0 }).scheduled++;
    insist(/^[a-f0-9]{64}$/.test(sourceSha256 ?? '') && plan?.schema_version === 1 && bounded(plan) && plan.tool === 'fault-canary' && plan.tool_version === '1.0.0' && plan.inventory_only === true && plan.scope_complete === true && plan.source_tree_sha256 === sourceSha256 && plan.scheduled === expected.length && canonicalJson(plan.inventory) === canonicalJson(expected), 'Bounded pre-outcome definitions differ from the complete source-bound corpus.');
    insist(Array.isArray(plan.tests) && plan.tests.length > 0, 'Bounded test inventory is empty.');
    const tests = new Map();
    for (const test of plan.tests) {
      insist(typeof test?.id === 'string' && test.id.length > 0 && !tests.has(test.id) && relative(test.source) && test.source_sha256 === fingerprint(sourceHashes, test.source), 'Bounded test inventory is duplicate or stale.');
      tests.set(test.id, test);
    }
    insist(report?.schema_version === 1 && bounded(report) && report.tool === 'fault-canary' && report.source_tree_sha256 === sourceSha256 && report.complete === true && Array.isArray(report.outcomes) && report.outcomes.length === expected.length, 'Bounded outcomes are missing or incomplete.');
    const outcomes = new Map();
    for (const outcome of report.outcomes) {
      insist(typeof outcome?.id === 'string' && !outcomes.has(outcome.id), 'Bounded outcomes repeat a definition.');
      outcomes.set(outcome.id, outcome);
    }
    for (const item of expected) {
      const outcome = outcomes.get(item.id), definition = item.definition;
      const selected = [...tests.values()].filter(test => test.source === definition.test.split('::')[0] && (definition.runner === 'vitest' || (definition.runner === 'rust' ? test.name === definition.assertion : test.id === definition.test || test.id.startsWith(definition.test + '::'))));
      insist(selected.length > 0, `Bounded fault has no independently collected test: ${item.id}`);
      const selectedIds = new Set(selected.map(test => test.id));
      insist(outcome?.definition_sha256 === item.definition_sha256 && outcome.status === 'Killed' && outcome.failure_kind === 'assertion' && Array.isArray(outcome.killed_by) && outcome.killed_by.length > 0 && new Set(outcome.killed_by).size === outcome.killed_by.length && outcome.killed_by.every(id => tests.has(id)) && outcome.killed_by.some(id => selectedIds.has(id)), `Bounded fault lacks a clean, bound assertion kill: ${item.id}`);
      if (definition.runner === 'rust') {
        const evidence = outcome.evidence, phases = evidence?.phase_results;
        insist(evidence?.baseline?.phase?.process_status === 'Success' && evidence.source_restored === true && evidence.assertion_evidence?.valid === true && evidence.assertion_evidence.artifacts_complete === true && Array.isArray(phases) && phases.length === 3 && phases[0].process_status === 'Success' && phases[1].process_status === 'Success' && canonicalJson(phases[2].process_status) === canonicalJson({ Failure: 101 }) && phases[2].artifacts_complete === true, `Rust fault has incomplete compilation, baseline or assertion evidence: ${item.id}`);
      } else insist(clean(outcome.evidence?.baseline, 0) && clean(outcome.evidence?.execution, 1), `Bounded fault has a failed baseline or runtime execution: ${item.id}`);
      result.killed++; result.per_language[definition.language].killed++;
    }
  } catch (error) { result.errors.push(error instanceof Error ? error.message : String(error)); }
  return result;
}
