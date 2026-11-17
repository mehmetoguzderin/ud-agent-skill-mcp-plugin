/** Read-only descriptive projections; no execution, grading or model calls. MIT. */
import path from 'node:path';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parse } from 'yaml';
import { requestNativeResults } from './native-observations.mjs';

const families = { S1: 'ud-validate', S2: 'ud-edit', S3: 'ud-compare', S4: 'ud-investigate', S5: 'ud-rules-docs', S6: 'ud-release' };
const relevant = {
  S1: ['validation_report', 'sentence_validation_report'],
  S2: ['token_form_set', 'token_lemma_set', 'tree_text_set', 'treebank_edit'],
  S3: ['predictions_evaluate', 'annotation_pair_scores'],
  S4: ['relation_profile', 'dependency_order_profile', 'treebank_profile'],
  S5: ['language_rules_report', 'documentation_preview', 'guideline_example_preview', 'sentence_render'],
  S6: ['release_plan', 'release_candidate_build', 'release_deposit_prepare', 'handover_package_build'],
};
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const canonical = value => JSON.stringify(value, (_key, item) => object(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const digest = value => createHash('sha256').update(value).digest('hex');
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
function walk(value, action, depth = 0) {
  if (depth > 40 || value == null) return;
  action(value);
  if (typeof value === 'object') for (const child of Object.values(value)) walk(child, action, depth + 1);
}
function strings(value) { const result = []; walk(value, item => { if (typeof item === 'string') result.push(item); }); return result; }
function installedFile(installation, relative) {
  try {
    const base = realpathSync(installation), file = realpathSync(path.join(base, relative));
    if (!file.startsWith(base + path.sep) || !statSync(file).isFile() || statSync(file).size > 4 * 1024 ** 2) return null;
    return readFileSync(file, 'utf8');
  } catch { return null; }
}
function skillMetadata(installation, name) {
  if (!name) return null;
  const source = installedFile(installation, `skills/${name}/SKILL.md`), frontmatter = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(source ?? '');
  try {
    const value = frontmatter && parse(frontmatter[1], { uniqueKeys: true });
    return value?.name === name && typeof value.description === 'string' && value.description.trim()
      ? { name, description: value.description, installed_sha256: digest(source) } : null;
  } catch { return null; }
}
function catalog(installation) {
  try {
    const rows = ['contracts/ud-interfaces.json', 'contracts/environment.json'].flatMap(file => JSON.parse(installedFile(installation, file)));
    return rows.every(row => typeof row?.name === 'string') ? rows : null;
  } catch { return null; }
}
function protocol(body) { return Array.isArray(body?.input) ? 'responses' : Array.isArray(body?.contents) ? 'gemini' : Array.isArray(body?.system) || body?.messages?.some(message => Array.isArray(message.content) && message.content.some(part => part.type === 'tool_result')) ? 'messages' : 'chat'; }
function resultBlocks(body) {
  const rows = [];
  for (const message of body?.messages ?? []) {
    if (message.role === 'tool') rows.push({ id: message.tool_call_id, content: message.content });
    if (message.role === 'user') for (const part of Array.isArray(message.content) ? message.content : []) if (part.type === 'tool_result') rows.push({ id: part.tool_use_id, content: part.content });
  }
  for (const item of Array.isArray(body?.input) ? body.input : []) if (item.type === 'function_call_output') rows.push({ id: item.call_id, content: item.output });
  for (const message of body?.contents ?? []) for (const part of message.parts ?? []) if (part.functionResponse) rows.push({ id: part.functionResponse.id, content: part.functionResponse.response });
  return rows;
}
function interpretation(verification) {
  if (verification?.status === 'passed') return true;
  const checks = verification?.checks?.filter(check => /^(?:accurate_final_|no_false_|ordinary_wording_help$|wording_changed_in_suggestion$|final_archive_hash_reported$|no_official_acceptance_claim$)/.test(check.name ?? '')) ?? [];
  if (checks.some(check => check.status === 'failed')) return false;
  return checks.length && checks.every(check => check.status === 'passed') ? true : null;
}

/** Preserve outcome/oracles. False stage observations never become a new grade. */
export function observeIterationEpisode(root, installation, row, result) {
  void root; // Never fall back to current source when installed evidence is missing.
  const events = Array.isArray(result.events) ? result.events : [], requests = events.filter(event => event.type === 'provider_request' && object(event.body));
  const metadata = skillMetadata(installation, families[row.scenario_id]), entry = requests[0];
  let exposure = null;
  if (metadata && entry) {
    exposure = strings(entry.body).some(text => text.includes(metadata.name) && text.includes(metadata.description));
    walk(entry.body, item => { if (object(item) && item.name === metadata.name && item.description === metadata.description) exposure = true; });
  }
  const contracts = catalog(installation), names = new Set((contracts ?? []).map(item => item.name)), wanted = new Set(relevant[row.scenario_id] ?? []), discovery = [];
  const operationName = name => typeof name === 'string' ? [...wanted].find(value => names.has(value) && (name === value || name.endsWith('__' + value) || name.endsWith('.' + value))) : undefined;
  const calls = [], seenIds = new Set();
  for (const [index, event] of events.entries()) if (event.type === 'native_calls_admitted') for (const call of event.calls ?? []) {
    if (typeof call.name !== 'string' || typeof call.id === 'string' && seenIds.has(call.id)) continue;
    if (typeof call.id === 'string') seenIds.add(call.id);
    calls.push({ ...call, event_index: index });
  }
  const statuses = new Map(events.filter(event => event.type === 'native_result_observed' && typeof event.failed === 'boolean').map(event => [event.id, event.failed]));
  for (const request of requests) {
    walk(request.body.tools, item => {
      if (!object(item)) return;
      const name = operationName(item.name), schema = item.input_schema ?? item.parameters;
      if (name && object(schema)) discovery.push({ source: 'native-tool-schema-declaration', request_id: request.id ?? null, operation: name });
    });
    try { for (const observed of requestNativeResults(protocol(request.body), request.body)) if (!statuses.has(observed.id)) statuses.set(observed.id, observed.failed); } catch { /* Unrecognized protocol results remain unknown. */ }
    for (const block of resultBlocks(request.body)) {
      if (statuses.get(block.id) !== false) continue;
      const call = calls.find(item => item.id === block.id), command = call?.arguments?.command ?? call?.arguments?.cmd;
      const texts = strings(block.content), decoded = object(block.content) ? [block.content] : [];
      // Decode only recorded tool-result JSON; no command execution or argument repair.
      for (let index = 0; index < texts.length && index < 1000; index++) {
        try { const value = JSON.parse(texts[index]); decoded.push(value); texts.push(...strings(value)); } catch { /* Plain native output is retained as text. */ }
      }
      for (const value of decoded) walk(value, item => {
        const name = operationName(item?.name);
        if (!name || item.kind !== 'installed-operation-description') return;
        const source = installedFile(installation, `contracts/schema/operations/${name}.input.schema.json`);
        try { if (source && item.input_schema_sha256 === digest(JSON.stringify(JSON.parse(source)))) discovery.push({ source: 'installed-schema-receipt-in-tool-result', request_id: request.id ?? null, operation: name }); } catch { /* Unknown schema binding. */ }
      });
      if (typeof command === 'string') for (const name of wanted) {
        if (!names.has(name) || !new RegExp(`(?:^|&&\\s*)ud-agent\\s+describe\\s+${name}(?:\\s|$)`).test(command)) continue;
        const source = installedFile(installation, `contracts/schema/operations/${name}.input.schema.json`), contract = contracts.find(item => item.name === name);
        try {
          const expected = source && digest(JSON.stringify(JSON.parse(source)));
          if (expected && texts.some(text => text.includes(`${name} (${contract.id}):`) && text.includes(`Input schema: ${expected};`))) discovery.push({ source: 'successful-cli-describe-result', request_id: request.id ?? null, operation: name });
        } catch { /* Missing bytes cannot establish discovery. */ }
      }
    }
  }
  const counters = result.metrics?.counters ?? {}, operations = events.filter(event => event.type === 'operation_start'), udCount = count(counters.ud_operations);
  const dispatched = operations.length > 0 || udCount > 0 ? true : udCount === 0 ? false : null;
  const stages = { exposure, activation: typeof result.observations?.skill_activation === 'boolean' ? result.observations.skill_activation : null,
    discovery: discovery.length ? true : contracts && requests.length && result.observations?.complete === true ? false : null,
    valid_call: dispatched === true ? true : null, dispatch: dispatched, interpretation: interpretation(result.verification),
    verified_completion: result.verification?.status === 'passed' ? true : result.verification?.status === 'failed' ? false : null };
  const signatures = new Map(), repeats = [];
  for (const call of calls) {
    const signature = digest(canonical({ name: call.name, arguments: call.arguments })), previous = signatures.get(signature);
    if (previous) repeats.push({ signature_sha256: signature, name: call.name, previous_call_id: previous.id ?? null, call_id: call.id ?? null,
      classification: events.slice(previous.event_index, call.event_index).some(event => event.type === 'response_loss') ? 'possible-required-response-loss-recovery' : 'identical-attempt; necessity-unknown' });
    signatures.set(signature, call);
  }
  const failures = events.flatMap((event, index) => event.type === 'backend_generation_observation' && event.status === 'observed' && event.parser_status === 'rejected'
    ? [{ stage: 'valid_call', event_index: index, reason: 'backend-parser-rejection', termination: event.termination ?? null }]
    : event.type === 'operation_result' && (event.response?.isError === true || ['failed', 'rejected'].includes(event.response?.structuredContent?.execution?.status))
      ? [{ stage: 'dispatch', event_index: index, reason: 'UD-operation-returned-error' }]
      : event.type === 'native_result_observed' && event.failed === true ? [{ stage: 'native_tool', event_index: index, reason: 'native-tool-returned-error', call_id: event.id }]
        : event.type === 'gateway_rejection' ? [{ stage: 'provider_boundary', event_index: index, reason: event.reason ?? null }] : []);
  const gradeFailure = result.verification?.checks?.find(check => check.status === 'failed');
  if (gradeFailure) failures.push({ stage: 'verified_completion', event_index: null, reason: gradeFailure.name, source: 'independent-grade' });
  const diagnostic_metrics = { inference_requests: count(counters.inference), tool_calls: count(counters.tools), ud_operations: udCount,
    captured_provider_requests: requests.length || (result.observations?.complete === true ? 0 : null), captured_tool_attempts: calls.length || (result.observations?.complete === true ? 0 : null),
    observed_operation_starts: operations.length || (udCount === 0 ? 0 : null), operation_count_conflict: udCount === 0 && operations.length > 0,
    input_tokens: count(counters.input), generated_tokens: count(counters.output), elapsed_ms: count(result.metrics?.elapsed_ms), total_elapsed_ms: count(result.metrics?.total_elapsed_ms), context: result.metrics?.context ?? null,
    identical_tool_attempts: repeats.length, repeated_exact_calls: repeats, redundant_identical_tool_attempts: null,
    first_failure: failures[0] ?? null, first_observed_gap: Object.entries(stages).find(([name, value]) => name !== 'activation' && value === false)?.[0] ?? null,
    exposure_evidence: metadata && entry ? { skill: metadata.name, installed_sha256: metadata.installed_sha256, entry_request_id: entry.id ?? null } : null,
    discovery_evidence: discovery, activation_optional: true, activation_scope: 'Existing independent any-UD-skill activation observation; no relevant-skill claim is added.',
    interpretation_scope: 'Independent final-answer checks only; incomplete or absent grades stay unknown.',
    failure_order_scope: 'Recorded event order; late backend receipts do not establish causal chronology. Stage gaps and identical attempts are descriptive, never new grades.' };
  return { ...result, stages, diagnostic_metrics };
}
