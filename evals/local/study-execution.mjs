/** Actual bounded diagnostic execution. Imports never load models. MIT. */
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { sourceReceipt, sha256, fileReceipt } from '../../scripts/release/candidate.mjs';
import { assertOptIn, readPreparation, writeNew } from './preparation.mjs';
import { frozenHashes, installSnapshot, runEpisode, deriveSeed } from './campaign.mjs';
import { MODELS } from './registry.mjs';
import { inspectHarnesses, nativeAdapterIdentity } from './native.mjs';
import { createStudy, openStudy, runStudy } from './study.mjs';
import { captureStudyRequest, observedSkillBody, transformStudyRequest } from './study-requests.mjs';
import { admitModel } from './serving.mjs';
import { openCalibrationLedger } from './calibration.mjs';
import { createBudgetAuthority } from './budget.mjs';
import { createGateway } from './gateway.mjs';
import { createForwardSupervisor, compareForwardResults } from './study-forward-process.mjs';
import { SCENARIOS } from './scenarios.mjs';
import { writeStudyAnalysis } from './study-analysis.mjs';
import { readObservation } from './study-observation.mjs';
import { scientificStudyStorage } from './study-storage.mjs';
import { collectGenerationEvidence, summarizeGenerationEvidence } from './generation-evidence.mjs';
import { cleanupObservation, failureObservation, observedCounters } from './lifecycle.mjs';
import Ajv from 'ajv/dist/2020.js';


const proposalRelative = '.artifacts/local-evals/implementation-20261112-scientific-repair/product-proposal';
const read = file => JSON.parse(readFileSync(file, 'utf8'));
const hash = value => sha256(JSON.stringify(value));
const receipt = file => ({ path: file, sha256: sha256(readFileSync(file)) });
const persist = (file, value) => { writeNew(file, value); return receipt(file); };

export function installationIdentity(directory) {
  const files = [];
  function walk(current) {
    for (const name of readdirSync(current).sort()) {
      const file = path.join(current, name), relative = path.relative(directory, file).split(path.sep).join('/'), info = lstatSync(file);
      if (info.isSymbolicLink()) {
        const target = realpathSync(file); if (!target.startsWith(directory + path.sep)) throw new Error('STUDY_INSTALLED_LINK_ESCAPES');
        files.push({ path: relative, link_target: path.relative(directory, target) });
      } else if (info.isDirectory()) walk(file);
      else if (info.isFile()) files.push(fileReceipt(directory, relative));
      else throw new Error('STUDY_INSTALLED_SPECIAL_FILE');
    }
  }
  walk(directory); return { algorithm: 'sha256-installed-file-inventory-v1', files, sha256: hash(files) };
}
export function verifyStudyInputs(root, metadata) {
  const realRoot = realpathSync(root), verified = [];
  function verify(item) {
    if (!item || typeof item.path !== 'string' || !/^[a-f0-9]{64}$/.test(item.sha256 ?? '')) throw new Error('STUDY_INPUT_RECEIPT_REQUIRED');
    const selected = path.resolve(item.path);
    if (!lstatSync(selected).isFile() || lstatSync(selected).isSymbolicLink() || !realpathSync(selected).startsWith(realRoot + path.sep) || sha256(readFileSync(selected)) !== item.sha256) throw new Error(`STUDY_INPUT_BYTES_CHANGED:${selected}`);
    verified.push(selected); return read(selected);
  }
  verify(metadata.analysis); verify(metadata.interventions); const proposal = verify(metadata.proposal);
  if (metadata.analysis.sha256 !== metadata.analysis_sha256 || metadata.interventions.sha256 !== metadata.interventions_sha256) throw new Error('STUDY_ANALYSIS_BINDING_CHANGED');
  for (const [key, captures] of Object.entries(metadata.captures ?? {})) for (const [condition, item] of Object.entries(captures)) {
    const capture = verify(item);
    if (capture.inference !== false || capture.owned_cleanup_verified !== true || capture.selected_sha256 !== hash(capture.selected) || item.request_sha256 !== capture.selected_sha256 ||
        (condition === 'activated' && !capture.activated) || (condition === 'neutral' && !capture.neutral)) throw new Error(`STUDY_CAPTURE_BINDING_CHANGED:${key}/${condition}`);
  }
  for (const [directory, expected] of [[metadata.installation, metadata.installed], [metadata.variant_installation, metadata.variant_installed]]) {
    if (!directory || !expected?.sha256 || installationIdentity(directory).sha256 !== expected.sha256) throw new Error('STUDY_INSTALLED_BYTES_CHANGED');
  }
  for (const file of proposal.files ?? []) {
    const source = path.join(path.dirname(metadata.proposal.path), 'files', file.path);
    if (sha256(readFileSync(source)) !== file.sha256) throw new Error('STUDY_PROPOSAL_BYTES_CHANGED');
  }
  for (const file of proposal.compiled ?? []) {
    const source = path.join(path.dirname(metadata.proposal.path), 'compiled', file.path);
    if (sha256(readFileSync(source)) !== file.sha256) throw new Error('STUDY_PROPOSAL_COMPILED_BYTES_CHANGED');
  }
  return { status: 'verified', input_files: verified.length, installation_count: 2 };
}

export function measureForwardEffect(reference, intervention, { inputIntervention } = {}) {
  const left = reference?.next_logits, right = intervention?.next_logits;
  if (!inputIntervention && reference?.prefix_token_ids_sha256 && intervention?.prefix_token_ids_sha256 && reference.prefix_token_ids_sha256 !== intervention.prefix_token_ids_sha256) return { status: 'unverified', reason: 'FORWARD_CONTEXT_MISMATCH' };
  if (reference?.status !== 'observed' || intervention?.status !== 'observed' || !Array.isArray(left) || !left.length || !Array.isArray(right) || left.length !== right.length || [...left, ...right].some(value => !Number.isFinite(value))) return { status: 'unverified', reason: 'FORWARD_EFFECT_OBSERVATIONS_MISSING' };
  const before = reference.continuation_log_probabilities, after = intervention.continuation_log_probabilities;
  let maximum = 0, squared = 0, topLeft = 0, topRight = 0;
  for (let index = 0; index < left.length; index++) { const delta = right[index] - left[index]; maximum = Math.max(maximum, Math.abs(delta)); squared += delta * delta;
    if (left[index] > left[topLeft]) topLeft = index; if (right[index] > right[topRight]) topRight = index; }
  const likelihood = Array.isArray(before) && before.length && Array.isArray(after) && before.length === after.length && [...before, ...after].every(Number.isFinite)
    ? { reference: before.reduce((a, b) => a + b, 0), intervention: after.reduce((a, b) => a + b, 0), delta: after.reduce((a, b) => a + b, 0) - before.reduce((a, b) => a + b, 0), token_count: before.length } : null;
  return { status: 'observed', compared_logits: left.length, maximum_absolute_logit_delta: maximum, logit_delta_l2: Math.sqrt(squared),
    reference_top1: topLeft, intervention_top1: topRight, top1_changed: topLeft !== topRight, continuation_log_likelihood: likelihood,
    input_intervention: inputIntervention ?? null, scope: inputIntervention ? 'lexical-marker likelihood under declared tool-result representation change; not complete action probability or native skill success' : 'lexical-marker likelihood and last-position operator intervention; not complete action probability or native skill success' };
}
export function studyBindings(root, preparation, metadata) {
  const hashes = frozenHashes(root, preparation);
  return { evaluator: hashes.evaluator, oracle: hashes.oracle, fixtures: hashes.tasks, product: sourceReceipt(root).sha256,
    models: hash(preparation.models), clients: hash([nativeAdapterIdentity(), metadata.harness_inventory ?? metadata.harnesses]), runtimes: hash(preparation.runtimes),
    interventions: metadata.interventions_sha256, analysis: metadata.analysis_sha256 };
}
async function prepareScientificStudyImpl(root, { optIn, directory, onProgress = () => {}, storage, signal, setCancelOwned } = {}) {
  assertOptIn({ optIn });
  const preparation = readPreparation(root), id = randomUUID();
  const inputs = path.join(root, '.artifacts/local-evals/study-inputs', id);
  mkdirSync(inputs, { recursive: true, mode: 0o700 });
  onProgress('Installing frozen baseline product for diagnostic captures (no inference).');
  const installation = path.join(inputs, 'installation'), installed = await installSnapshot(root, installation);
  const proposal = path.join(root, proposalRelative), proposalFile = path.join(proposal, 'manifest.json');
  if (!existsSync(proposalFile)) throw new Error('REVIEWED_DIAGNOSTIC_PRODUCT_PROPOSAL_REQUIRED');
  const { materializeStudyVariantInstallation } = await import(pathToFileURL(path.join(proposal, 'materialize.mjs')).href);
  const variant = materializeStudyVariantInstallation(installation, path.join(inputs, 'variant-installation'));
  const harnessInventory = await inspectHarnesses(root), harnesses = harnessInventory.filter(row => ['qwen-code', 'mini-swe-agent'].includes(row.id));
  storage.watch(inputs);
  let capture;
  setCancelOwned(async () => { signal.controller.abort(new Error('STUDY_STORAGE_CANCELLED')); await capture?.catch(() => {}); });
  const captures = {};
  for (const model of MODELS) for (const harness of harnesses) for (const scenario of ['S2', 'S3']) {
    const key = `${model.id}/${harness.id}/${scenario}`; captures[key] = {};
    for (const condition of ['original', 'activated', ...(harness.id === 'mini-swe-agent' ? ['neutral'] : [])]) {
      const target = path.join(inputs, 'captures', model.id, harness.id, scenario, condition);
      onProgress(`Capturing actual inert native request ${key}/${condition}`);
      await storage.check();
      capture = captureStudyRequest({ root, directory: target, harness, installation, model: model.artifact, scenarioId: scenario,
        activated: condition === 'activated', neutral: condition === 'neutral', optIn, signal: signal.controller.signal });
      const evidence = await capture; await storage.check();
      captures[key][condition] = { ...receipt(path.join(target, 'capture.json')), request_sha256: evidence.selected_sha256 };
    }
  }
  const analysis = { version: 1, hypotheses: read(path.join(root, 'evals/local/study-hypotheses.json')),
    stage_order: ['exposure', 'activation', 'discovery', 'valid_call', 'dispatch', 'interpretation', 'verified_completion'],
    comparisons: 'within-model/harness/intent/seed paired conditions; unknown remains unknown; descriptive rates only for fixed tasks',
    native_contrast: 'current versus canonical actionable guidance plus task-neutral mini framing; combined practical intervention',
    forwards: { seed17: 'initial prefix parity pair', seed23: 'earliest accepted CURRENT native request containing an actual tool result',
      seed47: 'earliest accepted CURRENT native request containing the actual relevant loaded skill body; then earliest tool result; otherwise initial with explicit fallback',
      observed_choice: 'actual next model response for the selected gateway request ID; missing or interleaved response remains unknown',
      observational: 'seed17 instrumented parity rows and seed23/47 reference rows collect observational attention after initial parity; context hashes deduplicate repeated prefixes',
      intervention: 'seed23 paired instrumented rows zero a last-position deep hybrid operator; seed47 pairs change only CoNLL-U tool-result representation; lexical marker likelihood only; missing CoNLL-U is explicit sham',
      parity: { maximum_absolute_error: 0.001, maximum_relative_scale: 0.001, top1_equal: true } },
    primary_probe_metric: 'semantically valid discovery or operation-call choice; no exact call sequence required',
    native_observation_rules: 'Classify each accepted request only with its matching observed response; unknown or interleaved remains unknown. Actual operation_start establishes UD dispatch. Zero dispatch becomes false only with complete capture. Exact call signatures ignore ephemeral IDs; response-loss recovery is not presumed redundant. First failure is a directly failed event in captured order; late-collected backend receipt order does not establish global causal chronology, never a forced activation chain. Termination observations can coexist.',
    no_claims: ['forced activation is not implicit selection', 'attention correlation is not causal evidence', 'seed repetitions are not independent tasks', 'model identity bundles architecture, precision, tokenizer and runtime'] };
  const analysisReceipt = persist(path.join(inputs, 'analysis.json'), analysis);
  const interventionReceipt = persist(path.join(inputs, 'interventions.json'), { proposal: receipt(proposalFile), variant, captures });
  const metadata = { preparation, harnesses, harness_inventory: harnessInventory, inputs, installation, installed, variant_installation: variant.installation, variant_installed: installationIdentity(variant.installation),
    proposal: receipt(proposalFile), captures, interventions_sha256: interventionReceipt.sha256, analysis_sha256: analysisReceipt.sha256,
    analysis: analysisReceipt, interventions: interventionReceipt };
  verifyStudyInputs(root, metadata);
  const created = createStudy({ root, directory: directory ?? path.join(root, '.artifacts/local-evals/studies', id), optIn,
    bindings: studyBindings(root, preparation, metadata), metadata });
  onProgress(`Study frozen without starting live clock: ${created.directory}`);
  return created;
}
export function probeObservation(root, row, events) {
  const request = events.findLast(event => event.type === 'upstream_request')?.body;
  const response = events.findLast(event => event.type === 'model_visible_response');
  const stages = { exposure: request ? /ud-edit|ud-compare/.test(JSON.stringify(request)) : null,
    activation: row.condition === 'activated-skill' && request ? true : null,
    discovery: null, valid_call: null, dispatch: null, interpretation: null, verified_completion: null };
  if (!response || !request) return { stages, syntax_valid_calls: null, semantic_calls: [], classification: 'unobserved' };
  const calls = events.filter(event => event.type === 'native_calls_admitted').flatMap(event => event.calls ?? []);
  const declarations = new Map((request.tools ?? []).filter(tool => tool.type === 'function').map(tool => [tool.function.name, tool.function]));
  const relevant = row.scenario_id === 'S2' ? /^(?:workspace_inspect|treebank_edit|tree_edit|token_edit|tree_list|tree_get|token_list|token_get|tree_text_set|token_form_set|token_lemma_set|validation_report)$/ : /^(?:workspace_inspect|predictions_evaluate|annotation_pair_scores)$/;
  const relevantQuery = row.scenario_id === 'S2' ? /edit|tree|token|dependency|ud-edit/i : /predict|score|compar|ud-compare|attachment/i;
  const skill = row.scenario_id === 'S2' ? 'ud-edit' : 'ud-compare';
  const ajv = new Ajv({ strict: false, allErrors: true });
  const semantic = []; let syntax = 0;
  for (const call of calls) {
    const declaration = declarations.get(call.name); let valid = false;
    try { valid = Boolean(declaration && ajv.compile(declaration.parameters)(call.arguments)); } catch { /* Unknown syntax cannot become valid. */ }
    if (!valid) continue;
    syntax++;
    let choice = null;
    if (call.name === 'skill' && call.arguments.skill === skill) choice = 'skill-discovery';
    else if (call.name === 'tool_search' && typeof call.arguments.query === 'string' && relevantQuery.test(call.arguments.query)) choice = 'operation-discovery';
    else if (call.name === 'tool_call' && typeof call.arguments.name === 'string') {
      const operation = call.arguments.name.replace(/^mcp__ud__/, '');
      if (relevant.test(operation)) try { if (ajv.compile(read(path.join(root, 'contracts/schema/operations', operation + '.input.schema.json')))(call.arguments.arguments)) choice = 'operation-proposal'; } catch { /* Invalid or inaccessible schema. */ }
    } else if (relevant.test(call.name)) choice = 'operation-proposal';
    else if (['bash', 'run_shell_command'].includes(call.name)) {
      const command = call.arguments.command;
      if (typeof command === 'string') {
        const clear = command.replace(/^which ud-agent\s*&&\s*/, '');
        if (/^ud-agent --help\s*$/.test(clear) || /^ud-agent (?:tools|describe)\b/.test(clear) && relevantQuery.test(clear)) choice = 'cli-discovery';
        else if (new RegExp('^cat\\s+[^;&|]*' + skill + '/SKILL\\.md[\\s\"\']*$').test(clear)) choice = 'skill-discovery';
      }
    }
    semantic.push({ id: call.id, name: call.name, syntax_valid: true, semantic_role: choice, semantic_validity: choice ? 'supported-next-step' : 'unclassified' });
  }
  stages.discovery = semantic.some(call => /discovery/.test(call.semantic_role ?? ''));
  stages.valid_call = semantic.some(call => call.semantic_role !== null);
  return { stages, syntax_valid_calls: syntax, semantic_calls: semantic,
    classification: 'conservative-supported-next-step; shell compound commands remain unclassified; proposals are never execution' };
}
export function selectMechanisticPrefix({ row, captured, nativeEpisode, nativeReceipt, initialProbe, initialProbeReceipt, skillBody, root = process.cwd() }) {
  const initial = captured.selected.body;
  const contextHash = body => hash({ messages: body.messages, tools: body.tools ?? [], tool_choice: body.tool_choice ?? null });
  const events = nativeEpisode?.events ?? [];
  const candidates = events.flatMap((event, index) => event.type === 'upstream_request' && Array.isArray(event.body?.messages) ? [{ event, index }] : []);
  const hasResult = body => body.messages.some(message => message.role === 'tool');
  const hasSkill = body => observedSkillBody({ messages: body.messages.filter(message => message.role === 'tool') }, skillBody);
  let selected, reason;
  if (row.seed === 17) reason = 'initial-capture-parity';
  else if (row.seed === 47 && (selected = candidates.find(item => hasSkill(item.event.body)))) reason = 'earliest-actual-activated-skill-result';
  else if ((selected = candidates.find(item => hasResult(item.event.body)))) reason = row.seed === 47 ? 'fallback-earliest-actual-tool-result-no-skill-body' : 'earliest-actual-tool-result';
  else reason = 'fallback-initial-no-accepted-tool-result-prefix';
  const body = selected?.event.body ?? initial, requestId = selected?.event.id ?? null;
  let nextChoice = null;
  if (selected) {
    const responseIndex = events.findIndex((event, index) => index > selected.index && event.type === 'model_visible_response' && event.id === requestId);
    if (responseIndex >= 0 && !events.slice(selected.index + 1, responseIndex).some(event => event.type === 'upstream_request')) {
      const interval = events.slice(selected.index, responseIndex + 1);
      nextChoice = probeObservation(root, { ...row, condition: 'actual-native-prefix' }, interval);
    }
  }
  if (!selected && initialProbe) {
    const upstream = initialProbe.events?.find(event => event.type === 'upstream_request');
    if (upstream && contextHash(upstream.body) === contextHash(initial)) nextChoice = probeObservation(root, { ...row, condition: 'unchanged' }, initialProbe.events);
  }
  return { body, source: { policy: row.seed === 17 ? 'initial-parity' : row.seed === 23 ? 'earliest-tool-result' : 'earliest-skill-result-then-tool-result',
    selection: reason, fallback: reason.startsWith('fallback'), request_id: requestId,
    request_sha256: hash(body), context_sha256: contextHash(body), context_identity_method: 'messages-tools-tool-choice; generation seeds/settings excluded',
    native_episode: selected ? nativeReceipt : null, initial_probe: !selected && nextChoice ? initialProbeReceipt : null, initial_capture_sha256: hash(captured),
    next_response_observed: nextChoice !== null, observed_valid_next_action: nextChoice?.stages?.valid_call ?? null,
    next_choice: nextChoice, no_expected_answers_supplied: true } };
}
export function nativeEpisodeObservation(root, row, episode) {
  const events = episode.events ?? [], accepted = events.flatMap((event, index) => event.type === 'upstream_request' ? [{ event, index }] : []);
  const choices = accepted.map(({ event, index }) => {
    const end = events.findIndex((value, position) => position > index && value.type === 'model_visible_response' && value.id === event.id);
    if (end < 0 || events.slice(index + 1, end).some(value => value.type === 'upstream_request')) return { request_id: event.id, status: 'unknown', reason: 'Missing or interleaved corresponding response.' };
    return { request_id: event.id, status: 'observed', ...probeObservation(root, row, events.slice(index, end + 1)) };
  });
  const complete = episode.observations?.complete === true && !events.some(event => ['gateway_rejection', 'telemetry_gap', 'native_result_missing'].includes(event.type)) && accepted.length > 0 && choices.every(choice => choice.status === 'observed');
  const stageAny = name => choices.some(choice => choice.stages?.[name] === true) ? true : complete ? false : null;
  const operations = events.filter(event => event.type === 'operation_start');
  const stages = { exposure: accepted.length ? true : null, activation: episode.observations?.skill_activation ?? null,
    discovery: stageAny('discovery'), valid_call: stageAny('valid_call'), dispatch: operations.length ? true : complete ? false : null,
    interpretation: episode.observations?.final_answer_verified === true ? true : null,
    verified_completion: episode.verification?.status === 'passed' ? true : episode.verification?.status === 'failed' ? false : null };
  const seen = new Map(), repeated = [], failures = [], counts = { gateway_rejections: {}, provider_finish_reasons: {}, parser_rejections: {}, backend_termination: {}, native_termination: {} };
  const add = (kind, value) => { if (typeof value === 'string') counts[kind][value] = (counts[kind][value] ?? 0) + 1; };
  for (const [index, event] of events.entries()) {
    if (event.type === 'native_calls_admitted') for (const call of event.calls ?? []) {
      const key = sha256(JSON.stringify({ name: call.name, arguments: call.arguments }, (_key, value) => value && typeof value === 'object' && !Array.isArray(value) ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) : value));
      if (seen.has(key)) repeated.push({ signature_sha256: key, name: call.name, previous_call_id: seen.get(key).id, call_id: call.id,
        classification: events.slice(seen.get(key).index, index).some(value => value.type === 'response_loss') ? 'possible-required-response-loss-recovery' : 'exact-repeat; redundancy-unresolved' });
      seen.set(key, { id: call.id, index });
    }
    if (event.type === 'native_result_observed' && event.failed === true) failures.push({ stage: 'dispatch', event_index: index, reason: 'native-tool-returned-error', call_id: event.id });
    if (event.type === 'operation_result' && (event.response?.isError === true || ['failed', 'rejected'].includes(event.response?.structuredContent?.execution?.status))) failures.push({ stage: 'dispatch', event_index: index, reason: 'UD-operation-failed', operation_id: event.operation_id });
    if (event.type === 'gateway_rejection') { add('gateway_rejections', event.reason); failures.push({ stage: 'provider-boundary', event_index: index, reason: event.reason }); }
    if (event.type === 'backend_generation_observation' && event.status === 'observed') {
      add('backend_termination', event.termination);
      if (event.parser_status === 'rejected') { add('parser_rejections', event.parser_failure ?? 'rejected'); failures.push({ stage: 'valid_call', event_index: index, reason: 'backend-parser-rejection', termination: event.termination }); }
    }
    if (event.type === 'model_visible_response') for (const chunk of Array.isArray(event.body) ? event.body : [event.body]) for (const choice of chunk?.choices ?? []) add('provider_finish_reasons', choice.finish_reason);
    if (['turn.failed', 'turn.completed'].includes(event.type)) add('native_termination', event.exit_status ?? event.type);
  }
  if (episode.metrics?.stopped) add('native_termination', episode.metrics.stopped);
  return { stages, accepted_requests: accepted.length, choices, complete_observations: complete,
    failure_order_scope: 'Captured event order; late-collected backend receipts do not establish global causal chronology.',
    first_known_failure: failures[0] ?? { stage: null, reason: 'No directly observed failed transition; unknown is retained and activation is optional.' },
    known_failures: failures, repeated_exact_calls: repeated, repeated_exact_call_count: repeated.length, proven_redundant_attempts: null,
    competing_termination_observations: counts, semantics: 'Supported UD discovery/proposal labels are descriptive. Exact repeats can be required recovery; no forced skill stage or qualification verdict is inferred.' };
}
export function representationContrast(request) {
  const body = structuredClone(request), mapping = [];
  function adapt(text, location) {
    let decoded = text, returncode = null, wrapped = false;
    try { const parsed = JSON.parse(text); if (parsed && Number.isInteger(parsed.returncode) && typeof parsed.output === 'string') { if (Object.keys(parsed).sort().join(',') !== 'output,returncode') return text; decoded = parsed.output; returncode = parsed.returncode; wrapped = true; } } catch { /* Native plaintext. */ }
    // Require actual CoNLL-U data, not a skill describing its format or JSON-only data.
    const lines = decoded.split(/\r?\n/).filter(line => line.trim());
    if (!/^# sent_id\s*=/m.test(decoded) || !/^\d+\t[^\n]*(?:\t[^\n]*){8}$/m.test(decoded) ||
        !lines.every(line => /^# /.test(line) || /^(?:[1-9]\d*(?:[-.]\d+)?)\t(?:[^\t\r\n]*\t){8}[^\t\r\n]*$/.test(line))) return text;
    const result = `${wrapped ? `Native shell returncode: ${returncode}\n` : ''}<conllu-file-content byte_length="${Buffer.byteLength(decoded)}">\n${decoded}\n</conllu-file-content>`;
    mapping.push({ location, wrapped, returncode, original_text_sha256: sha256(text), decoded_bytes_sha256: sha256(decoded), decoded_bytes: Buffer.byteLength(decoded), transformed_text_sha256: sha256(result) });
    return result;
  }
  for (const [index, message] of body.messages.entries()) if (message.role === 'tool') {
    if (typeof message.content === 'string') message.content = adapt(message.content, `messages/${index}/content`);
    else if (Array.isArray(message.content)) for (const [partIndex, part] of message.content.entries()) if (part.type === 'text') part.text = adapt(part.text, `messages/${index}/content/${partIndex}/text`);
  }
  return { body, intervention: { kind: 'conllu-tool-result-representation', sham: mapping.length === 0, mapping,
    source_request_sha256: hash(request), effective_request_sha256: hash(body), preserves_decoded_content_bytes: true, changes: 'Only native tool-result presentation; no tool arguments, skill bodies, user intent or expected values are supplied.' } };
}
export function studyAdmissionStore({ directory, manifest, prepared, runtime, deadline }) {
  const file = path.join(directory, `admission-${prepared.id}.json`), proof = file + '.sha256.json';
  const identity = { study_id: manifest.id, manifest_sha256: hash(manifest), bindings: manifest.bindings, prepared_sha256: hash(prepared), runtime_sha256: hash(runtime), deadline };
  function load() {
    if (!existsSync(file)) { if (existsSync(proof)) throw new Error('STUDY_ADMISSION_RECEIPT_WITHOUT_RECORD'); return undefined; }
    if (!existsSync(proof) || receipt(file).sha256 !== read(proof).sha256) throw new Error('STUDY_ADMISSION_BYTES_CHANGED');
    const record = read(file);
    if (record.identity_sha256 !== hash(identity) || hash(record.identity) !== hash(identity) || record.admission_sha256 !== hash(record.admission)) throw new Error('STUDY_ADMISSION_BINDING_CHANGED');
    return record.admission;
  }
  return { load, save(admission) {
    const value = JSON.parse(JSON.stringify(admission));
    persist(file, { schema_version: 1, identity, identity_sha256: hash(identity), admission: value, admission_sha256: hash(value) }); chmodSync(file, 0o400);
    persist(proof, receipt(file)); chmodSync(proof, 0o400); return value;
  } };
}
export async function admitStudyModel({ store, calibration, modelId, admit }) {
  const prior = store.load();
  if (prior && prior.status !== 'admitted') return { active: prior, admission: prior, reused: true };
  if (!prior && (calibration.per_model[modelId] ?? 0) > 0) throw new Error('STUDY_PARTIAL_ADMISSION_UNRECONCILED');
  const active = await admit(prior);
  const admission = prior ?? store.save(active);
  return { active, admission, reused: prior !== undefined };
}
export function probeInferenceEvidence(events, generation) {
  const attempted = events.some(event => event.type === 'upstream_request');
  const verified = events.some(event => event.type === 'model_visible_response' && Number.isSafeInteger(event.outputTokens) && event.outputTokens >= 0) || generation?.observations?.some(row => row.status === 'observed');
  return { inference_attempted: attempted, real_inference: verified ? true : attempted ? null : false,
    verification: verified ? 'validated provider usage or exact private generation receipt' : attempted ? 'dispatch attempt only; generation unverified' : 'no upstream dispatch attempt' };
}
export async function executeProbe({ root, directory, row, reservation, resident, metadata }) {
  const selected = metadata.captures[`${row.model_id}/${row.harness_id}/${row.scenario_id}`];
  const original = read(selected.original.path), activated = read(selected.activated.path), neutral = selected.neutral ? read(selected.neutral.path) : undefined;
  const guidance = readFileSync(path.join(metadata.variant_installation, 'skills', row.scenario_id === 'S2' ? 'ud-edit' : 'ud-compare', 'SKILL.md'), 'utf8');
  const mapping = guidance.split(/---\r?\n/).slice(2).join('---\n').split('\n\n').slice(0, 2).join('\n\n');
  const transformed = transformStudyRequest({ condition: row.condition, original, activated, neutral,
    guidance: mapping + '\n\n' + guidance.slice(guidance.indexOf('## Connected tools')) });
  const request = { ...transformed.body, model: row.model_artifact, max_tokens: 512 };
  const started = Date.now(), events = []; let gateway, authority, responseStatus, output, failure, observerCleanupVerified = true, preAuthorityRelease;
  const observerCleanup = [];
  try {
    await resident.resetConversationCache?.({ idle: true });
    authority = await createBudgetAuthority({ directory: path.join(directory, 'budget'), limits: { inference: 1, output: 512, input: 16384 },
      deadline: reservation.deadline, onEvent: event => events.push(event), onStop: async () => resident.stop('diagnostic-probe-stopped') });
    gateway = await createGateway({ upstream: resident.upstream, model: row.model_artifact, wireModel: resident.wire_model ?? row.model_artifact,
      budget: authority, tokenize: resident.tokenize, sampling: resident.sampling, supportedSampling: resident.protocol_fields,
      seed: deriveSeed(row.seed, 0), record: event => events.push(event) });
    const response = await fetch(gateway.url + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), signal: authority.signal });
    responseStatus = response.status; output = await response.text();
  } catch (error) {
    failure = error;
    if (!authority) {
      try { preAuthorityRelease = cleanupObservation(await resident.stop('diagnostic-prebudget-failure')); }
      catch (releaseError) { preAuthorityRelease = { cleanupVerified: false, failure: failureObservation(releaseError) }; }
    }
  }
  finally {
    const closed = await Promise.allSettled([gateway?.close(), authority?.close()]);
    observerCleanup.push(...closed.map((result, index) => ({ observer: index ? 'budget' : 'gateway', outcome: result.status, ...(result.status === 'rejected' ? { failure: failureObservation(result.reason) } : {}) })));
    if (closed.some(result => result.status === 'rejected')) { observerCleanupVerified = false; failure ??= new Error('PROBE_OBSERVER_CLEANUP_FAILED'); }
  }
  const state = authority?.snapshot(), upstream = events.find(event => event.type === 'upstream_request');
  let generation = { status: 'not_applicable', observations: [], receipts: [] };
  if (row.model_id === 'minicpm') {
    generation = await collectGenerationEvidence({ events, evidenceDirectory: path.join(resident.evidence_directory, 'private-generations'), modelPath: resident.wire_model,
      startedAtMs: started, endedAtMs: Date.now() });
    events.push(...generation.observations);
  }
  const inference = probeInferenceEvidence(events, generation), generationSummary = summarizeGenerationEvidence(generation);
  const evidence = persist(path.join(directory, 'probe.json'), { row, request, transformed, response_status: responseStatus ?? null, output: output ?? null, error: failure?.message ?? null,
    failure: failureObservation(failure), cleanup: { observers: observerCleanup, preauthority_release: preAuthorityRelease ?? null },
    events, budget: state ?? null, ...inference, inference: inference.real_inference, backend_generation: generationSummary, backend_generations: generation.receipts, tools_dispatched: false, native_pending_proposals_are_not_dispatched: true });
  const bodyFile = path.join(directory, 'effective-request.json');
  if (upstream) persist(bodyFile, upstream.body);
  const observation = probeObservation(root, row, events); observation.exposure_source = 'serialized provider request only; model consumption requires verified real_inference';
  const observed = !failure && responseStatus >= 200 && responseStatus < 300;
  return { status: observed ? 'observed' : 'failed', ...(observed ? {} : { reason: failure?.message ?? events.findLast(event => event.type === 'gateway_rejection')?.reason ?? `HTTP_${responseStatus}` }),
    elapsed_ms: Date.now() - started, stages: observation.stages, probe_observation: observation, ...inference, backend_generation: generationSummary, evidence: [evidence, ...generation.receipts],
    failure: failureObservation(failure), cleanup: { observers: observerCleanup, preauthority_release: preAuthorityRelease ?? null }, counters: observedCounters(state),
    owned_cleanup_verified: Boolean(observerCleanupVerified && (state ? !['unverified', 'pending'].includes(state.cleanup) && state.pending_requests === 0 && state.pending_operations === 0 : preAuthorityRelease?.cleanupVerified === true)),
    ...(upstream ? { request_identity: { body_path: bodyFile, body_sha256: hash(upstream.body), derived_seed: deriveSeed(row.seed, 0) } } : {}) };

}

/** Forecast whole comparison blocks without altering frozen clocks or counters. */
export function forecastStudyBlock({ manifest, state, row, now = Date.now() }) {
  const model = state.models?.[row?.model_id], deadline = Math.min(model?.deadline ?? -1, (state.deadline ?? -1) - (manifest.policy?.reconciliation_ms ?? 0));
  const expected = manifest.rows.find(item => item.model_id === state.active_model && !state.rows[item.id]);
  if (!row || expected?.id !== row.id || state.active_row || !Number.isSafeInteger(now) || !Number.isSafeInteger(deadline) || deadline < 0)
    return { allowed: false, reason: 'No next frozen unit or unreconciled active work/deadline.', row_id: row?.id ?? null, deadline };
  const peers = manifest.rows.filter(item => item.kind === row.kind && item.block === row.block);
  const remainingPeers = peers.filter(item => !state.rows[item.id]), begun = peers.some(item => state.rows[item.id]?.status === 'recorded');
  const durations = manifest.rows.filter(item => item.kind === row.kind && item.model_id === row.model_id).flatMap(item => {
    const record = state.rows[item.id], value = record?.recorded_at - record?.claimed_at;
    return record?.status === 'recorded' && Number.isFinite(value) && value >= 0 ? [value] : [];
  });
  const unitCeiling = 95_000 + (row.kind === 'native' ? manifest.policy?.native_setup_ms ?? 0 : 0);
  const perUnit = durations.length ? Math.max(10_000, Math.min(unitCeiling, Math.max(...durations))) : unitCeiling;
  const priorRecorded = manifest.rows.filter(item => item.model_id === row.model_id && state.rows[item.id]?.status === 'recorded').at(-1);
  const switchReserve = !begun && (!priorRecorded || priorRecorded.kind !== row.kind) ? 30_000 : 0;
  const estimatedRemaining = remainingPeers.length * perUnit + switchReserve, available = Math.max(0, deadline - now);
  const required = begun ? unitCeiling : Math.max(unitCeiling, estimatedRemaining);
  return { allowed: available >= required, row_id: row.id, kind: row.kind, block: row.block, model_id: row.model_id,
    comparison_block_started: begun, remaining_peer_rows: remainingPeers.length, comparable_recorded_units: durations.length,
    per_unit_estimate_ms: perUnit, mode_switch_reserve_ms: switchReserve, estimated_remaining_block_ms: estimatedRemaining,
    hard_next_unit_floor_ms: 95_000, required_to_start_ms: required, available_ms: available, deadline,
    can_finish_remaining_peers: available >= estimatedRemaining,
    reason: available >= required ? begun ? 'Continue begun block under original deadline; completion remains observed, never assumed.' : 'Complete remaining comparison block fits the measured conservative forecast.' : 'Insufficient original model time; remaining rows stay unfinished.',
    policy: 'Maximum observed same-model/kind claim-to-record duration, clipped10seconds through native-loop+setup+grace ceiling; conservative ceiling default;30second initial/mode-switch reserve. No seed/task selection, clock reset or counter refund.' };
}
async function runScientificStudyImpl(root, { optIn, directory, onProgress = () => {}, storage, signal, setCancelOwned } = {}) {
  assertOptIn({ optIn });
  const manifest = read(path.join(directory, 'manifest.json')), metadata = manifest.metadata, preparation = readPreparation(root);
  verifyStudyInputs(root, metadata);
  const study = openStudy({ root, directory, optIn, bindings: studyBindings(root, preparation, metadata) });
  const calibration = openCalibrationLedger(path.join(directory, 'calibration.json'));
  storage.watch([directory, path.join(root, '.artifacts/local-evals/admission')]);
  let active, admission, specification, forward;
  setCancelOwned(async () => {
    signal.controller.abort(new Error('STUDY_STORAGE_CANCELLED'));
    const [forwardRelease, serverRelease] = await Promise.allSettled([stopForward(), active?.stop?.('study-storage-cancelled')]);
    const cleanupVerified = forwardRelease.status === 'fulfilled' && serverRelease.status === 'fulfilled' && (!active?.stop || serverRelease.value?.cleanupVerified === true);
    const output = path.join(directory, 'reports', 'interrupted-' + randomUUID()); mkdirSync(output, { recursive: true, mode: 0o700 });
    const partial = study.report(); writeNew(path.join(output, 'report.json'), partial);
    writeNew(path.join(output, 'cancellation.json'), { cleanupVerified, forward: forwardRelease.status, server: serverRelease.status,
      ...(serverRelease.status === 'fulfilled' ? { server_cleanup_verified: serverRelease.value?.cleanupVerified ?? null } : { server_error: serverRelease.reason?.message }),
      ...(forwardRelease.status === 'rejected' ? { forward_error: forwardRelease.reason?.message } : {}), active_row_retained: study.snapshot().active_row });
    writeStudyAnalysis(output, partial, { studyDirectory: directory });
    if (!cleanupVerified) throw new Error('STUDY_STORAGE_CANCEL_CLEANUP_UNVERIFIED');
  });
  async function stopForward() {
    if (!forward) return;
    const released = await forward.stop('diagnostic-execution-mode-switch');
    if (released.cleanupVerified !== true) throw new Error('FORWARD_RELEASE_UNVERIFIED');
    forward = undefined;
  }
  async function ensureServer() {
    await stopForward();
    if (active && active.status === 'admitted' && !active.stopped) return active;
    const prepared = preparation.models.find(model => model.id === specification.id), runtime = preparation.runtimes.find(runtime => runtime.id === prepared.runtime_id);
    const store = studyAdmissionStore({ directory, manifest, prepared, runtime, deadline: study.snapshot().models[specification.id].deadline });
    const result = await admitStudyModel({ store, calibration, modelId: prepared.id, admit: reuseAdmission => admitModel(root, prepared, runtime, {
      deadline: study.snapshot().models[specification.id].deadline, calibration, reuseAdmission,
      translationRuntime: preparation.runtimes.find(runtime => runtime.id === 'mlx'), onProgress }) });
    active = result.active; admission = result.admission;
    if (active.status === 'admitted') {
      const stop = active.stop; active.stop = async (...args) => { const result = await stop(...args); if (result.cleanupVerified === true) active.stopped = true; return result; };
    }
    return active;
  }
  const report = await runStudy({ study, onProgress: event => onProgress(`${event.type}: ${event.row.model_id}/${event.row.kind}/${event.row.harness_id}/${event.row.scenario_id}/${event.row.seed}/${event.row.condition}`),
    admit: async model => { await storage.check(); verifyStudyInputs(root, metadata); specification = model; active = undefined; admission = undefined; calibration.selectModel(model.id); return ensureServer(); },
    execute: async ({ row, reservation }) => {
      const work = path.join(directory, 'units', row.id); mkdirSync(work, { recursive: true, mode: 0o700 });
      if (row.kind === 'forward') {
        if (admission && admission.status !== 'admitted') return { status: 'blocked', reason: admission.reason ?? 'FROZEN_MECHANICAL_ADMISSION_BLOCKED', owned_cleanup_verified: admission.cleanup?.cleanupVerified === true };
        if (active?.stop && !active.stopped) {
          const released = await active.stop('diagnostic-forward-mode-switch');
          if (released.cleanupVerified !== true) throw new Error('SERVER_RELEASE_UNVERIFIED');
        }
        const prepared = preparation.models.find(model => model.id === row.model_id), runtime = preparation.runtimes.find(runtime => runtime.id === prepared.runtime_id);
        if (row.seed !== 17) {
          const parityRows = study.manifest.rows.filter(item => item.kind === 'forward' && item.model_id === row.model_id && item.seed === 17 && item.condition === 'instrumented-forward');
          if (parityRows.some(item => study.snapshot().rows[item.id]?.result?.parity?.status !== 'passed')) return { status: 'blocked', reason: 'INSTRUMENTATION_PARITY_UNVERIFIED', owned_cleanup_verified: true };
        }
        forward ??= await createForwardSupervisor(root, prepared, runtime, { directory: path.join(directory, 'forward-workers', row.model_id + '-' + randomUUID()), deadline: study.snapshot().models[row.model_id].deadline, readyTimeoutMs: Math.max(1, reservation.deadline - Date.now()), optIn });
        const captured = read(metadata.captures[`${row.model_id}/${row.harness_id}/${row.scenario_id}`].original.path);
        const skill = row.scenario_id === 'S2' ? 'ud-edit' : 'ud-compare', skillText = readFileSync(path.join(metadata.installation, 'skills', skill, 'SKILL.md'), 'utf8');
        const description = /^description: (.+)$/m.exec(skillText)?.[1], skillBody = skillText.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
        const nativeRow = study.manifest.rows.find(item => item.kind === 'native' && item.model_id === row.model_id && item.harness_id === row.harness_id && item.scenario_id === row.scenario_id && item.seed === row.seed && item.condition === 'current');
        const nativeReceipt = nativeRow ? study.snapshot().rows[nativeRow.id]?.result?.evidence?.[0] : undefined;
        const probeRow = study.manifest.rows.find(item => item.kind === 'probe' && item.model_id === row.model_id && item.harness_id === row.harness_id && item.scenario_id === row.scenario_id && item.seed === row.seed && item.condition === 'unchanged');
        const initialProbeReceipt = probeRow ? study.snapshot().rows[probeRow.id]?.result?.evidence?.[0] : undefined;
        const selected = selectMechanisticPrefix({ row, captured, skillBody, nativeReceipt, initialProbeReceipt,
          nativeEpisode: nativeReceipt ? readObservation(nativeReceipt) : undefined, initialProbe: initialProbeReceipt ? readObservation(initialProbeReceipt) : undefined, root });
        const instrument = row.condition === 'instrumented-forward', collect = instrument || row.seed !== 17;
        const representation = instrument && row.seed === 47 ? representationContrast(selected.body) : null;
        const request = { request: representation?.body ?? selected.body, ...(representation ? { input_intervention: representation.intervention } : {}), prefix_source: selected.source, span_texts: [{ name: 'user-intent', text: SCENARIOS.find(item => item.id === row.scenario_id).prompt },
          ...(description ? [{ name: 'relevant-skill-metadata', text: description }] : []),
          ...(observedSkillBody(selected.body, skillBody) ? [{ name: 'activated-skill-body', text: skillBody }] : [])],
          continuation: row.harness_id === 'qwen-code' ? 'tool_search' : 'ud-agent', instrument: collect,
          ...(instrument && row.seed === 23 ? { intervention: { kind: 'zero_operator_last_position', layer: row.model_id === 'lfm3' ? 23 : 22 } } : {}) };
        const output = await forward.run(request, { deadline: reservation.deadline });
        let parity, componentEffect;
        if (instrument && row.seed === 17) {
          const reference = study.manifest.rows.find(item => item.kind === 'forward' && item.block === row.block && item.condition === 'reference-forward');
          const prior = study.snapshot().rows[reference.id]?.result;
          const priorFile = prior?.evidence?.[0]?.path;
          parity = priorFile ? compareForwardResults(readObservation(prior.evidence[0]).response, output) : { status: 'unverified', reason: 'REFERENCE_FORWARD_MISSING' };
        }
        if (instrument && row.seed !== 17) {
          const reference = study.manifest.rows.find(item => item.kind === 'forward' && item.block === row.block && item.condition === 'reference-forward');
          const prior = study.snapshot().rows[reference.id]?.result, priorFile = prior?.evidence?.[0]?.path;
          componentEffect = priorFile ? measureForwardEffect(readObservation(prior.evidence[0]).response, output, { inputIntervention: representation?.intervention }) : { status: 'unverified', reason: 'REFERENCE_FORWARD_MISSING' };
        }
        return { status: output.status === 'observed' && (!parity || parity.status === 'passed') ? 'observed' : 'blocked', reason: output.reason ?? (parity && parity.status !== 'passed' ? 'INSTRUMENTATION_PARITY_FAILED' : undefined),
          evidence: [output.evidence], counters: { inference: 0, tools: 0, ud_operations: 0, input: output.forward_tokens ?? null, output: 0 },
          parity, component_effect: componentEffect, input_intervention: representation?.intervention ?? null, prefix_source: selected.source, forward_observation: { attention_layers: output.attention?.length ?? null, hybrid_layers: output.hybrid?.length ?? null,
            span_observations: output.span_observations, intervention_scope: output.intervention_scope, marker_likelihood_only: true },
          owned_cleanup_verified: true };
      }
      const model = await ensureServer();
      if (model.status !== 'admitted') return { status: 'blocked', reason: model.reason, owned_cleanup_verified: model.cleanup?.cleanupVerified === true };
      if (row.kind === 'probe') return executeProbe({ root, directory: work, row, reservation, resident: model, metadata });
      const installation = row.condition === 'current' ? metadata.installation : metadata.variant_installation;
      const rowInstallation = row.condition === 'current' ? metadata.installed : { sha256: metadata.interventions_sha256 };
      const episode = await runEpisode(root, { signal: signal.controller.signal, deadline: reservation.deadline + 45 * 60_000, phase_allocations_ms: { reconciliation: 45 * 60_000 }, installation: rowInstallation },
        { ...row, row_id: row.id, skills_enabled: true, snapshot: 'diagnostic', study_variant: row.condition }, model,
        metadata.harnesses.find(harness => harness.id === row.harness_id), installation, work);
      const evidence = persist(path.join(work, 'episode.json'), episode), nativeObservation = nativeEpisodeObservation(root, row, episode);
      return { status: episode.outcome === 'passed' ? 'observed' : 'incomplete', reason: episode.reason || episode.outcome,
        stages: nativeObservation.stages, native_observation: nativeObservation,
        independent_verification: { status: episode.verification?.status, ...persist(path.join(work, 'verification.json'), episode.verification ?? null) },
        counters: episode.metrics?.counters, evidence: [evidence, ...(episode.evidence?.backend_generations ?? [])], owned_cleanup_verified: episode.owned_cleanup_verified === true };
    },
    release: async () => { await stopForward(); const cleanup = await active?.stop?.('diagnostic-model-block-finished'); const evidence = persist(path.join(directory, `release-${specification.id}-${randomUUID()}.json`), cleanup ?? { model_never_loaded: true });
      return { owned_cleanup_verified: active?.stop ? cleanup?.cleanupVerified === true : active?.cleanup?.cleanupVerified === true, ...evidence }; },
    shouldStart: async (row, state) => {
      await storage.check(); const forecast = forecastStudyBlock({ manifest: study.manifest, state, row });
      persist(path.join(directory, 'forecasts', row.id + '-' + randomUUID() + '.json'), forecast);
      onProgress(`comparison-block-forecast: ${JSON.stringify(forecast)}`); return forecast.allowed;
    },
  });
  const output = path.join(directory, 'reports', randomUUID()); mkdirSync(output, { recursive: true, mode: 0o700 });
  writeNew(path.join(output, 'report.json'), report);
  const analysis = writeStudyAnalysis(output, report, { studyDirectory: directory });
  return { directory, analysis: analysis.json, readable_analysis: analysis.markdown, report: path.join(output, 'report.json'), counts: report.counts };
}

async function withScientificStorage(root, phase, options, execute) {
  assertOptIn({ optIn: options?.optIn });
  const signal = { controller: new AbortController() }; let cancelOwned = async () => signal.controller.abort(new Error('STUDY_STORAGE_CANCELLED'));
  const storage = scientificStudyStorage(root, phase, { onCancel: () => cancelOwned() });
  try {
    const result = await execute(root, { ...options, storage, signal, setCancelOwned: callback => { cancelOwned = callback; } });
    await storage.check(); return result;
  } finally { await storage.cleanup(); }
}
export async function prepareScientificStudy(root, options = {}) { return withScientificStorage(root, 'prepare', options, prepareScientificStudyImpl); }
export async function runScientificStudy(root, options = {}) { return withScientificStorage(root, 'run', options, runScientificStudyImpl); }
