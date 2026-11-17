/** Study execution projections and identity checks; no model admission. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { installationIdentity, measureForwardEffect, probeObservation, verifyStudyInputs } from '../../evals/local/study-execution.mjs';
const row = { scenario_id: 'S3', condition: 'unchanged' };
const declaration = (name, required, properties) => ({ type: 'function', function: { name, parameters: { type: 'object', properties, required, additionalProperties: false } } });
const request = { model: 'exact', messages: [{ role: 'system', content: 'ud-compare: prediction scoring' }], tools: [
  declaration('bash', ['command'], { command: { type: 'string' } }), declaration('tool_search', ['query'], { query: { type: 'string' } }),
  declaration('skill', ['skill'], { skill: { type: 'string' } }),
] };
const events = calls => [{ type: 'upstream_request', body: request }, { type: 'native_calls_admitted', calls }, { type: 'model_visible_response', body: { choices: [{ message: { content: 'I might use tool_search for this.' } }] } }];
test('semantic probe classification uses actual declared schema-valid relevant calls, never narrative mentions', () => {
  const none = probeObservation(process.cwd(), row, events([])); assert.equal(none.stages.discovery, false); assert.equal(none.stages.valid_call, false);
  const generic = probeObservation(process.cwd(), row, events([{ id: 'one', name: 'bash', arguments: { command: 'ls -la' } }]));
  assert.equal(generic.syntax_valid_calls, 1); assert.equal(generic.stages.valid_call, false);
  const relevant = probeObservation(process.cwd(), row, events([{ id: 'two', name: 'tool_search', arguments: { query: 'prediction scoring' } }]));
  assert.equal(relevant.stages.discovery, true); assert.equal(relevant.stages.valid_call, true); assert.equal(relevant.stages.dispatch, null);
  const bad = probeObservation(process.cwd(), row, events([{ id: 'two', name: 'tool_search', arguments: { typo: 'prediction scoring' } }]));
  assert.equal(bad.syntax_valid_calls, 0); assert.equal(bad.stages.valid_call, false);
  const echo = probeObservation(process.cwd(), row, events([{ id: 'one', name: 'bash', arguments: { command: "echo 'ud-agent --help'" } }])); assert.equal(echo.stages.discovery, false);
  const shell = probeObservation(process.cwd(), row, events([{ id: 'one', name: 'bash', arguments: { command: 'which ud-agent && ud-agent --help' } }])); assert.equal(shell.stages.discovery, true);
});
test('component intervention effect measures marker likelihood and logit changes without a parity verdict', () => {
  const before = { status: 'observed', next_logits: [0, 2, 1], continuation_log_probabilities: [-2, -1] };
  const after = { status: 'observed', next_logits: [3, 1, 1], continuation_log_probabilities: [-1, -0.5] };
  const result = measureForwardEffect(before, after); assert.equal(result.status, 'observed'); assert.equal(result.top1_changed, true);
  assert.equal(result.maximum_absolute_logit_delta, 3); assert.equal(result.continuation_log_likelihood.delta, 1.5); assert.equal(result.logit_delta_l2, Math.sqrt(10));
  assert.equal(measureForwardEffect(before, { status: 'blocked' }).status, 'unverified'); assert.ok(result.scope.includes('not complete action'));
});
test('capture, analysis, proposal and exact installed bytes are independently reverified before live admission', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-study-inputs-'));
  try {
    const persist = (name, value) => { const file = path.join(root, name), bytes = JSON.stringify(value); writeFileSync(file, bytes); return { path: file, sha256: sha256(bytes) }; };
    const installation = path.join(root, 'installed'), variant = path.join(root, 'variant'); mkdirSync(installation); mkdirSync(variant); writeFileSync(path.join(installation, 'program'), 'current'); writeFileSync(path.join(variant, 'program'), 'variant');
    const selected = { body: request }, capture = { selected, selected_sha256: sha256(JSON.stringify(selected)), inference: false, owned_cleanup_verified: true };
    const cap = { ...persist('capture.json', capture), request_sha256: capture.selected_sha256 };
    const analysis = persist('analysis.json', {}), interventions = persist('interventions.json', {}), proposal = persist('manifest.json', { files: [], compiled: [] });
    const metadata = { analysis, analysis_sha256: analysis.sha256, interventions, interventions_sha256: interventions.sha256, proposal,
      installation, installed: installationIdentity(installation), variant_installation: variant, variant_installed: installationIdentity(variant), captures: { block: { original: cap } } };
    assert.equal(verifyStudyInputs(root, metadata).status, 'verified');
    writeFileSync(path.join(variant, 'program'), 'tampered'); assert.throws(() => verifyStudyInputs(root, metadata), /INSTALLED_BYTES_CHANGED/);
    writeFileSync(path.join(variant, 'program'), 'variant'); writeFileSync(cap.path, '{}'); assert.throws(() => verifyStudyInputs(root, metadata), /INPUT_BYTES_CHANGED/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('mechanistic prefixes use accepted current-native result states and their own subsequent choice', async () => {
  const { selectMechanisticPrefix } = await import('../../evals/local/study-execution.mjs');
  const skillBody = '# Canonical comparison\nUse registered prediction scoring.';
  const captured = { selected: { body: request } }, resultBody = { ...structuredClone(request), messages: [...request.messages, { role: 'tool', content: 'Actual directory error' }] }, skillRequest = { ...structuredClone(request), messages: [...resultBody.messages, { role: 'tool', content: skillBody }] };
  const response = id => ({ type: 'model_visible_response', id, body: { choices: [{ message: { content: 'Continue' } }] } });
  const nativeEpisode = { events: [
    { type: 'provider_received', id: 'context-rejected', body: skillRequest },
    { type: 'upstream_request', id: 'first', body: request }, response('first'),
    { type: 'upstream_request', id: 'result', body: resultBody },
    { type: 'native_calls_admitted', calls: [{ id: 'search', name: 'tool_search', arguments: { query: 'prediction scoring' } }] }, response('result'),
    { type: 'upstream_request', id: 'skill', body: skillRequest },
    { type: 'native_calls_admitted', calls: [{ id: 'generic', name: 'bash', arguments: { command: 'ls' } }] }, response('skill'),
  ] };
  const base = { row: { ...row, seed: 23 }, captured, nativeEpisode, skillBody, nativeReceipt: { path: 'episode.json', sha256: 'a'.repeat(64) } };
  const result = selectMechanisticPrefix(base); assert.equal(result.source.request_id, 'result'); assert.equal(result.source.observed_valid_next_action, true); assert.equal(result.source.fallback, false);
  const activated = selectMechanisticPrefix({ ...base, row: { ...row, seed: 47 } }); assert.equal(activated.source.request_id, 'skill'); assert.equal(activated.source.observed_valid_next_action, false);
  assert.deepEqual(selectMechanisticPrefix({ ...base, row: { ...row, seed: 47, condition: 'reference-forward' } }).body, selectMechanisticPrefix({ ...base, row: { ...row, seed: 47, condition: 'instrumented-forward' } }).body);
  const fallback = selectMechanisticPrefix({ ...base, row: { ...row, seed: 47 }, skillBody: 'Not present' }); assert.equal(fallback.source.request_id, 'result'); assert.equal(fallback.source.fallback, true);
  const rejected = selectMechanisticPrefix({ ...base, nativeEpisode: { events: nativeEpisode.events.slice(0, 1) } }); assert.equal(rejected.source.request_id, null); assert.equal(rejected.source.observed_valid_next_action, null);
  const missing = selectMechanisticPrefix({ ...base, nativeEpisode: { events: nativeEpisode.events.filter(event => event.id !== 'result' || event.type !== 'model_visible_response') } }); assert.equal(missing.source.observed_valid_next_action, null);
});

test('representation contrast preserves exact decoded CoNLL-U and returncode, and leaves instructions/non-data untouched', async () => {
  const { representationContrast } = await import('../../evals/local/study-execution.mjs');
  const data = '# sent_id = sample\n# text = Birds fly\n1\tBirds\tbird\tNOUN\t_\t_\t2\tnsubj\t_\t_\n2\tfly\tfly\tVERB\t_\t_\t0\troot\t_\t_\n\n';
  const original = { messages: [{ role: 'user', content: 'Compare supplied data.' }, { role: 'tool', content: JSON.stringify({ returncode: 0, output: data }) }, { role: 'tool', content: [{ type: 'text', text: data }] }, { role: 'tool', content: '# Skill\nUse tools.\n```conllu\n' + data + '```' }] };
  const before = structuredClone(original), result = representationContrast(original);
  assert.equal(result.intervention.mapping.length, 2); assert.equal(result.intervention.sham, false);
  assert.ok(result.body.messages[1].content.includes('Native shell returncode: 0\n')); assert.ok(result.body.messages[1].content.includes('\n' + data + '\n</conllu-file-content>'));
  assert.equal(result.intervention.mapping[0].decoded_bytes_sha256, sha256(data)); assert.equal(result.intervention.mapping[0].decoded_bytes, Buffer.byteLength(data));
  assert.equal(result.body.messages[0].content, original.messages[0].content); assert.equal(result.body.messages[3].content, original.messages[3].content); assert.deepEqual(original, before);
  const sham = representationContrast({ messages: [{ role: 'tool', content: 'Regular directory listing.' }] }); assert.equal(sham.intervention.sham, true); assert.equal(sham.intervention.source_request_sha256, sham.intervention.effective_request_sha256);
  const extra = { messages: [{ role: 'tool', content: JSON.stringify({ returncode: 0, output: data, important_extra: 'preserve' }) }] }; assert.deepEqual(representationContrast(extra).body, extra); assert.equal(representationContrast(extra).intervention.sham, true);
});
test('mechanical admission resumes four-spent calibration without new requests, and caches blockers', async () => {
  const { studyAdmissionStore, admitStudyModel } = await import('../../evals/local/study-execution.mjs');
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-study-admission-'));
  try {
    const manifest = { id: 'frozen-study', bindings: { source: 'exact' } }, prepared = { id: 'minicpm', directory: '/exact/model' }, runtime = { id: 'exact-runtime', sha256: 'exact' };
    const store = studyAdmissionStore({ directory: root, manifest, prepared, runtime, deadline: 123 });
    const original = { status: 'admitted', artifact: 'exact', admission_kind: 'mechanical' }; store.save(original);
    let inference = 0, charged = 0;
    const result = await admitStudyModel({ store, calibration: { per_model: { minicpm: 4 }, onCharge() { charged++; } }, modelId: 'minicpm', admit: async prior => { assert.deepEqual(prior, original); if (!prior) { inference++; charged++; } return { ...prior, current_server: true }; } });
    assert.equal(result.reused, true); assert.equal(inference, 0); assert.equal(charged, 0);
    const changed = studyAdmissionStore({ directory: root, manifest: { ...manifest, bindings: { source: 'changed' } }, prepared, runtime, deadline: 123 }); assert.throws(() => changed.load(), /BINDING_CHANGED/);
    const blockedRoot=path.join(root,'blocked');mkdirSync(blockedRoot);const blockedStore=studyAdmissionStore({directory:blockedRoot,manifest,prepared,runtime,deadline:123});blockedStore.save({status:'model_blocked',reason:'mechanical failure',cleanup:{cleanupVerified:false}});
    const blocked=await admitStudyModel({store:blockedStore,calibration:{per_model:{minicpm:4}},modelId:'minicpm',admit:async()=>{throw new Error('Must not retry or load forwards');}}); assert.equal(blocked.active.status,'model_blocked');assert.equal(blocked.active.cleanup.cleanupVerified,false);
    const partialRoot=path.join(root,'partial');mkdirSync(partialRoot);const partialStore=studyAdmissionStore({directory:partialRoot,manifest,prepared,runtime,deadline:123});await assert.rejects(admitStudyModel({store:partialStore,calibration:{per_model:{minicpm:1}},modelId:'minicpm',admit:async()=>{throw new Error('Must not run');}}),/PARTIAL_ADMISSION_UNRECONCILED/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test('an upstream attempt alone never establishes real inference, while trusted generation receipts do', async () => {
 const {probeInferenceEvidence}=await import('../../evals/local/study-execution.mjs');
 assert.equal(probeInferenceEvidence([{type:'upstream_request'}],{observations:[]}).real_inference,null);
 assert.equal(probeInferenceEvidence([],{}).real_inference,false);
 assert.equal(probeInferenceEvidence([{type:'upstream_request'}],{observations:[{status:'observed',generated_tokens:512,parser_status:'rejected',termination:'length'}]}).real_inference,true);
 assert.equal(probeInferenceEvidence([{type:'model_visible_response',outputTokens:12}],{}).real_inference,true);
});

test('native episode observations retain missing stages, optional activation and exact-repeat recovery distinctions', async () => {
  const { nativeEpisodeObservation } = await import('../../evals/local/study-execution.mjs');
  const call=id=>({type:'native_calls_admitted',calls:[{id,name:'tool_search',arguments:{query:'prediction scoring'}}]});
  const episode={observations:{complete:true,skill_activation:false},verification:{status:'failed'},events:[
    {type:'upstream_request',id:'a',body:request},call('call1'),{type:'model_visible_response',id:'a',body:{choices:[{finish_reason:'tool_calls'}]}},
    {type:'native_result_observed',id:'call1',failed:true},{type:'response_loss'},
    {type:'upstream_request',id:'b',body:request},call('call2'),{type:'model_visible_response',id:'b',body:{choices:[{finish_reason:'tool_calls'}]}},
    {type:'gateway_rejection',reason:'BUDGET_EXCEEDED_OUTPUT'},
  ]};
  const result=nativeEpisodeObservation(process.cwd(),row,episode);assert.equal(result.stages.discovery,true);assert.equal(result.stages.activation,false);assert.equal(result.stages.dispatch,null);
  assert.equal(nativeEpisodeObservation(process.cwd(),row,{...episode,events:episode.events.filter(event=>event.type!=='gateway_rejection')}).stages.dispatch,false);
  assert.equal(result.first_known_failure.reason,'native-tool-returned-error');assert.equal(result.repeated_exact_call_count,1);assert.equal(result.repeated_exact_calls[0].classification,'possible-required-response-loss-recovery');assert.equal(result.proven_redundant_attempts,null);
  assert.equal(result.competing_termination_observations.gateway_rejections.BUDGET_EXCEEDED_OUTPUT,1);
  const incomplete=nativeEpisodeObservation(process.cwd(),row,{events:[{type:'upstream_request',id:'missing',body:request}],observations:{complete:false}});
  assert.equal(incomplete.stages.discovery,null);assert.equal(incomplete.stages.dispatch,null);assert.equal(incomplete.first_known_failure.stage,null);
});
