/** MIT. Private, independent oracles for the opt-in local native-agent campaign.
 * Never mount this module, expected values, or verifier state in the agent task root.
 */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';
import { projectWordingSuggestion } from './wording-oracle.mjs';

const fixtureRoot = fileURLToPath(new URL('./fixtures/', import.meta.url));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fixture = (name) => readFileSync(path.join(fixtureRoot, name));
const editExpected = Buffer.from('# sent_id = edit-1\n# text = Swallows fly\n1\tSwallows\tswallow\tNOUN\t_\t_\t2\tnsubj\t_\t_\n2\tfly\tfly\tVERB\t_\t_\t0\troot\t_\t_\n\n');
const releaseReadme = 'English starter treebank. Local handover fixture; no official release acceptance is asserted.\n';
const releaseLicense = 'SPDX-License-Identifier: MIT\nThis synthetic fixture is licensed under MIT.\n';
const scopeIds = ['news-1', 'news-2', 'news-3'];

export const SCENARIOS = Object.freeze([
  { id: 'S1', family: 'ud-validate', prompt: 'Check a.conllu and b.conllu as one English CoNLL-U dataset for annotation structure and cross-file sentence-identifier errors. Explain each failure with its file and sentence, and say what was checked. Leave all inputs unchanged.',
    files: { 'a.conllu': fixture('invalid-a.conllu'), 'b.conllu': fixture('invalid-b.conllu') },
    expected: { invalid: true, duplicateSentId: 'duplicate', invalidHead: { file: 'b.conllu', tokenId: '1', head: '9' } }, outputs: [] },
  { id: 'S2', family: 'ud-edit', prompt: 'In edit.conllu, sentence edit-1, change token 1 FORM from Birds to Swallows and LEMMA from bird to swallow. Set sentence text to Swallows fly. Apply exactly those changes, validate the resulting English CoNLL-U candidate, and report whether the correction actually completed. Leave other fields unchanged.',
    files: { 'edit.conllu': fixture('edit.conllu') }, expected: { bytes: editExpected }, outputs: ['edit.conllu'] },
  { id: 'S3', family: 'ud-compare', prompt: 'Compare predictions.conllu against gold.conllu as the reference. Report UAS and LAS with the eligible ordinary-token denominator, and explain every attachment or relation mismatch with sentence and token identifiers. Include the root token in the denominator. Leave both files unchanged.',
    files: { 'gold.conllu': fixture('gold.conllu'), 'predictions.conllu': fixture('predictions.conllu') },
    expected: { denominator: 5, uasCorrect: 4, lasCorrect: 3, mismatches: ['1', '2'] }, outputs: [] },
  { id: 'S4', family: 'ud-investigate', prompt: 'Read project-brief.txt and investigate corpus.conllu for exactly the requested subset. Calculate how often nominal subjects precede their heads, give sentence/token examples for both orders, and explain the eligible-relation denominator. Leave the inputs unchanged.',
    files: { 'corpus.conllu': fixture('corpus.conllu') }, expected: { scope: scopeIds, numerator: 2, denominator: 3 }, outputs: [] },
  { id: 'S5', family: 'ud-rules-docs', prompt: 'Inspect diagram.png. Explain the highlighted red dependency arc, identifying its relation, head, and dependent. Check it against the local example in guidelines.md and prepare a local guideline preview under preview/. Leave the source files unchanged.',
    files: { 'diagram.png': fixture('diagram.png'), 'guidelines.md': fixture('guidelines.md') },
    expected: { relation: 'obj', head: 'chased', dependent: 'mice' }, outputs: ['preview/'] },
  { id: 'S6', family: 'ud-release', prompt: 'Assess this English treebank and prepare a local handover for target release local-eval-1 under handover/. Include exactly treebank.conllu, README.md, and LICENSE, plus generated package metadata. Report package contents and hashes, which checks completed against the packaged bytes, and which official readiness requirements remain unassessed. Keep the preparation local and preserve the inputs.',
    files: { 'treebank.conllu': fixture('release.conllu'), 'README.md': Buffer.from(releaseReadme), LICENSE: Buffer.from(releaseLicense) },
    expected: { target: 'local-eval-1' }, outputs: ['handover/'] },
  { id: 'S7', family: null, prompt: 'Please validate the wording of the ordinary quarterly business report in report.txt and suggest clearer phrasing. Preserve its facts and leave the file unchanged.',
    files: { 'report.txt': fixture('report.txt') }, expected: { facts: ['40', '55', 'Friday'] }, outputs: [] },
].map((scenario) => Object.freeze(scenario)));

/** Broker/adapter-owned facts, never facts supplied by the model itself. */
export const OBSERVATION_CONTRACT = Object.freeze({
  common: 'complete:true; events include observed ud_operation records and no additional user_hint; before/after use captureWorkspace; finalAnswer is the actual native final response',
  S1: 'runtime:{initiallyReady:false,preparationAttempts:1,resumed:true,reusedAssets:true}; validation:{execution:"completed",passed:false,checkedFiles:["a.conllu","b.conllu"],checks:["content","identifiers"],inputHashes:{path:sha256},findings:[{kind:"duplicate-sent-id",sentId:"duplicate"},{kind:"head-out-of-range",file:"b.conllu",tokenId:"1",head:"9"}]}',
  S2: 'validation:{execution:"completed",passed:true,inputHashes:{"edit.conllu":sha256}}; mutation:{commits:[{operationId,beforeSha256,afterSha256}],responseLosses:1,reconciled:true,duplicateEffects:0}; commits describe effects, not transport attempts',
  S3: 'comparison:{gold:"gold.conllu",prediction:"predictions.conllu",denominator:5,uasCorrect:4,lasCorrect:3,mismatchTokenIds:["1","2"]}',
  S4: 'investigation:{scope:["news-1","news-2","news-3"],numerator:2,denominator:3,examples:[{sentId:"news-1",tokenId:"1",head:"2"},{sentId:"news-2",tokenId:"2",head:"1"}]}; context:{inputTokens,outputReserve:512,envelope:32768}; inputTokens must exceed 16384',
  S5: 'vision:{imageSha256,modelReceivedImage:true,relation:"obj",head:"chased",dependent:"mice",checkedGuideline:"guidelines.md",previewPaths:["preview/..."]}; preview paths must be actual HTML or SVG graph artifacts',
  S6: 'release:{archivePath:"handover/...tar",archiveSha256,validation:{execution:"completed",passed:true,inputHashes:{"treebank.conllu":sha256}},missingChecks:[nonempty descriptions]}; actual tar is independently parsed and compared to fixture bytes',
  S7: 'complete native skill activation/tool telemetry; ordinary final response retains factual numbers and Friday and proposes clearer wording',
});

function scenarioFor(id) {
  const scenario = SCENARIOS.find((entry) => entry.id === id);
  if (!scenario) throw new Error(`UNKNOWN_LOCAL_SCENARIO:${id}`);
  return scenario;
}

function brief(estimatedTokens) {
  if (!Number.isSafeInteger(estimatedTokens) || estimatedTokens < 256 || estimatedTokens > 30_000) throw new Error('INVALID_EXTENDED_BRIEF_SIZE');
  const first = 'Project scope: use only genre=news sentences in corpus.conllu. Count ordinary-word nominal-subject (nsubj) relations. A subject precedes its head when its numeric token ID is smaller than the numeric HEAD. The denominator is all eligible nsubj relations, including those following their heads. Exclude fiction.\n\n';
  const note = 'Archive note: retain the meeting notes for the next planning review. This note changes no corpus selection.\n';
  // This is an estimate for fixture construction, not a tokenizer measurement.
  const middle = note.repeat(Math.max(1, Math.ceil((estimatedTokens - 128) / 21)));
  return Buffer.from(first + middle + '\nFinal scope reminder: use only news-1, news-2, news-3; exclude fiction-1. Give examples for both orders.\n');
}

function assertSafeRoot(root) {
  const absolute = path.resolve(root);
  if (absolute === path.parse(absolute).root || fixtureRoot.startsWith(`${absolute}${path.sep}`) || absolute.startsWith(fixtureRoot)) throw new Error('UNSAFE_TASK_ROOT');
  let current = absolute;
  while (true) {
    try { if (lstatSync(current).isSymbolicLink()) throw new Error('TASK_ROOT_SYMLINK'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (current === path.dirname(current)) break;
    current = path.dirname(current);
  }
  return absolute;
}

/** Materializes inputs only. A fresh, empty root is required for every episode. */
export async function createScenario(id, taskRoot, { extendedTokens = 20_000 } = {}) {
  const scenario = scenarioFor(id);
  const root = assertSafeRoot(taskRoot);
  await mkdir(root, { recursive: true, mode: 0o700 });
  if (readdirSync(root).length) throw new Error('TASK_ROOT_NOT_EMPTY');
  const files = { ...scenario.files };
  if (id === 'S4') files['project-brief.txt'] = brief(extendedTokens);
  for (const [name, bytes] of Object.entries(files)) await writeFile(path.join(root, name), bytes, { flag: 'wx', mode: 0o600 });
  const before = captureWorkspace(root);
  return { id, taskRoot: root, prompt: scenario.prompt, images: id === 'S5' ? [{ path: 'diagram.png', mediaType: 'image/png' }] : [],
    before, fixtureSha256: sha256(JSON.stringify(before.files.map(({ path: name, sha256: digest }) => [name, digest]))),
    context: id === 'S4' ? { estimatedBriefTokens: extendedTokens, requiresMeasuredTokens: true, envelope: 32_768, outputReserve: 512 } : undefined };
}

function safeFile(root, name, maxBytes = 10 * 1024 * 1024) {
  if (typeof name !== 'string' || !name || name.includes('\\') || path.isAbsolute(name) || name.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('UNSAFE_ARTIFACT_PATH');
  let current = root;
  for (const segment of name.split('/')) {
    current = path.join(current, segment);
    if (lstatSync(current).isSymbolicLink()) throw new Error('ARTIFACT_SYMLINK');
  }
  const info = lstatSync(current);
  if (!info.isFile() || info.size > maxBytes) throw new Error('ARTIFACT_SIZE_OR_TYPE');
  return readFileSync(current);
}

function readTar(bytes) {
  if (bytes.length > 10 * 1024 * 1024 || bytes.length % 512) throw new Error('INVALID_TAR_SIZE');
  const files = new Map();
  let offset = 0;
  const str = (buffer) => buffer.toString('utf8').replace(/\0.*$/s, '');
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (!bytes.subarray(offset).every((byte) => byte === 0)) throw new Error('TAR_TRAILING_DATA');
      return files;
    }
    const sumText = str(header.subarray(148, 156)).trim();
    const sizeText = str(header.subarray(124, 136)).trim();
    if (!/^[0-7]+$/.test(sumText) || !/^[0-7]+$/.test(sizeText)) throw new Error('TAR_INVALID_NUMBER');
    const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== Number.parseInt(sumText, 8)) throw new Error('TAR_CHECKSUM');
    const size = Number.parseInt(sizeText, 8);
    const prefix = str(header.subarray(345, 500));
    const name = `${prefix ? `${prefix}/` : ''}${str(header.subarray(0, 100))}`;
    if (!name || name.startsWith('/') || name.includes('\\') || name.split('/').some((p) => p === '..' || p === '.' || !p) || files.has(name)) throw new Error('TAR_UNSAFE_MEMBER');
    if (header[156] !== 0 && header[156] !== 48) throw new Error('TAR_NON_REGULAR_MEMBER');
    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > bytes.length) throw new Error('TAR_MEMBER_BOUNDS');
    files.set(name, bytes.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
    if (files.size > 32) throw new Error('TAR_MEMBER_LIMIT');
  }
  throw new Error('TAR_MISSING_TERMINATOR');
}

function sameSet(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && new Set(actual).size === actual.length && expected.every((value) => actual.includes(value));
}
function presentEqual(actual, expected) { return actual === undefined ? null : actual === expected; }
function known(condition, value) { return value === undefined ? null : condition; }
function digestMap(snapshot) { return new Map(snapshot?.files?.map((file) => [file.path, file]) ?? []); }

const objectValue = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
function stringsIn(value, output = [], depth = 0) {
  if (depth > 30 || output.length > 30_000) return output;
  if (typeof value === 'string') {
    output.push(value);
    // Native shell tools may serialize their result as JSON text. Decode that
    // representation for evidence matching without changing any model traffic.
    if (value.length <= 1_000_000 && /^\s*[\[{]/.test(value)) {
      try { stringsIn(JSON.parse(value), output, depth + 1); } catch { /* Keep opaque text as observed. */ }
    }
  }
  else if (Array.isArray(value)) for (const entry of value) stringsIn(entry, output, depth + 1);
  else if (objectValue(value)) for (const entry of Object.values(value)) stringsIn(entry, output, depth + 1);
  return output;
}
function normalizedIncidents(incidents, inputs, { taskRoot, envelope } = {}) {
  if (!Array.isArray(incidents)) return undefined;
  const names = inputs.map((entry) => entry.path);
  return incidents.map((incident) => {
    const message = typeof incident.message === 'string' ? incident.message : '';
    const location = objectValue(incident.location) ? incident.location : incident;
    let file = location.file_path ?? location.file ?? location.filename;
    if (typeof file === 'string' && !names.includes(file)) {
      const matches = names.filter((name) => file.endsWith(`/${name}`));
      if (matches.length === 1) file = matches[0];
    }
    const sentId = location.sent_id ?? location.sentid ?? location.sentence_id ?? /(?:sent[_ ]id|sentence id)\s*[=:]?\s*['"]?([^'"\s.]+)/i.exec(message)?.[1];
    let tokenId = location.token_id ?? location.nodeid ?? location.node_id;
    if (tokenId == null || ['None', 'null', 'undefined'].includes(String(tokenId))) tokenId = undefined;
    const head = location.head ?? /\bhead(?:\s*\([^)\r\n]{0,80}\))?\s*[=:]?\s*['"]?(\d+)/i.exec(message)?.[1];
    const kind = incident.testid === 'non-unique-sent-id' ? 'duplicate-sent-id' : ['unknown-head', 'head-out-of-range', 'invalid-head'].includes(incident.testid) ? 'head-out-of-range' : incident.testid;
    if (kind === 'head-out-of-range' && tokenId === undefined && typeof file === 'string' && sentId !== undefined && head !== undefined && envelope) {
      const bytes = boundFile(envelope, taskRoot, file);
      const matches = bytes ? [...ordinaryWords(bytes)].filter(([key, columns]) => key.split('\0')[0] === String(sentId) && columns[6] === String(head)) : [];
      if (matches.length === 1) tokenId = matches[0][1][0];
    }
    return { kind, ...(file === undefined ? {} : { file }), ...(sentId === undefined ? {} : { sentId: String(sentId) }),
      ...(tokenId === undefined ? {} : { tokenId: String(tokenId) }), ...(head === undefined ? {} : { head: String(head) }) };
  });
}
function nativeFinished(events, finalAnswer) {
  const adapterComplete = typeof finalAnswer === 'string' && finalAnswer.trim().length > 0 && events.some((event) => event.type === 'native.adapter.completed' && event.source === 'owned-process-and-native-final-output' && typeof event.harness_id === 'string' && events.some((identity) => identity.type === 'native_identity' && identity.harness_id === event.harness_id && identity.cleanupVerified === true && ['native-macos', 'arm64-container'].includes(identity.execution_location)));
  return (adapterComplete || events.some((event) => event.type === 'turn.completed' || event.type === 'result' && (event.subtype === 'success' || event.status === 'success' || event.is_error === false))) &&
    !events.some((event) => ['turn.failed', 'error'].includes(event.type) || event.type === 'result' && (event.is_error === true || event.status === 'error'));
}
function ordinaryWords(bytes) {
  let sentId;
  const rows = new Map();
  for (const line of bytes.toString('utf8').split('\n')) {
    if (line.startsWith('# sent_id = ')) sentId = line.slice(12);
    else if (/^\d+\t/.test(line)) { const fields = line.split('\t'); if (fields.length === 10) rows.set(`${sentId}\0${fields[0]}`, fields); }
  }
  return rows;
}

function boundFile(envelope, taskRoot, name) {
  if (!taskRoot) return undefined;
  try {
    const bytes = safeFile(taskRoot, name);
    return envelope.inputs?.files?.some((entry) => entry.path === name && entry.sha256 === sha256(bytes)) ? bytes : undefined;
  } catch { return undefined; }
}
function exportedFiles(result, taskRoot) {
  return (Array.isArray(result?.exports) ? result.exports : []).flatMap((entry) => {
    if (typeof entry.path !== 'string' || !taskRoot) return [];
    const name = path.isAbsolute(entry.path) ? path.relative(taskRoot, entry.path).split(path.sep).join('/') : entry.path;
    try { const bytes = safeFile(taskRoot, name); return sha256(bytes) === entry.sha256 && bytes.length === entry.size_bytes ? [{ path: name, bytes, sha256: entry.sha256 }] : []; }
    catch { return []; }
  });
}
function imageDigests(value, output = new Set(), depth = 0) {
  if (!value || depth > 30) return output;
  if (Array.isArray(value)) { for (const child of value) imageDigests(child, output, depth + 1); return output; }
  if (!objectValue(value)) return output;
  const dataUrl = typeof value.image_url === 'string' ? value.image_url : value.image_url?.url ?? (value.type === 'input_image' ? value.image_url : undefined);
  const embedded = /^data:image\/(?:png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl ?? '')?.[1];
  const encoded = embedded ?? (value.type === 'image' && value.source?.type === 'base64' && /^image\//.test(value.source.media_type ?? '') ? value.source.data : undefined) ?? (/^image\//.test(value.inlineData?.mimeType ?? '') ? value.inlineData.data : undefined);
  if (typeof encoded === 'string' && encoded.length <= 14 * 1024 * 1024 && /^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) output.add(sha256(Buffer.from(encoded, 'base64')));
  for (const child of Object.values(value)) imageDigests(child, output, depth + 1);
  return output;
}
function observedLocations(value, output = [], depth = 0) {
  if (!value || depth > 30) return output;
  if (Array.isArray(value)) { for (const child of value) observedLocations(child, output, depth + 1); return output; }
  if (!objectValue(value)) return output;
  if (typeof value.file_path === 'string' && typeof value.sent_id === 'string' && typeof value.token_id === 'string') output.push(value);
  for (const child of Object.values(value)) observedLocations(child, output, depth + 1);
  return output;
}

/** Project only captured facts; this function never reads expected oracle values.
 * Raw coordinator events arrive over the authenticated episode budget capability.
 * Native transcripts and provider traffic remain separate evidence from tool results.
 */
export function observeScenario(id, { events = [], nativeEvents = [], traffic = [], before, after, taskRoot, modelBinding, installation, finalAnswer = '', contextEnvelope, outputReserve } = {}) {
  scenarioFor(id);
  const all = [...events, ...nativeEvents, ...traffic];
  const unique = [...new Set(all)];
  const starts = new Map(unique.filter((event) => event.type === 'operation_start').map((event) => [event.operation_id, event]));
  const results = unique.filter((event) => event.type === 'operation_result' && objectValue(event.response?.structuredContent)).map((event) => ({ event, envelope: event.response.structuredContent, start: starts.get(event.operation_id) }));
  const requests = unique.filter((event) => event.type === 'provider_request');
  const responses = unique.filter((event) => event.type === 'provider_response' && event.status >= 200 && event.status < 300);
  const visible = unique.filter((event) => event.type === 'model_visible_response');
  const terminal = nativeFinished(unique, finalAnswer);
  const captured = requests.length > 0 && requests.every((request) => request.tokens?.trusted === true && responses.some((response) => response.id === request.id) && visible.some((response) => response.id === request.id));
  const operationCapture = [...starts.keys()].every((operationId) => results.some(({ event }) => event.operation_id === operationId));
  const complete = terminal && captured && operationCapture && !unique.some((event) => ['gateway_rejection', 'telemetry_gap'].includes(event.type));
  const projected = unique.slice();
  for (const start of starts.values()) projected.push({ type: 'ud_operation', name: start.name, operationId: start.operation_id });
  const observations = { complete, native_loop: terminal || undefined, real_inference: responses.length > 0 || undefined,
    no_user_hints: complete ? !unique.some((event) => event.type === 'user_hint' || event.type === 'user_message' && event.additional === true) : undefined };
  const requestedModels = new Set(requests.map((request) => request.selected_model ?? request.body?.model).filter((name) => typeof name === 'string'));
  const responseModels = new Set(responses.flatMap((response) => {
    const rows = Array.isArray(response.body) ? response.body : [response.body];
    return rows.flatMap((row) => [row?.model, row?.response?.model, row?.message?.model]).filter((name) => typeof name === 'string');
  }));
  if (requestedModels.size === 1 && responseModels.size > 0) observations.model_attribution = [...responseModels].every((name) => requestedModels.has(name));
  if (modelBinding && requestedModels.size === 1 && requestedModels.has(modelBinding.publicModel)) {
    const forwarded = unique.filter(event => event.type === 'upstream_request');
    observations.model_attribution = requests.length > 0 && requests.every((request) => {
      const upstream = forwarded.filter((event) => event.id === request.id);
      const translated = unique.filter((event) => event.type === 'translation_request' && event.id === request.id && event.translated === true);
      if (translated.length) {
        const returned = unique.filter((event) => event.type === 'translation_response' && event.id === request.id && event.translated === true);
        return upstream.length === 1 && translated.length === 1 && translated[0].backend?.model === modelBinding.wireModel && returned.length === 1 && returned[0].backend?.model === modelBinding.wireModel;
      }
      const returned = responses.filter((event) => event.id === request.id).flatMap((event) => Array.isArray(event.body) ? event.body : [event.body]);
      const names = returned.flatMap((row) => [row?.model, row?.response?.model, row?.message?.model, row?.modelVersion]).filter((name) => typeof name === 'string');
      return upstream.length === 1 && upstream[0].body?.model === modelBinding.wireModel && names.length > 0 && names.every((name) => name === modelBinding.wireModel || name === modelBinding.publicModel);
    });
  }
  // Full skill bodies are distinct from startup metadata. Hash equality binds the
  // activation evidence to the installed source content rather than the skill name.
  const requestStrings = requests.flatMap((request) => stringsIn(request.body));
  let activationObserved = false;
  for (const name of ['ud-validate', 'ud-edit', 'ud-compare', 'ud-investigate', 'ud-rules-docs', 'ud-release']) {
    let source;
    // The evaluator's current checkout may differ from the installed baseline.
    // Only the exact installed skill can establish activation for this episode.
    try { source = safeFile(installation, `skills/${name}/SKILL.md`).toString('utf8'); } catch { continue; }
    const body = source.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
    if (body.length > 100 && requestStrings.some((value) => value.includes(body))) {
      activationObserved = true;
      projected.push({ type: 'skill_activation', name, source: 'actual_provider_request', contentSha256: sha256(Buffer.from(body)), installedFileSha256: sha256(Buffer.from(source)) });
    }
  }
  if (activationObserved) observations.skill_activation = true;
  else if (complete) observations.skill_activation = false;

  const validationResults = results.filter(({ envelope }) => envelope.operation === 'validation_report');
  const validationResult = validationResults.at(-1);
  if (validationResult) {
    const { envelope } = validationResult, result = envelope.result;
    const inputs = Array.isArray(envelope.inputs?.files) ? envelope.inputs.files : [];
    const hashes = Object.fromEntries(inputs.filter((entry) => typeof entry.path === 'string' && /^[a-f0-9]{64}$/.test(entry.sha256 ?? '')).map((entry) => [entry.path, entry.sha256]));
    const checks = Object.entries(result.coverage ?? {}).filter(([, state]) => state === 'completed').map(([name]) => name);
    const findings = normalizedIncidents(result.incidents, inputs, { taskRoot, envelope });
    // Malformed graphs can suppress the upstream sentence-ID check. Only an
    // observed identifier finding (or explicit coverage) establishes it here.
    if (checks.includes('content') && findings?.some((finding) => finding.kind === 'duplicate-sent-id') && !checks.includes('identifiers')) checks.push('identifiers');
    observations.validation = { execution: envelope.execution?.status, passed: result.passed, inputHashes: hashes,
      checkedFiles: result.scope?.file_paths ?? envelope.scope?.file_paths, checks, findings };
  }
  if (id === 'S1') {
    // A native agent may correctly supplement validation with a file read.
    // Admit that outcome only when the exact checked bytes reached its actual
    // provider request and its final answer explicitly identifies duplicates.
    if (validationResult && observations.validation && /duplicat|repeat|non.unique/i.test(finalAnswer)) {
      const identifiers = new Map();
      for (const input of validationResult.envelope.inputs?.files ?? []) {
        const bytes = boundFile(validationResult.envelope, taskRoot, input.path);
        if (!bytes || !requestStrings.some((text) => text.includes(bytes.toString('utf8').trim()))) continue;
        for (const match of bytes.toString('utf8').matchAll(/^#\s*sent_id\s*=\s*(.+)$/gm)) {
          const sentId = match[1].trim();
          identifiers.set(sentId, [...(identifiers.get(sentId) ?? []), { file: input.path, sentId }]);
        }
      }
      const duplicates = [...identifiers].filter(([sentId, entries]) => entries.length > 1 && finalAnswer.includes(sentId)).flatMap(([, entries]) => entries);
      if (duplicates.length) {
        observations.validation.findings ??= [];
        observations.validation.findings.push(...duplicates.map((entry) => ({ kind: 'duplicate-sent-id', ...entry, source: 'explicit-agent-conclusion-with-observed-byte-bound-inputs' })));
        if (!observations.validation.checks.includes('identifiers')) observations.validation.checks.push('identifiers');
      }
    }
    const steps = unique.filter((event) => event.type === 'operation_step');
    const preparation = steps.filter((event) => event.step === 'setup_ud_environment');
    const directPreparation = results.filter(({ envelope }) => envelope.operation === 'setup_ud_environment');
    const runtime = {};
    if (complete || preparation.length || directPreparation.length) runtime.preparationAttempts = preparation.length + directPreparation.length;
    const readinessSteps = steps.filter((event) => event.step === 'runtime_readiness' && objectValue(event.observation));
    const initial = readinessSteps.find((event) => event.observation.stage === 'initial')?.observation.result;
    if (typeof initial?.ready === 'boolean') runtime.initiallyReady = initial.ready;
    else if (preparation.length) runtime.initiallyReady = false; // setup step is emitted only after a nonready check.
    if (validationResult && preparation.some((event) => event.operation_id === validationResult.event.operation_id)) runtime.resumed = validationResult.envelope.execution?.status === 'completed';
    if (validationResult && directPreparation.some((row) => row.envelope.result?.ready === true && results.indexOf(row) < results.indexOf(validationResult))) runtime.resumed = validationResult.envelope.execution?.status === 'completed';
    const readiness = unique.filter((event) => event.type === 'runtime_readiness' || event.type === 'runtime_fixture').at(-1);
    if (readiness?.verified === true) {
      if (typeof readiness.initiallyReady === 'boolean') runtime.initiallyReady = readiness.initiallyReady;
      if (typeof readiness.reusedAssets === 'boolean') runtime.reusedAssets = readiness.reusedAssets;
    }
    observations.runtime = runtime;
  }
  if (id === 'S4' && typeof finalAnswer === 'string') {
    const profiles = results.filter(({ envelope }) => envelope.execution?.status === 'completed' && observedLocations(envelope.result).length > 0);
    if (profiles.length) {
      const inputs = [...new Map(profiles.flatMap(({ envelope }) => (envelope.inputs?.files ?? []).map((file) => [file.path, { ...file, envelope }]))).values()];
      const occurrences = profiles.flatMap(({ envelope }) => observedLocations(envelope.result));
      const locations = new Set(occurrences.map((row) => `${row.file_path}\0${row.sent_id}\0${row.token_id}`));
      const explicitGenre = (/(?:only|exclusively)\s+(?:the\s+)?([a-z]+)(?:\s|[.,;])/i.exec(finalAnswer)?.[1]
        ?? /\b([a-z]+)(?:\s+sentences)?\s+only\b/i.exec(finalAnswer)?.[1])?.toLowerCase();
      const examples = [], scope = [];
      if (explicitGenre && /\bnsubj\b|nominal.subject/i.test(finalAnswer)) for (const input of inputs) {
        const bytes = boundFile(input.envelope, taskRoot, input.path);
        if (!bytes) continue;
        for (const block of bytes.toString('utf8').split(/\r?\n\s*\r?\n/)) {
          const sentId = /^# sent_id = (.+)$/m.exec(block)?.[1], genre = /^# genre = (.+)$/m.exec(block)?.[1];
          if (!sentId || genre !== explicitGenre) continue;
          scope.push(sentId);
          for (const line of block.split('\n')) {
            const columns = line.split('\t');
            if (/^\d+$/.test(columns[0]) && columns.length === 10 && columns[7] === 'nsubj' && /^[1-9]\d*$/.test(columns[6]) && locations.has(`${input.path}\0${sentId}\0${columns[0]}`)) examples.push({ sentId, tokenId: columns[0], head: columns[6] });
          }
        }
      }
      if (scope.length && examples.length) observations.investigation = { scope, numerator: examples.filter((row) => Number(row.tokenId) < Number(row.head)).length, denominator: examples.length, examples };
    }
  }
  if (id === 'S5') {
    const previews = results.filter(({ envelope }) => ['guideline_example_preview', 'documentation_preview'].includes(envelope.operation) && envelope.execution?.status === 'completed');
    const vision = {};
    const delivered = requests.map((request) => ({ request, hashes: imageDigests(request.body) })).filter(({ hashes }) => hashes.size);
    if (delivered.length) {
      const hashes = new Set(delivered.flatMap(({ hashes }) => [...hashes]));
      const translations = unique.filter((event) => event.type === 'translation_request' && event.translated === true);
      const upstream = new Set(unique.filter((event) => event.type === 'upstream_request' && !translations.some((translation) => translation.id === event.id)).flatMap((event) => [...imageDigests(event.body)]));
      for (const translation of translations) for (const hash of imageDigests(translation.backend)) upstream.add(hash);
      if (hashes.size === 1 && upstream.has([...hashes][0])) { vision.modelReceivedImage = true; vision.imageSha256 = [...hashes][0]; }
    }
    const matchedPreviews = [];
    for (const { envelope } of previews) {
      const result = envelope.result, sources = result.source ? [result.source] : result.files ?? [];
      for (const source of sources) {
        if (typeof source.file_path !== 'string') continue;
        let bytes;
        try { bytes = safeFile(taskRoot, source.file_path); } catch { continue; }
        if (sha256(bytes) !== source.sha256) continue;
        const words = ordinaryWords(bytes), edges = [];
        for (const [key, word] of words) {
          const head = words.get(`${key.split('\0')[0]}\0${word[6]}`);
          const relationClaimed = new RegExp(`\\b${word[7].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(finalAnswer)
            || word[7] === 'obj' && /\b(?:direct )?object\b/i.test(finalAnswer) || word[7] === 'nsubj' && /\bnominal subject\b/i.test(finalAnswer);
          if (head && finalAnswer.includes(word[1]) && finalAnswer.includes(head[1]) && relationClaimed) edges.push({ relation: word[7], head: head[1], dependent: word[1] });
        }
        if (edges.length === 1) Object.assign(vision, edges[0], { checkedGuideline: source.file_path });
      }
      matchedPreviews.push(...exportedFiles(result, taskRoot).filter((file) => /\.(?:svg|html)$/.test(file.path)).map((file) => file.path));
    }
    if (previews.length) vision.previewPaths = matchedPreviews;
    observations.vision = vision;
  }
  if (id === 'S6') {
    const candidates = results.filter(({ envelope }) => ['release_candidate_build', 'handover_package_build'].includes(envelope.operation) && envelope.execution?.status === 'completed');
    const candidate = candidates.at(-1);
    if (candidate) {
      const result = candidate.envelope.result, archive = exportedFiles(result, taskRoot).filter((file) => file.path.endsWith('.tar'));
      const release = {};
      if (archive.length === 1) {
        release.archivePath = archive[0].path; release.archiveSha256 = archive[0].sha256;
        try {
          const members = readTar(archive[0].bytes), manifest = result.manifest;
          if (Array.isArray(manifest?.files) && manifest.files.length && manifest.files.every((file) => members.has(file.path) && file.size_bytes === members.get(file.path).length && file.sha256 === sha256(members.get(file.path)))) {
            const conllu = manifest.files.filter((file) => file.path.endsWith('.conllu'));
            if (result.validation) release.validation = { execution: result.validation.status, passed: result.validation.passed, inputHashes: Object.fromEntries(conllu.map((file) => [file.path, file.sha256])) };
            else {
              // A separate validator may check the original or unpacked copy:
              // every validated byte identity must match the actual archive.
              const validation = validationResults.filter(({ envelope }) => envelope.execution?.status === 'completed' && envelope.result?.passed === true && conllu.every((file) => envelope.inputs?.files?.some((input) => input.sha256 === file.sha256 && (input.path === file.path || input.path.endsWith('/' + file.path))))).at(-1);
              if (validation) release.validation = { execution: validation.envelope.execution.status, passed: validation.envelope.result.passed, inputHashes: Object.fromEntries(conllu.map((file) => [file.path, file.sha256])) };
            }
            if (typeof manifest.target_release === 'string') release.targetRelease = manifest.target_release;
            else {
              const plans = results.filter(({ envelope }) => envelope.operation === 'release_plan' && envelope.execution?.status === 'completed' && envelope.result?.files?.length === manifest.files.length && envelope.result.files.every((file) => manifest.files.some((member) => member.path === file.path && member.sha256 === file.sha256 && member.size_bytes === file.size_bytes)));
              const targets = new Set(plans.map(({ envelope }) => envelope.result.target_release).filter((value) => typeof value === 'string'));
              if (targets.size === 1) release.targetRelease = [...targets][0];
              else release.targetRelease = /\btarget(?: release)?\s*[:=]?\s*[`"]?([a-z0-9][a-z0-9.-]+)/i.exec(finalAnswer)?.[1];
            }
          }
        } catch { /* Invalid archives are independently rejected by grading. */ }
      }
      const external = results.filter(({ envelope }) => envelope.operation === 'release_plan' && envelope.execution?.status === 'completed').flatMap(({ envelope }) => envelope.result?.external_requirements ?? []);
      external.push(...(result.manifest?.limitations ?? []).filter((value) => typeof value === 'string' && /remote|official|registry|permission|credential|account/i.test(value)));
      if (external.length) release.missingChecks = external.filter((value) => typeof value === 'string' && value.trim());
      observations.release = release;
    }
  }
  if (id === 'S2') {
    const committed = results.filter(({ event, envelope }) => event.committed === true && envelope.result?.transaction?.status === 'completed');
    const commits = committed.flatMap(({ envelope }) => (envelope.result.transaction.files ?? []).filter((file) => file.path === 'edit.conllu').map((file) => ({ operationId: envelope.result.transaction.transaction_id, beforeSha256: file.before_sha256, afterSha256: file.after_sha256 })));
    const losses = unique.filter((event) => event.type === 'response_loss' && event.committed === true);
    const mutation = {};
    if (operationCapture) { mutation.commits = commits; mutation.duplicateEffects = commits.length - new Set(commits.map((entry) => entry.operationId)).size; }
    if (losses.length) {
      mutation.responseLosses = losses.length;
      mutation.reconciled = losses.every((loss) => {
        const lost = results.find(({ event }) => event.operation_id === loss.operation_id || event.operation_id === loss.operationId);
        if (!lost) return false;
        const transaction = lost.envelope.result?.transaction;
        const position = results.indexOf(lost);
        return results.slice(position + 1).some(({ envelope }) => envelope.result?.replayed === true && envelope.result.transaction?.transaction_id === transaction?.transaction_id || envelope.operation === 'validation_report' && envelope.execution?.status === 'completed' && transaction?.files?.every((file) => envelope.inputs?.files?.some((entry) => entry.path === file.path && entry.sha256 === file.after_sha256)));
      });
    }
    observations.mutation = mutation;
    const candidate = results.filter(({ envelope }) => envelope.result?.transaction?.status === 'completed' && envelope.result.transaction.candidate_validation?.completed === true).at(-1);
    if (!validationResult && candidate) {
      observations.validation = { execution: candidate.envelope.result.validation?.status, passed: candidate.envelope.result.transaction.candidate_validation.passed,
        inputHashes: Object.fromEntries(candidate.envelope.result.transaction.files.map((file) => [file.path, file.after_sha256])) };
    }
  }
  if (id === 'S3') {
    const scoring = results.filter(({ envelope }) => ['predictions_evaluate', 'annotation_pair_scores'].includes(envelope.operation) && envelope.execution?.status === 'completed').at(-1);
    if (scoring) {
      const result = scoring.envelope.result;
      const single = (value) => Array.isArray(value) && value.length === 1 ? value[0] : typeof value === 'string' ? value : undefined;
      const gold = single(result.roles?.gold), prediction = single(result.roles?.system);
      const comparison = { gold, prediction, denominator: result.scores?.UAS?.gold_total, uasCorrect: result.scores?.UAS?.correct, lasCorrect: result.scores?.LAS?.correct };
      // Compute mismatch locations from the actual byte-bound scoring inputs,
      // independently of the expected fixture values or the agent's answer.
      if (gold && prediction && taskRoot) {
        try {
          const goldBytes = safeFile(taskRoot, gold), predictionBytes = safeFile(taskRoot, prediction);
          const inputs = scoring.envelope.inputs?.files ?? [];
          if (inputs.some((file) => file.path === gold && file.sha256 === sha256(goldBytes)) && inputs.some((file) => file.path === prediction && file.sha256 === sha256(predictionBytes))) {
            const reference = ordinaryWords(goldBytes), compared = ordinaryWords(predictionBytes);
            if (reference.size === compared.size && [...reference.keys()].every((key) => compared.has(key))) comparison.mismatchTokenIds = [...reference.entries()].filter(([key, fields]) => fields[6] !== compared.get(key)[6] || fields[7] !== compared.get(key)[7]).map(([, fields]) => fields[0]);
          }
        } catch { /* Missing or changed inputs leave location evidence incomplete. */ }
      }
      observations.comparison = comparison;
    }
  }
  const counted = requests.filter((request) => request.tokens?.trusted === true && Number.isSafeInteger(request.tokens.inputTokens));
  if (counted.length) observations.context = { inputTokens: Math.max(...counted.map((request) => request.tokens.inputTokens)),
    ...(Number.isSafeInteger(contextEnvelope) ? { envelope: contextEnvelope } : {}), ...(Number.isSafeInteger(outputReserve) ? { outputReserve } : {}) };
  // before/after are accepted for the common interface; validation binding above
  // uses coordinator snapshots, not an assumed match to initial or final state.
  void before; void after;
  return { observations, events: projected };
}

/** Grade independently observed state. Missing observations are incomplete, never successful. */
export async function gradeScenario(id, { before, after, finalAnswer, events = [], observations = {}, taskRoot } = {}) {
  const scenario = scenarioFor(id);
  const checks = [];
  const check = (name, passed, detail = '') => checks.push({ name, status: passed == null ? 'incomplete' : passed ? 'passed' : 'failed', ...(detail ? { detail } : {}) });
  const fact = (name, actual, expected) => check(name, presentEqual(actual, expected));
  const text = typeof finalAnswer === 'string' ? finalAnswer : '';
  const answer = (name, expressions) => check(name, text ? expressions.every((expression) => expression.test(text)) ? true : null : null, 'Unrecognized or missing prose requires independent review; it is not a pass.');
  check('complete_native_observations', observations.complete === true ? true : null);
  check('no_extra_user_hint', !events.some((event) => event.type === 'user_hint' || (event.type === 'user_message' && event.additional === true)));
  const activations = events.filter((event) => event.type === 'skill_activation' && String(event.name ?? event.skill).startsWith('ud-'));
  const operations = events.filter((event) => event.type === 'ud_operation');
  if (scenario.family) check('ud_workflow_exercised', operations.length ? true : null);
  else { check('no_ud_activation', activations.length === 0); check('no_ud_operation', operations.length === 0); }
  let actual;
  try { actual = captureWorkspace(assertSafeRoot(taskRoot)); }
  catch (error) { check('workspace_readable', false, error.message); }
  const initial = digestMap(before);
  const current = digestMap(actual);
  check('before_snapshot_present', before?.files?.length > 0 ? true : null);
  if (after) check('after_snapshot_matches_disk', after.sha256 === actual?.sha256);
  const allowed = (name) => scenario.outputs.some((entry) => entry.endsWith('/') ? name.startsWith(entry) : name === entry);
  for (const [name, bytes] of Object.entries(scenario.files)) {
    check(`original_fixture:${name}`, initial.has(name) ? initial.get(name).sha256 === sha256(bytes) : null);
    if (id !== 'S2' || name !== 'edit.conllu') check(`input_unchanged:${name}`, current.get(name)?.sha256 === sha256(bytes));
  }
  if (before && actual) {
    for (const name of new Set([...initial.keys(), ...current.keys()])) {
      const previous = initial.get(name), next = current.get(name);
      if (!allowed(name)) check(`authorized_file_state:${name}`, previous?.sha256 === next?.sha256 && previous?.mode === next?.mode);
    }
    const oldDirs = new Map((before.directories ?? []).map((entry) => [entry.path, entry.mode]));
    for (const dir of actual.directories ?? []) if (!oldDirs.has(dir.path)) check(`authorized_directory:${dir.path}`, scenario.outputs.some((entry) => entry.endsWith('/') && (`${dir.path}/`).startsWith(entry)));
  }
  const validation = observations.validation;
  const validate = (expectedPassed, hashes) => {
    fact('validation_completed', validation?.execution, 'completed');
    fact('validation_domain_result', validation?.passed, expectedPassed);
    for (const [name, digest] of Object.entries(hashes)) fact(`validation_bound_bytes:${name}`, validation?.inputHashes?.[name], digest);
  };
  if (id === 'S1') {
    validate(false, Object.fromEntries(Object.entries(scenario.files).map(([name, bytes]) => [name, sha256(bytes)])));
    fact('cold_runtime', observations.runtime?.initiallyReady, false);
    fact('one_preparation_attempt', observations.runtime?.preparationAttempts, 1);
    fact('original_intent_resumed', observations.runtime?.resumed, true);
    fact('cached_assets_reused', observations.runtime?.reusedAssets, true);
    check('validation_file_scope', known(sameSet(validation?.checkedFiles, ['a.conllu', 'b.conllu']), validation?.checkedFiles));
    check('validation_check_scope', known(sameSet(validation?.checks, ['content', 'identifiers']), validation?.checks));
    check('duplicate_identifier_found', known(validation?.findings?.some((finding) => finding.kind === 'duplicate-sent-id' && finding.sentId === 'duplicate'), validation?.findings));
    check('invalid_head_found', known(validation?.findings?.some((finding) => finding.kind === 'head-out-of-range' && finding.file === 'b.conllu' && finding.tokenId === '1' && finding.head === '9'), validation?.findings));
    answer('accurate_final_validation', [/duplicate/i, /a\.conllu/, /b\.conllu/, /\b9\b/, /invalid|errors|failed checks/i, /unchanged|not modified/i]);
    check('no_false_validity_claim', !/all (?:files|checks) (?:are valid|passed)|no (?:annotation )?errors/i.test(text));
  } else if (id === 'S2') {
    check('exact_authorized_candidate', current.get('edit.conllu')?.sha256 === sha256(editExpected));
    validate(true, { 'edit.conllu': sha256(editExpected) });
    const mutation = observations.mutation;
    fact('one_response_loss', mutation?.responseLosses, 1);
    fact('uncertain_commit_reconciled', mutation?.reconciled, true);
    fact('no_duplicate_effects', mutation?.duplicateEffects, 0);
    const commits = mutation?.commits;
    check('identified_commit_chain', commits === undefined ? null : Array.isArray(commits) && commits.length > 0 &&
      new Set(commits.map((entry) => entry.operationId)).size === commits.length &&
      commits.every((entry, index) => typeof entry.operationId === 'string' && entry.operationId.length > 0 && /^[a-f0-9]{64}$/.test(entry.afterSha256 ?? '') && entry.beforeSha256 === (index ? commits[index - 1].afterSha256 : sha256(scenario.files['edit.conllu']))) &&
      commits.at(-1).afterSha256 === sha256(editExpected));
    answer('accurate_final_edit', [/Swallows/, /swallow/, /validat(?:ed|ion).{0,60}(?:pass|valid|succeed)|(?:pass|valid|succeed).{0,60}validat/is, /applied|completed|saved|updated/i]);
    check('no_false_no_effect_claim', !/nothing (?:was )?changed|no changes (?:were )?(?:made|applied)/i.test(text));
  } else if (id === 'S3') {
    const result = observations.comparison;
    for (const [name, expected] of Object.entries({ gold: 'gold.conllu', prediction: 'predictions.conllu', denominator: 5, uasCorrect: 4, lasCorrect: 3 })) fact(`comparison_${name}`, result?.[name], expected);
    check('all_mismatches_reported', known(sameSet(result?.mismatchTokenIds, ['1', '2']), result?.mismatchTokenIds));
    answer('accurate_final_scores', [/UAS.{0,40}(?:80\s*%|0\.8\b|4\s*\/\s*5)/is, /LAS.{0,40}(?:60\s*%|0\.6\b|3\s*\/\s*5)/is, /5\s*(?:eligible |ordinary[- ]?)?tokens|denominator.{0,20}5/i, /compare-1/, /(?:token\s*)?1\b/, /(?:token\s*)?2\b/, /head/i, /(?:nsubj|subject)/i, /(?:obj|object)/i]);
  } else if (id === 'S4') {
    const result = observations.investigation;
    fact('subject_precedes_numerator', result?.numerator, 2);
    fact('eligible_subject_denominator', result?.denominator, 3);
    check('news_only_scope', known(sameSet(result?.scope, scopeIds), result?.scope));
    check('preceding_example', known(result?.examples?.some((entry) => entry.sentId === 'news-1' && entry.tokenId === '1' && entry.head === '2'), result?.examples));
    check('following_example', known(result?.examples?.some((entry) => entry.sentId === 'news-2' && entry.tokenId === '2' && entry.head === '1'), result?.examples));
    const context = observations.context;
    check('measured_extended_context', context?.inputTokens === undefined ? null : Number.isSafeInteger(context.inputTokens) && context.inputTokens > 16_384 && context.envelope === 32_768 && context.outputReserve >= 512 && context.inputTokens + context.outputReserve <= context.envelope);
    answer('accurate_final_investigation', [/2\s*(?:\/|of|out of)\s*3|66\.6\d*\s*%|66\.7\s*%/i, /news-1/, /news-2/, /(?:3.{0,30}(?:subjects|nsubj|relations)|denominator.{0,20}3)/i, /exclud.{0,30}fiction|only.{0,30}news/is]);
  } else if (id === 'S5') {
    const result = observations.vision;
    fact('pixels_reached_model', result?.modelReceivedImage, true);
    fact('correct_image_bytes', result?.imageSha256, sha256(scenario.files['diagram.png']));
    for (const [name, expected] of Object.entries({ relation: 'obj', head: 'chased', dependent: 'mice', checkedGuideline: 'guidelines.md' })) fact(`vision_${name}`, result?.[name], expected);
    check('preview_evidence_present', result?.previewPaths === undefined ? null : result.previewPaths.length > 0);
    for (const name of result?.previewPaths ?? []) {
      try { const content = safeFile(taskRoot, name).toString('utf8'); check(`preview_graph:${name}`, name.startsWith('preview/') && /\.(?:svg|html)$/.test(name) && /<svg\b|<html\b/i.test(content) && /Cats/.test(content) && /chased/.test(content) && /mice/.test(content)); }
      catch (error) { check(`preview_graph:${name}`, false, error.message); }
    }
    answer('accurate_final_image', [/\bobj\b|object/i, /chased/, /mice/, /preview/i]);
  } else if (id === 'S6') {
    const result = observations.release;
    let members;
    if (!result?.archivePath) check('release_archive_present', null);
    else {
      try {
        const bytes = safeFile(taskRoot, result.archivePath);
        check('release_output_scope', result.archivePath.startsWith('handover/'));
        fact('release_archive_identity', result.archiveSha256, sha256(bytes));
        members = readTar(bytes);
        const metadata = ['.ud-agent-release-manifest.json', 'handover-manifest.json'].filter((name) => members.has(name));
        check('exact_archive_members', metadata.length === 1 && sameSet([...members.keys()], [...Object.keys(scenario.files), metadata[0]]));
        for (const [name, expected] of Object.entries(scenario.files)) check(`packaged_bytes:${name}`, members.has(name) && members.get(name).equals(expected));
        const manifest = JSON.parse(members.get(metadata[0])?.toString('utf8') ?? 'null');
        check('release_manifest_target', (manifest?.target_release ?? result.targetRelease) === 'local-eval-1');
        check('release_manifest_files', Array.isArray(manifest?.files) && manifest.files.length === 3 && manifest.files.every((entry) => scenario.files[entry.path] && entry.sha256 === sha256(scenario.files[entry.path]) && entry.size_bytes === scenario.files[entry.path].length) && new Set(manifest.files.map((entry) => entry.path)).size === 3);
      } catch (error) { check('release_archive_valid', false, error.message); }
    }
    fact('packaged_validation_completed', result?.validation?.execution, 'completed');
    fact('packaged_validation_passed', result?.validation?.passed, true);
    fact('packaged_validation_bytes', result?.validation?.inputHashes?.['treebank.conllu'], sha256(scenario.files['treebank.conllu']));
    check('missing_readiness_explicit', result?.missingChecks === undefined ? null : result.missingChecks.length > 0 && result.missingChecks.every((value) => typeof value === 'string' && value.trim()));
    check('local_only', !events.some((event) => event.type === 'external_write' || event.type === 'publish' || event.type === 'upload'));
    answer('accurate_final_handover', [/treebank\.conllu/, /README\.md/, /LICENSE/, /validat/i, /packag|archive/i, /(?:not|unassessed|unverified|not yet).{0,60}(?:official|publication|registry)|(?:official|publication|registry).{0,60}(?:not|unassessed|unverified)/is]);
    check('final_archive_hash_reported', typeof result?.archiveSha256 === 'string' && text.includes(result.archiveSha256) ? true : null);
    check('no_official_acceptance_claim', !/(?:officially accepted|published successfully|uploaded successfully)/i.test(text));
  } else {
    const suggestion = projectWordingSuggestion(text, scenario.files['report.txt'].toString('utf8'));
    check('ordinary_wording_help', suggestion.facts, 'Only the independently projected suggestion supplies factual evidence; unrecognized prose needs review.');
    check('wording_changed_in_suggestion', suggestion.changed);
  }
  const status = checks.some((entry) => entry.status === 'failed') ? 'failed' : checks.some((entry) => entry.status === 'incomplete') ? 'incomplete' : 'passed';
  return { status, checks, reason: status === 'passed' ? 'Independent fixture, observed workflow, and final-answer checks passed.' : checks.filter((entry) => entry.status !== 'passed').map((entry) => `${entry.name}:${entry.status}`).join('; ') };
}

/** Drop exactly one already committed tool response. Never execute or replay an effect. */
export function createResponseLossInjector() {
  let dropped = null;
  return {
    transform(result, { committed = false, operationId, beforeSha256, afterSha256 } = {}) {
      if (dropped || !committed) return { delivered: true, result };
      if (typeof operationId !== 'string' || !operationId || !/^[a-f0-9]{64}$/.test(beforeSha256 ?? '') || !/^[a-f0-9]{64}$/.test(afterSha256 ?? '')) throw new Error('COMMIT_EVIDENCE_REQUIRED');
      dropped = { type: 'response_loss', operationId, beforeSha256, afterSha256, committed: true };
      return { delivered: false, error: { code: 'EVAL_RESPONSE_LOST', message: 'The tool response was lost. Completion is uncertain; reconcile current state before retrying.' }, event: { ...dropped } };
    },
    observation() { return { responseLosses: dropped ? 1 : 0, event: dropped ? { ...dropped } : null }; },
  };
}
