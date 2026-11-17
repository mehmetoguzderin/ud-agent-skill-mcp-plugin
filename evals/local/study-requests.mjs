/** Native prompt capture and declared causal input interventions. MIT. */
import http from 'node:http';
import path from 'node:path';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { startNative } from './native.mjs';
import { createScenario } from './scenarios.mjs';
import { assertOptIn } from './preparation.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

const textParts = message => typeof message.content === 'string' ? [message.content] : Array.isArray(message.content) ? message.content.filter(part => part.type === 'text').map(part => part.text) : [];
const captureBody = capture => capture?.selected?.body ?? capture?.body;
const skillName = scenario => scenario === 'S2' ? 'ud-edit' : 'ud-compare';
export function observedSkillBody(requestBody, skillBody) {
  const text = requestBody.messages.flatMap(message => textParts(message).map(value => {
    if (message.role !== 'tool') return value;
    try { const envelope = JSON.parse(value); return envelope.returncode === 0 && typeof envelope.output === 'string' ? envelope.output : value; } catch { return value; }
  })).join('\n');
  return typeof skillBody === 'string' && skillBody.length > 0 && text.includes(skillBody);
}
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";
function replyChat(response, request, message) {
  const finish = message.tool_calls?.length ? 'tool_calls' : 'stop';
  const base = { id: randomUUID(), model: request.model, created: 1 };
  if (!request.stream) { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ ...base, object: 'chat.completion', choices: [{ index: 0, message, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })); return; }
  response.writeHead(200, { 'content-type': 'text/event-stream' });
  const delta = { ...message, ...(message.tool_calls ? { tool_calls: message.tool_calls.map((call, index) => ({ index, ...call })) } : {}) };
  for (const row of [{ choices: [{ index: 0, delta, finish_reason: null }] }, { choices: [{ index: 0, delta: {}, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }]) response.write('data: ' + JSON.stringify({ ...base, object: 'chat.completion.chunk', ...row }) + '\n\n');
  response.end('data: [DONE]\n\n');
}
/** This uses an inert provider and actual native skill loading, never weights.
 * The resulting prefix is diagnostic input; it cannot certify model selection. */
export async function captureStudyRequest({ root, directory, harness, installation, model, scenarioId, activated = false, neutral = false, optIn, signal }) {
  assertOptIn({ optIn });
  if (!['qwen-code', 'mini-swe-agent'].includes(harness.id) || !['S2', 'S3'].includes(scenarioId)) throw new Error('STUDY_CAPTURE_ROUTE_UNSUPPORTED');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'profile'), scenario = await createScenario(scenarioId, taskRoot);
  const requests = []; let native, selected, result;
  const server = http.createServer(async (request, response) => {
    if (request.method === 'GET') { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ object: 'list', data: [{ id: model, object: 'model' }] })); return; }
    let text = ''; for await (const chunk of request) { text += chunk; if (text.length > 2 ** 21) { response.writeHead(413); response.end(); return; } }
    const body = JSON.parse(text); requests.push({ path: request.url, body });
    if (requests.length > 4) { response.writeHead(429); response.end(); void native?.stop('inert-capture-bound'); return; }
    if (activated && requests.length === 1) {
      const name = harness.id === 'qwen-code' ? 'skill' : 'bash';
      const args = name === 'skill' ? { skill: skillName(scenarioId) } : { command: 'cat ' + shellQuote(path.join(taskRoot, '.agents/skills', skillName(scenarioId), 'SKILL.md')) };
      replyChat(response, body, { role: 'assistant', content: '', tool_calls: [{ id: 'inert-load-skill', type: 'function', function: { name, arguments: JSON.stringify(args) } }] }); return;
    }
    selected ??= { path: request.url, body };
    const message = harness.id === 'mini-swe-agent' ? { role: 'assistant', content: '', tool_calls: [{ id: 'inert-finish', type: 'function', function: { name: 'bash', arguments: JSON.stringify({ command: "printf 'COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\\ninert-capture-complete\\n'" }) } }] } : { role: 'assistant', content: 'inert-capture-complete' };
    replyChat(response, body, message);
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    native = await startNative({ root, harness, installation, taskRoot, profile, model, endpoint: `http://127.0.0.1:${server.address().port}`, prompt: scenario.prompt, skillsEnabled: true,
      allowUnverified: true, ...(signal ? { signal } : {}), ...(neutral ? { studyVariant: 'task-neutral' } : {}) });
    result = await native.done;
  } finally {
    const released = await native?.stop('inert-prompt-capture-finished');
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    if (native && released?.cleanupVerified !== true) throw new Error('STUDY_CAPTURE_CLEANUP_UNVERIFIED');
  }
  if (!selected || result?.cleanupVerified !== true) throw new Error('STUDY_NATIVE_PROMPT_CAPTURE_FAILED');
  const body = readFileSync(path.join(installation, 'skills', skillName(scenarioId), 'SKILL.md'), 'utf8').replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
  if (activated && !observedSkillBody(selected.body, body)) throw new Error('STUDY_NATIVE_SKILL_BODY_NOT_OBSERVED');
  const evidence = { kind: 'inert-native-prompt-capture', inference: false, harness_id: harness.id, model, scenario_id: scenarioId, task_root: taskRoot, profile_root: profile, activated, neutral,
    selected, requests, owned_cleanup_verified: true, native_identity: native.identity, native_exit: result.code, selected_sha256: sha256(JSON.stringify(selected)), skill_body_sha256: activated ? sha256(body) : null, skill_body: activated ? body : null };
  writeFileSync(path.join(directory, 'capture.json'), JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
  return evidence;
}

function mapText(body, transform) {
  for (const message of body.messages) {
    if (typeof message.content === 'string') message.content = transform(message.content, message);
    else if (Array.isArray(message.content)) for (const part of message.content) if (part.type === 'text') part.text = transform(part.text, message);
  }
}
function moveMetadata(body) {
  const pieces = [];
  // Never consume an earlier reminder, user intent, image or tool result.
  const reminder = /<system-reminder>(?:(?!<\/system-reminder>)[\s\S])*?<available_skills>(?:(?!<\/available_skills>)[\s\S])*?<\/available_skills>(?:(?!<\/system-reminder>)[\s\S])*?<\/system-reminder>/g;
  const shell = /Installed optional workflow skills \(read a skill only when relevant\):\n[\s\S]*?The installed ud-agent executable exposes the coordinator CLI; use ud-agent --help for its interface\.\n?/g;
  mapText(body, (text, message) => {
    if (!['system', 'user'].includes(message.role)) return text;
    return text.replace(reminder, match => { pieces.push({ role: message.role, bytes: match }); return ''; })
      .replace(shell, match => { pieces.push({ role: message.role, bytes: match }); return ''; });
  });
  for (const piece of pieces) {
    const destination = body.messages.findLast(message => message.role === piece.role && (typeof message.content === 'string' || Array.isArray(message.content) && message.content.some(part => part.type === 'text')));
    if (typeof destination.content === 'string') destination.content += piece.bytes;
    else destination.content.findLast(part => part.type === 'text').text += piece.bytes;
  }
  return pieces.length;
}
function removeNativeExamples(text, message) {
  if (message.role !== 'user') return text;
  const marker = text.lastIndexOf('## Command Execution Rules');
  if (marker < 0 || !text.slice(marker).includes('<system_information>')) return text;
  const intent = text.slice(0, marker);
  let native = text.slice(marker);
  // Restrict edits to the pinned native suffix; a following user paragraph makes
  // this condition a sham rather than discarding user content.
  native = native.replace(/\n## Useful command examples\n[\s\S]*?### Any other command you want to run\n\n```bash\nanything\n```\s*$/, '');
  native = native.replace(/Example of a CORRECT response:\n<example_response>(?:(?!<\/example_response>)[\s\S])*?<\/example_response>/g, '');
  return intent + native;
}
function normalizedCapturePaths(body, selected, original) {
  const mapping = ['task_root', 'profile_root'].flatMap(key => typeof selected?.[key] === 'string' && typeof original?.[key] === 'string' && selected[key] !== original[key]
    ? [{ field: key, from: selected[key], to: original[key] }] : []);
  function values(value) {
    if (typeof value === 'string') {
      for (const item of mapping) value = value.replaceAll(item.from, item.to);
      return value;
    }
    if (Array.isArray(value)) return value.map(values);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, values(child)]));
    return value;
  }
  return { body: values(body), mapping };
}
/** Inputs are frozen actual native requests; interventions never execute tools,
 * repair arguments or inject expected factual answers. */
export function transformStudyRequest({ condition, original, activated, neutral, guidance }) {
  const originalBody = captureBody(original);
  const selected = condition === 'activated-skill' ? activated : condition === 'neutral-framing' ? neutral ?? original : original;
  const selectedBody = captureBody(selected);
  if (!originalBody || !selectedBody || !Array.isArray(selectedBody.messages)) throw new Error('STUDY_CAPTURE_REQUIRED');
  if (condition === 'activated-skill' && !(activated?.activated === true && activated?.inference === false && typeof activated?.skill_body_sha256 === 'string' &&
    activated?.selected_sha256 === sha256(JSON.stringify(activated.selected)) && typeof activated.skill_body === 'string' &&
    activated.skill_body_sha256 === sha256(activated.skill_body) && observedSkillBody(selectedBody, activated.skill_body))) throw new Error('STUDY_NATIVE_ACTIVATION_PROVENANCE_REQUIRED');
  if (condition === 'neutral-framing' && neutral && neutral.neutral !== true) throw new Error('STUDY_NATIVE_NEUTRAL_PROVENANCE_REQUIRED');
  const normalization = normalizedCapturePaths(structuredClone(selectedBody), selected, original);
  const body = normalization.body, normalizedSelectedHash = sha256(JSON.stringify(normalization.body));
  let metadataPieces = 0;
  if (condition === 'metadata-near-request') metadataPieces = moveMetadata(body);
  else if (condition === 'reduced-narrative') mapText(body, removeNativeExamples);
  else if (condition === 'actionable-guidance') {
    if (typeof guidance !== 'string' || !guidance.trim()) throw new Error('FROZEN_ACTIONABLE_GUIDANCE_REQUIRED');
    const user = body.messages.findLast(message => message.role === 'user');
    if (!user) throw new Error('STUDY_USER_REQUEST_REQUIRED');
    if (typeof user.content === 'string') user.content += '\n\n' + guidance;
    else if (Array.isArray(user.content)) user.content.push({ type: 'text', text: guidance });
    else throw new Error('STUDY_USER_TEXT_REQUIRED');
  } else if (!['unchanged', 'unchanged-repeat', 'neutral-framing', 'activated-skill'].includes(condition)) throw new Error('STUDY_CONDITION_UNKNOWN');
  const changed = JSON.stringify(body) !== JSON.stringify(originalBody);
  return { body, original_sha256: sha256(JSON.stringify(originalBody)), request_sha256: sha256(JSON.stringify(body)), changed,
    selected_native_request_sha256: sha256(JSON.stringify(selectedBody)), normalized_selected_sha256: normalizedSelectedHash,
    path_normalization: normalization.mapping, intervention: condition, forced_activation: condition === 'activated-skill', qualification_evidence: false,
    sham: !changed, metadata_pieces_moved: metadataPieces,
    activation_provenance: condition === 'activated-skill' ? { capture_sha256: sha256(JSON.stringify(activated)), skill_body_sha256: activated.skill_body_sha256 } : null };
}
