/** Exact observed context and bounded, count-only marginal measurements. MIT. */
import { readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const integer = value => Number.isSafeInteger(value) && value >= 0;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const digest = value => createHash('sha256').update(value).digest('hex');
const SKILLS = ['ud-validate', 'ud-edit', 'ud-compare', 'ud-investigate', 'ud-rules-docs', 'ud-release'];
const ORDER = ['ud_tool_metadata', 'activated_skill_bodies', 'images', 'tool_result_payloads', 'native_harness_overhead'];
const LIMITS = { count_calls: 6, duration_ms: 10_000 };

function protocol(request, upstream) {
  if (['chat', 'responses', 'messages', 'gemini'].includes(upstream?.protocol)) return upstream.protocol;
  if (request.path === '/v1/chat/completions') return 'chat';
  if (request.path === '/v1/responses') return 'responses';
  if (request.path === '/v1/messages') return 'messages';
  if (/\/models\/.+:(?:streamGenerateContent|generateContent)/.test(request.path ?? '')) return 'gemini';
  return undefined;
}

function generatedTokens(response, selectedProtocol) {
  if (!response || !(response.status >= 200 && response.status < 300)) return undefined;
  let body = response.body;
  if (response.streaming) {
    if (!Array.isArray(body)) return undefined;
    if (selectedProtocol === 'responses') {
      const finals = body.filter(row => ['response.completed', 'response.incomplete'].includes(row.type));
      if (finals.length !== 1) return undefined;
      body = finals[0].response;
    } else if (selectedProtocol === 'messages') {
      if (!body.some(row => row.type === 'message_stop')) return undefined;
      body = { usage: body.findLast(row => row.type === 'message_delta' && row.usage)?.usage };
    } else if (selectedProtocol === 'chat') body = body.findLast(row => row.usage);
    else body = body.findLast(row => row.usageMetadata);
  }
  const usage = selectedProtocol === 'gemini' ? body?.usageMetadata : body?.usage;
  if (!object(usage)) return undefined;
  const count = selectedProtocol === 'chat' ? usage.completion_tokens : selectedProtocol === 'gemini' ? usage.candidatesTokenCount : usage.output_tokens;
  if (!integer(count)) return undefined;
  if (selectedProtocol === 'gemini') {
    const thinking = usage.thoughtsTokenCount ?? 0;
    return integer(thinking) ? count + thinking : undefined;
  }
  return count;
}

function total(rows, field, selected = () => true) {
  const relevant = rows.filter(selected), available = relevant.filter(row => integer(row[field]));
  return { status: !relevant.length ? 'unavailable' : available.length === relevant.length ? 'complete' : 'partial',
    observed_tokens: available.reduce((sum, row) => sum + row[field], 0), observed_requests: available.length, expected_requests: relevant.length };
}

function installedSkills(installation) {
  if (typeof installation !== 'string') return { bodies: [], unavailable: SKILLS };
  let root; try { root = realpathSync(installation); } catch { return { bodies: [], unavailable: SKILLS }; }
  const bodies = [], unavailable = [];
  for (const name of SKILLS) {
    try {
      const file = realpathSync(path.join(root, 'skills', name, 'SKILL.md'));
      if (!file.startsWith(root + path.sep) || !statSync(file).isFile() || statSync(file).size > 128 * 1024) throw new Error('Unbound skill source.');
      const source = readFileSync(file, 'utf8'), body = source.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
      if (body.length < 100) throw new Error('Skill body is incomplete.');
      bodies.push({ name, body, body_sha256: digest(body), installed_sha256: digest(source) });
    } catch { unavailable.push(name); }
  }
  return { bodies, unavailable };
}

function operationNames(operations) {
  if (!Array.isArray(operations)) return null;
  const names = new Set(operations.map(operation => typeof operation === 'string' ? operation : operation?.operation ?? operation?.name).filter(name => typeof name === 'string'));
  return names.size ? names : null;
}
function udTool(name, names) {
  if (typeof name !== 'string' || !names) return false;
  // These aliases bind to the repository's exact `ud` server registration.
  return names.has(name) || ['mcp__ud__', 'ud__', 'ud.'].some(prefix => name.startsWith(prefix) && names.has(name.slice(prefix.length)));
}
function toolsWithout(body, selectedProtocol, predicate) {
  const removed = [];
  if (!Array.isArray(body.tools)) return removed;
  if (selectedProtocol === 'gemini') {
    body.tools = body.tools.flatMap(tool => {
      if (!Array.isArray(tool.functionDeclarations)) return [tool];
      const kept = tool.functionDeclarations.filter(declaration => { if (!predicate(declaration.name)) return true; removed.push(declaration.name); return false; });
      return kept.length ? [{ ...tool, functionDeclarations: kept }] : [];
    });
  } else body.tools = body.tools.filter(tool => {
    const name = tool.function?.name ?? tool.name;
    if (!predicate(name)) return true;
    removed.push(name); return false;
  });
  return removed;
}
function mapStrings(value, convert) {
  if (typeof value === 'string') return convert(value);
  if (Array.isArray(value)) return value.map(child => mapStrings(child, convert));
  if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, mapStrings(child, convert)]));
  return value;
}
function dropImages(value, removed) {
  if (Array.isArray(value)) return value.filter(child => {
    const image = object(child) && (child.type === 'image' && object(child.source) || ['image_url', 'input_image'].includes(child.type) && child.image_url !== undefined || object(child.inlineData) && /^image\//.test(child.inlineData.mimeType ?? ''));
    if (image) removed.push(digest(JSON.stringify(child)));
    return !image;
  }).map(child => dropImages(child, removed));
  if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, dropImages(child, removed)]));
  return value;
}
function clearResults(body, removed) {
  if (Array.isArray(body.messages)) body.messages = body.messages.map(message => {
    if (message.role === 'tool' && Object.hasOwn(message, 'content')) {
      removed.push({ kind: 'chat-tool-result', id: message.tool_call_id }); return { ...message, content: '' };
    }
    if (!Array.isArray(message.content)) return message;
    return { ...message, content: message.content.map(block => {
      if (block.type !== 'tool_result' || !Object.hasOwn(block, 'content')) return block;
      removed.push({ kind: 'messages-tool-result', id: block.tool_use_id }); return { ...block, content: '' };
    }) };
  });
  if (Array.isArray(body.input)) body.input = body.input.map(item => {
    if (!['function_call_output', 'shell_call_output', 'apply_patch_call_output'].includes(item.type) || !Object.hasOwn(item, 'output')) return item;
    removed.push({ kind: item.type, id: item.call_id }); return { ...item, output: '' };
  });
  if (Array.isArray(body.contents)) body.contents = body.contents.map(content => ({ ...content, ...(Array.isArray(content.parts) ? { parts: content.parts.map(part => {
    if (!object(part.functionResponse) || !Object.hasOwn(part.functionResponse, 'response')) return part;
    removed.push({ kind: 'gemini-tool-result', name: part.functionResponse.name }); return { ...part, functionResponse: { ...part.functionResponse, response: {} } };
  }) } : {}) }));
  return body;
}

function ablate(component, original, selectedProtocol, skills, names) {
  let body = structuredClone(original);
  const evidence = [];
  if (component === 'ud_tool_metadata') {
    if (!names) return { unavailable: 'Canonical operation inventory was not supplied.' };
    evidence.push(...toolsWithout(body, selectedProtocol, name => udTool(name, names)));
  } else if (component === 'activated_skill_bodies') {
    if (!skills.bodies.length) return { unavailable: 'Installed canonical skill bodies could not be verified.' };
    body = mapStrings(body, value => {
      let changed = value;
      for (const skill of skills.bodies) {
        const pieces = changed.split(skill.body);
        if (pieces.length > 1) { evidence.push({ name: skill.name, occurrences: pieces.length - 1, body_sha256: skill.body_sha256, installed_sha256: skill.installed_sha256 }); changed = pieces.join(''); }
      }
      return changed;
    });
  } else if (component === 'images') body = dropImages(body, evidence);
  else if (component === 'tool_result_payloads') body = clearResults(body, evidence);
  else {
    if (!names) return { unavailable: 'Cannot distinguish native tools without the canonical operation inventory.' };
    evidence.push(...toolsWithout(body, selectedProtocol, name => typeof name === 'string' && !udTool(name, names)));
    let ambiguous = false;
    const includesUd = value => /\bud-(?:validate|edit|compare|investigate|rules-docs|release)\b|\bmcp__ud__/.test(JSON.stringify(value));
    for (const field of ['system', 'instructions', 'systemInstruction']) if (Object.hasOwn(body, field)) {
      if (includesUd(body[field])) ambiguous = true;
      else { evidence.push({ instruction_field: field }); delete body[field]; }
    }
    for (const field of ['messages', 'input']) if (Array.isArray(body[field])) body[field] = body[field].filter(message => {
      if (!['system', 'developer'].includes(message.role)) return true;
      if (includesUd(message)) { ambiguous = true; return true; }
      evidence.push({ instruction_role: message.role }); return false;
    });
    return { body, evidence, partial: ambiguous, scope: 'Remaining non-UD tool definitions and unambiguous system/developer instructions; conversation framing stays in residual.', ...(ambiguous ? { reason: 'UD registration text remains mixed with native instructions; its attribution is unavailable.' } : {}) };
  }
  return { body, evidence, ...(component === 'activated_skill_bodies' && skills.unavailable.length ? { partial: true, reason: 'Some installed skill sources were unavailable.' } : {}) };
}

/** Never generates: callers supply the admitted exact count-only tokenizer. */
export async function measureEpisodeContext({ events = [], tokenize, installation, operations } = {}) {
  const started = Date.now(), deadline = started + LIMITS.duration_ms;
  const rows = [], seen = new Set();
  for (const request of events.filter(event => event.type === 'provider_request')) {
    if (typeof request.id !== 'string' || seen.has(request.id)) continue;
    seen.add(request.id);
    const repeated = events.filter(event => event.type === 'provider_request' && event.id === request.id).length !== 1;
    const upstream = events.filter(event => event.type === 'upstream_request' && event.id === request.id);
    const response = events.filter(event => event.type === 'provider_response' && event.id === request.id);
    const visible = events.filter(event => event.type === 'model_visible_response' && event.id === request.id);
    const backend = events.filter(event => event.type === 'translation_backend_response' && event.id === request.id);
    const selectedProtocol = protocol(request, upstream[0]);
    const input = !repeated && request.tokens?.trusted === true && integer(request.tokens.inputTokens) ? request.tokens.inputTokens : undefined;
    const providerGenerated = response.length === 1 ? generatedTokens(response[0], selectedProtocol) : undefined;
    const generated = providerGenerated ?? (backend.length === 1 ? generatedTokens(backend[0], backend[0].protocol) : undefined);
    rows.push({ id: request.id, protocol: selectedProtocol, dispatched: upstream.length === 1, accepted_by_gateway: visible.length === 1,
      ...(input === undefined ? {} : { input_tokens: input }), ...(integer(request.tokens?.contextTokens) ? { context_tokens: request.tokens.contextTokens } : {}),
      ...(generated === undefined ? {} : { generated_tokens: generated, generated_token_source: providerGenerated === undefined ? 'captured-backend-response' : 'captured-native-provider-response' }),
      ...(visible.length === 1 && integer(visible[0].outputTokens) ? { model_visible_output_tokens: visible[0].outputTokens } : {}),
      ...(!repeated && upstream.length === 1 && object(upstream[0].body) ? { accounting_body: upstream[0].body } : {}),
      ...(repeated ? { unavailable: 'Duplicate provider request identity.' } : {}) });
  }
  const report = { schema_version: 1, kind: 'local-episode-context-measurements', inference_requests: 0,
    observed: { provider_requests: rows.length, submitted_input: total(rows, 'input_tokens', row => row.dispatched),
      accepted_input: total(rows, 'input_tokens', row => row.accepted_by_gateway), generated_output: total(rows, 'generated_tokens', row => row.dispatched),
      model_visible_output: total(rows, 'model_visible_output_tokens', row => row.dispatched),
      per_request: rows.map(({ accounting_body, ...row }) => row) },
    startup: rows.length ? { request_id: rows[0].id, ...(integer(rows[0].input_tokens) ? { observed_input_tokens: rows[0].input_tokens } : { status: 'unavailable' }) } : { status: 'unavailable' },
    decomposition: { method: 'ordered-exact-token-count-marginal-ablation', generation: false, limits: { ...LIMITS }, order: [...ORDER], count_calls: 0, components: {},
      caveats: ['Ablated requests are counted only; they are never sent to model generation.', 'Signed marginal deltas depend on removal order and tokenizer interactions; they are not independent additive costs.', 'Unrecognized registration text and conversation framing remain unattributed.', 'No absent, failed or timed-out component is inferred to have zero token cost.'] } };
  const decomposition = report.decomposition;
  const selected = rows.filter(row => row.accounting_body && row.protocol && integer(row.input_tokens)).sort((a, b) => b.input_tokens - a.input_tokens)[0];
  const unavailable = reason => { for (const component of ORDER) decomposition.components[component] ??= { status: 'unavailable', reason }; };
  if (!selected || typeof tokenize !== 'function') {
    decomposition.status = 'unavailable'; unavailable(!selected ? 'No uniquely captured request with exact input count and upstream body.' : 'An exact count-only tokenizer was not supplied.'); return report;
  }
  decomposition.request_id = selected.id; decomposition.selection = 'largest-observed-input;first-in-event-order-on-ties';
  decomposition.original_input_tokens = selected.input_tokens;
  const controller = new AbortController();
  let expire;
  const expired = new Promise((_, reject) => { expire = setTimeout(() => { controller.abort(new Error('MEASUREMENT_DEADLINE_EXCEEDED')); reject(new Error('MEASUREMENT_DEADLINE_EXCEEDED')); }, Math.max(0, deadline - Date.now())); });
  // Keep timeout rejection handled even when every component was absent.
  expired.catch(() => {});
  async function count(body) {
    if (decomposition.count_calls >= LIMITS.count_calls || controller.signal.aborted || Date.now() >= deadline) throw new Error('MEASUREMENT_BUDGET_EXCEEDED');
    decomposition.count_calls++;
    const value = await Promise.race([Promise.resolve().then(() => tokenize({ protocol: selected.protocol, body, signal: controller.signal, countOnly: true })), expired]);
    if (value?.trusted !== true || !integer(value.inputTokens) || !integer(value.contextTokens ?? value.inputTokens)) throw new Error('MEASUREMENT_TOKEN_COUNT_UNVERIFIED');
    return value.inputTokens;
  }
  try {
    let body = structuredClone(selected.accounting_body), previous = await count(body);
    if (previous !== selected.input_tokens) throw new Error('MEASUREMENT_BASELINE_COUNT_MISMATCH');
    decomposition.baseline_reconciled = true;
    const skills = installedSkills(installation), names = operationNames(operations);
    for (const component of ORDER) {
      if (controller.signal.aborted || Date.now() >= deadline) { unavailable('Count-only measurement deadline reached.'); break; }
      const candidate = ablate(component, body, selected.protocol, skills, names);
      if (candidate.unavailable) { decomposition.components[component] = { status: 'unavailable', reason: candidate.unavailable }; continue; }
      if (!candidate.evidence.length) { decomposition.components[component] = { status: candidate.partial ? 'unavailable' : 'not_observed', reason: candidate.reason ?? 'No identifiable component occurred in the selected request.', ...(candidate.scope ? { scope: candidate.scope } : {}) }; continue; }
      try {
        const current = await count(candidate.body);
        decomposition.components[component] = { status: candidate.partial ? 'partial' : 'measured', marginal_input_tokens: previous - current,
          before_tokens: previous, after_tokens: current, removed: candidate.evidence, ...(candidate.reason ? { reason: candidate.reason } : {}), ...(candidate.scope ? { scope: candidate.scope } : {}) };
        body = candidate.body; previous = current;
      } catch (error) { decomposition.components[component] = { status: 'unavailable', reason: error.message }; }
    }
    decomposition.residual_input_tokens = previous;
    decomposition.status = Object.values(decomposition.components).some(component => ['unavailable', 'partial'].includes(component.status)) ? 'partial' : 'complete';
  } catch (error) { decomposition.status = 'unavailable'; unavailable(error.message); }
  finally { clearTimeout(expire); controller.abort(); decomposition.elapsed_ms = Date.now() - started; }
  return report;
}
