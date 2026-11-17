/** Causal intervention invariants, inert payloads only. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { observedSkillBody, transformStudyRequest } from '../../evals/local/study-requests.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';
const metadata = '<system-reminder>Available: <available_skills><skill>ud-compare: prediction scoring</skill></available_skills></system-reminder>';
const tools = [{ type: 'function', function: { name: 'bash', parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } } }];
const request = messages => ({ body: { model: 'exact-artifact', messages, tools: structuredClone(tools), max_tokens: 512, stream: true } });
const text = body => body.messages.flatMap(message => typeof message.content === 'string' ? [message.content] : message.content.filter(part => part.type === 'text').map(part => part.text)).join('');

test('unchanged and repeated requests preserve exact bodies, roles, schema and seed inputs', () => {
  const original = request([{ role: 'system', content: 'Native instructions' }, { role: 'user', content: 'Compare the supplied annotations.' }]);
  const before = structuredClone(original);
  for (const condition of ['unchanged', 'unchanged-repeat']) {
    const transformed = transformStudyRequest({ condition, original });
    assert.deepEqual(transformed.body, original.body); assert.equal(transformed.changed, false); assert.equal(transformed.sham, true);
    assert.equal(transformed.request_sha256, sha256(JSON.stringify(original.body))); assert.equal(transformed.qualification_evidence, false);
  }
  assert.deepEqual(original, before);
});
test('metadata relocation preserves bytes and roles, leaves other reminders and images intact', () => {
  const safety = '<system-reminder>Preserve files and grants.</system-reminder>';
  const original = request([{ role: 'system', content: 'Native policy' }, { role: 'user', content: [
    { type: 'text', text: safety + metadata }, { type: 'image_url', image_url: { url: 'data:image/png;base64,AA==' } },
    { type: 'text', text: 'Actual natural request.' },
  ] }]);
  const before = structuredClone(original), result = transformStudyRequest({ condition: 'metadata-near-request', original });
  assert.equal(result.metadata_pieces_moved, 1); assert.equal(result.body.messages[1].content[0].text, safety);
  assert.equal(result.body.messages[1].content[2].text, 'Actual natural request.' + metadata);
  assert.deepEqual(result.body.messages.map(message => message.role), original.body.messages.map(message => message.role));
  assert.deepEqual(result.body.messages[1].content[1], original.body.messages[1].content[1]);
  assert.deepEqual(result.body.tools, tools); assert.equal(text(result.body).length, text(original.body).length);
  assert.deepEqual(original, before);
});
test('metadata does not cross role boundaries; already-last and missing metadata are explicit shams', () => {
  const original = request([{ role: 'system', content: 'Native policy' + metadata }, { role: 'user', content: 'Actual intent' }]);
  const result = transformStudyRequest({ condition: 'metadata-near-request', original });
  assert.deepEqual(result.body, original.body); assert.equal(result.sham, true);
  assert.equal(transformStudyRequest({ condition: 'neutral-framing', original }).sham, true);
  assert.throws(() => transformStudyRequest({ condition: 'neutral-framing', original, neutral: original }), /NEUTRAL_PROVENANCE/);
});
test('narrative reduction preserves intent and essential execution rules, never alters tool data', () => {
  const examples = '\n## Useful command examples\n### Create a new file:\nexample\n### Any other command you want to run\n\n```bash\nanything\n```';
  const native = '## Command Execution Rules\nMUST use bash.\nExample of a CORRECT response:\n<example_response>ls-first</example_response>\n<system_information>Linux</system_information>';
  const intent = 'Leave both inputs unchanged. Compare both files.\n';
  const original = request([{ role: 'user', content: intent + native + examples }, { role: 'tool', content: 'File content' + examples }]);
  const result = transformStudyRequest({ condition: 'reduced-narrative', original });
  assert.ok(result.body.messages[0].content.startsWith(intent)); assert.ok(result.body.messages[0].content.includes('MUST use bash.'));
  assert.ok(!result.body.messages[0].content.includes('ls-first')); assert.ok(!result.body.messages[0].content.includes('## Useful command examples'));
  assert.equal(result.body.messages[1].content, original.body.messages[1].content); assert.deepEqual(result.body.tools, tools);
  const followed = request([{ role: 'user', content: intent + native + examples + '\nFinal user requirement: do not edit.' }]);
  assert.ok(transformStudyRequest({ condition: 'reduced-narrative', original: followed }).body.messages[0].content.endsWith('Final user requirement: do not edit.'));
  const userExample = request([{ role: 'user', content: 'Explain <example_response>my example</example_response> exactly.' }]);
  assert.deepEqual(transformStudyRequest({ condition: 'reduced-narrative', original: userExample }).body, userExample.body);
});
test('activation needs native capture provenance and guidance is an explicit diagnostic intervention', () => {
  const original = request([{ role: 'user', content: 'Compare files.' }]);
  assert.throws(() => transformStudyRequest({ condition: 'activated-skill', original, activated: original }), /ACTIVATION_PROVENANCE/);
  const selected = request([{ role: 'user', content: 'Compare files.' }, { role: 'tool', content: 'Canonical skill body.' }]);
  const activated = { activated: true, inference: false, selected, selected_sha256: sha256(JSON.stringify(selected)), skill_body_sha256: sha256('Canonical skill body.'), skill_body: 'Canonical skill body.' };
  const result = transformStudyRequest({ condition: 'activated-skill', original, activated });
  assert.equal(result.forced_activation, true); assert.equal(result.qualification_evidence, false); assert.deepEqual(result.body, selected.body);
  assert.equal(result.activation_provenance.skill_body_sha256, activated.skill_body_sha256);
  const guidance = 'Inspect the operation schema using the installed discovery interface.';
  const guided = transformStudyRequest({ condition: 'actionable-guidance', original, guidance });
  assert.equal(guided.body.messages[0].content, 'Compare files.\n\n' + guidance); assert.deepEqual(guided.body.tools, original.body.tools);
  assert.throws(() => transformStudyRequest({ condition: 'actionable-guidance', original }), /GUIDANCE_REQUIRED/);
});


test('native shell skill observation decodes only successful actual tool-result envelopes', () => {
  const body = '# Skill\nUse `predictions_evaluate`.\nKeep inputs unchanged.';
  assert.equal(observedSkillBody({ messages: [{ role: 'tool', content: JSON.stringify({ returncode: 0, output: body }) }] }, body), true);
  assert.equal(observedSkillBody({ messages: [{ role: 'tool', content: JSON.stringify({ returncode: 1, output: body }) }] }, body), false);
  assert.equal(observedSkillBody({ messages: [{ role: 'tool', content: [{ type: 'text', text: 'Base directory: /skills/example\n' + body }] }] }, body), true);
  assert.equal(observedSkillBody({ messages: [{ role: 'user', content: 'There is a skill available.' }] }, body), false);
});

test('counterfactual prefixes normalize captured task/profile paths before the named intervention', () => {
  const original = { ...request([{ role: 'user', content: 'Compare /original/task/prediction.conllu using /original/profile/bin/coordinator.' }]), task_root: '/original/task', profile_root: '/original/profile' };
  const neutral = { ...request([{ role: 'user', content: 'Compare /neutral/task/prediction.conllu using /neutral/profile/bin/coordinator.' }]), task_root: '/neutral/task', profile_root: '/neutral/profile', neutral: true };
  neutral.body.tools[0].function.parameters.properties.command.description = '/neutral/task is the working tree';
  original.body.tools[0].function.parameters.properties.command.description = '/original/task is the working tree';
  const result = transformStudyRequest({ condition: 'neutral-framing', original, neutral });
  assert.deepEqual(result.body, original.body, 'Path-only differences are an explicit sham after normalization.');
  assert.equal(result.path_normalization.length, 2); assert.equal(result.sham, true);
  assert.ok(neutral.body.messages[0].content.includes('/neutral/task')); assert.ok(result.selected_native_request_sha256 !== result.normalized_selected_sha256);
  assert.deepEqual(Object.keys(result.body.tools[0].function.parameters.properties), ['command']);
});
