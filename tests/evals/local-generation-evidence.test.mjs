import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, linkSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { collectGenerationEvidence, summarizeGenerationEvidence } from '../../evals/local/generation-evidence.mjs';

const start = 1794440000000, end = start + 100;
const body = { model: '/owned/exact', messages: [{ role: 'user', content: 'Report αé 😀' }], seed: 23, temperature: 1e-7, max_tokens: 512 };
const events = (request = body, id = 'r1') => [{ type: 'token_accounting', id, tokens: { trusted: true, inputTokens: 42 } }, { type: 'upstream_request', id, protocol: 'chat', body: request }];
const fixture = async action => {
  const directory = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-generation-evidence-'))); chmodSync(directory, 0o700);
  try { await action(directory); } finally { rmSync(directory, { recursive: true, force: true }); }
};
function receipt(directory, record = {}, request = body) {
  const filename = path.join(directory, randomUUID().replaceAll('-', '') + '.json');
  const code = `import hashlib,json,os,sys
p=json.loads(sys.stdin.read());body=p['body'];record={'schema_version':1,'model':body['model'],'seed':body['seed'],'prompt_tokens':42,'completion_tokens':3,'maximum_tokens':512,'token_ids':[11,22,33],'text':'private raw generation Bearer secret','termination':'eos','parser_status':'accepted','dispatch_eligible':True,'started_at_ns':int(p['started']),'recorded_at_ns':int(p['ended']),'request_sha256':hashlib.sha256(json.dumps(body,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()}
record.update(p['record'])
for name in ('started_at_ns','recorded_at_ns'):
 if isinstance(record[name],str): record[name]=int(record[name])
with open(p['filename'],'x') as f: json.dump(record,f,ensure_ascii=False,allow_nan=False)
os.chmod(p['filename'],0o600)
print(record['request_sha256'])`;
  const hash = execFileSync('python3', ['-I', '-B', '-c', code], { input: JSON.stringify({ filename, body: request, record,
    started: String(BigInt(start + 10) * 1_000_000n + 123n), ended: String(BigInt(start + 80) * 1_000_000n + 456n) }), encoding: 'utf8', timeout: 10_000 }).trim();
  return { filename, hash };
}
const collect = (directory, other = {}) => collectGenerationEvidence({ events: events(), evidenceDirectory: directory, modelPath: '/owned/exact', startedAtMs: start, endedAtMs: end, ...other });

posixTest('matches exact Python canonical hashes and integer nanoseconds without disclosing raw generations', () => fixture(async directory => {
  const saved = receipt(directory), result = await collect(directory), observed = result.observations[0];
  assert.equal(result.status, 'observed'); assert.equal(observed.request_sha256, saved.hash);
  assert.equal(observed.started_at_ns, String(BigInt(start + 10) * 1_000_000n + 123n));
  assert.equal(observed.recorded_at_ns, String(BigInt(start + 80) * 1_000_000n + 456n));
  assert.equal(observed.generated_tokens, 3); assert.equal(observed.termination, 'eos');
  assert.deepEqual(result.receipts, [{ path: saved.filename, sha256: createHash('sha256').update(readFileSync(saved.filename)).digest('hex') }]);
  assert.equal(JSON.stringify(result).includes('private raw'), false);
  assert.equal(JSON.stringify(result).includes('secret'), false);
  assert.equal(Object.hasOwn(observed, 'token_ids'), false);
}));

posixTest('parser rejection retains charged output and length censorship while EOS at the output ceiling remains distinct', () => fixture(async directory => {
  receipt(directory, { completion_tokens: 512, token_ids: Array(512).fill(7), termination: 'length', parser_status: 'rejected', dispatch_eligible: false, failure: 'ValueError:TOOL_ARGUMENTS_INCOMPLETE' });
  const result = await collect(directory), observed = result.observations[0];
  assert.equal(result.status, 'observed'); assert.equal(observed.generated_tokens, 512);
  assert.equal(observed.termination, 'length'); assert.equal(observed.parser_status, 'rejected');
  assert.equal(observed.failure, 'ValueError:TOOL_ARGUMENTS_INCOMPLETE'); assert.equal(observed.dispatch_eligible, false);
}));

posixTest('EOS exactly at512 tokens is preserved rather than inferred to be truncation', () => fixture(async directory => {
  receipt(directory, { completion_tokens: 512, token_ids: Array(512).fill(7), termination: 'eos' });
  const result = await collect(directory);
  assert.equal(result.observations[0].termination, 'eos'); assert.equal(result.observations[0].generated_tokens, 512);
}));

posixTest('translated backend Chat bytes and native trusted counts identify the generation without altering continuation', () => fixture(async directory => {
  const continuation = { ...body, messages: [...body.messages, { role: 'assistant', tool_calls: [{ id: 'call-a', type: 'function', function: { name: 'read', arguments: '{"path":"a"}' } }] }, { role: 'tool', tool_call_id: 'call-a', content: 'actual result' }] };
  const saved = receipt(directory, {}, continuation);
  const capture = [{ type: 'token_accounting', id: 'r1', tokens: { trusted: true, inputTokens: 42 } },
    { type: 'upstream_request', id: 'r1', protocol: 'messages', body: { model: '/owned/exact', messages: [] } },
    { type: 'translation_request', id: 'r1', translated: true, backend: continuation }];
  const before = structuredClone(capture), result = await collect(directory, { events: capture });
  assert.equal(result.status, 'observed'); assert.equal(result.observations[0].request_sha256, saved.hash);
  assert.deepEqual(capture, before);
}));

posixTest.each(['model', 'seed', 'prompt_tokens', 'maximum_tokens'])('a mismatched receipt %s cannot establish attribution', field => fixture(async directory => {
  receipt(directory, { [field]: field === 'model' ? '/other' : field === 'seed' ? 47 : field === 'maximum_tokens' ? 511 : 43 });
  const result = await collect(directory);
  assert.equal(result.status, 'unknown'); assert.equal(result.observations[0].reason, 'GENERATION_RECEIPT_BINDING_MISMATCH');
  assert.equal(Object.hasOwn(result.observations[0], 'generated_tokens'), false);
}));

posixTest('duplicate receipts and repeated identical requests remain ambiguous rather than selecting a favorable generation', () => fixture(async directory => {
  const saved = receipt(directory), duplicate = path.join(directory, randomUUID().replaceAll('-', '') + '.json');
  copyFileSync(saved.filename, duplicate); chmodSync(duplicate, 0o600);
  assert.equal((await collect(directory)).observations[0].reason, 'GENERATION_RECEIPT_AMBIGUOUS');
  rmSync(duplicate);
  const repeated = await collect(directory, { events: [...events(), ...events(body, 'r2')] });
  assert.ok(repeated.observations.every(row => row.reason === 'GENERATION_REQUEST_HASH_AMBIGUOUS'));
}));

posixTest('old, future and uncertain boundary timestamps cannot be attributed to the current unit', () => fixture(async directory => {
  for (const times of [
    { started_at_ns: String(BigInt(start - 20) * 1_000_000n), recorded_at_ns: String(BigInt(start - 1) * 1_000_000n) },
    { started_at_ns: String(BigInt(start) * 1_000_000n + 1n), recorded_at_ns: String(BigInt(start + 5) * 1_000_000n) },
    { started_at_ns: String(BigInt(end + 1) * 1_000_000n), recorded_at_ns: String(BigInt(end + 2) * 1_000_000n) },
  ]) {
    const saved = receipt(directory, times);
    assert.equal((await collect(directory)).observations[0].reason, 'GENERATION_RECEIPT_OUTSIDE_UNIT_WINDOW');
    rmSync(saved.filename);
  }
}));

posixTest.each(['count', 'ceiling', 'permission', 'symlink', 'hardlink', 'malformed'])('untrusted %s receipts cannot produce observations', kind => fixture(async directory => {
  const saved = receipt(directory, kind === 'count' ? { completion_tokens: 4 } : kind === 'ceiling' ? { maximum_tokens: 513 } : {});
  if (kind === 'permission') chmodSync(saved.filename, 0o644);
  if (kind === 'symlink' || kind === 'hardlink') {
    const other = path.join(directory, randomUUID().replaceAll('-', '') + '.json');
    if (kind === 'symlink') symlinkSync(saved.filename, other); else linkSync(saved.filename, other);
  }
  if (kind === 'malformed') writeFileSync(saved.filename, '{invalid');
  const result = await collect(directory);
  assert.equal(result.status, 'unknown'); assert.deepEqual(result.receipts, []);
  assert.equal(Object.hasOwn(result.observations[0], 'generated_tokens'), false);
}));

posixTest('missing evidence, missing trusted counts and missing translated Chat bodies are explicit unknowns', () => fixture(async directory => {
  assert.equal((await collect(directory)).observations[0].reason, 'GENERATION_RECEIPT_MISSING');
  receipt(directory);
  assert.equal((await collect(directory, { events: events().slice(1) })).observations[0].reason, 'GENERATION_PROMPT_COUNT_UNVERIFIED');
  const unavailable = events(); unavailable[1] = { ...unavailable[1], protocol: 'responses' };
  assert.equal((await collect(directory, { events: unavailable })).observations[0].reason, 'GENERATION_BACKEND_CHAT_REQUEST_MISSING');
  assert.equal((await collect(directory, { python: '/missing/python' })).observations[0].reason, 'GENERATION_COLLECTOR_UNAVAILABLE');
}));

posixTest('private arbitrary failure details remain private and no requests produce no invented zero count', () => fixture(async directory => {
  receipt(directory, { parser_status: 'rejected', dispatch_eligible: false, failure: 'ValueError:Bearer private-credential' });
  const result = await collect(directory);
  assert.equal(result.observations[0].failure, '[private failure detail retained in receipt]');
  assert.equal(JSON.stringify(result).includes('private-credential'), false);
  assert.deepEqual(await collect(directory, { events: [] }), { status: 'not_requested', observations: [], receipts: [] });
}));

test('partial or absent observations cannot manufacture complete usage or a zero generated-token count', () => {
  const known = { status: 'observed', generated_tokens: 512, termination: 'length', parser_status: 'rejected' };
  const partial = summarizeGenerationEvidence({ status: 'unknown', observations: [known, { status: 'unknown' }] });
  assert.equal(partial.generated_tokens, null); assert.equal(partial.known_generated_tokens, 512);
  assert.equal(partial.parser_rejections, 1); assert.deepEqual(partial.termination_counts, { length: 1 });
  const absent = summarizeGenerationEvidence({ status: 'unknown', observations: [{ status: 'unknown' }] });
  assert.equal(absent.generated_tokens, null); assert.equal(absent.known_generated_tokens, null);
  assert.equal(absent.parser_rejections, null); assert.equal(absent.termination_counts, null);
});

if (process.platform === 'win32') test('Windows generation evidence remains unknown without POSIX ownership authority', async () => {
  const result = await collect('C:\\unavailable-private-generation-evidence');
  assert.equal(result.status, 'unknown'); assert.deepEqual(result.receipts, []);
  assert.ok(result.observations.length > 0);
  assert.ok(result.observations.every(row => row.status === 'unknown' && row.reason === 'GENERATION_PLATFORM_UNSUPPORTED'));
  const summary = summarizeGenerationEvidence(result);
  assert.equal(summary.generated_tokens, null); assert.equal(summary.observed_requests, 0);
});
