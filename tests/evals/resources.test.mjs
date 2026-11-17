import { test } from 'vitest';
import assert from 'node:assert/strict';
import { verifiedWorkflowResource } from '../../scripts/quality/workflow-resources.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

const uri = 'ud://reports/01234567-89ab-4cde-8f01-23456789abcd';
const reference = bytes => ({ uri, sha256: sha256(bytes), size_bytes: bytes.length });
test('verifies actual small JSON/text and binary resources instead of trusting their advertised hashes', async () => {
  for (const content of [{ text: '{"passed":false}\n' }, { blob: Buffer.from([0, 255, 8]).toString('base64') }]) {
    const bytes = content.text ? Buffer.from(content.text) : Buffer.from(content.blob, 'base64');
    const client = { readResource: async () => ({ contents: [{ uri, ...content }] }) };
    assert.deepEqual(await verifiedWorkflowResource(client, reference(bytes)), bytes);
    await assert.rejects(verifiedWorkflowResource(client, { ...reference(bytes), sha256: '0'.repeat(64) }), /differ/);
  }
});
test('reassembles independently hash-bound immutable pages with exact offsets', async () => {
  const bytes = Buffer.alloc(65537, 8), ref = reference(bytes), requests = [];
  const client = { readResource: async ({ uri: requested }) => {
    requests.push(requested); const offset = requests.length === 1 ? 0 : 65536;
    return { contents: [{ uri: requested, text: JSON.stringify({ resource: ref, offset, encoding: 'base64', content_base64: bytes.subarray(offset, offset + 65536).toString('base64'), next_cursor: offset === 0 ? 'next.cursor' : null }) }] };
  } };
  assert.deepEqual(await verifiedWorkflowResource(client, ref), bytes);
  assert.deepEqual(requests, [uri, uri + '?cursor=next.cursor']);
});
test('rejects changed page identity, missing bytes, truncation and invalid references', async () => {
  const bytes = Buffer.from('abc'), ref = reference(bytes);
  for (const page of [
    { resource: { ...ref, sha256: '0'.repeat(64) }, offset: 0, encoding: 'base64', content_base64: 'YWJj', next_cursor: null },
    { resource: ref, offset: 1, encoding: 'base64', content_base64: 'YWJj', next_cursor: null },
    { resource: ref, offset: 0, encoding: 'base64', content_base64: 'YW', next_cursor: null },
    { resource: ref, offset: 0, encoding: 'base64', content_base64: 'YQ==', next_cursor: null },
  ]) await assert.rejects(verifiedWorkflowResource({ readResource: async () => ({ contents: [{ text: JSON.stringify(page) }] }) }, ref));
  await assert.rejects(verifiedWorkflowResource({ readResource: async () => ({ contents: [] }) }, ref));
  await assert.rejects(verifiedWorkflowResource({}, { ...ref, size_bytes: -1 }));
  await assert.rejects(verifiedWorkflowResource({}, { ...ref, uri: 'file:///outside' }));
});
