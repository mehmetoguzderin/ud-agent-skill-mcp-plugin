/** Independent export-byte and prerequisite contract; no browser is mocked as accepted native evidence. */
import { createHash } from 'node:crypto';
import { expect, test } from 'vitest';
import { RENDER_PROBE_SENTENCE, verifyRenderProbe } from '../../packages/coordinator/src/render-probe.js';

function artifact(format: 'png' | 'pdf', size = 150) {
  const bytes = Buffer.alloc(size);
  if (format === 'png') Buffer.from('89504e470d0a1a0a', 'hex').copy(bytes);
  else { bytes.write('%PDF-1.7'); bytes.write('%%EOF', size - 5); }
  return { relative_path: 'probe.' + format, mime_type: format === 'png' ? 'image/png' : 'application/pdf', content_base64: bytes.toString('base64'), sha256: createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length };
}
test('readiness records independently verified multilingual PNG and PDF byte identities', () => {
  expect(RENDER_PROBE_SENTENCE).toContain('English العربية 日本語');
  for (const format of ['png', 'pdf'] as const) {
    const output = artifact(format);
    expect(verifyRenderProbe({ status: 'complete', artifacts: [output] }, format)).toEqual({ sha256: output.sha256, size_bytes: 150 });
  }
});
test('incomplete execution and absent, extra or mismatched output never certify rendering', () => {
  const output = artifact('png');
  for (const result of [{ artifacts: [output] }, { status: 'incomplete', artifacts: [output] }, { status: 'complete' }, { status: 'complete', artifacts: [] }, { status: 'complete', artifacts: [output, output] }]) expect(() => verifyRenderProbe(result, 'png')).toThrow('RENDER_PROBE_INCOMPLETE');
  expect(() => verifyRenderProbe({ status: 'complete', artifacts: [artifact('pdf')] }, 'png')).toThrow('RENDER_PROBE_OUTPUT_INVALID');
});
test('hash, size, encoding, media and file-signature failures remain integrity or invalid-output failures', () => {
  const original = artifact('png');
  for (const patch of [{ sha256: '0'.repeat(64) }, { size_bytes: 151 }, { content_base64: original.content_base64 + '\n' }]) expect(() => verifyRenderProbe({ status: 'complete', artifacts: [{ ...original, ...patch }] }, 'png')).toThrow('WORKER_ARTIFACT_INTEGRITY_FAILED');
  for (const patch of [{ mime_type: 'text/plain' }, { ...artifact('png', 99) }]) expect(() => verifyRenderProbe({ status: 'complete', artifacts: [{ ...original, ...patch }] }, 'png')).toThrow('RENDER_PROBE_OUTPUT_INVALID');
  const bytes = Buffer.alloc(150), damaged = { ...original, content_base64: bytes.toString('base64'), sha256: createHash('sha256').update(bytes).digest('hex') };
  expect(() => verifyRenderProbe({ status: 'complete', artifacts: [damaged] }, 'png')).toThrow('RENDER_PROBE_OUTPUT_INVALID');
});
test('PDF requires both a header and bounded end marker in verified bytes', () => {
  for (const bytes of [Buffer.concat([Buffer.from('%PDF-1.7'), Buffer.alloc(150)]), Buffer.concat([Buffer.from('%%EOF'), Buffer.alloc(1200)])]) {
    const output = { ...artifact('pdf'), content_base64: bytes.toString('base64'), size_bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    expect(() => verifyRenderProbe({ status: 'complete', artifacts: [output] }, 'pdf')).toThrow('RENDER_PROBE_OUTPUT_INVALID');
  }
});
