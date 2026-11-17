import { decodeWorkerArtifact } from './worker-artifacts.js';
export const RENDER_PROBE_REVISION = 1;
export const RENDER_PROBE_SENTENCE = '# sent_id = render-probe\n# text = English العربية 日本語\n1\tEnglish\tenglish\tX\t_\t_\t0\troot\t_\t_\n2\tالعربية\tالعربية\tX\t_\t_\t1\tdep\t_\t_\n3\t日本語\t日本語\tX\t_\t_\t1\tdep\t_\t_\n\n';
export function verifyRenderProbe(result: Record<string, unknown>, format: 'png' | 'pdf'): { sha256: string; size_bytes: number } {
  const artifacts = result.artifacts;
  if (result.status !== 'complete' || !Array.isArray(artifacts) || artifacts.length !== 1) throw new Error('RENDER_PROBE_INCOMPLETE');
  const decoded = decodeWorkerArtifact(artifacts[0]), bytes = decoded.bytes;
  const valid = format === 'png' ? decoded.mime === 'image/png' && bytes.length >= 100 && bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) : decoded.mime === 'application/pdf' && bytes.length >= 100 && bytes.subarray(0, 5).equals(Buffer.from('%PDF-')) && bytes.subarray(-1024).includes(Buffer.from('%%EOF'));
  if (!valid) throw new Error('RENDER_PROBE_OUTPUT_INVALID');
  return { sha256: decoded.sha256, size_bytes: bytes.length };
}
