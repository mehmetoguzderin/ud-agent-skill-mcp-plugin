import { sha256 } from '../../workspace/src/journal.js';
import { validCandidatePath } from '../../workspace/src/transactions.js';

/** Compatibility decoder for existing text exports and binary artifact records. */
export function decodeWorkerArtifact(value: unknown): { relativePath: string; mime: string; bytes: Buffer; sha256: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('WORKER_ARTIFACT_INVALID');
  const item = value as Record<string, unknown>;
  const name = item.relative_path ?? item.filename;
  if (typeof name !== 'string' || !validCandidatePath(name) || typeof item.mime_type !== 'string' || (typeof item.content === 'string') === (typeof item.content_base64 === 'string')) throw new Error('WORKER_ARTIFACT_INVALID');
  let bytes: Buffer;
  if (typeof item.content === 'string') {
    if (Buffer.byteLength(item.content) > 64 * 1024 * 1024) throw new Error('WORKER_ARTIFACT_TOO_LARGE');
    bytes = Buffer.from(item.content, 'utf8'); if (bytes.toString('utf8') !== item.content) throw new Error('WORKER_ARTIFACT_INVALID_UNICODE');
  } else {
    const encoded = item.content_base64 as string;
    if (encoded.length > Math.ceil((64 * 1024 * 1024) / 3) * 4) throw new Error('WORKER_ARTIFACT_TOO_LARGE');
    bytes = Buffer.from(encoded, 'base64'); if (bytes.toString('base64') !== encoded) throw new Error('WORKER_ARTIFACT_INTEGRITY_FAILED');
  }
  if (bytes.length > 64 * 1024 * 1024 || bytes.length !== item.size_bytes || sha256(bytes) !== item.sha256) throw new Error('WORKER_ARTIFACT_INTEGRITY_FAILED');
  return { relativePath: name, mime: item.mime_type, bytes, sha256: item.sha256 as string };
}
