import { TRANSFER_CHUNK_BYTES } from './snapshot-transfer.js';
import type { SnapshotFrame } from './snapshot-transfer.js';

/** JSONL transport mapping for the Python receiver; expected digest travels separately. */
export function encodeSnapshotFrame(frame: SnapshotFrame): Buffer {
  let value: object;
  switch (frame.type) {
    case 'begin': value = { type: 'begin', manifest: frame.manifest, snapshot_sha256: frame.snapshot_sha256 }; break;
    case 'chunk':
      if (!Buffer.isBuffer(frame.bytes) || frame.bytes.length === 0 || frame.bytes.length > TRANSFER_CHUNK_BYTES || !Number.isSafeInteger(frame.offset) || frame.offset < 0) throw new Error('Invalid snapshot chunk.');
      value = { type: 'chunk', path: frame.path, offset: frame.offset, bytes_base64: frame.bytes.toString('base64') };
      break;
    case 'file_end': value = { type: 'file_end', path: frame.path }; break;
    case 'end': value = { type: 'end', snapshot_sha256: frame.snapshot_sha256 }; break;
    default: throw new Error('Unknown snapshot frame.');
  }
  const encoded = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (encoded.length > 8 * 1024 * 1024) throw new Error('Snapshot frame exceeds its wire limit.');
  return encoded;
}

export async function* encodeSnapshotFrames(frames: AsyncIterable<SnapshotFrame>): AsyncGenerator<Buffer> {
  for await (const frame of frames) yield encodeSnapshotFrame(frame);
}
