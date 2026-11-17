/** Bounded lossless evidence codecs for new diagnostic observations. MIT. */
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { sha256 } from '../../scripts/release/candidate.mjs';
export const MAXIMUM_OBSERVATION_BYTES = 16 * 1024 ** 2;
export function writeCompressedObservation(file, value) {
  const plain = Buffer.from(JSON.stringify(value));
  if (plain.length > MAXIMUM_OBSERVATION_BYTES) throw new Error('STUDY_OBSERVATION_DECOMPRESSED_LIMIT');
  const compressed = gzipSync(plain, { level: 6 });
  writeFileSync(file, compressed, { flag: 'wx', mode: 0o600 });
  return { path: file, sha256: sha256(compressed), payload_codec: 'gzip-json-v1', payload_sha256: sha256(plain),
    compressed_bytes: compressed.length, decompressed_bytes: plain.length };
}
export function readObservation(item) {
  const bytes = readFileSync(item.path);
  if (bytes.length > MAXIMUM_OBSERVATION_BYTES) throw new Error('STUDY_OBSERVATION_COMPRESSED_LIMIT');
  if (item.sha256 && sha256(bytes) !== item.sha256) throw new Error('STUDY_OBSERVATION_BYTES_CHANGED');
  if (item.payload_codec && item.payload_codec !== 'gzip-json-v1') throw new Error('STUDY_OBSERVATION_CODEC_UNSUPPORTED');
  const decoded = item.payload_codec === 'gzip-json-v1' ? gunzipSync(bytes, { maxOutputLength: MAXIMUM_OBSERVATION_BYTES }) : bytes;
  if (decoded.length > MAXIMUM_OBSERVATION_BYTES || item.decompressed_bytes !== undefined && decoded.length !== item.decompressed_bytes) throw new Error('STUDY_OBSERVATION_DECOMPRESSED_LIMIT');
  if (item.payload_sha256 && sha256(decoded) !== item.payload_sha256) throw new Error('STUDY_OBSERVATION_PAYLOAD_CHANGED');
  return JSON.parse(decoded.toString('utf8'));
}
