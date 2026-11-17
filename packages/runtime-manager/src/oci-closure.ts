import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';

type Descriptor = { digest: string; size: number; mediaType: string };
type Entry = { size: number; sha256: string; json?: Record<string, unknown> };
const SHA = /^sha256:[0-9a-f]{64}$/;
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function insist(value: unknown, reason: string): asserts value { if (!value) throw new Error(`OCI_CLOSURE_INVALID: ${reason}`); }
function descriptor(value: unknown): Descriptor {
  const item = object(value);
  insist(item && typeof item.digest === 'string' && SHA.test(item.digest) && typeof item.mediaType === 'string' && Number.isSafeInteger(item.size) && (item.size as number) >= 0, 'descriptor');
  return item as Descriptor;
}
function text(bytes: Buffer): string { return new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\0.*$/s, ''); }
function octal(bytes: Buffer): number { const raw = text(bytes).trim(); insist(/^[0-7]*$/.test(raw), 'tar number'); const value = raw ? Number.parseInt(raw, 8) : 0; insist(Number.isSafeInteger(value), 'tar number bounds'); return value; }

/** Verify all referenced OCI bytes without extraction or a registry request. */
export async function verifyOciClosure(filename: string, expected: { manifestDigest: string; architecture: 'amd64' | 'arm64'; indexDigest?: string; configDigest?: string; diffIds?: readonly string[]; timestampPax?: boolean }): Promise<{ manifestDigest: string; configDigest: string; layers: string[]; indexDigest: string }> {
  if (!path.isAbsolute(filename) || !SHA.test(expected.manifestDigest) || expected.indexDigest !== undefined && !SHA.test(expected.indexDigest) || expected.configDigest !== undefined && !SHA.test(expected.configDigest)) throw new Error('OCI_CLOSURE_RECEIPT_INVALID');
  const file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await file.stat({ bigint: true });
    insist(before.isFile() && before.nlink === 1n && before.size <= 20n * 1024n * 1024n * 1024n, 'archive bounds');
    const total = Number(before.size); let offset = 0; let zeros = 0; let headers = 0; let pendingPax = false;
    const entries = new Map<string, Entry>(); const buffer = Buffer.alloc(1024 * 1024);
    const exact = async (count: number, at: number): Promise<Buffer> => {
      const bytes = Buffer.alloc(count); let done = 0;
      while (done < count) { const result = await file.read(bytes, done, count - done, at + done); insist(result.bytesRead > 0, 'truncated'); done += result.bytesRead; }
      return bytes;
    };
    while (offset + 512 <= total) {
      const header = await exact(512, offset); offset += 512;
      if (header.every(value => value === 0)) { zeros++; if (zeros === 2) break; continue; }
      insist(zeros === 0 && ++headers <= 50_000, 'tar framing');
      const checksum = octal(header.subarray(148, 156)); let sum = 0;
      for (let index = 0; index < 512; index++) sum += index >= 148 && index < 156 ? 32 : header[index]!;
      insist(sum === checksum, 'tar checksum');
      const prefix = text(header.subarray(345, 500)); let name = `${prefix ? `${prefix}/` : ''}${text(header.subarray(0, 100))}`;
      if (name.startsWith('./')) name = name.slice(2);
      const type = header[156]; const size = octal(header.subarray(124, 136));
      // Apple's native exporter emits per-entry timestamp PAX records. These
      // are never extracted and cannot override names, sizes or link targets.
      // Other archive users retain the original strict no-extension policy.
      if (type === 120 && expected.timestampPax === true) {
        insist(!pendingPax && size > 0 && size <= 32768 && size <= total - offset && /^[A-Za-z0-9._/-]{1,256}$/.test(name) && !name.split('/').includes('..'), 'PAX metadata bounds');
        const bytes = await exact(size, offset); let cursor = 0; const keys = new Set<string>();
        while (cursor < bytes.length) {
          const space = bytes.indexOf(32, cursor); insist(space > cursor && space - cursor <= 6, 'PAX record length'); const digits = bytes.subarray(cursor, space).toString('ascii'); insist(/^[1-9][0-9]{0,5}$/.test(digits), 'PAX record length'); const length = Number(digits); insist(length > space - cursor + 2 && length <= bytes.length - cursor && bytes[cursor + length - 1] === 10, 'PAX record framing');
          const pair = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(space + 1, cursor + length - 1)); const match = /^(atime|ctime|mtime)=(-?[0-9]{1,20}(?:\.[0-9]{1,9})?)$/.exec(pair); insist(match && !keys.has(match[1]!), 'PAX timestamp-only metadata'); keys.add(match[1]!); cursor += length;
        }
        offset += Math.ceil(size / 512) * 512; pendingPax = true; continue;
      }
      insist(type === 0 || type === 48 || type === 53, 'links and extended tar entries are forbidden');
      pendingPax = false;
      if (type === 53) { insist(size === 0 && (/^(?:blobs\/?|blobs\/sha256\/?)$/.test(name) || expected.timestampPax === true && (name === '' || name === '.')), 'unexpected directory'); continue; }
      insist(name === 'oci-layout' || name === 'index.json' || /^blobs\/sha256\/[0-9a-f]{64}$/.test(name), 'unexpected path');
      insist(!entries.has(name) && size <= total - offset && size <= 20 * 1024 * 1024 * 1024, 'duplicate or excessive entry');
      const digest = createHash('sha256'); const retained: Buffer[] = [];
      let consumed = 0;
      while (consumed < size) { const count = Math.min(buffer.length, size - consumed); const result = await file.read(buffer, 0, count, offset + consumed); insist(result.bytesRead > 0, 'truncated payload'); const chunk = buffer.subarray(0, result.bytesRead); digest.update(chunk); if (size <= 16 * 1024 * 1024) retained.push(Buffer.from(chunk)); consumed += result.bytesRead; }
      const hash = `sha256:${digest.digest('hex')}`;
      if (name.startsWith('blobs/sha256/')) insist(hash === `sha256:${name.slice(13)}`, 'blob digest');
      const entry: Entry = { size, sha256: hash };
      if (retained.length || size === 0) {
        try { const parsed = object(JSON.parse(text(Buffer.concat(retained)))); if (parsed) entry.json = parsed; }
        catch { /* Layer bytes need not be JSON. Descriptor consumers require it. */ }
      }
      entries.set(name, entry); offset += Math.ceil(size / 512) * 512;
    }
    insist(zeros === 2 && !pendingPax, 'missing tar end marker');
    while (offset < total) { const count = Math.min(buffer.length, total - offset); const result = await file.read(buffer, 0, count, offset); insist(result.bytesRead > 0 && buffer.subarray(0, result.bytesRead).every(value => value === 0), 'trailing payload'); offset += result.bytesRead; }
    insist(entries.get('oci-layout')?.json?.imageLayoutVersion === '1.0.0', 'layout version');
    const index = entries.get('index.json'); const root = index?.json;
    insist(root?.schemaVersion === 2 && Array.isArray(root.manifests) && root.manifests.length > 0 && root.manifests.length <= 128, 'root index');
    insist(expected.indexDigest === undefined || index?.sha256 === expected.indexDigest, 'index receipt');
    const read = (raw: unknown): { entry: Entry; descriptor: Descriptor } => {
      const selected = descriptor(raw); const entry = entries.get(`blobs/sha256/${selected.digest.slice(7)}`);
      insist(entry && entry.sha256 === selected.digest && entry.size === selected.size, 'missing or mismatched blob'); return { entry, descriptor: selected };
    };
    const visited = new Set<string>(); let found = false;
    const walk = (raw: unknown, depth: number) => {
      insist(depth <= 8, 'index depth'); const item = read(raw); if (visited.has(item.descriptor.digest)) return; visited.add(item.descriptor.digest);
      const json = item.entry.json;
      if (item.descriptor.mediaType.endsWith('image.index.v1+json') || item.descriptor.mediaType.endsWith('manifest.list.v2+json')) {
        insist(json?.schemaVersion === 2 && Array.isArray(json.manifests) && json.manifests.length > 0 && json.manifests.length <= 128, 'nested index');
        for (const nested of json.manifests) walk(nested, depth + 1);
      } else if (item.descriptor.mediaType.endsWith('image.manifest.v1+json') || item.descriptor.mediaType.endsWith('manifest.v2+json')) {
        insist(json?.schemaVersion === 2 && Array.isArray(json.layers) && json.layers.length > 0 && json.layers.length <= 1024, 'manifest');
        read(json.config); for (const layer of json.layers) read(layer);
        if (item.descriptor.digest === expected.manifestDigest) found = true;
      } else throw new Error('OCI_CLOSURE_INVALID: unexpected index media type');
    };
    for (const raw of root.manifests) walk(raw, 0);
    insist(found, 'expected platform manifest absent');
    const manifest = entries.get(`blobs/sha256/${expected.manifestDigest.slice(7)}`)?.json;
    insist(manifest && Array.isArray(manifest.layers), 'platform manifest');
    const config = read(manifest.config); const body = config.entry.json; const rootfs = object(body?.rootfs);
    insist(body?.os === 'linux' && body.architecture === expected.architecture && rootfs?.type === 'layers' && Array.isArray(rootfs.diff_ids) && rootfs.diff_ids.length === manifest.layers.length && rootfs.diff_ids.every(value => typeof value === 'string' && SHA.test(value)), 'platform config');
    insist(expected.configDigest === undefined || config.descriptor.digest === expected.configDigest, 'config receipt');
    insist(expected.diffIds === undefined || JSON.stringify(rootfs.diff_ids) === JSON.stringify(expected.diffIds), 'rootfs receipt');
    const after = await file.stat({ bigint: true });
    insist(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs, 'archive changed');
    return { manifestDigest: expected.manifestDigest, configDigest: config.descriptor.digest, layers: manifest.layers.map(value => descriptor(value).digest), indexDigest: index!.sha256 };
  } finally { await file.close(); }
}
