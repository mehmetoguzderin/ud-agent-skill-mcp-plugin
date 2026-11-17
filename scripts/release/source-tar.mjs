/** Streaming USTAR inspection; source archives remain opaque ordinary files. */
import { createHash } from 'node:crypto';
const HASH = /^[0-9a-f]{64}$/;
function insist(value, message) { if (!value) throw new Error(message); }
function name(value) { return value === 'MATERIALS.json' || /^receipts\/[a-z0-9][a-z0-9-]{0,80}\.json$/.test(value) || /^blobs\/[0-9a-f]{64}$/.test(value); }
function receipt(value) { return value && typeof value.path === 'string' && name(value.path) && HASH.test(value.sha256 ?? '') && Number.isSafeInteger(value.size_bytes) && value.size_bytes >= 0 && value.size_bytes <= 8 * 1024 ** 3; }
function octal(field) { const text = field.toString('ascii').replace(/\0.*$/, '').trim(); insist(/^[0-7]+$/.test(text), 'Source archive has an invalid octal field.'); const result = Number.parseInt(text, 8); insist(Number.isSafeInteger(result), 'Source archive numeric field exceeds its bound.'); return result; }
function string(field) { const end = field.indexOf(0); if (end >= 0) { insist(field.subarray(end).every(byte => byte === 0), 'Source archive string has nonzero trailing bytes.'); field = field.subarray(0, end); } return new TextDecoder('utf-8', { fatal: true }).decode(field); }

export class SourceTarVerifier {
  constructor(index) { this.index = index; this.header = Buffer.alloc(0); this.pending = null; this.padding = 0; this.zeros = 0; this.seen = new Set(); this.expected = null; this.manifest = null; this.total = 0; }
  feed(input) {
    this.total += input.length;
    let bytes = input;
    while (bytes.length) {
      if (this.zeros >= 2) { insist(bytes.every(byte => byte === 0), 'Source archive has bytes after its end marker.'); return; }
      if (this.pending) {
        const size = Math.min(bytes.length, this.pending.remaining), part = bytes.subarray(0, size); bytes = bytes.subarray(size); this.pending.remaining -= size; this.pending.hash.update(part);
        if (this.pending.metadata) this.pending.chunks.push(Buffer.from(part));
        if (!this.pending.remaining) this.complete();
        continue;
      }
      if (this.padding) { const count = Math.min(bytes.length, this.padding); insist(bytes.subarray(0, count).every(byte => byte === 0), 'Source archive padding is nonzero.'); this.padding -= count; bytes = bytes.subarray(count); continue; }
      const amount = Math.min(bytes.length, 512 - this.header.length); this.header = Buffer.concat([this.header, bytes.subarray(0, amount)]); bytes = bytes.subarray(amount);
      if (this.header.length !== 512) continue;
      const header = this.header; this.header = Buffer.alloc(0);
      if (header.every(byte => byte === 0)) { this.zeros++; continue; }
      insist(this.zeros === 0 && header.subarray(257, 263).equals(Buffer.from('ustar\0')) && header.subarray(263, 265).equals(Buffer.from('00')), 'Source archive is not ordinary USTAR.');
      const expectedChecksum = octal(header.subarray(148, 156)), unsigned = Buffer.from(header); unsigned.fill(32, 148, 156); insist(unsigned.reduce((sum, byte) => sum + byte, 0) === expectedChecksum, 'Source archive header checksum differs.');
      const prefix = string(header.subarray(345, 500)), leaf = string(header.subarray(0, 100)), filename = prefix ? prefix + '/' + leaf : leaf, size = octal(header.subarray(124, 136));
      insist(name(filename) && !this.seen.has(filename) && this.seen.size < 100_000 && [0, 48].includes(header[156]) && string(header.subarray(157, 257)) === '' && size <= 8 * 1024 ** 3, 'Source archive has an unsafe, duplicate, linked or oversized member.');
      insist(this.seen.size > 0 || filename === 'MATERIALS.json', 'Source archive must start with its closed inventory.');
      insist(filename !== 'MATERIALS.json' || this.manifest === null, 'Source inventory is duplicated.');
      if (filename !== 'MATERIALS.json') insist(this.expected?.has(filename), 'Source archive contains an undeclared member.');
      this.seen.add(filename); this.padding = (512 - size % 512) % 512;
      const metadata = filename === 'MATERIALS.json'; insist(!metadata || size <= 32 * 1024 * 1024, 'Source inventory exceeds its bound.');
      this.pending = { filename, size, remaining: size, hash: createHash('sha256'), metadata, chunks: [] }; if (!size) this.complete();
    }
  }
  complete() {
    const member = this.pending; this.pending = null; const fingerprint = member.hash.digest('hex');
    if (member.metadata) {
      insist(fingerprint === this.index.manifest_sha256, 'Source inventory differs from its external index.');
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(member.chunks)));
      insist(data.schema_version === 1 && data.qualification === this.index.qualification && data.complete_product_coverage === this.index.complete_product_coverage && Array.isArray(data.files) && data.files.length > 0 && data.files.length <= 100_000 && Array.isArray(data.collections) && data.collections.length > 0 && data.collections.length <= 1000, 'Source member inventory is invalid.');
      this.expected = new Map(); const put = row => { insist(receipt(row) && !this.expected.has(row.path), 'Source member declarations conflict.'); this.expected.set(row.path, row); };
      for (const row of data.files) { insist(row.path === 'blobs/' + row.sha256, 'Source blob path is not content-bound.'); put(row); }
      const ids = new Set();
      for (const collection of data.collections) {
        insist(typeof collection.id === 'string' && /^[a-z0-9][a-z0-9-]{0,80}$/.test(collection.id) && !ids.has(collection.id) && collection.receipt_path === `receipts/${collection.id}.json` && Array.isArray(collection.members) && collection.members.length > 0 && collection.members.length <= 100_000, 'Source collection declaration is invalid.'); ids.add(collection.id);
        put({ path: collection.receipt_path, sha256: collection.receipt_sha256, size_bytes: collection.receipt_size_bytes });
        for (const row of collection.members) { const expected = this.expected.get(row.path); insist(expected && expected.sha256 === row.sha256 && expected.size_bytes === row.size_bytes, 'Source collection references an absent or different blob.'); }
      }
      insist(Array.isArray(this.index.collections) && this.index.collections.length === ids.size && this.index.collections.every(row => ids.has(row.id) && data.collections.some(collection => collection.id === row.id && collection.receipt_sha256 === row.sha256)) && new Set(this.index.collections.map(row => row.id)).size === ids.size && this.index.unique_source_files === data.files.length, 'External source collections differ from the archive inventory.');
      this.manifest = data;
    } else {
      const expected = this.expected.get(member.filename); insist(expected && expected.sha256 === fingerprint && expected.size_bytes === member.size, 'Source archive member bytes differ from the closed inventory.'); this.expected.delete(member.filename);
    }
  }
  finish() { insist(this.total % 512 === 0 && !this.pending && !this.padding && !this.header.length && this.zeros >= 2 && this.manifest && this.expected?.size === 0, 'Source archive is truncated or omits declared members.'); return { verified: true, files: this.seen.size, complete_product_coverage: this.manifest.complete_product_coverage }; }
}
