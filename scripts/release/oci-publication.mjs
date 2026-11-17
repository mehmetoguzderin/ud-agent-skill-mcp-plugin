/** Publish and compare the complete graph of a verified OCI layout archive. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { verifyOciArchive } from './oci.mjs';
import { HttpTransport, OciDistributionAdapter } from './http-transports.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function insist(value, message) { if (!value) throw new Error(message); }
function exact(fd, size, offset) {
  insist(Number.isSafeInteger(size) && size >= 0 && size <= 512 * 1024 * 1024, 'OCI publication object exceeds its bound.');
  const bytes = Buffer.alloc(size); let read = 0;
  while (read < size) { const count = readSync(fd, bytes, read, size - read, offset + read); insist(count > 0, 'OCI publication archive is truncated.'); read += count; }
  return bytes;
}

export class OciArchivePublicationAdapter {
  constructor(http, repository, filename, receipt, indexDigest, platforms) {
    insist(http instanceof HttpTransport, 'OCI publication transport is required.');
    verifyOciArchive(filename, indexDigest, platforms, receipt);
    this.http = http; this.registry = new OciDistributionAdapter(http, repository); this.receipt = { ...receipt }; this.indexDigest = indexDigest;
    this.fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      this.stat = fstatSync(this.fd, { bigint: true });
      insist(this.stat.isFile() && Number(this.stat.size) === receipt.size, 'OCI publication archive changed.');
      const hash = createHash('sha256'), chunk = Buffer.alloc(1024 * 1024); let offset = 0;
      while (offset < receipt.size) { const count = readSync(this.fd, chunk, 0, Math.min(chunk.length, receipt.size - offset), offset); insist(count > 0, 'OCI publication archive is truncated.'); hash.update(chunk.subarray(0, count)); offset += count; }
      insist(hash.digest('hex') === receipt.sha256, 'OCI publication archive changed.');
      const members = new Map(); offset = 0;
      while (offset + 512 <= receipt.size) {
        const header = exact(this.fd, 512, offset); offset += 512;
        if (header.every(byte => byte === 0)) break;
        const field = bytes => bytes.toString('utf8').replace(/\0.*$/, '');
        const prefix = field(header.subarray(345, 500)), leaf = field(header.subarray(0, 100));
        const name = (prefix ? `${prefix}/${leaf}` : leaf).replace(/^\.\//, '');
        const size = Number.parseInt(field(header.subarray(124, 136)).trim() || '0', 8);
        if (header[156] === 0 || header[156] === 48) members.set(name, { size, offset });
        offset += Math.ceil(size / 512) * 512;
      }
      const get = digest => {
        const entry = members.get(`blobs/sha256/${digest.slice(7)}`); insist(entry, 'Verified OCI object is missing.');
        return { ...entry, digest };
      };
      let root = members.get('index.json'); insist(root, 'Verified OCI index is missing.');
      let indexBytes = exact(this.fd, root.size, root.offset);
      if (`sha256:${sha(indexBytes)}` !== indexDigest) { root = get(indexDigest); indexBytes = exact(this.fd, root.size, root.offset); }
      const index = JSON.parse(indexBytes.toString('utf8'));
      this.index = { ...root, digest: indexDigest, mediaType: index.mediaType };
      this.manifests = []; const blobs = new Map();
      for (const descriptor of index.manifests) {
        const object = get(descriptor.digest), bytes = exact(this.fd, object.size, object.offset), manifest = JSON.parse(bytes.toString('utf8'));
        this.manifests.push({ ...object, mediaType: descriptor.mediaType });
        for (const item of [manifest.config, ...manifest.layers]) blobs.set(item.digest, get(item.digest));
      }
      this.blobs = [...blobs.values()]; this.check();
    } catch (error) { closeSync(this.fd); this.fd = null; throw error; }
  }
  check() {
    insist(this.fd !== null, 'OCI publication archive has been closed.');
    const current = fstatSync(this.fd, { bigint: true });
    insist(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => current[key] === this.stat[key]), 'OCI publication archive changed during publication.');
  }
  bytes(object) {
    this.check(); const bytes = exact(this.fd, object.size, object.offset); insist(`sha256:${sha(bytes)}` === object.digest, 'OCI publication object changed.'); this.check(); return bytes;
  }
  async inspect() {
    this.check();
    for (const object of this.blobs) {
      const found = await this.registry.inspectBlob(object.digest, object.size);
      if (!found) return null;
      insist(found.sha256 === object.digest.slice(7) && found.size === object.size, 'Immutable OCI blob conflict.');
    }
    for (const object of [...this.manifests, this.index]) {
      const found = await this.registry.inspectManifest(object.digest, object.size);
      if (!found) return null;
      insist(found.sha256 === object.digest.slice(7) && found.size === object.size, 'Immutable OCI manifest conflict.');
    }
    this.check();
    // The remote representation has all of the exact verified graph objects;
    // tar framing is a local transport property, not registry content.
    return { sha256: this.receipt.sha256, size: this.receipt.size, oci_digest: this.indexDigest };
  }
  async publish(_item, archiveBytes) {
    insist(Buffer.isBuffer(archiveBytes) && archiveBytes.length === this.receipt.size && sha(archiveBytes) === this.receipt.sha256, 'OCI publication bytes differ from the accepted archive.');
    return this.publishArtifact(_item, this.receipt);
  }
  verifyArtifact(artifact) { insist(artifact.sha256 === this.receipt.sha256 && artifact.size === this.receipt.size, 'OCI archive differs from its accepted artifact.'); this.check(); }
  async publishArtifact(item, artifact) {
    this.verifyArtifact(artifact);
    for (const object of this.blobs) {
      const found = await this.registry.inspectBlob(object.digest, object.size);
      if (found) insist(found.sha256 === object.digest.slice(7) && found.size === object.size, 'Immutable OCI blob conflict.');
      else await this.registry.publishBlob(object.digest, this.bytes(object));
    }
    for (const object of [...this.manifests, this.index]) {
      const found = await this.registry.inspectManifest(object.digest, object.size);
      if (found) insist(found.sha256 === object.digest.slice(7) && found.size === object.size, 'Immutable OCI manifest conflict.');
      else await this.registry.publishManifest(object.digest, this.bytes(object), object.mediaType);
    }
    this.check();
  }
  async promote(tag) { this.check(); await this.registry.promote(tag, this.bytes(this.index), this.index.mediaType); }
  async verifyPromotion(tag) { const result = await this.registry.inspectManifest(tag, this.index.size); return result?.sha256 === this.indexDigest.slice(7) && result.size === this.index.size; }
  close() { if (this.fd !== null) { closeSync(this.fd); this.fd = null; } }
}
