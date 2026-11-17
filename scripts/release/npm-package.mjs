/** Public npm manifests are derived from, and checked against, the accepted tarball. */
import { gunzipSync } from 'node:zlib';
import { portablePathKey, validPortablePath } from './portable-policy.mjs';

const MAX_ARCHIVE = 128 * 1024 * 1024;
const MAX_EXPANDED = 512 * 1024 * 1024;
function insist(value, message) { if (!value) throw new Error(message); }
function plain(value) { return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
export function publishedNpmManifest(value) {
  insist(plain(value) && /^@[a-z0-9._-]+\/[a-z0-9._-]+$/.test(value.name ?? '') && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.version ?? ''), 'Invalid public npm package identity.');
  insist(value.private === undefined || value.private === false, 'Private or malformed npm packages cannot be published.');
  insist(value.publishConfig === undefined || plain(value.publishConfig) && Object.keys(value.publishConfig).every(key => key === 'access') && value.publishConfig.access === 'public', 'npm publication must use public access and the authorized registry.');
  const result = { ...value, publishConfig: { access: 'public' } }; delete result.private;
  return result;
}
function field(bytes) {
  const end = bytes.indexOf(0); const value = new TextDecoder('utf-8', { fatal: true }).decode(end < 0 ? bytes : bytes.subarray(0, end));
  insist(end < 0 || bytes.subarray(end).every(byte => byte === 0), 'Invalid npm tar field.'); return value;
}
function number(bytes) { const value = bytes.toString('ascii').replace(/[\0 ]+$/, '').trim(); insist(/^[0-7]+$/.test(value), 'Invalid npm tar number.'); const result = Number.parseInt(value, 8); insist(Number.isSafeInteger(result), 'Invalid npm tar number.'); return result; }
function safePath(value) { return value.startsWith('package/') && validPortablePath(value.replace(/\/$/, '')); }
function pax(bytes) {
  const result = {}; let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset); insist(space > offset && space - offset <= 10, 'Invalid npm PAX record.');
    const digits = bytes.subarray(offset, space).toString('ascii'); insist(/^[1-9][0-9]*$/.test(digits), 'Invalid npm PAX record.');
    const size = Number(digits), end = offset + size; insist(end <= bytes.length && end > space + 2 && bytes[end - 1] === 10, 'Invalid npm PAX record.');
    const entry = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(space + 1, end - 1)); const equals = entry.indexOf('='); insist(equals > 0, 'Invalid npm PAX entry.');
    const key = entry.slice(0, equals); insist(['path', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname', 'SCHILY.dev', 'SCHILY.ino', 'SCHILY.nlink'].includes(key) && !Object.hasOwn(result, key), 'Unsupported npm PAX entry.');
    result[key] = entry.slice(equals + 1); offset = end;
  }
  return result;
}
export function npmManifestFromTarball(archive) {
  insist(Buffer.isBuffer(archive) && archive.length > 0 && archive.length <= MAX_ARCHIVE, 'npm tarball exceeds its bound.');
  const bytes = gunzipSync(archive, { maxOutputLength: MAX_EXPANDED }); const seen = new Set(), ordinary = new Set(), ordinaryExact = new Set(), directories = new Set(); let offset = 0, manifest, pending, ended = false;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512); offset += 512;
    if (header.every(byte => byte === 0)) { insist(bytes.length - offset >= 512 && bytes.subarray(offset).every(byte => byte === 0) && !pending, 'Invalid npm tar ending.'); ended = true; break; }
    const checksum = number(header.subarray(148, 156)); let actual = 0; for (let index = 0; index < 512; index++) actual += index >= 148 && index < 156 ? 32 : header[index];
    insist(checksum === actual && field(header.subarray(257, 263)) === 'ustar', 'Invalid npm tar header.');
    const size = number(header.subarray(124, 136)); insist(size <= MAX_EXPANDED && offset + Math.ceil(size / 512) * 512 <= bytes.length, 'Truncated npm tar member.');
    const content = bytes.subarray(offset, offset + size); const padding = bytes.subarray(offset + size, offset + Math.ceil(size / 512) * 512); insist(padding.every(byte => byte === 0), 'Invalid npm tar padding.'); offset += Math.ceil(size / 512) * 512;
    const type = header[156]; if (type === 120) { insist(!pending && size <= 64 * 1024, 'Invalid npm PAX header.'); pending = pax(content); continue; }
    const prefix = field(header.subarray(345, 500)), leaf = field(header.subarray(0, 100)); const name = pending?.path ?? (prefix ? `${prefix}/${leaf}` : leaf); pending = undefined;
    insist(safePath(name) && [0, 48, 53].includes(type) && (type !== 53 || size === 0) && !field(header.subarray(157, 257)), 'Unsafe npm tar member.');
    const key = portablePathKey(name.replace(/\/$/, '')); insist(!seen.has(key) && seen.size < 50_000, 'Duplicate npm tar member.'); for (let parent = key.lastIndexOf('/'); parent > 0; parent = key.lastIndexOf('/', parent - 1)) { const name = key.slice(0, parent); insist(!ordinary.has(name), 'npm tar member has an ordinary-file parent.'); directories.add(name); }
    if (type !== 53) { insist(!directories.has(key), 'npm tar file aliases an existing directory.'); ordinary.add(key); ordinaryExact.add(name); } else directories.add(key);
    seen.add(key);
    if (name === 'package/package.json') { insist(type !== 53 && size <= 1024 * 1024 && manifest === undefined, 'Invalid npm package manifest.'); manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content)); }
  }
  insist(ended && manifest, 'npm tarball has no complete package manifest.');
  const normalized = publishedNpmManifest(manifest);
  const bins = typeof manifest.bin === 'string' ? [manifest.bin] : plain(manifest.bin) ? Object.values(manifest.bin) : [];
  insist(bins.length > 0 && bins.every(value => typeof value === 'string' && validPortablePath(value) && ordinaryExact.has('package/' + value)), 'npm executable metadata does not identify an ordinary packaged file.');
  insist(manifest.publishConfig?.access === 'public', 'Accepted npm tarball must declare public access.');
  return normalized;
}
