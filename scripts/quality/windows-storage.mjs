/** Original Windows storage controls before the native guard is built. MIT. */
import { lstatSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const helper = fileURLToPath(new URL('./windows-storage-acl.py', import.meta.url));
const checkout = path.resolve(path.dirname(helper), '../..');
const need = (condition, message) => { if (!condition) throw new Error('Storage admission: ' + message); };
let pending;

export function windowsStorageEnvironment(python, environment = process.env) {
  if (process.platform !== 'win32') return environment;
  const selected = python ?? environment.UD_STORAGE_WINDOWS_PYTHON ?? environment.UD_AGENT_PYTHON ?? path.join(checkout, '.venv/Scripts/python.exe');
  need(typeof selected === 'string' && path.isAbsolute(selected) && !/[\0\r\n]/.test(selected), 'Windows ACL checks require the selected absolute Python');
  const actual = realpathSync(selected), info = lstatSync(actual);
  need(info.isFile() && !info.isSymbolicLink(), 'Windows ACL Python is not an ordinary executable');
  return { ...environment, UD_STORAGE_WINDOWS_PYTHON: selected };
}

function invoke(requests) {
  const env = windowsStorageEnvironment();
  const result = spawnSync(env.UD_STORAGE_WINDOWS_PYTHON, ['-I', '-B', helper], { env, input: JSON.stringify(requests), encoding: 'utf8', timeout: 10_000, maxBuffer: 65536, windowsHide: true });
  need(!result.error && result.status === 0, 'Windows ownership/ACL verification failed: ' + (result.error?.message ?? result.stderr?.slice(-4000) ?? result.status));
  let values;
  try { values = JSON.parse(result.stdout); } catch { throw new Error('Storage admission: Windows ACL helper response is invalid'); }
  need(Array.isArray(values) && values.length === requests.length, 'Windows ACL helper response is incomplete');
  return values;
}

function verify(rows) {
  if (!rows.length) return;
  const results = invoke(rows.map(row => row.request));
  for (let i = 0; i < rows.length; i++) {
    const { request, before } = rows[i], after = lstatSync(request.path, { bigint: true }), actual = results[i];
    // Scratch directory contents legitimately grow while monitoring. Their
    // identities must remain fixed; immutable ownership files also keep bytes.
    const keys = request.kind === 'directory' ? ['dev', 'ino', 'mode'] : ['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'];
    need(actual?.device === String(before.dev) && actual?.inode === String(before.ino)
      && keys.every(key => before[key] === after[key]), 'Windows storage identity changed during ACL verification');
  }
}

export function verifyWindowsStorage(filename, kind, privateMode) {
  const row = { request: { operation: 'check', path: path.resolve(filename), kind, private: privateMode }, before: lstatSync(filename, { bigint: true }) };
  if (pending) pending.push(row); else verify([row]);
}

/** Batch read-only lease checks; all ACLs verify before the caller can mutate. */
export function batchWindowsStorage(callback) {
  if (process.platform !== 'win32' || pending) return callback();
  pending = [];
  try { const value = callback(); verify(pending); return value; }
  finally { pending = undefined; }
}

export function createWindowsStorage(filename, kind, body) {
  const request = { operation: 'create', path: path.resolve(filename), kind, ...(body === undefined ? {} : { body: Buffer.from(body).toString('base64') }) };
  const [actual] = invoke([request]), info = lstatSync(filename, { bigint: true });
  need(actual?.device === String(info.dev) && actual?.inode === String(info.ino) && !info.isSymbolicLink()
    && (kind === 'directory' ? info.isDirectory() : info.isFile() && info.nlink === 1n), 'new Windows storage identity changed');
}

export function windowsStorageLeaseEnvironment() {
  return process.platform === 'win32' ? { UD_STORAGE_WINDOWS_PYTHON: windowsStorageEnvironment().UD_STORAGE_WINDOWS_PYTHON } : {};
}
