/** Explicit local HTTP/1.1 sockets for fixtures inside network-denied test jobs. */
import { request } from 'node:http';
import { Readable } from 'node:stream';
import path from 'node:path';
const connections = new WeakSet();
function insist(value, message) { if (!value) throw new Error(message); }
export function localHttpConnection(socketPath) {
  insist(typeof socketPath === 'string' && !/[\0\r\n]/.test(socketPath), 'Invalid local HTTP socket.');
  if (process.platform === 'win32') insist(/^\\\\\.\\pipe\\LOCAL\\[A-Za-z0-9._-]+$/.test(socketPath), 'Windows HTTP fixtures require an owned LOCAL named pipe.');
  else insist(path.isAbsolute(socketPath) && Buffer.byteLength(socketPath) <= 103 && !socketPath.split('/').some(part => part === '..'), 'Invalid local HTTP socket path.');
  const connection = Object.freeze({ socketPath }); connections.add(connection); return connection;
}
export function assertLocalHttpConnection(connection) {
  insist(connections.has(connection), 'Local HTTP connection must be an explicit socket capability.');
}
export async function requestLocalHttp(connection, url, options) {
  assertLocalHttpConnection(connection);
  const endpoint = new URL(url); insist(endpoint.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname), 'Local HTTP capability cannot contact a remote authority.');
  insist(options.redirect === 'manual' && (options.body === undefined || Buffer.isBuffer(options.body) || options.body instanceof Readable), 'Unsupported local HTTP request framing.');
  return new Promise((resolve, reject) => {
    const outgoing = request(endpoint, { socketPath: connection.socketPath, method: options.method, headers: options.headers, signal: options.signal }, incoming => {
      const headers = new Headers();
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) headers.append(incoming.rawHeaders[index], incoming.rawHeaders[index + 1]);
      const noBody = options.method === 'HEAD' || [204, 205, 304].includes(incoming.statusCode);
      if (noBody) incoming.resume();
      resolve(new Response(noBody ? null : /** @type {any} */ (Readable.toWeb(incoming)), { status: incoming.statusCode, statusText: incoming.statusMessage, headers }));
    });
    outgoing.once('error', reject);
    if (options.body instanceof Readable) { options.body.once('error', error => outgoing.destroy(error)); options.body.pipe(outgoing); } else outgoing.end(options.body);
  });
}
