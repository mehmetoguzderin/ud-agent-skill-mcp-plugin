/** MIT. Transparent, task-bound stdio transport to the owned native coordinator.
 * It never chooses operations, edits JSON arguments, or supplies tool results. */
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { realpathSync } from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { startOwned } from './process.mjs';
import { cleanupObservation, failureObservation } from './lifecycle.mjs';

export function validateCoordinatorArguments(args, taskRoot, { temporaryInputRoot } = {}) {
  if (!Array.isArray(args) || args.length > 128 || args.some(arg => typeof arg !== 'string' || arg.length > 8192 || arg.includes('\0'))) throw new Error('COORDINATOR_BRIDGE_ARGUMENTS_INVALID');
  if (!['mcp', 'call', 'validate', 'doctor', 'check', 'setup', 'resource', 'read-resource', 'tools', 'describe', 'help', '--help'].includes(args[0])) throw new Error('COORDINATOR_BRIDGE_COMMAND_FORBIDDEN');
  if (args[0] === 'read-resource') {
    let uri, json = false;
    for (let index = 1; index < args.length; index++) {
      if (args[index] === '--allow-root') {
        if (!args[index + 1] || path.resolve(taskRoot, args[++index]) !== taskRoot) throw new Error('COORDINATOR_BRIDGE_GRANT_FORBIDDEN');
      } else if (args[index] === '--json' && !json) json = true;
      else if (!uri && !args[index].startsWith('-')) uri = args[index];
      else throw new Error('COORDINATOR_BRIDGE_RESOURCE_ARGUMENTS_INVALID');
    }
    if (!uri?.startsWith('ud://')) throw new Error('COORDINATOR_BRIDGE_RESOURCE_ARGUMENTS_INVALID');
    // URI, cursor, context and exact grant-snapshot authorization stay with
    // the installed ResourceStore. The transport grants no filesystem path.
    return args;
  }
  for (let index = 1; index < args.length; index++) {
    if (['--allow-root', '--working-tree'].includes(args[index])) {
      if (!args[index + 1] || path.resolve(taskRoot, args[++index]) !== taskRoot) throw new Error('COORDINATOR_BRIDGE_GRANT_FORBIDDEN');
    } else if (args[index] === '--input') {
      const file = args[++index];
      if (!file) throw new Error('COORDINATOR_BRIDGE_INPUT_INVALID');
      const target = realpathSync(path.resolve(taskRoot, file));
      if (!target.startsWith(taskRoot + path.sep) && !(temporaryInputRoot && target.startsWith(temporaryInputRoot + path.sep))) throw new Error('COORDINATOR_BRIDGE_INPUT_FORBIDDEN');
    }
  }
  return args;
}

export async function createCoordinatorBridge({ coordinator, taskRoot, environment, temporaryInputRoot, signal, start = startOwned, record = () => {} }) {
  if (![coordinator, taskRoot].every(path.isAbsolute) || realpathSync(taskRoot) !== taskRoot) throw new Error('COORDINATOR_BRIDGE_PATH_INVALID');
  if (temporaryInputRoot !== undefined && (!path.isAbsolute(environment.HOME ?? '') || temporaryInputRoot !== path.join(environment.HOME, 'tmp') || realpathSync(temporaryInputRoot) !== temporaryInputRoot)) throw new Error('COORDINATOR_BRIDGE_TEMPORARY_INPUT_INVALID');
  const token = randomBytes(32).toString('hex'), active = new Set(), sockets = new Set(), results = [];
  const stoppingChildren = new WeakMap();
  const stopChild = (child, reason) => {
    if (!stoppingChildren.has(child)) stoppingChildren.set(child, (async () => {
      // MCP transport EOF aborts the coordinator lifetime and its owned workers.
      // Reserve four of the five grace seconds for forced group cleanup.
      child.child.stdin.end(); let timer;
      const cooperative = await Promise.race([child.done, new Promise(resolve => { timer = setTimeout(() => resolve(undefined), 1000); })]);
      clearTimeout(timer); return cooperative ?? await child.stop(reason);
    })());
    return stoppingChildren.get(child);
  };
  let closing, requests = 0;
  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET' && authorized(req)) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"transport":"authenticated-stdio","ready":true}'); }
    else { res.writeHead(404); res.end(); }
  });
  const authorized = request => {
    const supplied = Buffer.from(String(request.headers.authorization ?? ''));
    const expected = Buffer.from(`Bearer ${token}`);
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  };
  server.on('upgrade', (request, socket, head) => {
    if (closing || !authorized(request) || request.url !== '/stdio' || requests >= 24 || active.size >= 12 || request.headers.upgrade !== 'ud-coordinator-stdio') {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
    }
    let args;
    try {
      const value = request.headers['x-ud-argv'];
      if (typeof value !== 'string' || value.length > 32_768) throw new Error('COORDINATOR_BRIDGE_ARGUMENTS_INVALID');
      args = validateCoordinatorArguments(JSON.parse(Buffer.from(value, 'base64url').toString('utf8')), taskRoot, { temporaryInputRoot });
    } catch { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
    requests++;
    // A container can race its task input paths. A path check alone cannot
    // authorize the host filesystem: macOS additionally denies reads of the
    // owner's home except the immutable installation and this task/profile.
    const installation = path.resolve(coordinator, '../../../../..');
    const allowed = [installation, taskRoot, environment.HOME].filter(value => typeof value === 'string' && path.isAbsolute(value));
    const policy = `(version 1) (allow default) (deny file-read-data (require-all (subpath ${JSON.stringify(os.homedir())}) ${allowed.map(directory => `(require-not (subpath ${JSON.stringify(directory)}))`).join(' ')}))`;
    const command = process.platform === 'darwin' ? '/usr/bin/sandbox-exec' : process.execPath;
    const argv = process.platform === 'darwin' ? ['-p', policy, process.execPath, coordinator, ...args] : [coordinator, ...args];
    if (process.platform !== 'darwin') { socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n'); return; }
    const child = start(command, argv, { cwd: taskRoot,
      env: { ...environment, UD_AGENT_ALLOWED_ROOTS: JSON.stringify([taskRoot]) }, timeout: 90_000, cancellationMs: 4000 });
    active.add(child); sockets.add(socket);
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ud-coordinator-stdio\r\n\r\n');
    const send = frame => { if (!socket.destroyed) socket.write(JSON.stringify(frame) + '\n'); };
    child.child.stdout.on('data', data => send({ stream: 'stdout', data: data.toString('base64') }));
    child.child.stderr.on('data', data => send({ stream: 'stderr', data: data.toString('base64') }));
    let inputBytes = 0;
    const input = bytes => {
      inputBytes += bytes.length;
      if (inputBytes > 8 * 1024 ** 2) { socket.destroy(); void child.stop('bridge-input-limit'); return; }
      if (!child.child.stdin.destroyed) child.child.stdin.write(bytes);
    };
    socket.on('data', input); if (head.length) input(head);
    socket.on('end', () => child.child.stdin.end());
    socket.on('error', () => { void stopChild(child, 'bridge-client-error'); });
    socket.on('close', () => { sockets.delete(socket); void stopChild(child, 'bridge-client-closed'); });
    record({ type: 'coordinator_bridge_start', command: 'ud-agent', arguments: args, runtime_location: 'native-macos', transport: 'authenticated-stdio' });
    child.done.then(result => {
      active.delete(child); results.push(result);
      send({ stream: 'exit', code: result.code, signal: result.signal, cleanupVerified: result.cleanupVerified });
      record({ type: 'coordinator_bridge_finish', code: result.code, cleanupVerified: result.cleanupVerified });
      socket.end();
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const stop = async () => {
    if (!closing) closing = (async () => {
      const stopping = [...active].map(child => stopChild(child, 'coordinator-bridge-stopped'));
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
      const settled = await Promise.allSettled(stopping);
      return { cleanupVerified: settled.every(result => result.status === 'fulfilled' && result.value.cleanupVerified === true) && results.every(result => result.cleanupVerified === true),
        steps: settled.map(result => result.status === 'fulfilled' ? { outcome: 'completed', ...cleanupObservation(result.value) } : { outcome: 'failed', failure: failureObservation(result.reason) }),
        completed_children: results.map(cleanupObservation) };
    })();
    return closing;
  };
  signal?.addEventListener('abort', () => { void stop(); }, { once: true });
  return { url, token, stop, runtime_location: 'native-macos', transport: 'authenticated-stdio' };
}
