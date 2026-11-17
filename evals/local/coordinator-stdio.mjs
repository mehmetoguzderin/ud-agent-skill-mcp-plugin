#!/usr/bin/env node
/** MIT. Raw stdio client; deliberately no operation or argument interpretation. */
import http from 'node:http';
import { readFileSync } from 'node:fs';

let config;
try {
  config = JSON.parse(process.env.UD_EVAL_COORDINATOR_BRIDGE ?? readFileSync(new URL('./coordinator-capability.json', import.meta.url), 'utf8'));
  const url = new URL(config.url);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'host.docker.internal'].includes(url.hostname) || !/^[a-f0-9]{64}$/.test(config.token)) throw new Error();
} catch { process.stderr.write('UD coordinator bridge configuration is invalid.\n'); process.exit(1); }
const request = http.request(new URL('/stdio', config.url), { headers: {
  authorization: `Bearer ${config.token}`, connection: 'Upgrade', upgrade: 'ud-coordinator-stdio',
  'x-ud-argv': Buffer.from(JSON.stringify(process.argv.slice(2))).toString('base64url'),
} });
request.setTimeout(90_000, () => request.destroy(new Error('UD coordinator bridge timeout')));
request.on('error', error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
request.on('response', response => { response.resume(); process.stderr.write(`UD coordinator bridge rejected request: ${response.statusCode}\n`); process.exitCode = 1; });
request.on('upgrade', (_response, socket, head) => {
  let pending = '', ended = false;
  function consume(bytes) {
    pending += bytes.toString('utf8');
    if (pending.length > 12 * 1024 ** 2) { socket.destroy(new Error('UD coordinator bridge frame limit')); return; }
    let index;
    while ((index = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, index); pending = pending.slice(index + 1);
      try {
        const frame = JSON.parse(line);
        if (frame.stream === 'stdout' || frame.stream === 'stderr') process[frame.stream].write(Buffer.from(frame.data, 'base64'));
        else if (frame.stream === 'exit') {
          ended = true; process.exitCode = frame.cleanupVerified === true && Number.isInteger(frame.code) ? frame.code : 1;
          process.stdin.unpipe(socket); process.stdin.pause(); socket.end();
        } else throw new Error('UD coordinator bridge invalid frame');
      } catch (error) { socket.destroy(error); }
    }
  }
  socket.on('data', consume); if (head.length) consume(head);
  socket.on('error', error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
  socket.on('close', () => { if (!ended) process.exitCode = 1; process.stdin.unpipe(socket); process.stdin.pause(); });
  process.stdin.pipe(socket, { end: false });
});
request.end();
