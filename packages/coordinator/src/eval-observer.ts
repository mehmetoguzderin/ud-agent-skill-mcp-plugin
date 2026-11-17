// SPDX-License-Identifier: MIT
/** Dormant unless an owned local evaluation supplies its private budget capability. */
import net from 'node:net';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { lstat } from 'node:fs/promises';

type Event = { type: 'operation_start' | 'operation_step' | 'operation_result'; operation_id: string; [key: string]: unknown };

export async function openEvaluationOperation(name: string, args: Record<string, unknown>) {
  const configured = process.env.UD_AGENT_EVAL_BUDGET;
  if (configured === undefined) return undefined;
  let capability: { socketPath?: unknown; url?: unknown; token?: unknown };
  try { capability = JSON.parse(configured) as typeof capability; } catch { throw new Error('EVALUATION_CAPABILITY_INVALID'); }
  if (!capability || typeof capability !== 'object' || typeof capability.token !== 'string' || !/^[0-9a-f]{64}$/.test(capability.token) || (capability.socketPath === undefined) === (capability.url === undefined)) throw new Error('EVALUATION_CAPABILITY_INVALID');
  const token = capability.token;
  let socketPath: string | undefined, endpoint: URL | undefined;
  if (capability.socketPath !== undefined) {
    if (typeof capability.socketPath !== 'string' || !path.isAbsolute(capability.socketPath)) throw new Error('EVALUATION_CAPABILITY_INVALID');
    socketPath = capability.socketPath;
    const info = await lstat(socketPath);
    if (!info.isSocket() || (info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('EVALUATION_CAPABILITY_INVALID');
  } else {
    if (typeof capability.url !== 'string') throw new Error('EVALUATION_CAPABILITY_INVALID');
    try { endpoint = new URL(capability.url); } catch { throw new Error('EVALUATION_CAPABILITY_INVALID'); }
    if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'host.docker.internal'].includes(endpoint.hostname) || !endpoint.port || endpoint.pathname !== '/__eval_budget' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('EVALUATION_CAPABILITY_INVALID');
  }
  const operationId = randomUUID();
  const send = async (event: Event): Promise<{ dropResponse?: boolean }> => {
    const payload = `${JSON.stringify({ token, action: 'event', arguments: { event } })}\n`;
    if (Buffer.byteLength(payload) > 2 * 1024 * 1024) throw new Error('EVALUATION_EVENT_TOO_LARGE');
    if (endpoint) {
      const response = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: payload, redirect: 'error', signal: AbortSignal.timeout(6000) });
      const reader = response.body?.getReader();
      if (!reader) throw new Error('EVALUATION_AUTHORITY_RESPONSE_INVALID');
      const chunks: Uint8Array[] = []; let size = 0;
      try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 65536) throw new Error('EVALUATION_AUTHORITY_RESPONSE_INVALID'); chunks.push(part.value); } }
      finally { await reader.cancel(); }
      const result = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok?: unknown; error?: unknown; value?: { dropResponse?: boolean } };
      if (!response.ok || result.ok !== true) throw new Error(typeof result.error === 'string' ? result.error : 'EVALUATION_AUTHORITY_RESPONSE_INVALID');
      return result.value ?? {};
    }
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(socketPath!); let data = '';
      socket.setTimeout(6000, () => socket.destroy(new Error('EVALUATION_AUTHORITY_TIMEOUT')));
      socket.on('error', reject);
      socket.on('connect', () => socket.write(payload));
      socket.on('data', bytes => { data += bytes.toString('utf8'); if (Buffer.byteLength(data) > 65536) socket.destroy(new Error('EVALUATION_AUTHORITY_RESPONSE_INVALID')); });
      socket.on('end', () => {
        try {
          const response = JSON.parse(data) as { ok?: unknown; error?: unknown; value?: { dropResponse?: boolean } };
          if (response.ok !== true) throw new Error(typeof response.error === 'string' ? response.error : 'EVALUATION_AUTHORITY_RESPONSE_INVALID');
          resolve(response.value ?? {});
        } catch (error) { reject(error); }
      });
    });
  };
  await send({ type: 'operation_start', operation_id: operationId, name, arguments: args });
  return {
    async step(step: string, charge = false) { await send({ type: 'operation_step', operation_id: operationId, name, step, charge }); },
    async observation(kind: string, observation: Record<string, unknown>) { await send({ type: 'operation_step', operation_id: operationId, name, step: kind, observation, charge: false }); },
    async result(response: { structuredContent: Record<string, unknown>; isError?: boolean }, writesWorkspace: boolean) {
      const result = response.structuredContent.result as { transaction?: { status?: unknown; replayed?: unknown }; replayed?: unknown } | undefined;
      const execution = response.structuredContent.execution as { status?: unknown } | undefined;
      const committed = writesWorkspace && response.isError !== true && execution?.status === 'completed' && result?.transaction?.status === 'completed' && result.replayed !== true && result.transaction.replayed !== true;
      const outcome = await send({ type: 'operation_result', operation_id: operationId, name, response, committed });
      if (outcome.dropResponse) throw new Error('EVAL_TRANSPORT_RESPONSE_LOST');
    },
  };
}
