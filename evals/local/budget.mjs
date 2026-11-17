// SPDX-License-Identifier: MIT
/** Private, serial budget authority. Every admitted action is charged before dispatch. */
import net from 'node:net';
import path from 'node:path';
import { chmod, lstat, mkdir, mkdtemp, realpath, rm, unlink } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { failureObservation } from './lifecycle.mjs';

const integer = value => Number.isSafeInteger(value) && value >= 0;
const failure = message => Object.assign(new Error(message), { code: message });
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
export const DEFAULT_LIMITS = Object.freeze({ inference: 10, tools: 12, ud_operations: 12, output_per_request: 512, output: 2048, retries: 1, wall_ms: 90000, cancellation_ms: 5000 });

export async function createBudgetAuthority({ directory, limits = {}, deadline, contextEnvelope = 16384, onStop = async () => {}, onEvent = async () => {}, faults = {}, deferredStart = false, setupMs = 60_000 }) {
  if (!['linux', 'darwin'].includes(process.platform)) throw failure('BUDGET_PLATFORM_UNSUPPORTED');
  if (!integer(contextEnvelope) || contextEnvelope < 1 || typeof directory !== 'string' || !path.isAbsolute(directory)) throw failure('BUDGET_CONFIGURATION_INVALID');
  const ceilings = { ...DEFAULT_LIMITS, input: 6 * contextEnvelope };
  if (Object.entries(limits).some(([key, value]) => !Object.hasOwn(ceilings, key) || !integer(value) || value > ceilings[key])) throw failure('BUDGET_LIMIT_INVALID');
  const policy = { ...ceilings, ...limits };
  const prepared = Date.now(), outerDeadline = deadline ?? prepared + policy.wall_ms;
  let started = deferredStart ? null : prepared;
  deadline = deferredStart ? Math.min(outerDeadline, prepared + setupMs) : outerDeadline;
  if (typeof deferredStart !== 'boolean' || !integer(setupMs) || setupMs < 1 || setupMs > 60_000 || !Number.isSafeInteger(outerDeadline) || outerDeadline <= prepared || !deferredStart && deadline > prepared + policy.wall_ms) throw failure('BUDGET_DEADLINE_INVALID');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(directory) !== directory || (info.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw failure('BUDGET_DIRECTORY_NOT_PRIVATE');
  const initialSocket = path.join(directory, `b-${randomBytes(5).toString('hex')}.sock`);
  const socketDirectory = Buffer.byteLength(initialSocket) > 103 ? await mkdtemp(path.join(await realpath('/tmp'), 'ud-eval-budget-')) : undefined;
  const socketPath = socketDirectory ? path.join(socketDirectory, 'authority.sock') : initialSocket;
  const token = randomBytes(32).toString('hex'), controller = new AbortController();
  const counters = { inference: 0, tools: 0, ud_operations: 0, output: 0, input: 0 };
  if (Object.keys(faults).some(key => key !== 'lostResponseAfterCommit') || faults.lostResponseAfterCommit !== undefined && typeof faults.lostResponseAfterCommit !== 'boolean') throw failure('BUDGET_FAULT_INVALID');
  const retries = new Map(), reservations = new Map(), operations = new Map(), failedRequests = new Set(), sockets = new Set(), abandonedInference = [];
  const nativeCalls = new Map(), nativeFailures = new Map();
  let lostResponseInjected = false;
  let stopped = null, cleanup = 'not_requested', stopping, closed = false, cleanupObservation = null;
  const snapshot = () => {
    const reservedOutput = [...reservations.values()].reduce((sum, row) => sum + row.maxOutputTokens, 0);
    const unknownOutput = abandonedInference.reduce((sum, row) => sum + row.reserved_output_tokens, 0);
    return { limits: { ...policy }, contextEnvelope, prepared_at: prepared, started, deadline, native_loop_started: started !== null, counters: { ...counters }, retries: Object.fromEntries(retries), reserved_output: reservedOutput, pending_requests: reservations.size, pending_operations: operations.size,
      abandoned_inference: abandonedInference.map(row => ({ ...row })), output_usage_verified: reservations.size === 0 && abandonedInference.length === 0,
      unknown_output_tokens_upper_bound: unknownOutput, output_tokens_upper_bound: counters.output + reservedOutput + unknownOutput,
      native_recovery: { observed_calls: nativeCalls.size, observed_results: [...nativeCalls.values()].filter(row => row.status !== 'pending').length,
        pending_results: [...nativeCalls.values()].filter(row => row.status === 'pending').length,
        verified: [...nativeCalls.values()].every(row => ['completed', 'failed'].includes(row.status)),
        failures: [...nativeFailures.values()].map(row => ({ ...row })) },
      lost_response_injected: lostResponseInjected, stopped, cleanup, cleanup_observation: cleanupObservation };
  };
  function stop(reason) {
    if (stopping) return stopping;
    stopped = String(reason); cleanup = 'pending'; cleanupObservation = { status: 'pending', reason: stopped, cancellation_ms: policy.cancellation_ms };
    let timer;
    stopping = Promise.race([
      Promise.resolve().then(() => onStop(stopped)).then(value => { cleanupObservation = { ...cleanupObservation, callback: { status: 'fulfilled', result: value ?? null } }; return value === true || value?.cleanupVerified === true ? 'verified' : 'unverified'; }, error => { cleanupObservation = { ...cleanupObservation, callback: { status: 'rejected', failure: failureObservation(error) } }; return 'unverified'; }),
      new Promise(resolve => { timer = setTimeout(() => { cleanupObservation = { ...cleanupObservation, status: 'grace_expired' }; resolve('unverified'); }, policy.cancellation_ms); }),
    ]).then(result => {
      clearTimeout(timer);
      if (result === 'verified') {
        // Process release establishes that no more inference can occur. It does not
        // establish how many tokens an interrupted response generated.
        for (const reservation of reservations.values()) abandonedInference.push({ id: reservation.id, usage: 'unknown', actual_output_tokens: null, reserved_output_tokens: reservation.maxOutputTokens, release_verified: true, reason: stopped });
        reservations.clear();
      }
      // A released process cannot replace an authoritative operation terminal event.
      cleanup = result === 'verified' && operations.size === 0 ? 'verified' : 'unverified';
      cleanupObservation = { ...cleanupObservation, status: cleanupObservation.status === 'grace_expired' ? 'grace_expired' : 'settled', result: cleanup };
      return snapshot();
    });
    // Assign stopping before abort listeners run; they may themselves call stop.
    controller.abort(failure(stopped));
    return stopping;
  }
  const reject = reason => { void stop(reason); throw failure(reason); };
  function active() {
    if (closed) throw failure('BUDGET_CLOSED');
    if (stopped) throw failure(stopped);
    if (Date.now() >= deadline) reject('EPISODE_TIMEOUT');
    if (started === null) throw failure('NATIVE_LOOP_NOT_STARTED');
  }
  function begin() {
    if (!deferredStart || started !== null || closed || stopped || Date.now() >= deadline) throw failure('BUDGET_START_INVALID');
    started = Date.now(); deadline = Math.min(outerDeadline, started + policy.wall_ms);
    clearTimeout(timer); timer = setTimeout(() => { void stop('EPISODE_TIMEOUT'); }, Math.max(1, deadline - Date.now())); timer.unref();
    return snapshot();
  }
  function check(kind, amount) {
    if (!integer(amount)) throw failure('BUDGET_AMOUNT_INVALID');
    if (counters[kind] + amount > policy[kind]) reject(`BUDGET_EXCEEDED_${kind.toUpperCase()}`);
  }
  function charge(kind, amount = 1, options = {}) {
    active();
    if (kind === 'retry') {
      if (!integer(amount) || typeof options.key !== 'string' || !options.key || options.key.length > 512) throw failure('BUDGET_RETRY_IDENTITY_REQUIRED');
      const previous = retries.get(options.key) ?? 0;
      if (previous + amount > policy.retries) reject('BUDGET_EXCEEDED_RETRIES');
      retries.set(options.key, previous + amount);
    } else {
      if (!['tools', 'ud_operations'].includes(kind)) throw failure('BUDGET_CHARGE_KIND_INVALID');
      check(kind, amount); counters[kind] += amount;
    }
    return snapshot();
  }
  function reserveInference({ inputTokens, maxOutputTokens = policy.output_per_request, contextTokens = inputTokens } = {}) {
    active();
    if (![inputTokens, maxOutputTokens, contextTokens].every(integer) || contextTokens < inputTokens || maxOutputTokens < 1) throw failure('TOKEN_COUNT_UNVERIFIED');
    if (reservations.size) throw failure('INFERENCE_ALREADY_ACTIVE');
    const output = Math.min(maxOutputTokens, policy.output_per_request, policy.output - counters.output);
    if (output < 1) reject('BUDGET_EXCEEDED_OUTPUT');
    if (contextTokens + output > contextEnvelope) reject('CONTEXT_ENVELOPE_EXCEEDED');
    check('inference', 1); check('input', inputTokens);
    const id = randomUUID(); counters.inference++; counters.input += inputTokens;
    const reservation = { id, maxOutputTokens: output }; reservations.set(id, reservation);
    return reservation;
  }
  function finishInference({ id, outputTokens, toolCalls = 0 } = {}) {
    active();
    const reservation = reservations.get(id);
    if (!reservation || !integer(outputTokens) || !integer(toolCalls)) return reject('OUTPUT_USAGE_UNVERIFIED');
    if (outputTokens > reservation.maxOutputTokens) reject('BUDGET_EXCEEDED_OUTPUT_PER_REQUEST');
    check('output', outputTokens); check('tools', toolCalls);
    counters.output += outputTokens; counters.tools += toolCalls; reservations.delete(id);
    return snapshot();
  }
  /** Validate the whole native batch before exposing any call to its executor.
   * Calls already count in finishInference; this gate charges recovery only.
   * Recovery lineage survives changed arguments and a failed recovery attempt.
   */
  function admitNativeCalls({ calls } = {}) {
    active();
    if (!Array.isArray(calls) || calls.length > policy.tools) throw failure('NATIVE_CALLS_INVALID');
    if (!calls.length) return snapshot();
    if ([...nativeCalls.values()].some(row => row.status === 'pending')) reject('NATIVE_RESULTS_PENDING');
    if ([...nativeCalls.values()].some(row => row.status === 'unknown')) reject('NATIVE_RESULT_UNVERIFIED');
    const batch = new Set();
    const admitted = calls.map(call => {
      if (!call || typeof call.id !== 'string' || !call.id || call.id.length > 128 || batch.has(call.id) || nativeCalls.has(call.id) ||
          typeof call.name !== 'string' || !call.name || call.name.length > 256 || call.namespace !== undefined && (typeof call.namespace !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(call.namespace)) || !call.arguments || typeof call.arguments !== 'object' || Array.isArray(call.arguments)) throw failure('NATIVE_CALLS_INVALID');
      batch.add(call.id);
      const identity = { name: call.name, ...(call.namespace === undefined ? {} : { namespace: call.namespace }), arguments: call.arguments };
      return { id: call.id, name: call.name, ...(call.namespace === undefined ? {} : { namespace: call.namespace }), key: createHash('sha256').update(canonical(identity)).digest('hex'), status: 'pending', recoveryOf: null };
    });
    // No generic shell parser can prove which of multiple failures a new call
    // repairs. Ambiguous recovery is unqualified rather than guessed.
    if (nativeFailures.size > 1) reject('NATIVE_RECOVERY_AMBIGUOUS');
    const pending = [...nativeFailures.values()][0];
    if (pending) {
      if (pending.attempts + admitted.length > policy.retries) reject('BUDGET_EXCEEDED_RETRIES');
      charge('retry', admitted.length, { key: `native:${pending.id}` });
      pending.attempts += admitted.length;
      for (const call of admitted) call.recoveryOf = pending.id;
    }
    for (const call of admitted) nativeCalls.set(call.id, call);
    return snapshot();
  }
  function nativeResult({ id, failed } = {}) {
    const call = nativeCalls.get(id);
    if (!call || call.status !== 'pending' || failed !== null && typeof failed !== 'boolean') throw failure('NATIVE_RESULT_INVALID');
    call.status = failed === null ? 'unknown' : failed ? 'failed' : 'completed';
    if (failed === null) return reject('NATIVE_RESULT_UNVERIFIED');
    if (failed) {
      if (!call.recoveryOf) nativeFailures.set(call.id, { id: call.id, name: call.name, ...(call.namespace === undefined ? {} : { namespace: call.namespace }), attempts: 0 });
    } else if (call.recoveryOf) nativeFailures.delete(call.recoveryOf);
    return snapshot();
  }
  async function event({ event: value } = {}) {
    if (!value || typeof value !== 'object' || !['operation_start', 'operation_step', 'operation_result'].includes(value.type) || typeof value.operation_id !== 'string' || value.operation_id.length > 128) throw failure('BUDGET_EVENT_INVALID');
    if (value.type === 'operation_start') {
      if (operations.has(value.operation_id) || typeof value.name !== 'string') throw failure('BUDGET_EVENT_INVALID');
      const key = createHash('sha256').update(canonical({ name: value.name, arguments: value.arguments })).digest('hex');
      if (failedRequests.has(key)) charge('retry', 1, { key });
      charge('ud_operations'); operations.set(value.operation_id, { name: value.name, key });
    } else {
      if (!operations.has(value.operation_id)) throw failure('BUDGET_EVENT_IDENTITY_INVALID');
      if (value.type === 'operation_step') { if (value.charge === true) charge('ud_operations'); else active(); }
    }
    try { await onEvent(value); } catch { return reject('EVALUATION_RECORDING_FAILED'); }
    let dropResponse = false;
    if (value.type === 'operation_result') {
      const operation = operations.get(value.operation_id);
      if (value.response?.isError === true || value.response?.structuredContent?.execution?.status !== 'completed') failedRequests.add(operation.key);
      else failedRequests.delete(operation.key);
      operations.delete(value.operation_id);
      if (faults.lostResponseAfterCommit && !lostResponseInjected && value.committed === true) {
        lostResponseInjected = true; dropResponse = true;
        failedRequests.add(operation.key);
        try { await onEvent({ type: 'response_loss', operation_id: value.operation_id, name: value.name, committed: true, fault: 'injected-response-failure-after-commit' }); }
        catch { return reject('EVALUATION_RECORDING_FAILED'); }
      }
    }
    return { dropResponse };
  }
  const actions = { charge: ({ kind, amount, options }) => charge(kind, amount, options), reserveInference, finishInference, admitNativeCalls, nativeResult, event, snapshot, stop: ({ reason }) => stop(reason) };
  const server = net.createServer(socket => {
    sockets.add(socket); socket.setTimeout(5000, () => socket.destroy()); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let data = '', handled = false;
    socket.on('data', bytes => {
      if (handled) return;
      data += bytes.toString('utf8');
      if (Buffer.byteLength(data) > 2 * 1024 * 1024) { socket.destroy(); return; }
      if (!data.includes('\n')) return;
      handled = true;
      Promise.resolve().then(async () => {
        const request = JSON.parse(data);
        const supplied = Buffer.from(String(request.token ?? ''));
        if (supplied.length !== token.length || !timingSafeEqual(supplied, Buffer.from(token))) throw failure('BUDGET_UNAUTHORIZED');
        if (!Object.hasOwn(actions, request.action)) throw failure('BUDGET_ACTION_INVALID');
        return actions[request.action](request.arguments ?? {});
      }).then(value => socket.end(`${JSON.stringify({ ok: true, value })}\n`), error => socket.end(`${JSON.stringify({ ok: false, error: error.code ?? error.message })}\n`));
    });
  });
  await new Promise((resolve, rejectListen) => { server.once('error', rejectListen); server.listen(socketPath, resolve); });
  try { await chmod(socketPath, 0o600); }
  catch (error) {
    // The constructor has not returned a handle yet. Release the socket here so
    // callers can neither lose the listener nor infer absence from undefined.
    const steps = [], deadline = Date.now() + policy.cancellation_ms;
    const cleanupStep = async (step, action) => {
      try { await action(); steps.push({ step, outcome: 'completed' }); }
      catch (failure) { steps.push({ step, outcome: 'failed', failure: failureObservation(failure) }); }
    };
    for (const socket of sockets) socket.destroy();
    await cleanupStep('budget-setup-server-close', async () => {
      let timer;
      try {
        await Promise.race([new Promise((resolve, reject) => server.close(cause => cause ? reject(cause) : resolve())),
          new Promise((_, reject) => { timer = setTimeout(() => reject(failure('BUDGET_SETUP_CLEANUP_TIMEOUT')), Math.max(1, deadline - Date.now())); })]);
      } finally { clearTimeout(timer); }
      if (server.listening) throw failure('BUDGET_SETUP_SERVER_STILL_LISTENING');
    });
    await cleanupStep('budget-setup-socket-remove', async () => {
      await unlink(socketPath).catch(cause => { if (cause.code !== 'ENOENT') throw cause; });
      try { await lstat(socketPath); throw failure('BUDGET_SETUP_SOCKET_REMAINS'); }
      catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
    });
    if (socketDirectory) await cleanupStep('budget-setup-directory-remove', () => rm(socketDirectory, { recursive: true }));
    error.budget_cleanup = { cleanupVerified: !server.listening && Date.now() <= deadline && steps.every(step => step.outcome === 'completed'),
      socket_path: socketPath, socket_directory: socketDirectory ?? null, steps };
    throw error;
  }
  let timer = setTimeout(() => { void stop(started === null ? 'NATIVE_SETUP_TIMEOUT' : 'EPISODE_TIMEOUT'); }, Math.max(1, deadline - Date.now())); timer.unref();
  return {
    socketPath, token, signal: controller.signal, limits: policy, begin, charge, reserveInference, finishInference, admitNativeCalls, nativeResult, event: value => event({ event: value }), snapshot, stop,
    async close() {
      if (closed) return;
      if ((reservations.size || operations.size) && !stopped) await stop(reservations.size ? 'INFERENCE_CLEANUP_REQUIRED' : 'OPERATION_CLEANUP_REQUIRED');
      if (stopping) await stopping;
      closed = true; clearTimeout(timer); for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
      await unlink(socketPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
      if (socketDirectory) await rm(socketDirectory, { recursive: true });
    },
  };
}

/** Client capability is passed only to the owned CLI/MCP processes, never the model. */
export function connectBudgetAuthority({ socketPath, token }) {
  async function request(action, args = {}) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(socketPath); let data = '';
      socket.setTimeout(6000, () => socket.destroy(failure('BUDGET_AUTHORITY_TIMEOUT')));
      socket.on('error', reject);
      socket.on('connect', () => socket.write(`${JSON.stringify({ token, action, arguments: args })}\n`));
      socket.on('data', bytes => { data += bytes.toString('utf8'); if (Buffer.byteLength(data) > 65536) socket.destroy(failure('BUDGET_RESPONSE_TOO_LARGE')); });
      socket.on('end', () => {
        try { const result = JSON.parse(data); if (!result.ok) throw failure(result.error); resolve(result.value); } catch (error) { reject(error); }
      });
    });
  }
  return { charge: (kind, amount = 1, options = {}) => request('charge', { kind, amount, options }), reserveInference: args => request('reserveInference', args), finishInference: args => request('finishInference', args),
    admitNativeCalls: args => request('admitNativeCalls', args), nativeResult: args => request('nativeResult', args),
    event: event => request('event', { event }), snapshot: () => request('snapshot'), stop: reason => request('stop', { reason }) };
}
