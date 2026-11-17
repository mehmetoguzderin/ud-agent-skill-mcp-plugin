import { randomUUID } from 'node:crypto';
import { sha256 } from '../../workspace/src/journal.js';
import type { Contract } from './catalog.js';
import { setTimeout, clearTimeout } from 'node:timers';

export type ToolResponse = { content: { type: 'text'; text: string }[]; structuredContent: Record<string, unknown>; isError?: boolean };
type Control = { token?: string; budget_ms?: number; cancel?: boolean };
export type ContinuationProgress = (completed: number, total: number, message: string) => Promise<void>;
type Progress = { completed: number; total: number; message: string };
type Job = { id: string; hash: string; operation: string; controller: AbortController; created: number; phase: 'working' | 'completed' | 'failed' | 'cancelled'; promise: Promise<ToolResponse>; result?: ToolResponse; progress?: Progress; listeners: Map<symbol, ContinuationProgress> };
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

/** Session-owned same-tool continuations; no extra application tools. */
export class Continuations {
  private readonly jobs = new Map<string, Job>();
  constructor(private readonly policyIdentity: string) {}
  close(): void { for (const job of this.jobs.values()) { job.listeners.clear(); job.controller.abort(); } this.jobs.clear(); }
  async run(contract: Contract, args: Record<string, unknown>, control: Control, execute: (signal: AbortSignal, progress: ContinuationProgress) => Promise<ToolResponse>, signal?: AbortSignal, progress?: ContinuationProgress): Promise<ToolResponse> {
    const budget = control.budget_ms ?? 1000;
    if (!Number.isSafeInteger(budget) || budget < 1 || budget > 30_000 || (control.cancel !== undefined && typeof control.cancel !== 'boolean')) throw new Error('CONTINUATION_CONTROL_INVALID');
    const hash = sha256(canonical({ operation: contract.name, arguments: args, product_version: '0.1.0-beta.1', policy: this.policyIdentity }));
    const now = Date.now();
    for (const [id, job] of this.jobs) if (now - job.created > 3_600_000 && job.phase !== 'working') this.jobs.delete(id);
    let job: Job;
    if (control.token !== undefined) {
      const match = /^cont-v1:([0-9a-f-]{36}):([0-9a-f]{64})$/.exec(control.token);
      const selected = match ? this.jobs.get(match[1]!) : undefined;
      if (!selected || selected.hash !== hash || match![2] !== hash || selected.operation !== contract.name) throw new Error('CONTINUATION_IDENTITY_MISMATCH');
      job = selected;
    } else {
      if (control.cancel) throw new Error('CONTINUATION_TOKEN_REQUIRED');
      if (signal?.aborted) throw new Error('WORKER_CANCELLED');
      if (this.jobs.size >= 32) throw new Error('CONTINUATION_SESSION_LIMIT');
      const id = randomUUID(), controller = new AbortController();
      job = { id, hash, controller, operation: contract.name, created: now, phase: 'working', promise: Promise.resolve({ content: [], structuredContent: {} }), listeners: new Map() };
      this.jobs.set(id, job);
      job.promise = Promise.resolve().then(() => execute(controller.signal, async (completed, total, message) => {
        job.progress = { completed, total, message };
        for (const [id, listener] of job.listeners) this.notify(job, id, listener, job.progress);
      })).then(result => {
        job.result = result; job.phase = controller.signal.aborted ? 'cancelled' : result.isError ? 'failed' : 'completed'; return result;
      }, error => {
        job.phase = controller.signal.aborted ? 'cancelled' : 'failed';
        const message = error instanceof Error ? error.message : 'Operation execution failed.';
        const result = this.envelope(contract, job, { status: 'rejected', reason: message }, true); job.result = result; return result;
      });
    }
    const listenerId = Symbol('continuation request');
    if (progress && !signal?.aborted && job.listeners.size < 64) {
      job.listeners.set(listenerId, progress);
      if (job.progress) this.notify(job, listenerId, progress, job.progress);
    }
    if (control.cancel || signal?.aborted) job.controller.abort();
    const abort = () => { job.listeners.delete(listenerId); job.controller.abort(); };
    signal?.addEventListener('abort', abort, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      if (job.result) return job.result;
      const result = await Promise.race([job.promise, new Promise<undefined>(resolve => { timer = setTimeout(() => resolve(undefined), budget); })]);
      if (result) return result;
      return this.envelope(contract, job, { status: 'pending', continuation_token: `cont-v1:${job.id}:${hash}`, operation_resource: `ud://operations/${job.id}`, state: job.phase, poll_after_ms: 250 });
    } finally { job.listeners.delete(listenerId); if (timer) clearTimeout(timer); signal?.removeEventListener('abort', abort); }
  }
  private notify(job: Job, id: symbol, listener: ContinuationProgress, value: Progress): void {
    if (job.listeners.get(id) !== listener) return;
    // A token belongs only to the currently waiting RPC, never to background
    // work after a pending response. Advisory IO cannot hold a job lease.
    try { void Promise.resolve(listener(value.completed, value.total, value.message)).catch(() => { job.listeners.delete(id); }); }
    catch { job.listeners.delete(id); }
  }
  read(uri: URL): { contents: { uri: string; mimeType: string; text: string }[] } | undefined {
    if (uri.protocol !== 'ud:' || uri.hostname !== 'operations' || uri.search || uri.hash) return undefined;
    const job = this.jobs.get(uri.pathname.slice(1)); if (!job) return undefined;
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ operation: job.operation, state: job.phase, request_sha256: job.hash, created_at: new Date(job.created).toISOString(), session_owned: true, expires_at: new Date(job.created + 3_600_000).toISOString(), result_available: job.result !== undefined }) }] };
  }
  private envelope(contract: Contract, job: Job, result: Record<string, unknown>, failed = false): ToolResponse {
    return { content: [{ type: 'text', text: failed ? String(result.reason) : 'Operation is pending. Repeat the same tool and arguments with the continuation token.' }], structuredContent: { schema_version: '1', operation: contract.name, operation_id: contract.id, execution: { status: failed ? 'rejected' : 'incomplete', elapsed_ms: Date.now() - job.created }, scope: {}, inputs: { request_sha256: job.hash }, provenance: { product_version: '0.1.0-beta.1' }, result, diagnostics: [], artifacts: [], coverage: { requested: [contract.name], completed: [], skipped: [] }, limitations: ['The operation belongs to this MCP session and cancels when the session closes.'] }, ...(failed ? { isError: true } : {}) };
  }
}
