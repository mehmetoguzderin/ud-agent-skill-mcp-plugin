import { randomUUID } from 'node:crypto';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

type Message = Parameters<NonNullable<StdioServerTransport['onmessage']>>[0];
type Task = { taskId: string; status: 'working' | 'completed' | 'failed' | 'cancelled'; createdAt: string; lastUpdatedAt: string; ttl: number; pollInterval: number };
type Job = { task: Task; requestId: string; result?: unknown; waiters: (string | number)[]; cancellation: boolean; controller: AbortController; timer: ReturnType<typeof setTimeout> };
function record(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }

/** Optional 2025 Tasks adapter. The SDK still validates and executes every tool. */
export class TaskTransport {
  onmessage?: (message: Message) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  private legacy = false;
  private initializeId?: string | number;
  private initialized = false;
  private readonly jobs = new Map<string, Job>();
  constructor(private readonly inner: Pick<StdioServerTransport, 'start' | 'close' | 'send' | 'onmessage' | 'onclose' | 'onerror'> = new StdioServerTransport()) {}
  signalForRequest(id: string | number): AbortSignal | undefined { return [...this.jobs.values()].find(job => job.requestId === id)?.controller.signal; }
  async start(): Promise<void> {
    this.inner.onmessage = message => { void this.receive(message).catch(error => this.onerror?.(error instanceof Error ? error : new Error(String(error)))); };
    this.inner.onclose = () => { for (const job of this.jobs.values()) { clearTimeout(job.timer); job.controller.abort(); } this.jobs.clear(); this.onclose?.(); };
    this.inner.onerror = error => this.onerror?.(error);
    await this.inner.start();
  }
  async close(): Promise<void> { await this.inner.close(); }
  private async emit(message: Record<string, unknown>): Promise<void> { await this.inner.send(message as Message); }
  private async error(id: string | number, code: number, message: string): Promise<void> { await this.emit({ jsonrpc: '2.0', id, error: { code, message } }); }
  private expire(): void {
    const now = Date.now();
    for (const [id, job] of this.jobs) if (now >= Date.parse(job.task.createdAt) + job.task.ttl && job.task.status !== 'working') this.jobs.delete(id);
  }
  private async receive(message: Message): Promise<void> {
    const raw = message as Record<string, unknown>, params = record(raw.params), id = raw.id;
    if (raw.method === 'initialize' && (typeof id === 'string' || typeof id === 'number')) {
      this.initializeId = id;
      this.legacy = params?.protocolVersion === '2025-11-25';
    }
    if (raw.method === 'notifications/initialized') this.initialized = true;
    if (typeof raw.method !== 'string' || !this.initialized || !this.legacy || (typeof id !== 'string' && typeof id !== 'number')) { this.onmessage?.(message); return; }
    this.expire();
    if (raw.method.startsWith('tasks/')) {
      if (raw.method === 'tasks/list') { await this.emit({ jsonrpc: '2.0', id, result: { tasks: [...this.jobs.values()].map(job => job.task) } }); return; }
      const job = typeof params?.taskId === 'string' ? this.jobs.get(params.taskId) : undefined;
      if (!job) { await this.error(id, -32602, 'Unknown or expired task.'); return; }
      if (raw.method === 'tasks/get') { await this.emit({ jsonrpc: '2.0', id, result: job.task }); return; }
      if (raw.method === 'tasks/cancel') {
        if (job.task.status !== 'working') { await this.error(id, -32602, 'Task is already terminal.'); return; }
        job.cancellation = true;
        job.controller.abort();
        // The worker retains its cleanup duty; the task result is not available
        // until normal request cancellation and owned cleanup have settled.
        await this.emit({ jsonrpc: '2.0', id, result: { ...job.task, statusMessage: 'Cancellation requested; cleanup is pending.' } }); return;
      }
      if (raw.method === 'tasks/result') {
        if (job.result !== undefined) await this.emit({ jsonrpc: '2.0', id, result: job.result });
        else if (job.waiters.length < 64 && !job.waiters.includes(id)) job.waiters.push(id);
        else await this.error(id, -32603, 'Task waiter limit reached.');
        return;
      }
      await this.error(id, -32601, 'Unknown task method.'); return;
    }
    if (raw.method === 'tools/call' && params?.task !== undefined) {
      const augmented = record(params.task);
      if (!augmented || Object.keys(augmented).some(key => key !== 'ttl') || (augmented.ttl !== undefined && (!Number.isSafeInteger(augmented.ttl) || (augmented.ttl as number) < 1 || (augmented.ttl as number) > 3_600_000))) { await this.error(id, -32602, 'Invalid task TTL.'); return; }
      if (this.jobs.size >= 32) { await this.error(id, -32603, 'Session task limit reached.'); return; }
      const now = new Date().toISOString(), taskId = randomUUID(), requestId = `ud-task-${taskId}`;
      const task: Task = { taskId, status: 'working', createdAt: now, lastUpdatedAt: now, ttl: augmented.ttl as number ?? 3_600_000, pollInterval: 250 };
      const controller = new AbortController();
      const timer = setTimeout(() => { const job = this.jobs.get(taskId); if (job?.task.status === 'working') { job.cancellation = true; controller.abort(); } }, task.ttl); timer.unref();
      this.jobs.set(taskId, { task, requestId, waiters: [], cancellation: false, controller, timer });
      await this.emit({ jsonrpc: '2.0', id, result: { task } });
      const { task: _task, ...forwarded } = params;
      this.onmessage?.({ ...raw, id: requestId, params: forwarded } as Message); return;
    }
    this.onmessage?.(message);
  }
  async send(message: Message): Promise<void> {
    const raw = message as Record<string, unknown>;
    if (raw.id === this.initializeId && this.legacy && record(raw.result)) {
      const result = record(raw.result)!;
      await this.emit({ ...raw, result: { ...result, capabilities: { ...record(result.capabilities), tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } } } }); return;
    }
    const job = [...this.jobs.values()].find(job => job.requestId === raw.id);
    if (job && (raw.result !== undefined || raw.error !== undefined)) {
      clearTimeout(job.timer);
      job.result = raw.result ?? { content: [{ type: 'text', text: 'Task execution failed.' }], isError: true, error: raw.error };
      job.task.status = job.cancellation ? 'cancelled' : raw.error !== undefined || record(raw.result)?.isError === true ? 'failed' : 'completed';
      job.task.lastUpdatedAt = new Date().toISOString();
      for (const id of job.waiters.splice(0)) await this.emit({ jsonrpc: '2.0', id, result: job.result });
      await this.emit({ jsonrpc: '2.0', method: 'notifications/tasks/status', params: job.task }); return;
    }
    if (this.legacy && record(raw.result) && Array.isArray(record(raw.result)!.tools)) {
      const result = record(raw.result)!;
      await this.emit({ ...raw, result: { ...result, tools: (result.tools as unknown[]).map(tool => ({ ...record(tool), execution: { taskSupport: 'optional' } })) } }); return;
    }
    await this.inner.send(message);
  }
}
