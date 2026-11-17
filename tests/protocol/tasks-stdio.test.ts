import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { installedCoordinator } from '../fixtures/installed-coordinator.js';

it('executes an actual legacy MCP tool task through the coordinator and returns its original validated result', async () => {
  const profile = await mkdtemp(path.join(os.tmpdir(), 'ud-task-profile-'));
  const entry = await installedCoordinator(path.join(profile, 'installed'));
  const child = spawn(process.execPath, [entry], { stdio: ['pipe', 'pipe', 'pipe'], env: {
    PATH: process.env.PATH ?? '', HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile, XDG_DATA_HOME: profile,
    TMPDIR: profile, TMP: profile, TEMP: profile,
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
  } });
  const messages: Record<string, unknown>[] = []; let buffered = '', stderr = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => { buffered += chunk; for (;;) { const newline = buffered.indexOf('\n'); if (newline < 0) break; messages.push(JSON.parse(buffered.slice(0, newline))); buffered = buffered.slice(newline + 1); } });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const send = (message: unknown) => child.stdin.write(JSON.stringify(message) + '\n');
  const response = async (id: number): Promise<Record<string, unknown>> => {
    const deadline = Date.now() + 15000;
    for (;;) {
      const found = messages.find(item => item.id === id); if (found) { expect(found.error, stderr).toBeUndefined(); return found.result as Record<string, unknown>; }
      if (Date.now() > deadline || child.exitCode !== null) throw new Error(`Missing MCP response ${id}: ${stderr}`);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  };
  try {
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'tasks-fixture', version: '1' } } });
    expect(await response(1)).toMatchObject({ capabilities: { tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    // Exercise real task dispatch without probing ambient runner OCI daemons.
    // Userspace readiness inquiry remains an actual validated operation.
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'check_ud_environment', arguments: { engine: 'userspace' }, task: { ttl: 30000 } } });
    const created = await response(2); const task = created.task as { taskId: string };
    expect(task.taskId).toMatch(/^[a-f0-9-]{36}$/);
    send({ jsonrpc: '2.0', id: 3, method: 'tasks/result', params: { taskId: task.taskId } });
    expect(await response(3)).toMatchObject({ structuredContent: { operation: 'check_ud_environment', operation_id: 'ENV-001', execution: { status: 'completed' }, result: { runtime: { engine: 'userspace' } } } });
    send({ jsonrpc: '2.0', id: 4, method: 'tasks/get', params: { taskId: task.taskId } });
    expect(await response(4)).toMatchObject({ taskId: task.taskId, status: 'completed' });
  } finally {
    child.stdin.end(); await new Promise<void>(resolve => { if (child.exitCode !== null) resolve(); else child.once('close', () => resolve()); });
    await rm(profile, { recursive: true, force: true });
  }
}, 30000);
