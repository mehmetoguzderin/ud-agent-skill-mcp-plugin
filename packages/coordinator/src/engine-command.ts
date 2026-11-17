import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import { runCommand } from '../../runtime-manager/src/command.js';
import type { CommandOptions, CommandResult } from '../../runtime-manager/src/command.js';
import type { CommandSupervisor } from '../../runtime-manager/src/supervised-command.js';

export type EngineSupervisor = CommandSupervisor & Readonly<{ engine: string; signal?: AbortSignal }>;
const scopes = new AsyncLocalStorage<Readonly<EngineSupervisor>>();
const SHA = /^sha256:[0-9a-f]{64}$/;

/** Scope only an already verified engine/helper identity to one async workflow. */
export function withEngineSupervisor<T>(authority: EngineSupervisor, action: () => Promise<T>): Promise<T> {
  if (!path.isAbsolute(authority.engine) || !path.isAbsolute(authority.guard) || [authority.engine, authority.guard].some(value => value.includes('\0')) || !SHA.test(authority.guardSha256) || !SHA.test(authority.executableSha256)) throw new Error('ENGINE_SUPERVISOR_AUTHORITY_INVALID');
  return scopes.run(Object.freeze({ ...authority }), action);
}

export function withoutEngineCancellation<T>(action: () => Promise<T>): Promise<T> {
  const current = scopes.getStore();
  if (!current) return action();
  const { signal: _cancelled, ...cleanup } = current;
  return scopes.run(Object.freeze(cleanup), action);
}

export function engineSupervisor(engine: string): CommandSupervisor | undefined {
  const current = scopes.getStore();
  if (!current) return undefined;
  if (current.engine !== engine) throw new Error('ENGINE_SUPERVISOR_SCOPE_MISMATCH');
  return { guard: current.guard, guardSha256: current.guardSha256, executableSha256: current.executableSha256 };
}

/** Read-only discovery retains its legacy API; admitted workflows carry a scope. */
export async function runEngineCommand(engine: string, args: readonly string[], options: CommandOptions): Promise<CommandResult> {
  const supervisor = engineSupervisor(engine);
  if (supervisor && options.supervisor && (supervisor.guard !== options.supervisor.guard || supervisor.guardSha256 !== options.supervisor.guardSha256 || supervisor.executableSha256 !== options.supervisor.executableSha256)) throw new Error('ENGINE_SUPERVISOR_SCOPE_MISMATCH');
  const signal = options.signal ?? scopes.getStore()?.signal;
  return runCommand(engine, args, { ...options, ...(supervisor ? { supervisor } : {}), ...(signal ? { signal } : {}) });
}

export function workerStreamError(problem: unknown): never {
  const code = problem && typeof problem === 'object' ? (problem as { code?: unknown }).code : undefined;
  if (code === 'SUPERVISED_COMMAND_CANCELLED') throw new Error('WORKER_CANCELLED');
  if (code === 'SUPERVISED_COMMAND_TIMEOUT') throw new Error('WORKER_TIMEOUT');
  if (code === 'SUPERVISED_COMMAND_OUTPUT_LIMIT') throw new Error('WORKER_OUTPUT_TOO_LARGE');
  throw problem;
}
