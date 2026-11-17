import { readBoundedReceiptBytes } from '../../runtime-manager/src/receipt.js';
import type { SetupInput } from '../../runtime-manager/src/environment.js';
import { sha256 } from '../../workspace/src/journal.js';
import path from 'node:path';
import { ResourceStore } from './resources.js';

const VERSION = '0.1.0-beta.1';
async function sourceIdentity(sourceRoot: string): Promise<string> {
  try { return sha256(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/runtime.lock.json'))); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return sha256('no-runtime-lock'); throw error; }
}

/** Continuations retain original setup arguments in authorized immutable state. */
export async function setupContinuation(input: SetupInput, sourceRoot: string, resources: ResourceStore, run: (args: SetupInput) => Promise<Record<string, unknown>>, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (input.mode !== 'resume' && input.continuation_token !== undefined) throw new Error('SETUP_CONTINUATION_REQUIRES_RESUME');
  if (input.mode === 'resume' && input.dry_run === true) throw new Error('SETUP_CONTINUATION_DRY_RUN_INVALID');
  if (input.dry_run) return run(input);
  const source = await sourceIdentity(sourceRoot);
  let request: SetupInput, token: string;
  if (input.mode === 'resume') {
    if (typeof input.continuation_token !== 'string' || !/^setup-v1:[0-9a-f-]{36}$/.test(input.continuation_token)) throw new Error('SETUP_CONTINUATION_INVALID');
    token = input.continuation_token;
    const value = JSON.parse((await resources.bytes(`ud://operations/${token.slice(9)}`, 'operations')).toString('utf8')) as Record<string, unknown>;
    if (value.version !== 1 || value.product_version !== VERSION || value.source_sha256 !== source || value.kind !== 'setup' || !value.arguments || typeof value.arguments !== 'object' || Array.isArray(value.arguments) || value.request_sha256 !== sha256(JSON.stringify(value.arguments))) throw new Error('SETUP_CONTINUATION_STALE_OR_INVALID');
    request = value.arguments as SetupInput;
    for (const [key, argument] of Object.entries(input)) if (!['mode', 'continuation_token', 'dry_run'].includes(key) && JSON.stringify(argument) !== JSON.stringify((request as Record<string, unknown>)[key])) throw new Error('SETUP_CONTINUATION_ARGUMENT_MISMATCH');
  } else {
    request = { ...input };
    delete request.continuation_token;
    const resource = await resources.put('operations', Buffer.from(JSON.stringify({ version: 1, kind: 'setup', product_version: VERSION, source_sha256: source, request_sha256: sha256(JSON.stringify(request)), arguments: request })), 'application/json');
    token = `setup-v1:${new URL(resource.uri).pathname.slice(1)}`;
  }
  let result: Record<string, unknown>;
  try { result = await run(request); }
  catch (error) {
    const value = error as { code?: unknown; message?: unknown };
    result = { status: 'failed', ready: false, code: signal?.aborted ? 'WORKER_CANCELLED' : typeof value?.code === 'string' ? value.code : 'SETUP_EXECUTION_FAILED', reason: signal?.aborted ? 'Setup was cancelled.' : typeof value?.message === 'string' ? value.message : 'Setup did not complete.' };
  }
  return { ...result, ...(input.mode === 'resume' ? { mode: 'resume', resumed: true } : {}), continuation_token: token, operation_resource: `ud://operations/${token.slice(9)}` };
}
