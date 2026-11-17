import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { authorizeWorkspace } from '../../workspace/src/authorization.js';
import { sha256 } from '../../workspace/src/journal.js';

/** Roots come from the host protocol, never an application tool argument. */
export async function hostRoots(value: unknown): Promise<string[]> {
  if (!Array.isArray(value) || value.length > 128) throw new Error('HOST_ROOTS_INVALID');
  const roots = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof (item as { uri?: unknown }).uri !== 'string') throw new Error('HOST_ROOTS_INVALID');
    const uri = new URL((item as { uri: string }).uri);
    if (uri.protocol !== 'file:' || uri.search || uri.hash || (uri.hostname !== '' && uri.hostname !== 'localhost')) throw new Error('HOST_ROOTS_INVALID');
    const filename = fileURLToPath(uri);
    roots.push(await authorizeWorkspace(filename, [filename]));
  }
  return [...new Set(roots)];
}

export class RootChallenges {
  private readonly pending = new Map<string, { hash: string; expires: number }>();
  issue(operation: string, args: Record<string, unknown>): string {
    for (const [id, record] of this.pending) if (record.expires < Date.now()) this.pending.delete(id);
    if (this.pending.size >= 32) throw new Error('HOST_ROOT_CHALLENGE_LIMIT');
    const id = `ud-workspace-${randomUUID()}`;
    this.pending.set(id, { hash: sha256(JSON.stringify({ operation, args }, (_key, value) => value && typeof value === 'object' && !Array.isArray(value) ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : value)), expires: Date.now() + 120000 });
    return id;
  }
  async accept(id: unknown, operation: string, args: Record<string, unknown>, roots: unknown): Promise<string[]> {
    if (typeof id !== 'string') throw new Error('HOST_ROOT_CHALLENGE_INVALID');
    const record = this.pending.get(id);
    if (!record || record.expires < Date.now() || record.hash !== sha256(JSON.stringify({ operation, args }, (_key, value) => value && typeof value === 'object' && !Array.isArray(value) ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : value))) throw new Error('HOST_ROOT_CHALLENGE_INVALID');
    const verified = await hostRoots(roots); this.pending.delete(id); return verified;
  }
}
