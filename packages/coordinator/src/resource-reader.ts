/** Public CLI resource reads retain ResourceStore authorization and cursors. MIT. */
import { lstat } from 'node:fs/promises';
import { ResourceStore } from './resources.js';
import { userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { loadNativeGuardReceipt } from '../../runtime-manager/src/receipt.js';

export async function readAuthorizedResource(sourceRoot: string, value: string, grants: readonly string[]): Promise<Awaited<ReturnType<ResourceStore['read']>>> {
  if (value.length > 8192) throw new Error('RESOURCE_URI_INVALID');
  const uri = new URL(value);
  if (uri.protocol !== 'ud:' || uri.username || uri.password || uri.port || !['reports', 'plans', 'contexts', 'operations', 'artifacts'].includes(uri.hostname)) throw new Error('RESOURCE_URI_INVALID');
  const root = `${userspaceStateRoot()}-resources`;
  // Reading a nonexistent resource does not bootstrap a runtime or state cache.
  try { if (!(await lstat(root)).isDirectory()) throw new Error('RESOURCE_STATE_INVALID'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('RESOURCE_NOT_FOUND'); throw error; }
  const guard = process.platform === 'win32' ? (await loadNativeGuardReceipt(sourceRoot, { platform: process.platform, arch: process.arch })).guard : undefined;
  try { return await (await ResourceStore.open(root, grants, guard)).read(uri); }
  catch (error) {
    const distinct = [...new Set(grants)];
    // MCP normalizes duplicate launch grants; historical CLI calls retain the
    // exact array. Both scopes describe the same authorized set. Never remove
    // a distinct root, expand a parent, or retry integrity/cursor/expiry errors.
    if (!(error instanceof Error) || error.message !== 'RESOURCE_ACCESS_DENIED' || distinct.length === grants.length || distinct.some(root => !grants.includes(root)) || grants.some(root => !distinct.includes(root))) throw error;
    return (await ResourceStore.open(root, distinct, guard)).read(uri);
  }
}
