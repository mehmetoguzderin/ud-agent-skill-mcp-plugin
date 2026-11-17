/** Full owned-storage accounting without blocking native I/O. MIT. */
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { ownedStorageBytes } from '../../scripts/quality/storage-lifecycle.mjs';

if (!isMainThread && workerData?.kind === 'ud-local-storage-accounting') {
  try { parentPort.postMessage({ bytes: ownedStorageBytes(workerData.roots, workerData.limit) }); }
  catch (error) { parentPort.postMessage({ error: { message: error.message, code: error.code } }); }
}

/** Use the same inode, sparse-file and symlink rules as admission. No cache or
 * sampled subtree can stand in for the requested complete inventory. */
export function measureOwnedStorage(roots, limit = Number.MAX_SAFE_INTEGER) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), { workerData: { kind: 'ud-local-storage-accounting', roots, limit }, execArgv: [] });
    let result;
    worker.once('message', message => { result = message; });
    worker.once('error', reject);
    worker.once('exit', code => {
      if (code !== 0) return reject(new Error(`Owned-storage inventory worker exited ${code}.`));
      if (result?.error) return reject(Object.assign(new Error(result.error.message), { code: result.error.code }));
      if (!Number.isSafeInteger(result?.bytes) || result.bytes < 0) return reject(new Error('Owned-storage inventory returned no trustworthy byte count.'));
      resolve(result.bytes);
    });
  });
}
