/** Explicit sequential acquisition of every pinned headless ARM64 client. MIT. */
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { CLIENT_LOCK, prepareNativeClients } from './native-clients.mjs';
import { buildNativeClientImage } from './container.mjs';
import { assertOptIn, writeNew } from './preparation.mjs';
import { runOwned } from './process.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { failureObservation } from './lifecycle.mjs';

export const CONTAINER_BASES = Object.freeze(JSON.parse(readFileSync(new URL('./container-bases.lock.json', import.meta.url), 'utf8')));
export const CONTAINER_BASES_SHA256 = sha256(JSON.stringify(CONTAINER_BASES));
function unverifiedCleanup(error, depth = 0) {
  if (!error || typeof error !== 'object' || depth > 4) return false;
  if (Object.hasOwn(error, 'cleanupVerified') && error.cleanupVerified !== true) return true;
  if (['result', 'native_cleanup', 'container_cleanup', 'budget_cleanup'].some(key => error[key] && error[key].cleanupVerified !== true)) return true;
  return unverifiedCleanup(error.cause, depth + 1) || Array.isArray(error.errors) && error.errors.some(item => unverifiedCleanup(item, depth + 1));
}

/** Pure recipe validation keeps a malformed lock from launching acquisition. */
export function containerBaseReferences(lock = CONTAINER_BASES) {
  if (lock?.schema_version !== 1 || lock.platform !== 'linux/arm64' ||
      !/^node:26\.[\d.]+-bookworm-slim@sha256:[a-f0-9]{64}$/.test(lock.images?.node?.reference ?? '') ||
      !/^python:3\.12[\w.-]*@sha256:[a-f0-9]{64}$/.test(lock.images?.python?.reference ?? '') ||
      ![lock.images.node, lock.images.python].every(image => /^sha256:[a-f0-9]{64}$/.test(image.config_digest ?? ''))) throw new Error('CLIENT_CONTAINER_BASE_LOCK_INVALID');
  return { node: lock.images.node.reference, python: lock.images.python.reference };
}

/** Preparation never launches a model or declares native conformance. Existing
 * per-client storage admission and immutable image receipts remain authoritative.
 * Dependency failures stay attached to their client; no substitute is selected. */
export async function prepareNativeContainers(root, { optIn, onProgress = () => {}, runner = runOwned,
  prepareClients = prepareNativeClients, buildImage = buildNativeClientImage, persist = writeNew } = {}) {
  assertOptIn({ optIn });
  const bases = containerBaseReferences();
  const clients = await prepareClients(root, { optIn: true, runner, onProgress });
  if (!Array.isArray(clients) || clients.length !== CLIENT_LOCK.clients.length ||
      new Set(clients.map(client => client.id)).size !== CLIENT_LOCK.clients.length ||
      CLIENT_LOCK.clients.some(pin => !clients.some(client => client.id === pin.id))) throw new Error('CLIENT_PREPARATION_INVENTORY_INCOMPLETE');
  const images = []; let cleanupBlocker;
  for (const pin of CLIENT_LOCK.clients) {
    if (cleanupBlocker) {
      images.push({ id: pin.id, status: 'blocked', stage: 'not-attempted', blocked_by: cleanupBlocker,
        reason: 'A prior image preparation did not verify owned process cleanup; no further image build was attempted.', inference: false });
      continue;
    }
    const client = clients.find(item => item.id === pin.id);
    if (client.status === 'blocked') {
      images.push({ id: pin.id, status: 'blocked', reason: client.reason, stage: 'private-client', inference: false });
      continue;
    }
    try {
      const receipt = await buildImage(root, pin.id, { optIn: true, runner, onProgress,
        baseImage: pin.manager === 'npm' ? bases.node : bases.python,
        baseConfigDigest: CONTAINER_BASES.images[pin.manager === 'npm' ? 'node' : 'python'].config_digest,
        ...(pin.manager === 'npm' ? {} : { nodeImage: bases.node, nodeConfigDigest: CONTAINER_BASES.images.node.config_digest }) });
      images.push({ ...receipt, status: 'prepared' });
    } catch (error) {
      if (unverifiedCleanup(error)) cleanupBlocker = pin.id;
      images.push({ id: pin.id, status: 'blocked', reason: error.message, stage: 'arm64-image', inference: false,
        ...(cleanupBlocker ? { owned_cleanup_verified: false, failure: failureObservation(error) } : {}) });
    }
  }
  const receipt = { schema_version: 1, inference: false, platform: 'linux/arm64',
    base_lock_sha256: CONTAINER_BASES_SHA256, bases: CONTAINER_BASES, clients, images,
    status: images.every(image => image.status === 'prepared') ? 'prepared' : 'blocked',
    ...(cleanupBlocker ? { halted_for_unverified_cleanup: true, cleanup_blocker: cleanupBlocker } : {}),
    qualification: 'private-client-images-only-native-conformance-required' };
  const file = path.join(root, '.artifacts/local-evals/container-preparations', `${randomUUID()}.json`);
  persist(file, receipt);
  return { ...receipt, receipt: file };
}
