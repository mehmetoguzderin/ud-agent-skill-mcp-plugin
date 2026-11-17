import path from 'node:path';
import { stageVerifiedArchive } from './archive.js';
import { runCommand } from './command.js';
import { verifyArchive } from './receipt.js';
import type { ImageReceipt } from './receipt.js';
import { appleLocalImageIdentity, isAppleRuntimeAdmitted } from './apple-runtime.js';
import type { ArchiveStagingOwner } from './archive.js';
import { verifyOciClosure } from './oci-closure.js';

type Runner = typeof runCommand;
export type TrustedAppleEngine = { executable: string; binarySha256: string };

/** Only exact descriptor identities qualify; a same-named tag is insufficient. */
export function appleImageIsPresent(raw: unknown, receipt: ImageReceipt): boolean {
  if (appleLocalImageIdentity(raw, receipt)) return true;
  if (!Array.isArray(raw)) return false;
  return raw.some(value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const item = value as Record<string, unknown>;
    const configuration = item.configuration && typeof item.configuration === 'object' && !Array.isArray(item.configuration) ? item.configuration as Record<string, unknown> : undefined;
    const descriptor = configuration?.descriptor ?? item.descriptor;
    if ((configuration?.name ?? item.reference) !== receipt.reference || !descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) return false;
    return (descriptor as Record<string, unknown>).digest === receipt.digest;
  });
}

/**
 * Imports only a digest-verified offline archive. Image import is allowed during
 * explicit setup, never ordinary work. A successful import is not runtime
 * readiness: host/worker isolation and local-only execution still need probes.
 */
export async function importAppleOfflineImage(engine: TrustedAppleEngine, receipt: ImageReceipt, archive: string, runner: Runner = runCommand, purpose: 'worker' | 'init' = 'worker', stagingOwner?: ArchiveStagingOwner): Promise<{ imported: boolean; digest: string }> {
  if (!path.isAbsolute(engine.executable) || !/^sha256:[0-9a-f]{64}$/.test(engine.binarySha256)) throw new Error('A verified absolute Apple Container executable is required.');
  const authorizedReference = purpose === 'worker' ? /^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(receipt.reference) : purpose === 'init' && /^(?:localhost\/ud-agent-skill-mcp-plugin-init|ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+)@sha256:[0-9a-f]{64}$/.test(receipt.reference);
  if (!/^sha256:[0-9a-f]{64}$/.test(receipt.digest) || !/^sha256:[0-9a-f]{64}$/.test(receipt.contextSha256) || !authorizedReference || !receipt.reference.endsWith(`@${receipt.digest}`)) throw new Error('Worker image identity is not an immutable publisher-bound digest.');
  // This validates expected binary bytes; release acceptance must additionally
  // attest the provider and executable path before treating the runtime as ready.
  await verifyArchive(engine.executable, engine.binarySha256);
  const options = { timeoutMs: 60_000, maxOutputBytes: 4 * 1024 * 1024 };
  const existing = await runner(engine.executable, ['image', 'list', '--format', 'json'], options);
  if (existing.code !== 0) throw new Error('Apple Container image inspection failed.');
  let list: unknown;
  try { list = JSON.parse(existing.stdout.toString('utf8')); } catch { throw new Error('Apple Container returned invalid image inspection data.'); }
  if (appleImageIsPresent(list, receipt)) return { imported: false, digest: receipt.digest };
  if (!receipt.transportSha256 || !receipt.transportSizeBytes) throw new Error('The frozen receipt does not authorize a bounded offline image transport.');
  const staged = await stageVerifiedArchive(archive, receipt.transportSha256, receipt.transportSizeBytes, stagingOwner);
  try {
    if (receipt.transportIndexDigest !== undefined) await verifyOciClosure(staged.filename, { manifestDigest: receipt.digest, architecture: 'arm64', indexDigest: receipt.transportIndexDigest, ...(receipt.configDigest ? { configDigest: receipt.configDigest } : {}), ...(receipt.diffIds ? { diffIds: receipt.diffIds } : {}) });
    const loaded = await runner(engine.executable, ['image', 'load', '--input', staged.filename], { timeoutMs: 600_000, maxOutputBytes: 4 * 1024 * 1024 });
    if (loaded.code !== 0) throw new Error('Apple Container rejected the verified offline archive.');
    const inspected = await runner(engine.executable, ['image', 'list', '--format', 'json'], options);
    if (inspected.code !== 0) throw new Error('Apple Container could not inspect the imported image.');
    try { list = JSON.parse(inspected.stdout.toString('utf8')); } catch { throw new Error('Apple Container returned invalid image inspection data.'); }
    // OCI transports need not carry engine-specific reference annotations.
    // Apple names those imports untagged@manifest; bind only that exact local
    // manifest/config closure to the frozen product reference. Tag is get-only
    // upstream and cannot pull an absent image.
    if (!appleImageIsPresent(list, receipt) && Array.isArray(list) && receipt.configDigest && receipt.diffIds?.length) {
      const anonymous = `untagged@${receipt.digest}`;
      const candidates = list.filter(raw => raw && typeof raw === 'object' && !Array.isArray(raw) && (raw as { configuration?: { name?: unknown } }).configuration?.name === anonymous);
      if (candidates.length === 1 && appleLocalImageIdentity(candidates, { ...receipt, reference: anonymous })) {
        const tagged = await runner(engine.executable, ['image', 'tag', anonymous, receipt.reference], options);
        if (tagged.code !== 0) throw new Error('Apple Container could not bind the verified offline image reference.');
        const named = await runner(engine.executable, ['image', 'list', '--format', 'json'], options);
        if (named.code !== 0) throw new Error('Apple Container could not inspect the imported image.');
        try { list = JSON.parse(named.stdout.toString('utf8')); } catch { throw new Error('Apple Container returned invalid image inspection data.'); }
      }
    }
    if (!appleImageIsPresent(list, receipt)) throw new Error('Imported image identity does not match the frozen receipt.');
    return { imported: true, digest: receipt.digest };
  } finally { await staged.cleanup(); }
}

/** Apple Container currently has no verified atomic no-pull execution control. */
export function appleExecutionAvailability(runtime?: import('./apple-runtime.js').AppleRuntime): { ready: boolean; code: string; reason: string } {
  if (isAppleRuntimeAdmitted(runtime)) return { ready: true, code: 'APPLE_LOCAL_CLOSURE_VERIFIED', reason: 'A complete local worker/init/kernel closure is admitted under a cooperative product lock. External engine-administrator cache mutation remains a trust boundary; atomic no-pull is not claimed.' };
  return { ready: false, code: 'APPLE_NO_PULL_UNVERIFIED', reason: 'The full local worker/init/kernel closure has not been admitted.' };
}
