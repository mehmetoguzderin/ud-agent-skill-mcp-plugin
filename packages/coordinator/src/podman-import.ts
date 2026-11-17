import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from '../../runtime-manager/src/profiles.js';
import type { ImageReceipt, ImageTransport } from '../../runtime-manager/src/receipt.js';
import { verifyArchive } from '../../runtime-manager/src/receipt.js';
import { runEngineCommand as runCommand } from './engine-command.js';
import { inspectPodmanStorageIdentity, inspectPodmanImageIdentity } from './podman-worker.js';
import { podmanVmContext, podmanVmStream, resolvePodmanVm, withPodmanVm } from './podman-vm.js';
import { JournalStore } from '../../workspace/src/journal.js';
import { beginImageImportStaging } from '../../runtime-manager/src/image-import-staging.js';

async function copyBound(source: string, destination: string, receipt: ImageTransport, signal?: AbortSignal): Promise<void> {
  const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  let output;
  try {
    output = await open(destination, 'wx', 0o600);
    const before = await input.stat({ bigint: true });
    if (!before.isFile() || before.size !== BigInt(receipt.sizeBytes)) throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH');
    const hash = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let position = 0;
    for (;;) {
      if (signal?.aborted) throw new Error('WORKER_CANCELLED');
      const part = await input.read(buffer, 0, buffer.length, position); if (!part.bytesRead) break;
      position += part.bytesRead; if (position > receipt.sizeBytes) throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH');
      hash.update(buffer.subarray(0, part.bytesRead));
      let written = 0;
      while (written < part.bytesRead) { const result = await output.write(buffer, written, part.bytesRead - written); if (!result.bytesWritten) throw new Error('PODMAN_TRANSPORT_WRITE_FAILED'); written += result.bytesWritten; }
    }
    const after = await input.stat({ bigint: true });
    if (position !== receipt.sizeBytes || `sha256:${hash.digest('hex')}` !== receipt.sha256 || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('PODMAN_TRANSPORT_INTEGRITY_FAILED');
    await output.sync();
  } finally { await input.close(); await output?.close(); }
}

async function download(destination: string, receipt: ImageTransport, fetcher: typeof fetch, signal?: AbortSignal): Promise<boolean> {
  let url = new URL(`https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/${encodeURIComponent(path.posix.basename(receipt.path))}`);
  let response: Response | undefined;
  for (let count = 0; count < 6; count++) {
    response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.any([AbortSignal.timeout(120_000), ...(signal ? [signal] : [])]) });
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    const location = response.headers.get('location'); await response.body?.cancel();
    if (!location) throw new Error('PODMAN_TRANSPORT_REDIRECT_INVALID');
    url = new URL(location, url);
    if (url.protocol !== 'https:' || (url.hostname !== 'github.com' && !url.hostname.endsWith('.githubusercontent.com')) || url.username || url.password || url.port) throw new Error('PODMAN_TRANSPORT_REDIRECT_INVALID');
    response = undefined;
  }
  if (!response) throw new Error('PODMAN_TRANSPORT_REDIRECT_INVALID');
  if (response.status === 404 || response.status === 503) { await response.body?.cancel(); return false; }
  if (!response.ok || !response.body) throw new Error('PODMAN_TRANSPORT_DOWNLOAD_FAILED');
  const declared = response.headers.get('content-length');
  if (declared !== null && declared !== String(receipt.sizeBytes)) { await response.body.cancel(); throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH'); }
  const output = await open(destination, 'wx', 0o600); let size = 0; const hash = createHash('sha256');
  try {
    for await (const chunk of response.body) {
      if (signal?.aborted) throw new Error('WORKER_CANCELLED');
      size += chunk.byteLength; if (size > receipt.sizeBytes) throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH');
      hash.update(chunk); let position = 0;
      while (position < chunk.byteLength) { const written = await output.write(chunk, position, chunk.byteLength - position); if (!written.bytesWritten) throw new Error('PODMAN_TRANSPORT_WRITE_FAILED'); position += written.bytesWritten; }
    }
    if (size !== receipt.sizeBytes || `sha256:${hash.digest('hex')}` !== receipt.sha256) throw new Error('PODMAN_TRANSPORT_INTEGRITY_FAILED');
    await output.sync(); return true;
  } finally { await output.close(); }
}

async function* verifiedTransport(filename: string, receipt: ImageTransport, signal?: AbortSignal): AsyncGenerator<Buffer> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size !== BigInt(receipt.sizeBytes)) throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH');
    const hash = createHash('sha256'), buffer = Buffer.alloc(1024 * 1024); let offset = 0;
    for (;;) { if (signal?.aborted) throw new Error('WORKER_CANCELLED'); const part = await file.read(buffer, 0, buffer.length, offset); if (!part.bytesRead) break; offset += part.bytesRead; if (offset > receipt.sizeBytes) throw new Error('PODMAN_TRANSPORT_SIZE_MISMATCH'); const bytes = Buffer.from(buffer.subarray(0, part.bytesRead)); hash.update(bytes); yield bytes; }
    const after = await file.stat({ bigint: true });
    if (offset !== receipt.sizeBytes || `sha256:${hash.digest('hex')}` !== receipt.sha256 || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('PODMAN_TRANSPORT_INTEGRITY_FAILED');
  } finally { await file.close(); }
}

/** Import only a frozen platform transport. Load never performs an image pull. */
export async function ensurePodmanImage(input: { sourceRoot: string; stateRoot: string; engine: string; host: Host; image: ImageReceipt; network: 'bootstrap_only' | 'offline'; guard?: string; signal?: AbortSignal; fetcher?: typeof fetch }): Promise<boolean> {
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (input.host.platform !== 'linux' && !podmanVmContext()) { const vm = await resolvePodmanVm(input.sourceRoot, input.engine, input.host, true); return withPodmanVm(vm, () => ensurePodmanImage(input)); }
  try { await inspectPodmanImageIdentity(input.engine, input.host, input.image); return true; }
  catch (error: unknown) { if (!(error instanceof Error) || error.message !== 'PODMAN_IMAGE_NOT_PRESENT') throw error; }
  if (!input.image.configDigest || !input.image.diffIds?.length) throw new Error('PODMAN_OFFLINE_IMAGE_IDENTITY_REQUIRED');
  const transports = [...(input.image.transports ?? [])].sort((a, b) => Number(b.format === 'oci-archive') - Number(a.format === 'oci-archive'));
  if (transports.length === 0) return false;
  await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
  const store = await JournalStore.open(input.stateRoot, input.guard);
  return store.withWorkspaceLock('podman-image-import', async () => {
    const daemon = await inspectPodmanStorageIdentity(input.engine, input.host);
    try { await inspectPodmanImageIdentity(input.engine, input.host, input.image); return true; }
    catch (error: unknown) { if (!(error instanceof Error) || error.message !== 'PODMAN_IMAGE_NOT_PRESENT') throw error; }
    for (const transport of transports) {
      const cached = path.join(input.stateRoot, `${transport.sha256.slice(7)}.tar`);
      let present = true;
      try {
        const info = await lstat(cached);
        if (!info.isFile() || info.isSymbolicLink() || info.size !== transport.sizeBytes || (process.platform !== 'win32' && (info.mode & 0o222) !== 0)) throw new Error('PODMAN_TRANSPORT_CACHE_INVALID');
        await verifyArchive(cached, transport.sha256, input.signal);
      } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; present = false; }
      if (!present) {
        const staging = input.guard ? await beginImageImportStaging(input.stateRoot, input.guard, transport) : undefined;
        const temporary = staging?.filename ?? `${cached}.${randomUUID()}.tmp`;
        try {
          const source = path.join(input.sourceRoot, ...transport.path.split('/'));
          try { await copyBound(source, temporary, transport, input.signal); }
          catch (error: unknown) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
            if (input.network === 'offline' || !(await download(temporary, transport, input.fetcher ?? fetch, input.signal))) continue;
          }
          if (staging) await staging.publish(); else { await chmod(temporary, 0o400); await rename(temporary, cached); }
        } finally { if (staging) await staging.cleanup(); else await rm(temporary, { force: true }); }
      }
      const current = await inspectPodmanStorageIdentity(input.engine, input.host);
      if (current.graphRoot !== daemon.graphRoot || current.graphIdentity !== daemon.graphIdentity || current.runRoot !== daemon.runRoot || current.runIdentity !== daemon.runIdentity) throw new Error('PODMAN_DAEMON_CHANGED');
      const vm = podmanVmContext();
      const loaded = vm ? { code: 0, stdout: await podmanVmStream(vm, ['image', 'load'], verifiedTransport(cached, transport, input.signal), undefined, input.signal) } : await runCommand(input.engine, ['--remote=false', 'image', 'load', '--input', cached], { timeoutMs: 600_000, maxOutputBytes: 4 * 1024 * 1024, ...(input.signal ? { signal: input.signal } : {}) });
      if (loaded.code !== 0) throw new Error('PODMAN_OFFLINE_IMPORT_FAILED');
      const imported = await inspectPodmanImageIdentity(input.engine, input.host, input.image);
      if (imported.graphRoot !== daemon.graphRoot || imported.graphIdentity !== daemon.graphIdentity || imported.runRoot !== daemon.runRoot || imported.runIdentity !== daemon.runIdentity) throw new Error('PODMAN_DAEMON_CHANGED');
      return true;
    }
    return false;
  });
}
