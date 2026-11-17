import { createHash } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { readBoundedReceiptBytes } from './receipt.js';

const ISOLATED_CONFIG = Buffer.from('[containers]\nmounts = []\n[engine]\nhooks_dir = []\n');

export async function verifyIsolatedPodmanConfig(file: string, expectedSha256: string): Promise<void> {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (stat.uid !== process.getuid?.() && stat.uid !== 0)) throw new Error('Podman isolated configuration is not a trusted regular file.');
  const bytes = await readBoundedReceiptBytes(file);
  if (!bytes.equals(ISOLATED_CONFIG) || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== expectedSha256) throw new Error('Podman isolated configuration differs from product policy.');
}

export async function verifyEmptyPodmanMounts(file: string): Promise<void> {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) throw new Error('Podman default mounts file is not private and user-owned.');
  if ((await readBoundedReceiptBytes(file)).length !== 0) throw new Error('Podman default mounts file must be empty.');
}
