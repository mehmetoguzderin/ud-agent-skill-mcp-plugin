import path from 'node:path';
import { runCommand } from './command.js';
import { readBoundedReceipt, verifyArchive } from './receipt.js';
import type { TrustedAppleEngine } from './apple.js';

type Runner = typeof runCommand;
type AppleEngineReceipt = { version: string; binarySha256: string; teamId: string; signingIdentifier: string };

export async function loadAppleEngineReceipt(sourceRoot: string): Promise<AppleEngineReceipt> {
  if (!path.isAbsolute(sourceRoot)) throw new Error('Release source root must be absolute.');
  const lock = await readBoundedReceipt(path.join(sourceRoot, 'runtime', 'engine-distributions.lock.json'));
  if (lock.schema_version !== 1 || lock.state !== 'frozen' || !lock.engines || typeof lock.engines !== 'object' || Array.isArray(lock.engines)) throw new Error('ENGINE_RECEIPT_NOT_FROZEN');
  const engine = (lock.engines as Record<string, unknown>)['apple-container'];
  if (!engine || typeof engine !== 'object' || Array.isArray(engine)) throw new Error('Apple engine receipt is absent.');
  const item = (engine as Record<string, unknown>)['darwin/arm64'];
  if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Apple arm64 engine receipt is absent.');
  const record = item as Record<string, unknown>;
  if (typeof record.version !== 'string' || !/^[0-9]+(?:\.[0-9]+){1,3}$/.test(record.version) || typeof record.binary_sha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(record.binary_sha256) || typeof record.publisher_team_id !== 'string' || !/^[A-Z0-9]{10}$/.test(record.publisher_team_id) || typeof record.signing_identifier !== 'string' || !/^[A-Za-z0-9.-]{1,200}$/.test(record.signing_identifier)) throw new Error('Apple engine release identity is invalid.');
  return { version: record.version, binarySha256: record.binary_sha256, teamId: record.publisher_team_id, signingIdentifier: record.signing_identifier };
}

/** Verify both exact frozen bytes and the operating system's code signature. */
export async function verifyAppleEngine(executable: string, receipt: AppleEngineReceipt, runner: Runner = runCommand): Promise<TrustedAppleEngine> {
  if (!path.isAbsolute(executable)) throw new Error('Apple Container executable must be absolute.');
  await verifyArchive(executable, receipt.binarySha256);
  const options = { timeoutMs: 30_000, maxOutputBytes: 1024 * 1024 };
  const verify = await runner('/usr/bin/codesign', ['--verify', '--strict', '--verbose=2', executable], options);
  if (verify.code !== 0) throw new Error('Apple Container code-signature verification failed.');
  const details = await runner('/usr/bin/codesign', ['-d', '--verbose=4', executable], options);
  if (details.code !== 0) throw new Error('Apple Container code-signature identity is unavailable.');
  const lines = details.stderr.toString('utf8').split(/\r?\n/);
  if (!lines.includes(`TeamIdentifier=${receipt.teamId}`) || !lines.includes(`Identifier=${receipt.signingIdentifier}`)) throw new Error('Apple Container code-signature publisher does not match the frozen receipt.');
  // Recheck after signature inspection; ordinary-job no-pull remains separate.
  await verifyArchive(executable, receipt.binarySha256);
  return { executable, binarySha256: receipt.binarySha256 };
}
