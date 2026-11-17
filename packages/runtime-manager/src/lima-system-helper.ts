import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { runCommand } from './command.js';
import type { LimaRuntimeReceipt } from './lima-nerdctl.js';

const SSH_KEYGEN = '/usr/bin/ssh-keygen';
type HelperIdentity = { executable: typeof SSH_KEYGEN; sha256: string };

/** Admit the fixed OS public-key reader; this is not a PATH-selected engine. */
export async function admitLimaSshKeygen(): Promise<HelperIdentity> {
  if (await realpath(SSH_KEYGEN) !== SSH_KEYGEN) throw new Error('LIMA_SYSTEM_HELPER_UNSAFE');
  for (const directory of ['/', '/usr', '/usr/bin']) {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || info.mode & 0o022) throw new Error('LIMA_SYSTEM_HELPER_UNSAFE');
  }
  const file = await open(SSH_KEYGEN, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== 0n || before.nlink !== 1n || before.size < 1n || before.size > 128n * 1024n * 1024n || Number(before.mode) & 0o022 || !(Number(before.mode) & 0o111)) throw new Error('LIMA_SYSTEM_HELPER_UNSAFE');
    const hash = createHash('sha256'), buffer = Buffer.alloc(1024 * 1024); let count = 0;
    for (;;) { const result = await file.read(buffer, 0, buffer.length, count); if (!result.bytesRead) break; count += result.bytesRead; if (BigInt(count) > before.size) throw new Error('LIMA_SYSTEM_HELPER_CHANGED'); hash.update(buffer.subarray(0, result.bytesRead)); }
    const after = await file.stat({ bigint: true }), named = await lstat(SSH_KEYGEN, { bigint: true });
    for (const current of [after, named]) if (!current.isFile() || current.isSymbolicLink() || ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].some(key => current[key as keyof typeof current] !== before[key as keyof typeof before])) throw new Error('LIMA_SYSTEM_HELPER_CHANGED');
    if (BigInt(count) !== before.size) throw new Error('LIMA_SYSTEM_HELPER_CHANGED');
    return { executable: SSH_KEYGEN, sha256: 'sha256:' + hash.digest('hex') };
  } finally { await file.close(); }
}

/** Every admitted command retains guardian cancellation and same-FD execution. */
export function limaProvisionRunner(receipt: LimaRuntimeReceipt, guard: string, guardSha256: string, runner: typeof runCommand = runCommand, admitHelper = admitLimaSshKeygen): typeof runCommand {
  let helper: Promise<HelperIdentity> | undefined;
  return async (executable, arguments_, options) => {
    let executableSha256: string;
    if (executable === receipt.executable) executableSha256 = receipt.binarySha256;
    else if (executable === SSH_KEYGEN && receipt.home && options.limaHome === receipt.home && options.input === undefined && arguments_.length === 3 && arguments_[0] === '-y' && arguments_[1] === '-f' && arguments_[2] === path.join(receipt.home, '_config/user')) {
      const selected = await (helper ??= admitHelper());
      if (selected.executable !== SSH_KEYGEN || !/^sha256:[0-9a-f]{64}$/.test(selected.sha256)) throw new Error('LIMA_SYSTEM_HELPER_UNSAFE');
      executableSha256 = selected.sha256;
    } else throw new Error('LIMA_PROVISION_COMMAND_UNAUTHORIZED');
    return runner(executable, arguments_, { ...options, supervisor: { guard, guardSha256, executableSha256 } });
  };
}
