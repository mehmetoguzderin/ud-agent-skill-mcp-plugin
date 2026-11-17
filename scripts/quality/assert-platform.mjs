/** Assert process/OS architecture; provider acceptance remains a separate gate. */
import os from 'node:os';
import { spawnSync } from 'node:child_process';
const platforms = { linux: 'linux', macos: 'darwin', windows: 'win32' };
const expectedPlatform = platforms[process.env.EXPECTED_PLATFORM];
const expectedArch = process.env.EXPECTED_ARCH;
if (!expectedPlatform || !['x64', 'arm64'].includes(expectedArch) || process.platform !== expectedPlatform || process.arch !== expectedArch || os.arch() !== expectedArch) {
  throw new Error(`Native platform mismatch: expected ${expectedPlatform}/${expectedArch}, got ${process.platform}/${process.arch} (${os.arch()})`);
}
if (process.platform === 'darwin') {
  const translated = spawnSync('/usr/sbin/sysctl', ['-n', 'sysctl.proc_translated'], { encoding: 'utf8', timeout: 5000 });
  if (translated.status === 0 && translated.stdout.trim() !== '0') throw new Error('Translated macOS process is not native acceptance.');
  if (translated.status !== 0 && !/unknown oid|no such file/i.test(translated.stderr ?? '')) throw new Error('Cannot verify whether the macOS process is translated.');
}
if (process.platform === 'win32') {
  const native = (process.env.PROCESSOR_ARCHITEW6432 ?? process.env.PROCESSOR_ARCHITECTURE ?? '').toLowerCase();
  if (native !== (expectedArch === 'arm64' ? 'arm64' : 'amd64')) throw new Error('Windows process is running under a different native architecture.');
}
if (process.platform === 'linux') {
  const machine = os.machine();
  if (machine !== (expectedArch === 'arm64' ? 'aarch64' : 'x86_64')) throw new Error('Linux kernel and process architecture differ.');
}
console.log(`Native process architecture: ${process.platform}/${process.arch}`);
