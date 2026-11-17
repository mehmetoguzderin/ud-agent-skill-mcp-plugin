import { randomUUID } from 'node:crypto';
import { lstat, mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runCommand } from './command.js';
import { JobJournal } from './job-journal.js';
import { verifyEmptyPodmanMounts, verifyIsolatedPodmanConfig } from './podman-config.js';
import { readBoundedReceiptBytes, verifyArchive } from './receipt.js';

type Runner = typeof runCommand;
export type NoPullProbe = {
  engine: string; engineSha256: string; tracer: string; tracerSha256: string;
  hooksDirectory: string; defaultMountsFile: string; containersConf: string; containersConfSha256: string;
  journal: JobJournal; runner?: Runner;
};

/**
 * Negative local-image test. The pinned tracer intercepts network syscalls and
 * blocks connect/send operations, so an unexpected pull cannot reach a remote
 * endpoint. A trace containing AF_INET/AF_INET6 is a failed probe regardless.
 */
export async function probePodmanNoPull(input: NoPullProbe): Promise<void> {
  if (![input.engine, input.tracer, input.hooksDirectory, input.defaultMountsFile, input.containersConf].every(path.isAbsolute)) throw new Error('No-pull probe paths must be absolute.');
  await verifyArchive(input.engine, input.engineSha256);
  await verifyArchive(input.tracer, input.tracerSha256);
  await verifyIsolatedPodmanConfig(input.containersConf, input.containersConfSha256);
  await verifyEmptyPodmanMounts(input.defaultMountsFile);
  const hooks = await lstat(input.hooksDirectory);
  if (!hooks.isDirectory() || hooks.isSymbolicLink() || (hooks.mode & 0o077) !== 0 || hooks.uid !== process.getuid?.() || (await readdir(input.hooksDirectory)).length !== 0) throw new Error('Podman hook directory is not a private empty product directory.');
  const runner = input.runner ?? runCommand;
  const name = `ud-agent-${randomUUID()}`;
  const digest = `sha256:${'0'.repeat(64)}`;
  const reference = `ghcr.io/mehmetoguzderin/ud-probe-${randomUUID()}@${digest}`;
  const common = ['--remote=false', `--hooks-dir=${input.hooksDirectory}`, `--default-mounts-file=${input.defaultMountsFile}`];
  const options = { timeoutMs: 30_000, maxOutputBytes: 1024 * 1024, containersConf: input.containersConf };
  const existing = await runner(input.engine, [...common, 'image', 'exists', reference], options);
  if (existing.code !== 1) throw new Error('The no-pull probe image is not proven absent.');
  await input.journal.create({ version: 1, name, engine: 'podman', engine_sha256: input.engineSha256, image_digest: digest, phase: 'planned' });
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-pull-probe-'));
  const trace = path.join(directory, 'trace');
  try {
    const args = [
      '-f', '-qq', '-s', '4096', '-e', 'trace=network,execve,io_uring_setup',
      '-e', 'inject=connect:error=ENETUNREACH', '-e', 'inject=sendto:error=ENETUNREACH',
      '-e', 'inject=sendmsg:error=ENETUNREACH', '-e', 'inject=sendmmsg:error=ENETUNREACH',
      '-e', 'inject=io_uring_setup:error=ENOSYS', '-o', trace, '--', input.engine,
      ...common, 'create', '--name', name, `--label=io.ud-agent.job=${name}`, '--pull=never', reference,
    ];
    const result = await runner(input.tracer, args, options);
    const exists = await runner(input.engine, [...common, 'container', 'exists', name], options);
    if (exists.code !== 1) throw new Error('NO_PULL_PROBE_CLEANUP_UNVERIFIED: the negative test may have created a container.');
    await input.journal.transition(name, 'cleanup_pending');
    await input.journal.transition(name, 'cleaned');
    if (result.code !== 125 || !/not known|not found|no such image|not present|not available/i.test(result.stderr.toString('utf8'))) throw new Error('Podman did not reject the absent image with pull disabled.');
    const traceBytes = await readBoundedReceiptBytes(trace);
    const text = traceBytes.toString('utf8');
    if (!text.includes(`execve(${JSON.stringify(input.engine)}`)) throw new Error('The tracer did not attest execution of the selected Podman binary.');
    if (/\bAF_INET6?\b/.test(text)) throw new Error('Podman attempted IP networking during the no-pull probe.');
  } finally { await rm(directory, { recursive: true, force: true }); }
}
