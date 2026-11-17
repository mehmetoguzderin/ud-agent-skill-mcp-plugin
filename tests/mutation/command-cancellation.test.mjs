import { test, expect } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { runMutationCommand } from '../../scripts/quality/mutation-gate.mjs';

const gate = new URL('../../scripts/quality/mutation-gate.mjs', import.meta.url).href;
const storage = new URL('../../scripts/quality/storage-lifecycle.mjs', import.meta.url).href;
const fixture = () => realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-command-cancellation-')));
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function waitFor(file) {
  for (let count = 0; count < 200; count++) { if (existsSync(file)) return; await delay(10); }
  throw new Error('Fixture child did not become ready');
}
async function exited(pid) {
  for (let count = 0; count < 200; count++) { try { process.kill(pid, 0); } catch { return true; } await delay(10); }
  return false;
}
const childProgram = "import{writeFileSync}from'node:fs';process.on('SIGTERM',()=>setTimeout(()=>{writeFileSync(process.argv[2],'cleanup complete');process.exit(0)},30));writeFileSync(process.argv[1],String(process.pid));setInterval(()=>{},1000);";

test('cancellation waits for owned processes to exit and remains a failed outcome', async () => {
  const root = fixture(), controller = new AbortController(), ready = path.join(root, 'ready'), cleaned = path.join(root, 'cleaned'), leader = path.join(root, 'leader');
  const program = process.platform === 'win32' ? childProgram : `import{spawn}from'node:child_process';import{writeFileSync}from'node:fs';writeFileSync(process.argv[3],String(process.pid));spawn(process.execPath,['--input-type=module','-e',${JSON.stringify(childProgram)},process.argv[1],process.argv[2]],{stdio:'inherit'});process.exit(0);`;
  let execution;
  try {
    execution = runMutationCommand('authored cancellation fixture', process.execPath, ['--input-type=module', '-e', program, ready, cleaned, leader], root, process.env, path.join(root, 'command.log'), 10_000, () => {}, controller.signal);
    await waitFor(ready);
    // POSIX descendants keep their detached group and output pipes after the
    // leader exits; Windows uses the directly owned child's native handle.
    // The descendant can report ready before the leader's exit is reaped, so
    // wait (bounded) for the leader to disappear instead of sampling once.
    if (process.platform !== 'win32') expect(await exited(Number(readFileSync(leader, 'utf8')))).toBe(true);
    controller.abort();
    const result = await execution;
    expect(result.cancelled).toBe(true); expect(result.error).toMatch(/cancelled/); expect(result.timeout).toBe(false);
    if (process.platform !== 'win32') expect(readFileSync(cleaned, 'utf8')).toBe('cleanup complete');
    const pid = Number(readFileSync(ready, 'utf8'));
    // The descendant was re-parented when its leader exited; after it closes
    // its pipes and exits it can remain a zombie until init reaps it, which
    // lags under load, so poll (bounded) instead of sampling once.
    if (process.platform !== 'win32') expect(await exited(pid)).toBe(true); else expect(() => process.kill(pid, 0)).toThrow();
  } finally { controller.abort(); if (execution) await execution; rmSync(root, { recursive: true, force: true }); }
});

test('already-cancelled commands never launch their executable', async () => {
  const root = fixture(), controller = new AbortController(); controller.abort(new Error('cancelled before launch'));
  try {
    await expect(runMutationCommand('never launched fixture', process.execPath, ['-e', 'process.exit(0)'], root, process.env, path.join(root, 'command.log'), 1000, () => {}, controller.signal)).rejects.toThrow('cancelled before launch');
    expect(existsSync(path.join(root, 'command.log'))).toBe(false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a normal authored command keeps its existing successful result and log', async () => {
  const root = fixture();
  try {
    const result = await runMutationCommand('successful fixture', process.execPath, ['-e', 'console.log("independent expected output")'], root, process.env, path.join(root, 'command.log'), 1000);
    expect(result.status).toBe(0); expect(result.error).toBeUndefined(); expect(result.cancelled).toBeUndefined();
    expect(readFileSync(result.log, 'utf8')).toBe('independent expected output\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('obsolete resource callbacks cannot fail a successful finite command', async () => {
  const root = fixture();
  try {
    const result = await runMutationCommand('finite unmonitored fixture', process.execPath, ['-e', 'setTimeout(()=>console.log("completed"),5100)'], root, process.env, path.join(root, 'command.log'), 10_000, () => { throw new Error('obsolete byte-budget scan'); });
    expect(result.status).toBe(0); expect(result.error).toBeUndefined(); expect(result.timeout).toBe(false);
    expect(readFileSync(result.log, 'utf8')).toBe('completed\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 15_000);

test('SIGINT stops a detached command before its parent reservation is removed', () => {
  const root = fixture();
  try {
    const program = `import{reserveStorage}from ${JSON.stringify(storage)};import{runMutationCommand}from ${JSON.stringify(gate)};import{existsSync,writeFileSync}from'node:fs';import path from'node:path';
const root=process.argv[1],controller=new AbortController();let active;
const lease=reserveStorage({root,plannedBytes:4096,onCancel:async()=>{controller.abort();if(active)await active;writeFileSync(path.join(root,'parent-observed-exit'),'yes')}});
writeFileSync(path.join(root,'scratch'),lease.directory);
active=runMutationCommand('signal cleanup fixture',process.execPath,['--input-type=module','-e',${JSON.stringify(childProgram)},path.join(root,'ready'),path.join(root,'cleaned')],root,process.env,path.join(root,'command.log'),10000,()=>{},controller.signal);
while(!existsSync(path.join(root,'ready')))await new Promise(resolve=>setTimeout(resolve,10));process.emit('SIGINT');await active;`;
    const env = { ...process.env }; delete env.UD_STORAGE_LEASE;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', program, root], { encoding: 'utf8', env, timeout: 15_000 });
    expect(result.status).toBe(130); expect(result.error).toBeUndefined(); expect(readFileSync(path.join(root, 'parent-observed-exit'), 'utf8')).toBe('yes');
    if (process.platform !== 'win32') expect(readFileSync(path.join(root, 'cleaned'), 'utf8')).toBe('cleanup complete');
    expect(existsSync(readFileSync(path.join(root, 'scratch'), 'utf8'))).toBe(false);
    expect(existsSync(path.join(root, '.artifacts/.storage-reservation'))).toBe(false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
