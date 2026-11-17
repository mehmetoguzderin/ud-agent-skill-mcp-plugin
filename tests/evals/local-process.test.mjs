import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import * as childProcess from 'node:child_process';
vi.mock('node:child_process', async original => ({ ...await original() }));
import { startOwned, runOwned, inspectOwnedProcessGroup } from '../../evals/local/process.mjs';

const node = process.execPath;
const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } };
const groupAlive = pid => alive(-pid);
const processTest = (name, run) => test(process.platform === 'win32' ? `Windows refuses unsupported POSIX launch: ${name}` : name, run);
async function windowsRefusal(command, args, options, invoke = startOwned) {
  if (process.platform !== 'win32') return false;
  const spawn = vi.spyOn(childProcess, 'spawn').mockImplementation(() => { throw new Error('Unsupported launch attempted to spawn.'); });
  const kill = vi.spyOn(process, 'kill').mockImplementation(() => { throw new Error('Unsupported launch attempted to signal.'); });
  try {
    await assert.rejects(async () => invoke(command, args, options), { message: 'OWNED_PROCESS_GROUP_UNSUPPORTED' });
    assert.equal(spawn.mock.calls.length, 0); assert.equal(kill.mock.calls.length, 0);
  } finally { spawn.mockRestore(); kill.mockRestore(); }
  return true;
}
// These parser cases inject both the process table and its observer UID; they
// model POSIX evidence without claiming native process ownership on Windows.
function tableTest(name, run) {
  test(name, () => {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'getuid');
    Object.defineProperty(process, 'getuid', { configurable: true, value: () => 1234 });
    try { return run(); }
    finally { if (descriptor) Object.defineProperty(process, 'getuid', descriptor); else delete process.getuid; }
  });
}
async function line(stream) {
  return new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => { stream.off('data', receive); reject(new Error('Fixture did not become ready.')); }, 2000);
    function receive(bytes) { text += bytes; if (text.includes('\n')) { clearTimeout(timer); stream.off('data', receive); resolve(text.split('\n')[0]); } }
    stream.on('data', receive);
  });
}
processTest('runOwned captures successful output and proves group cleanup', async () => {
  const args = ['-e', 'process.stdout.write("héllo\\n")'];
  if (await windowsRefusal(node, args, undefined, runOwned)) return;
  const result = await runOwned(node, args);
  assert.equal(result.stdout, 'héllo\n'); assert.equal(result.code, 0); assert.equal(result.cleanupVerified, true);
});
processTest('timeout waits for an owned SIGTERM-resistant parent to die', async () => {
  const args = ['-e', 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000);console.log("ready")'], options = { timeout: 100, cancellationMs: 250 };
  if (await windowsRefusal(node, args, options)) return;
  const started = Date.now();
  const owned = startOwned(node, args, options);
  const result = await owned.done;
  assert.equal(result.stop_reason, 'timed-out'); assert.equal(result.cleanupVerified, true);
  assert.equal(groupAlive(owned.child.pid), false); assert.ok(Date.now() - started < 1500);
});
processTest('stop reconciles a child retaining inherited pipes after the parent exits', async () => {
  const descendantSource = 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000)';
  const source = `const {spawn}=require('node:child_process');const c=spawn(process.execPath,['-e',${JSON.stringify(descendantSource)}],{stdio:['ignore','inherit','inherit']});console.log(c.pid);setTimeout(()=>process.exit(0),100);`;
  const options = { timeout: 2000, cancellationMs: 1000 };
  if (await windowsRefusal(node, ['-e', source], options)) return;
  const owned = startOwned(node, ['-e', source], options);
  const descendant = Number(await line(owned.child.stdout));
  const result = await owned.done;
  assert.equal(result.code, 0); assert.equal(result.cleanupVerified, true);
  assert.equal(alive(descendant), false); assert.equal(groupAlive(owned.child.pid), false);
});
processTest('natural successful parent exit cleans detached-stdio children before resolving done', async () => {
  const source = 'const {spawn}=require("node:child_process");const c=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});c.unref();console.log(c.pid);';
  if (await windowsRefusal(node, ['-e', source], { cancellationMs: 1000 })) return;
  const owned = startOwned(node, ['-e', source], { cancellationMs: 1000 });
  const descendant = Number(await line(owned.child.stdout));
  const result = await owned.done;
  assert.equal(result.code, 0); assert.equal(result.cleanupVerified, true);
  assert.equal(alive(descendant), false);
  const again = await owned.stop('late-cleanup'); assert.deepEqual(again, result);
});
processTest('owned cleanup leaves a separate process group running', async () => {
  if (await windowsRefusal(node, ['-e', 'setInterval(()=>{},1000);console.log("ready")'], { timeout: 3000 })) return;
  const unrelated = startOwned(node, ['-e', 'setInterval(()=>{},1000);console.log("ready")'], { timeout: 3000 });
  const owned = startOwned(node, ['-e', 'setInterval(()=>{},1000);console.log("ready")'], { timeout: 3000 });
  try {
    await Promise.all([line(unrelated.child.stdout), line(owned.child.stdout)]);
    const first = owned.stop('explicit-cancel');
    assert.equal(owned.stop('duplicate-cancel'), first);
    assert.equal((await first).cleanupVerified, true);
    assert.equal(groupAlive(owned.child.pid), false);
    assert.equal(alive(unrelated.child.pid), true);
  } finally { await unrelated.stop(); await owned.stop(); }
});
processTest('output ceiling stops computation and runOwned rejects a graceful cancellation', async () => {
  const args = ['-e', 'process.on("SIGTERM",()=>process.exit(0));setInterval(()=>console.log("too much output"),1);'], options = { maximumBytes: 8, cancellationMs: 250 };
  if (await windowsRefusal(node, args, options, runOwned)) return;
  await assert.rejects(runOwned(node, args, options), /process-output-budget/);
});
processTest('spawn failure and already-aborted signal settle without an orphan', async () => {
  const controller = new AbortController(); controller.abort('already-cancelled');
  if (await windowsRefusal('/definitely/not/a/command', [], undefined, runOwned)) {
    await windowsRefusal(node, ['-e', 'setInterval(()=>{},1000)'], { signal: controller.signal, cancellationMs: 250 });
    return;
  }
  await assert.rejects(runOwned('/definitely/not/a/command', []), /ENOENT/);
  const owned = startOwned(node, ['-e', 'setInterval(()=>{},1000)'], { signal: controller.signal, cancellationMs: 250 });
  const result = await owned.done;
  assert.equal(result.cleanupVerified, true); assert.equal(result.stop_reason, 'already-cancelled');
  assert.equal(groupAlive(owned.child.pid), false);
});
tableTest('EPERM remains failed evidence while an independent complete process table proves absence', () => {
  const denied = Object.assign(new Error('Signal query denied.'), { code: 'EPERM' });
  const observer = `${process.pid} ${process.pid} ${process.getuid()}\n2147483645 2147483645 -2\n`;
  let options;
  const result = inspectOwnedProcessGroup(0x7ffffffe, { probe() { throw denied; }, table(value) { options = value; return { status: 0, signal: null, stdout: observer, stderr: '' }; } });
  assert.equal(result.state, 'absent');
  assert.equal(result.evidence[0].outcome, 'failed'); assert.equal(result.evidence[0].code, 'EPERM');
  assert.equal(result.evidence[1].outcome, 'absent'); assert.deepEqual(result.evidence[1].arguments, ['-axo', 'pgid=,pid=,uid=']);
  assert.equal(options.timeout, 1000); assert.equal(options.env.LC_ALL, 'C');
});
tableTest('foreign groups and failed, empty, malformed or partial inventories never override EPERM', () => {
  const pgid = 0x7ffffffe, observer = `${process.pid} ${process.pid} ${process.getuid()}\n`;
  const foreignUid = process.getuid() === 0 ? 1 : 0;
  for (const tableResult of [
    { status: 0, stdout: observer + `${pgid} ${pgid} ${foreignUid}\n` },
    { status: 1, stdout: observer },
    { status: null, signal: 'SIGTERM', stdout: observer },
    { status: 0, stdout: observer, error: Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }) },
    { status: 0, stdout: '' },
    { status: 0, stdout: 'invalid output\n' },
    { status: 0, stdout: observer + '12 34\n' },
    { status: 0, stdout: observer + observer },
    { status: 0, stdout: '123 123 0\n' },
  ]) {
    const result = inspectOwnedProcessGroup(pgid, { probe() { throw Object.assign(new Error('denied'), { code: 'EPERM' }); }, table: () => tableResult });
    assert.equal(result.state, 'unverified'); assert.equal(result.evidence[0].code, 'EPERM');
  }
});
tableTest('complete same-owner group presence is independent evidence while the denied query remains recorded', () => {
  const pgid = 0x7ffffffe, uid = process.getuid();
  const result = inspectOwnedProcessGroup(pgid, { probe() { throw Object.assign(new Error('denied'), { code: 'EPERM' }); }, table: () => ({ status: 0, stdout: `${process.pid} ${process.pid} ${uid}\n${pgid} ${pgid} ${uid}\n` }) });
  assert.equal(result.state, 'present'); assert.equal(result.evidence[0].outcome, 'failed'); assert.equal(result.evidence[0].code, 'EPERM');
  assert.equal(result.evidence[1].outcome, 'present'); assert.equal(result.evidence[1].same_owner, true);
});
processTest('natural owned parent exit can reconcile a denied group query through actual ps without sending a signal', async () => {
  if (await windowsRefusal(node, ['-e', 'process.stdout.write("finished\\n")'], { cancellationMs: 2000 })) return;
  const kill = process.kill.bind(process); let selected, signals = [];
  const mock = vi.spyOn(process, 'kill').mockImplementation((pid, signal) => {
    if (pid === -selected && signal === 0) throw Object.assign(new Error('Synthetic signal-zero permission denial.'), { code: 'EPERM' });
    if (pid === -selected && signal !== 0) signals.push(signal);
    return kill(pid, signal);
  });
  let owned;
  try {
    owned = startOwned(node, ['-e', 'process.stdout.write("finished\\n")'], { cancellationMs: 2000 }); selected = owned.child.pid;
    const result = await owned.done;
    assert.equal(result.code, 0); assert.equal(result.cleanupVerified, true); assert.deepEqual(signals, []);
    assert.equal(result.cleanup_evidence[0].code, 'EPERM');
    assert.equal(result.cleanup_evidence.find(event => event.method === 'process-table').outcome, 'absent');
  } finally { mock.mockRestore(); await owned?.stop(); }
});
processTest('denied signals retain failure evidence while an owned graceful exit completes inside the grace', async () => {
  if (await windowsRefusal(node, ['-e', 'console.log("ready");setTimeout(()=>process.exit(0),150)'], { cancellationMs: 2000 })) return;
  const kill = process.kill.bind(process); let selected;
  const mock = vi.spyOn(process, 'kill').mockImplementation((pid, signal) => {
    if (pid === -selected) throw Object.assign(new Error(`Synthetic ${signal} permission denial.`), { code: 'EPERM' });
    return kill(pid, signal);
  });
  let owned;
  try {
    owned = startOwned(node, ['-e', 'console.log("ready");setTimeout(()=>process.exit(0),150)'], { cancellationMs: 2000 }); selected = owned.child.pid;
    await line(owned.child.stdout);
    const result = await owned.stop('already-shutting-down');
    assert.equal(result.code, 0); assert.equal(result.cleanupVerified, true);
    assert.ok(result.cleanup_evidence.some(event => event.method === 'process-table' && event.outcome === 'present' && event.same_owner));
    assert.ok(result.cleanup_evidence.some(event => event.method === 'process-table' && event.outcome === 'absent'));
    assert.ok(result.cleanup_evidence.some(event => event.method === 'signal' && event.signal === 'SIGTERM' && event.outcome === 'failed' && event.code === 'EPERM'));
  } finally { mock.mockRestore(); await owned?.stop(); }
});

test('a process table without a native observer UID cannot establish owned group presence', () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'getuid'), pgid = 0x7ffffffe;
  Object.defineProperty(process, 'getuid', { configurable: true, value: undefined });
  try {
    const result = inspectOwnedProcessGroup(pgid, { probe() { throw Object.assign(new Error('denied'), { code: 'EPERM' }); },
      table: () => ({ status: 0, stdout: `${process.pid} ${process.pid} 1234\n${pgid} ${pgid} 1234\n` }) });
    assert.equal(result.state, 'unverified'); assert.equal(result.evidence[0].code, 'EPERM');
    assert.equal(result.evidence[1].outcome, 'present'); assert.equal(result.evidence[1].same_owner, false);
  } finally { if (descriptor) Object.defineProperty(process, 'getuid', descriptor); else delete process.getuid; }
});

test('Windows launch policy rejects synchronous and asynchronous entry points before any process side effect', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' });
  try {
    assert.equal(await windowsRefusal(node, ['-e', 'throw new Error("must not run")']), true);
    assert.equal(await windowsRefusal(node, ['-e', 'throw new Error("must not run")'], { maximumBytes: 8 }, runOwned), true);
  } finally { Object.defineProperty(process, 'platform', descriptor); }
});
