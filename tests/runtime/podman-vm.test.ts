import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { bindPodmanVmIdentity, inspectPodmanVm, podmanVmCommand, podmanVmContext, podmanVmForIdentity, quotePodmanGuest, resolvePodmanVm, withPodmanVm } from '../../packages/coordinator/src/podman-vm.js';
import { providerInspection } from '../../packages/coordinator/src/provider-runtime.js';
import { writeNativeEngine } from './native-engine-fixture.js';

const digest = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const host = { platform: 'darwin', arch: process.arch };
const guestArch = process.arch === 'x64' ? 'amd64' : 'arm64';
const native = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));

/** Dedicated command/receipt fixture; it is never native VM acceptance. */
async function fixture(test: (v: { root: string; engine: string; state: string; key: string; log: string }) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-podman-vm-fixture-')));
  try {
    const state = path.join(root, 'guest-state.json'), key = path.join(root, 'machine-key'), log = path.join(root, 'calls.json');
    await writeFile(key, 'private fixture key', { mode: 0o600 });
    const guardName = process.platform === 'win32' ? 'guard.exe' : 'guard';
    const bytes = await readFile(native); await writeFile(path.join(root, guardName), bytes, { mode: 0o700 }); await chmod(path.join(root, guardName), 0o700);
    await mkdir(path.join(root, 'runtime'));
    const helper = { guard: { path: guardName, sha256: digest(bytes), size_bytes: bytes.length } };
    await writeFile(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, state: 'frozen', product_version: '0.1.0-beta.1', native_helpers: { [`darwin/${process.arch}`]: helper, [`linux/${process.arch}`]: helper } }));
    await writeFile(state, JSON.stringify({ running: true, rootful: false, rootless: true, boot: '11111111-1111-4111-8111-111111111111', installed: false, guestEngine: `sha256:${'b'.repeat(64)}` }));
    const program = String.raw`
const fs=require('node:fs'),crypto=require('node:crypto');
const state=${JSON.stringify(state)},key=${JSON.stringify(key)},log=${JSON.stringify(log)},guardHash=${JSON.stringify(digest(bytes))},arch=${JSON.stringify(guestArch)};
const s=JSON.parse(fs.readFileSync(state,'utf8')),a=process.argv.slice(2),calls=fs.existsSync(log)?JSON.parse(fs.readFileSync(log)):[];calls.push(a);fs.writeFileSync(log,JSON.stringify(calls));
const out=x=>process.stdout.write(typeof x==='string'?x:JSON.stringify(x));
if(a[0]==='machine'&&a[1]==='inspect'){out([{Name:'owned-fixture',State:s.running?'running':'stopped',Rootful:s.rootful,Created:'2026-11-09',ConfigDir:'fixture',SSHConfig:{RemoteUsername:'fixture',Port:2222,IdentityPath:key}}]);}
else if(a[0]==='machine'&&a[1]==='ssh'){
 // Parse only the exact single-quoted argv protocol emitted by the adapter.
 const input=a[3],parts=[];let i=0;
 while(i<input.length){if(input[i++]!=="'")process.exit(90);let word='';for(;;){const next=input.indexOf("'",i);if(next<0)process.exit(91);word+=input.slice(i,next);i=next+1;if(input.slice(i,i+3)==="\\''"){word+="'";i+=3;continue;}break;}parts.push(word);if(i<input.length&&input[i++]!==' ')process.exit(92);}
 let p=parts;if(p[0]==='/usr/bin/env'){let j=2;while(p[j]?.includes('='))j++;p=p.slice(j);}
 if(p[0]==='/usr/bin/id')out('1000\n');
 else if(p[0]==='/usr/bin/getent')out('fixture:x:1000:1000:fixture:/home/fixture:/bin/sh\n');
 else if(p[0]==='/usr/bin/cat')out(s.boot+'\n');
 else if(p[0]==='/usr/bin/sha256sum'){
  const files=p.slice(2);if(files.some(f=>f!=='/usr/bin/podman')&&!s.installed)process.exitCode=1;
  else out(files.map(f=>(f==='/usr/bin/podman'?s.guestEngine:guardHash).slice(7)+'  '+f).join('\n')+'\n');
 }
 else if(p[0]==='/usr/bin/podman'&&p[2]==='info')out({host:{os:'linux',arch,security:{rootless:s.rootless},cgroupVersion:'v2'}});
 else if(p[0]==='/usr/bin/podman')out({arguments:p.slice(2),environment:parts.slice(2,parts.indexOf('/usr/bin/podman'))});
 else if(p[0]==='/bin/sh'){
  const chunks=[];process.stdin.on('data',x=>chunks.push(x));process.stdin.on('end',()=>{const hash='sha256:'+crypto.createHash('sha256').update(Buffer.concat(chunks)).digest('hex');if(hash!==guardHash)process.exitCode=4;else{s.installed=true;fs.writeFileSync(state,JSON.stringify(s));}});
 }
 else process.exitCode=93;
}else process.exitCode=94;
`;
    const engine = await writeNativeEngine({ root, name: 'podman', program });
    await test({ root, engine, state, key, log });
  } finally { await rm(root, { recursive: true, force: true }); }
}

async function change(file: string, patch: Record<string, unknown>) { await writeFile(file, JSON.stringify({ ...JSON.parse(await readFile(file, 'utf8')), ...patch })); }

describe('existing Podman VM authority and dedicated guest transport', () => {
  it('quotes every guest argument without allowing shell control syntax', () => {
    expect(quotePodmanGuest("a'b;$(touch /bad)")).toBe("'a'\\''b;$(touch /bad)'");
    for (const value of ['a\0b', 'a\nb', 'a\rb']) expect(() => quotePodmanGuest(value)).toThrow('PODMAN_VM_ARGUMENT_INVALID');
  });
  it('checks availability read-only and never installs, starts, or changes a VM', async () => fixture(async v => {
    expect(await inspectPodmanVm(v.engine, host)).toMatchObject({ machine: 'owned-fixture', guestUid: 1000, guestHome: '/home/fixture', architecture: guestArch });
    expect(await providerInspection('podman', v.engine, host)).toMatchObject({ availability: 'available', rootless: null });
    const calls = JSON.parse(await readFile(v.log, 'utf8'));
    expect(calls.every((args: string[]) => args[0] === 'machine' && ['inspect', 'ssh'].includes(args[1]))).toBe(true);
    expect(calls.some((args: string[]) => args.join(' ').includes("'/bin/sh'"))).toBe(false);
    expect(JSON.parse(await readFile(v.state, 'utf8')).installed).toBe(false);
    await expect(resolvePodmanVm(v.root, v.engine, host)).rejects.toThrow('PODMAN_VM_GUEST_HELPER_REQUIRED');
  }), 30_000);
  it.each([{ running: false }, { rootful: true }, { rootless: false }])('reports unavailable for unsuitable existing guests %j', async patch => fixture(async v => {
    await change(v.state, patch); expect(await providerInspection('podman', v.engine, host)).toMatchObject({ availability: 'unavailable', rootless: null });
  }));
  it('stages only the pinned helper and reuses it without repeated installation', async () => fixture(async v => {
    const vm = await resolvePodmanVm(v.root, v.engine, host, true);
    expect(vm.guestGuard).toMatch(/^\/home\/fixture\/\.local\/share\/ud-agent-skill-mcp-plugin\/guest\/[0-9a-f]{64}\/ud-agent-guard$/);
    await resolvePodmanVm(v.root, v.engine, host, true);
    const calls = JSON.parse(await readFile(v.log, 'utf8'));
    expect(calls.filter((args: string[]) => args.join(' ').includes("'/bin/sh'"))).toHaveLength(1);
    const staging = calls.find((args: string[]) => args.join(' ').includes("'/bin/sh'"));
    expect(staging.join(' ')).toContain('test ! -L'); expect(staging.join(' ')).toContain('ln -T');
    expect(calls.some((args: string[]) => ['init', 'start', 'stop', 'rm', 'set'].includes(args[1]))).toBe(false);
  }), 30_000);
  it('keeps issued capabilities process-local and scopes sanitized guest commands', async () => fixture(async v => {
    const vm = await resolvePodmanVm(v.root, v.engine, host, true), identity = {};
    bindPodmanVmIdentity(identity, vm); expect(podmanVmForIdentity(identity)).toBe(vm); expect(podmanVmForIdentity({})).toBeUndefined();
    await expect(withPodmanVm({ ...vm }, async () => true)).rejects.toThrow('PODMAN_VM_AUTHORITY_REQUIRED');
    expect(podmanVmContext()).toBeUndefined();
    await withPodmanVm(vm, async () => {
      expect(podmanVmContext()).toBe(vm);
      const result = await podmanVmCommand(vm, ['image', 'inspect', "literal'argument;$(ignored)"]);
      const output = JSON.parse(result.stdout.toString());
      expect(output.arguments).toEqual(['image', 'inspect', "literal'argument;$(ignored)"]);
      expect(output.environment).toEqual(['PATH=/usr/bin:/bin', 'HOME=/home/fixture', 'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus', 'LANG=C']);
    });
    expect(podmanVmContext()).toBeUndefined();
  }), 30_000);
  it.each(['boot', 'engine', 'key', 'client'])('rejects changed %s before running another guest operation', async property => fixture(async v => {
    const vm = await resolvePodmanVm(v.root, v.engine, host, true);
    if (property === 'boot') await change(v.state, { boot: '22222222-2222-4222-8222-222222222222' });
    if (property === 'engine') await change(v.state, { guestEngine: `sha256:${'c'.repeat(64)}` });
    if (property === 'key') await writeFile(v.key, 'changed private key');
    if (property === 'client') await writeFile(v.engine, (await readFile(v.engine)).toString() + '\n// changed\n');
    await expect(podmanVmCommand(vm, ['volume', 'create', 'unrelated'])).rejects.toThrow(/(?:CHANGED|hash|digest|integrity)/i);
    const calls = JSON.parse(await readFile(v.log, 'utf8')); expect(calls.some((args: string[]) => args.join(' ').includes("'volume' 'create'"))).toBe(false);
  }), 30_000);
});
