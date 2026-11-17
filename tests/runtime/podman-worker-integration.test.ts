import { posixTest } from '../fixtures/native-scope.mjs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { podmanReadiness, podmanStateRoot, setupPodman } from '../../packages/coordinator/src/podman-readiness.js';
import { resolvePodmanAuthority, verifyPodmanAuthority } from '../../packages/coordinator/src/podman-authority.js';
import { ensurePodmanImage } from '../../packages/coordinator/src/podman-import.js';
import { PodmanJobJournal } from '../../packages/coordinator/src/podman-journal.js';
import { inspectPodmanImageIdentity, inspectPodmanStorageIdentity, recoverPodmanWorker, runPodmanWorker } from '../../packages/coordinator/src/podman-worker.js';
import { writeNativeEngine } from './native-engine-fixture.js';

const digest = (value: Buffer | string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const nativeGuard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const host = { platform: 'linux', arch: process.arch };
const arch = process.arch === 'x64' ? 'amd64' : 'arm64';

/** This is a protocol fixture, never native Podman acceptance evidence. */
async function fixture(mode: string, test: (input: { root: string; engine: string; guard: string; state: string; log: string; image: { digest: string; reference: string; contextSha256: string; configDigest: string; diffIds: string[]; seccompProfile: { path: string; sha256: string; sizeBytes: number } } }) => Promise<void>) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-podman-fixture-'));
  try {
    const root = await realpath(temporary), log = path.join(root, 'engine.json'), state = path.join(root, 'state'), graph = path.join(root, 'graph'), runRoot = path.join(root, 'run');
    const guard = path.join(root, 'guard' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(guard, await readFile(nativeGuard), { mode: 0o700 });
    await mkdir(graph, { mode: 0o700 }); await mkdir(runRoot, { mode: 0o700 }); await mkdir(state, { mode: 0o700 });
    const profile = Buffer.from(JSON.stringify({ defaultAction: 'SCMP_ACT_ERRNO', architectures: [arch === 'arm64' ? 'SCMP_ARCH_AARCH64' : 'SCMP_ARCH_X86_64'], syscalls: [] })), profilePath = path.join(root, 'seccomp.json'); await writeFile(profilePath, profile);
    const image = { digest: `sha256:${'a'.repeat(64)}`, reference: `ghcr.io/mehmetoguzderin/core@sha256:${'a'.repeat(64)}`, contextSha256: `sha256:${'c'.repeat(64)}`, configDigest: `sha256:${'b'.repeat(64)}`, diffIds: [`sha256:${'d'.repeat(64)}`], seccompProfile: { path: profilePath, sha256: digest(profile), sizeBytes: profile.length } };
    // The fake engine saves its database atomically: a cancelled (SIGKILLed)
    // attached start must not leave a truncated file for the cleanup commands.
    const program = String.raw`
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const file=${JSON.stringify(log)},graph=${JSON.stringify(graph)},runRoot=${JSON.stringify(runRoot)},image=${JSON.stringify(image)},mode=${JSON.stringify(mode)},arch=${JSON.stringify(arch)};
const raw=process.argv.slice(2),offset=raw.findIndex(x=>['info','image','volume','container','create','start'].includes(x)),args=raw.slice(offset);if(!raw.includes('--remote=false'))process.exit(5);
let db=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{containers:{},volumes:{},calls:[]};db.calls.push(args);const save=()=>{const next=file+'.'+process.pid;fs.writeFileSync(next,JSON.stringify(db));fs.renameSync(next,file);};const out=x=>{save();process.stdout.write(typeof x==='string'?x:JSON.stringify(x));};const idx=x=>args[args.indexOf(x)+1];const keyed=x=>args.find(a=>a.startsWith(x+'='))?.slice(x.length+1);const found=id=>db.containers[id]||Object.values(db.containers).find(c=>c.Name===id);
if(args[0]==='info'&&mode==='stopped'){save();process.exitCode=1;}
else if(args[0]==='info')out({host:{os:'linux',arch,security:{rootless:mode!=='rootful'},cgroupVersion:mode==='cgroup1'?'v1':'v2',kernel:'7.0.14-linuxkit'},store:{graphRoot:graph,runRoot}});
else if(args[0]==='image'&&args[1]==='inspect'){if(mode==='missing-image'||mode==='import'&&!db.loaded){save();process.exitCode=1;}else out([{Id:image.configDigest.slice(7),Os:'linux',Architecture:arch,RootFS:{Type:'layers',Layers:mode==='corrupt-image'?['sha256:'+'e'.repeat(64)]:image.diffIds},Config:{Env:['PATH=/usr/local/bin:/usr/bin:/bin','HOME=/tmp']},RepoDigests:[]}]);}
else if(args[0]==='image'&&args[1]==='load'){db.loaded=true;db.imported=fs.readFileSync(idx('--input')).toString('base64');out('loaded\n');}
else if(args[0]==='volume'&&args[1]==='create'){const name=args.at(-1),job=idx('--label').split('=')[1],mount=path.join(graph,'volumes',name,'_data');fs.mkdirSync(mount,{recursive:true,mode:0o700});db.volumes[name]={Name:name,Driver:'local',Scope:'local',Labels:{'io.ud-agent.job':job},Options:{},Mountpoint:mount};out(name+'\n');}
else if(args[0]==='volume'&&args[1]==='inspect'){const v=db.volumes[args[2]];if(v)out([v]);else{save();process.exitCode=1;}}
else if(args[0]==='volume'&&args[1]==='exists'){save();process.exitCode=db.volumes[args[2]]?0:1;}
else if(args[0]==='volume'&&args[1]==='rm'){delete db.volumes[args[2]];out(args[2]+'\n');}
else if(args[0]==='create'){
 const name=idx('--name'),job=idx('--label').split('=')[1],id=crypto.createHash('sha256').update(name).digest('hex'),vol=idx('--volume').split(':')[0],ro=idx('--volume').split(':')[2].split(',').includes('ro'),mount=db.volumes[vol].Mountpoint,command=args.slice(args.indexOf(image.configDigest)+1),entry=idx('--entrypoint'),env=args.flatMap((a,i)=>a==='--env'?[args[i+1]]:[]),seccomp=JSON.parse(fs.readFileSync(keyed('--security-opt')?.startsWith('seccomp=')?keyed('--security-opt').slice(8):args.find(a=>a.startsWith('--security-opt=seccomp=')).slice(23),'utf8'));
 const cfg=path.join(graph,'overlay-containers',id,'userdata','config.json');fs.mkdirSync(path.dirname(cfg),{recursive:true,mode:0o700});
 const spec={root:{readonly:true},process:{terminal:false,noNewPrivileges:true,cwd:'/tmp',user:{uid:10001,gid:10001},args:[entry,...command],env,capabilities:{bounding:[],effective:[],inheritable:[],permitted:[],ambient:[]},rlimits:[{type:'RLIMIT_NOFILE',soft:1024,hard:1024}]},linux:{namespaces:['pid','ipc','network','cgroup','user','mount','uts'].map(type=>({type})),seccomp,resources:{memory:{limit:2147483648},cpu:{quota:200000,period:100000},pids:{limit:128}}},mounts:[{type:'bind',source:mount,destination:'/input',options:[ro?'ro':'rw']},{type:'tmpfs',source:'tmpfs',destination:'/tmp',options:['rw','nosuid','nodev','noexec','size=67108864']}]};
 if(ro){
 if(mode==='bad-oci')spec.process.user.uid=0;
 if(mode==='writable-root')spec.root.readonly=false;
 if(mode==='capability')spec.process.capabilities.effective=['CAP_SYS_ADMIN'];
 if(mode==='privilege')spec.process.noNewPrivileges=false;
 if(mode==='shared-network')spec.linux.namespaces.find(x=>x.type==='network').path='/proc/1/ns/net';
 if(mode==='seccomp')spec.linux.seccomp.defaultAction='SCMP_ACT_ALLOW';
 if(mode==='memory')spec.linux.resources.memory.limit=-1;
 if(mode==='cpu')spec.linux.resources.cpu.quota=300000;
 if(mode==='pids')spec.linux.resources.pids.limit=0;
 if(mode==='environment')spec.process.env.push('UNTRUSTED=injected');
 if(mode==='tmpfs-exec')spec.mounts[1].options.push('exec');
 if(mode==='host-socket')spec.mounts.push({type:'bind',source:'/run/podman/podman.sock',destination:'/run/engine.sock',options:['rw']});
 if(mode==='groups')spec.process.user.additionalGids=[0];
 if(mode==='device')spec.linux.devices=[{path:'/dev/sda',type:'b',major:8,minor:0}];
 if(mode==='hook')spec.hooks={prestart:[{path:'/hostile'}]};
 if(mode==='file-limit')spec.process.rlimits[0].hard=2048;
}fs.writeFileSync(cfg,JSON.stringify(spec));
 db.containers[id]={Id:id,Name:name,Image:image.configDigest.slice(7),State:{Status:'created'},EffectiveCaps:[],BoundingCaps:[],OCIConfigPath:cfg,Config:{User:'10001:10001',Tty:false,OpenStdin:true,Labels:{'io.ud-agent.job':job},Entrypoint:entry,Cmd:command},HostConfig:{Privileged:false,ReadonlyRootfs:true,NetworkMode:'none',PublishAllPorts:false,Devices:[]},Mounts:[{Type:'volume',Name:vol,Source:mount,Destination:'/input',RW:mode==='writable'&&ro?true:!ro}]};out(id+'\n');
}
else if(args[0]==='container'&&args[1]==='init'){const c=found(args[2]);if(!c){save();process.exitCode=1;}else{c.State.Status='initialized';out(c.Id+'\n');}}
else if(args[0]==='container'&&args[1]==='inspect'){const c=found(args[2]);if(c)out([c]);else{save();process.exitCode=1;}}
else if(args[0]==='container'&&args[1]==='exists'){save();process.exitCode=found(args[2])?0:1;}
else if(args[0]==='container'&&args[1]==='rm'){delete db.containers[args.at(-1)];out(args.at(-1)+'\n');}
else if(args[0]==='start'){const c=found(args.at(-1));save();let chunks=[];process.stdin.on('data',x=>chunks.push(x));process.stdin.on('end',()=>{const input=Buffer.concat(chunks).toString();if(c.Name.endsWith('-loader')){const rows=input.trim().split('\n').map(JSON.parse),expected=c.Config.Cmd.at(-1);if(rows[0].snapshot_sha256!==expected||rows.at(-1).snapshot_sha256!==expected)process.exit(3);out(JSON.stringify({status:'loaded',snapshot_sha256:expected})+'\n');}else{if(mode==='block'){save();setInterval(()=>{},1000);return;}const req=JSON.parse(input);out(JSON.stringify({ok:true,result:{operation:req.operation,passed:false,incidents:[{testid:req.arguments.file_paths?.length===2?'non-unique-sent-id':'fixture'}],scope:{file_paths:req.arguments.file_paths}}})+'\n');}});}
else {save();process.exitCode=2;}
`;
    const engine = await writeNativeEngine({ root, name: 'podman', program }); await writeFile(path.join(root, 'a.conllu'), '# sent_id = a\n1\ta\t_\tX\t_\t_\t0\troot\t_\t_\n\n');
    await test({ root, engine, guard, state, log, image });
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

function runtime(input: { root: string; engine: string; guard: string; state: string; image: Parameters<typeof runPodmanWorker>[0]['image'] }) {
  return readFile(input.engine).then(async bytes => ({ engine: input.engine, engineSha256: digest(bytes), guard: input.guard, guardSha256: digest(await readFile(input.guard)), image: input.image, host, stateRoot: input.state, workingTree: input.root, allowedRoots: [input.root], filePaths: ['a.conllu'], options: { language_code: 'en' } }));
}

// Each fixture spawns dozens of fake-engine Node processes (~2-4 s idle). The
// 120 s budget keeps CPU oversubscription from surfacing as a timeout.
if (process.platform !== 'win32') describe('dedicated rootless Podman generic worker protocol fixture', () => {
  posixTest('admits an exact local configuration and layer identity without repository digests', async () => fixture('normal', async input => {
    expect(await inspectPodmanImageIdentity(input.engine, host, input.image)).toMatchObject({ imageId: input.image.configDigest, rootless: true, architecture: arch });
    expect(JSON.parse(await readFile(input.log, 'utf8')).calls.every((args: string[]) => !args.includes('pull'))).toBe(true);
  }), 120_000);
  posixTest.each(['rootful', 'cgroup1', 'corrupt-image'])('rejects %s before worker creation', async mode => fixture(mode, async input => {
    await expect(inspectPodmanImageIdentity(input.engine, host, input.image)).rejects.toThrow(/PODMAN_(?:ROOTLESS_REQUIRED|IMAGE_NOT_VERIFIED)/);
    expect(JSON.parse(await readFile(input.log, 'utf8')).calls.some((args: string[]) => args[0] === 'create')).toBe(false);
  }), 120_000);
  posixTest('executes generic operations through a named volume and removes only owned resources', async () => fixture('normal', async input => {
    const before = await readFile(path.join(input.root, 'a.conllu'));
    const outcome = await runPodmanWorker({ ...await runtime(input), operation: 'treebank_profile', arguments: { file_paths: ['a.conllu'], ud_context_path: '' } });
    expect(outcome.runtime).toBe('podman'); expect(outcome.result.operation).toBe('treebank_profile'); expect(await readFile(path.join(input.root, 'a.conllu'))).toEqual(before);
    const db = JSON.parse(await readFile(input.log, 'utf8')); expect(Object.keys(db.containers)).toEqual([]); expect(Object.keys(db.volumes)).toEqual([]);
    const creates = db.calls.filter((args: string[]) => args[0] === 'create'); expect(creates).toHaveLength(2);
    expect(creates.every((args: string[]) => args.includes('--pull=never') && args.includes('--network=none') && args.includes('--unsetenv-all') && !args.some(arg => arg.includes('type=bind')))).toBe(true);
    expect(creates[0][creates[0].indexOf('--volume') + 1]).toContain(':rw,'); expect(creates[1][creates[1].indexOf('--volume') + 1]).toContain(':ro,');
    expect(await (await PodmanJobJournal.open(input.state)).pending()).toEqual([]);
  }), 120_000);
  posixTest.each(['writable', 'bad-oci', 'writable-root', 'capability', 'privilege', 'shared-network', 'seccomp', 'memory', 'cpu', 'pids', 'environment', 'tmpfs-exec', 'host-socket', 'groups', 'device', 'hook', 'file-limit'])('rejects %s actual containment and still verifies cleanup', async mode => fixture(mode, async input => {
    await expect(runPodmanWorker(await runtime(input))).rejects.toThrow(/PODMAN_(?:CONTAINER|OCI)_POLICY_FAILED/);
    const db = JSON.parse(await readFile(input.log, 'utf8')); expect(Object.keys(db.containers)).toEqual([]); expect(Object.keys(db.volumes)).toEqual([]);
    expect(await (await PodmanJobJournal.open(input.state)).pending()).toEqual([]);
  }), 120_000);
  posixTest('requires a dead owner for recovery and resolves a labeled ambiguous volume create', async () => fixture('normal', async input => {
    const storage = await inspectPodmanStorageIdentity(input.engine, host), journal = await PodmanJobJournal.open(input.state), id = '11111111-1111-4111-8111-111111111111';
    await journal.create({ version: 1, id, engine: input.engine, engine_sha256: digest(await readFile(input.engine)), image_digest: input.image.digest, image_id: input.image.configDigest, graph_root: storage.graphRoot, graph_identity: storage.graphIdentity, owner_pid: process.pid, phase: 'planned' });
    await expect(recoverPodmanWorker(input.state, id)).rejects.toThrow('PODMAN_JOB_OWNER_ACTIVE');
    const filename = path.join(journal.directory, id, 'job.json'), record = JSON.parse(await readFile(filename, 'utf8')); record.owner_pid = 2_147_483_647; await writeFile(filename, JSON.stringify(record));
    await journal.transition(id, 'volume_pending');
    await expect(recoverPodmanWorker(input.state, id)).rejects.toThrow('PODMAN_CREATE_OUTCOME_UNKNOWN');
    execFileSync(input.engine, ['--remote=false', 'volume', 'create', '--label', `io.ud-agent.job=${id}`, `ud-agent-${id}-input`]);
    await recoverPodmanWorker(input.state, id); expect((await journal.load(id)).phase).toBe('cleaned');
  }), 120_000);
  posixTest('imports a verified per-architecture OCI transport offline and reuses the image without downloads', async () => fixture('import', async input => {
    const bytes = Buffer.from('fixture OCI transport bytes'), filename = path.join(input.root, 'worker-arm64.oci.tar'); await writeFile(filename, bytes);
    const image = { ...input.image, transports: [{ format: 'oci-archive' as const, path: path.basename(filename), sha256: digest(bytes), sizeBytes: bytes.length }] };
    let downloads = 0; const fetcher = (async () => { downloads++; throw new Error('unexpected download'); }) as typeof fetch;
    expect(await ensurePodmanImage({ sourceRoot: input.root, stateRoot: path.join(input.state, 'images'), engine: input.engine, host, image, network: 'offline', fetcher })).toBe(true);
    expect(await ensurePodmanImage({ sourceRoot: input.root, stateRoot: path.join(input.state, 'images'), engine: input.engine, host, image, network: 'offline', fetcher })).toBe(true);
    const db = JSON.parse(await readFile(input.log, 'utf8')); expect(Buffer.from(db.imported, 'base64')).toEqual(bytes); expect(db.calls.filter((args: string[]) => args[0] === 'image' && args[1] === 'load')).toHaveLength(1); expect(downloads).toBe(0);
  }), 120_000);
  posixTest('never downloads in offline mode and never falls back from corrupt transport bytes', async () => fixture('import', async input => {
    const expected = Buffer.from('expected'), image = { ...input.image, transports: [{ format: 'oci-archive' as const, path: 'missing.oci.tar', sha256: digest(expected), sizeBytes: expected.length }] };
    let downloads = 0; const fetcher = (async () => { downloads++; return new Response(expected); }) as typeof fetch;
    expect(await ensurePodmanImage({ sourceRoot: input.root, stateRoot: path.join(input.state, 'images'), engine: input.engine, host, image, network: 'offline', fetcher })).toBe(false);
    await writeFile(path.join(input.root, 'missing.oci.tar'), Buffer.from('corrupt!'));
    await expect(ensurePodmanImage({ sourceRoot: input.root, stateRoot: path.join(input.state, 'images'), engine: input.engine, host, image, network: 'bootstrap_only', fetcher })).rejects.toThrow(/PODMAN_TRANSPORT_(?:INTEGRITY_FAILED|SIZE_MISMATCH)/);
    expect(downloads).toBe(0); expect(JSON.parse(await readFile(input.log, 'utf8')).calls.some((args: string[]) => args[0] === 'image' && args[1] === 'load')).toBe(false);
  }), 120_000);
  posixTest('cancels image acquisition before engine access and removes an interrupted owned download', async () => fixture('import', async input => {
    const bytes = Buffer.from('verified fixture transport'), image = { ...input.image, transports: [{ format: 'oci-archive' as const, path: 'absent.oci.tar', sha256: digest(bytes), sizeBytes: bytes.length }] };
    const before = new AbortController(); before.abort();
    await expect(ensurePodmanImage({ sourceRoot: input.root, stateRoot: path.join(input.state, 'unused'), engine: input.engine, host, image, network: 'bootstrap_only', signal: before.signal })).rejects.toThrow('WORKER_CANCELLED');
    await expect(readFile(input.log)).rejects.toMatchObject({ code: 'ENOENT' });
    const controller = new AbortController(); let downloads = 0;
    const fetcher = (async (_url: unknown, init: RequestInit) => {
      downloads++; expect(init.signal).toBeInstanceOf(AbortSignal);
      return new Response(new ReadableStream({ start(stream) { stream.enqueue(bytes); controller.abort(); stream.close(); } }), { status: 200, headers: { 'content-length': String(bytes.length) } });
    }) as typeof fetch;
    const stateRoot = path.join(input.state, 'images');
    await expect(ensurePodmanImage({ sourceRoot: input.root, stateRoot, engine: input.engine, host, image, network: 'bootstrap_only', signal: controller.signal, fetcher })).rejects.toThrow('WORKER_CANCELLED');
    expect(downloads).toBe(1);
    expect((await readdir(stateRoot)).some(name => name.endsWith('.tmp') || name.endsWith('.tar'))).toBe(false);
    expect(JSON.parse(await readFile(input.log, 'utf8')).calls.some((args: string[]) => args[0] === 'image' && args[1] === 'load')).toBe(false);
  }), 120_000);
  posixTest('cancels a running attached worker and verifies owned container and volume removal', async () => fixture('block', async input => {
    const controller = new AbortController(); const execution = runPodmanWorker({ ...await runtime(input), signal: controller.signal });
    const watcher = setInterval(async () => { try { const db = JSON.parse(await readFile(input.log, 'utf8')); if (db.calls.filter((args: string[]) => args[0] === 'start').length === 2) controller.abort(); } catch {} }, 10);
    try { await expect(execution).rejects.toThrow('WORKER_CANCELLED'); } finally { clearInterval(watcher); }
    const db = JSON.parse(await readFile(input.log, 'utf8')); expect(Object.keys(db.containers)).toEqual([]); expect(Object.keys(db.volumes)).toEqual([]); expect(await (await PodmanJobJournal.open(input.state)).pending()).toEqual([]);
  }), 120_000);
  posixTest('binds read-only readiness to a real probe receipt and keeps warm setup idempotent', async () => fixture('normal', async input => {
    await mkdir(path.join(input.root, 'runtime'));
    const native = await readFile(input.guard); await writeFile(path.join(input.root, 'guard'), native, { mode: 0o700 }); await chmod(path.join(input.root, 'guard'), 0o700);
    const frozen = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', native_helpers: { [`linux/${process.arch}`]: { guard: { path: 'guard', sha256: digest(native), size_bytes: native.length } } }, packs: { core: { context_sha256: input.image.contextSha256, seccomp_profile: { path: 'seccomp.json', sha256: input.image.seccompProfile.sha256, size_bytes: input.image.seccompProfile.sizeBytes }, images: { [`linux/${arch}`]: { digest: input.image.digest, reference: input.image.reference, config_digest: input.image.configDigest, diff_ids: input.image.diffIds } } } } };
    await writeFile(path.join(input.root, 'runtime/runtime.lock.json'), JSON.stringify(frozen));
    const options = { sourceRoot: input.root, userspaceStateRoot: path.join(input.root, 'selection-state') };
    expect(await podmanReadiness(options, 'podman', input.engine, host, ['validation_report'])).toBeNull();
    expect(await setupPodman(options, 'podman', input.engine, host, ['validation_report'])).toMatchObject({ verification: 'verified', rootless: true, available_operations: ['validation_report'] });
    const before = JSON.parse(await readFile(input.log, 'utf8')).calls.filter((args: string[]) => args[0] === 'create').length;
    expect(await podmanReadiness(options, 'podman', input.engine, host, ['validation_report'])).toMatchObject({ verification: 'verified' });
    expect(await setupPodman(options, 'podman', input.engine, host, ['validation_report'])).toMatchObject({ verification: 'verified' });
    expect(JSON.parse(await readFile(input.log, 'utf8')).calls.filter((args: string[]) => args[0] === 'create')).toHaveLength(before);
    const authority = await resolvePodmanAuthority(input.root, input.engine, host); expect(await verifyPodmanAuthority(authority)).toBe(authority);
    await expect(verifyPodmanAuthority({ ...authority })).rejects.toThrow('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
    expect(podmanStateRoot(options, host)).toBe(`${options.userspaceStateRoot}-podman`);
    await writeFile(input.engine, (await readFile(input.engine)).toString() + '\n// replaced fixture\n');
    await expect(verifyPodmanAuthority(authority)).rejects.toThrow('PODMAN_EXECUTABLE_CHANGED');
  }), 120_000);
  posixTest('does not begin snapshot transfer after cancellation', async () => fixture('normal', async input => {
    const controller = new AbortController(); controller.abort(); await expect(runPodmanWorker({ ...await runtime(input), signal: controller.signal })).rejects.toThrow('WORKER_CANCELLED');
    await expect(readFile(input.log)).rejects.toMatchObject({ code: 'ENOENT' });
  }), 120_000);
});

if (process.platform === 'win32') it('Linux local Podman authority rejects Windows executable metadata before any engine operation', async () => fixture('normal', async input => {
  // Reach executable admission with a complete frozen product receipt.
  await mkdir(path.join(input.root, 'runtime'));
  const native = await readFile(input.guard);
  const frozen = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', native_helpers: { [`linux/${process.arch}`]: { guard: { path: path.basename(input.guard), sha256: digest(native), size_bytes: native.length } } }, packs: { core: { context_sha256: input.image.contextSha256, seccomp_profile: { path: 'seccomp.json', sha256: input.image.seccompProfile.sha256, size_bytes: input.image.seccompProfile.sizeBytes }, images: { [`linux/${arch}`]: { digest: input.image.digest, reference: input.image.reference, config_digest: input.image.configDigest, diff_ids: input.image.diffIds } } } } };
  await writeFile(path.join(input.root, 'runtime/runtime.lock.json'), JSON.stringify(frozen));
  const bytes = await readFile(input.engine);
  await expect(resolvePodmanAuthority(input.root, input.engine, host)).rejects.toThrow('PODMAN_EXECUTABLE_UNVERIFIED');
  expect(await readFile(input.engine)).toEqual(bytes);
  await expect(lstat(input.log)).rejects.toMatchObject({ code: 'ENOENT' });
  expect(await readdir(input.state)).toEqual([]);
}), 30000);
