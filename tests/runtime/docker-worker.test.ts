import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DockerJobJournal } from '../../packages/coordinator/src/docker-journal.js';
import { recoverDockerValidation, runDockerValidation } from '../../packages/coordinator/src/docker-worker.js';
import { writeNativeEngine } from './native-engine-fixture.js';

const digest = (data: Buffer | string) => `sha256:${createHash('sha256').update(data).digest('hex')}`;
const nativeGuard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));

async function fixture(corruptWorker: boolean, test: (root: string, engine: string, state: string, log: string, image: { digest: string; reference: string; contextSha256: string }, guard: string) => Promise<void>) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-worker-test-'));
  try {
    const root = await realpath(temporary); const guard = path.join(root, 'guard' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(guard, await readFile(nativeGuard), { mode: 0o700 }); const log = path.join(root, 'docker.json');
    const manifestDigest = `sha256:${'a'.repeat(64)}`; const imageId = `sha256:${'b'.repeat(64)}`;
    const image = { digest: manifestDigest, reference: `ghcr.io/mehmetoguzderin/core@${manifestDigest}`, contextSha256: `sha256:${'c'.repeat(64)}` };
    const program = String.raw`
const fs=require('node:fs');const crypto=require('node:crypto');
const file=${JSON.stringify(log)}, imageId=${JSON.stringify(imageId)}, ref=${JSON.stringify(image.reference)}, corrupt=${corruptWorker};
let db=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{volumes:{},containers:{},calls:[]};
const raw=process.argv.slice(2);if(raw[0]==='--host'&&raw[1]!=='unix:///private/tmp/docker-fixture.sock')process.exit(2);
const args=raw[0]==='--host'?raw.slice(2):raw;db.calls.push(args);const save=()=>fs.writeFileSync(file,JSON.stringify(db));
const output=x=>{save();process.stdout.write(typeof x==='string'?x:JSON.stringify(x));};
const idx=x=>args[args.indexOf(x)+1];
if(args[0]==='context'){output([{Endpoints:{docker:{Host:'unix:///private/tmp/docker-fixture.sock'}}}]);}
else if(args[0]==='info'){output({ID:'fixture-daemon',Architecture:process.arch==='x64'?'x86_64':'aarch64',ServerVersion:'fixture',SecurityOptions:['name=seccomp']});}
else if(args[0]==='image'&&args[1]==='inspect'){output([{Id:imageId,Os:'linux',Architecture:process.arch==='x64'?'amd64':process.arch,RepoDigests:[ref]}]);}
else if(args[0]==='volume'&&args[1]==='create'){const name=args.at(-1),job=idx('--label').split('=')[1];db.volumes[name]={Name:name,Driver:'local',Scope:'local',Options:null,Labels:{'io.ud-agent.job':job}};output(name+'\n');}
else if(args[0]==='volume'&&args[1]==='inspect'){const x=db.volumes[args[2]];if(x)output([x]);else {save();process.exitCode=1;}}
else if(args[0]==='volume'&&args[1]==='ls'){output(Object.keys(db.volumes).join('\n'));}
else if(args[0]==='volume'&&args[1]==='rm'){delete db.volumes[args[2]];output(args[2]+'\n');}
else if(args[0]==='create'){
 const name=idx('--name'),job=idx('--label').split('=')[1],id=crypto.createHash('sha256').update(name).digest('hex');
 const spec=idx('--mount').split(','),volume=spec.find(x=>x.startsWith('src=')).slice(4),ro=spec.includes('readonly');
 const command=args.slice(args.indexOf(imageId)+1); const input={Id:id,Name:'/'+name,Image:imageId,
  Config:{User:idx('--user'),Tty:false,OpenStdin:true,Labels:{'io.ud-agent.job':job},Entrypoint:[idx('--entrypoint')],Cmd:command},
  HostConfig:{ReadonlyRootfs:true,NetworkMode:idx('--network'),Privileged:false,CapDrop:['ALL'],CapAdd:null,Devices:null,Binds:null,SecurityOpt:['no-new-privileges'],Memory:Number(idx('--memory')),NanoCpus:Number(idx('--cpus'))*1e9,PidsLimit:Number(idx('--pids-limit')),Tmpfs:{'/tmp':idx('--tmpfs').slice(5)}},
  Mounts:[{Type:'volume',Name:volume,Destination:'/input',RW:corrupt&&ro?true:!ro}]};
 db.containers[id]=input;output(id+'\n');
}
else if(args[0]==='container'&&args[1]==='inspect'){const x=db.containers[args[2]];if(x)output([x]);else{save();process.exitCode=1;}}
else if(args[0]==='container'&&args[1]==='ls'){const filter=idx('--filter').slice(3);output(db.containers[filter]?filter+'\n':'');}
else if(args[0]==='container'&&args[1]==='rm'){delete db.containers[args.at(-1)];output(args.at(-1)+'\n');}
else if(args[0]==='start'){
 const id=args.at(-1),container=db.containers[id];if(!container){save();process.exit(1);}
 let chunks=[];process.stdin.on('data',c=>chunks.push(c));process.stdin.on('end',()=>{
  const input=Buffer.concat(chunks).toString('utf8');
  if(container.Name.endsWith('-loader')){const rows=input.trim().split('\n').map(JSON.parse);const expected=container.Config.Cmd.at(-1);if(rows[0].snapshot_sha256!==expected||rows.at(-1).snapshot_sha256!==expected)process.exit(1);output(JSON.stringify({status:'loaded',snapshot_sha256:expected})+'\n');}
  else {const request=JSON.parse(input);output(JSON.stringify({ok:true,result:{passed:false,scope:{file_paths:request.arguments.file_paths},incidents:[{testid:'fixture'}]}})+'\n');}
 });
}
else {save();process.exitCode=2;}
`;
    const engine = await writeNativeEngine({ root, name: 'docker', program });
    await writeFile(path.join(root, 'a.conllu'), '# sent_id = a\n1\ta\t_\tX\t_\t_\t0\troot\t_\t_\n\n');
    await mkdir(path.join(root, 'state'), { mode: 0o700 });
    await test(root, engine, path.join(root, 'state'), log, image, guard);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

describe('Docker validation lifecycle', () => {
  it('uses an owned loader and a read-only worker and verifies cleanup', async () => fixture(false, async (root, engine, state, log, image, guard) => {
    const original = await readFile(path.join(root, 'a.conllu'));
    const outcome = await runDockerValidation({ engine, engineSha256: digest(await readFile(engine)), guard, guardSha256: digest(await readFile(guard)), image, host: { platform: process.platform, arch: process.arch }, stateRoot: state, workingTree: root, allowedRoots: [root], filePaths: ['a.conllu'], options: { language_code: 'en' } });
    expect(outcome.result).toMatchObject({ passed: false, scope: { file_paths: ['a.conllu'] } });
    expect(await readFile(path.join(root, 'a.conllu'))).toEqual(original);
    const observed = JSON.parse(await readFile(log, 'utf8'));
    expect(Object.keys(observed.containers)).toHaveLength(0); expect(Object.keys(observed.volumes)).toHaveLength(0);
    const creates = observed.calls.filter((args: string[]) => args[0] === 'create');
    expect(creates).toHaveLength(2);
    expect(creates.every((args: string[]) => args.includes('--pull=never') && args.includes('--read-only') && args.includes('none'))).toBe(true);
    expect(creates[0].find((arg: string) => arg.startsWith('type=volume,'))).not.toContain('readonly');
    expect(creates[1].find((arg: string) => arg.startsWith('type=volume,'))).toContain('readonly');
    expect(await (await DockerJobJournal.open(state, guard)).pending()).toEqual([]);
  }), 30_000);

  it('rejects a worker whose mounted input is unexpectedly writable and cleans owned resources', async () => fixture(true, async (root, engine, state, log, image, guard) => {
    await expect(runDockerValidation({ engine, engineSha256: digest(await readFile(engine)), guard, guardSha256: digest(await readFile(guard)), image, host: { platform: process.platform, arch: process.arch }, stateRoot: state, workingTree: root, allowedRoots: [root], filePaths: ['a.conllu'], options: { language_code: 'en' } })).rejects.toThrow('DOCKER_CONTAINER_POLICY_FAILED');
    const observed = JSON.parse(await readFile(log, 'utf8'));
    expect(Object.keys(observed.containers)).toHaveLength(0); expect(Object.keys(observed.volumes)).toHaveLength(0);
    expect(await (await DockerJobJournal.open(state, guard)).pending()).toEqual([]);
  }), 30_000);

  it('recovers only a recorded dead owner and never deletes a volume with a different owner label', async () => fixture(false, async (_root, engine, state, _log, image, guard) => {
    const journal = await DockerJobJournal.open(state, guard);
    const id = '11111111-1111-4111-8111-111111111111';
    const volume = `ud-agent-${id}-input`;
    await journal.create({ version: 1, id, engine, engine_sha256: digest(await readFile(engine)), image_digest: image.digest, image_id: `sha256:${'b'.repeat(64)}`, endpoint: 'unix:///private/tmp/docker-fixture.sock', daemon_id: 'fixture-daemon', owner_pid: 2_147_483_647, phase: 'planned' });
    await journal.transition(id, 'volume_pending');
    execFileSync(engine, ['volume', 'create', '--label', 'io.ud-agent.job=other', volume]);
    await journal.transition(id, 'volume_ready');
    await expect(recoverDockerValidation(state, id, guard)).rejects.toThrow('DOCKER_CLEANUP_OWNERSHIP_MISMATCH');
    expect((await journal.load(id)).phase).toBe('cleanup_pending');
    execFileSync(engine, ['volume', 'rm', volume]);
    execFileSync(engine, ['volume', 'create', '--label', `io.ud-agent.job=${id}`, volume]);
    await recoverDockerValidation(state, id, guard);
    expect((await journal.load(id)).phase).toBe('cleaned');
  }), 30_000);

  it('reconciles a lost volume-create response from observed ownership and keeps an unobservable create pending', async () => fixture(false, async (_root, engine, state, _log, image, guard) => {
    const journal = await DockerJobJournal.open(state, guard);
    const id = '22222222-2222-4222-8222-222222222222', volume = `ud-agent-${id}-input`;
    await journal.create({ version: 1, id, engine, engine_sha256: digest(await readFile(engine)), image_digest: image.digest, image_id: `sha256:${'b'.repeat(64)}`, endpoint: 'unix:///private/tmp/docker-fixture.sock', daemon_id: 'fixture-daemon', owner_pid: 2_147_483_647, phase: 'planned' });
    await journal.transition(id, 'volume_pending');
    await expect(recoverDockerValidation(state, id, guard)).rejects.toThrow('DOCKER_CREATE_OUTCOME_UNKNOWN');
    expect((await journal.load(id)).phase).toBe('volume_pending');
    execFileSync(engine, ['volume', 'create', '--label', `io.ud-agent.job=${id}`, volume]);
    await recoverDockerValidation(state, id, guard);
    expect((await journal.load(id)).phase).toBe('cleaned');
  }), 30000);
});
