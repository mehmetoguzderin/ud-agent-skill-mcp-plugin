import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { supervisedCommand, supervisorFrame } from '../../packages/runtime-manager/src/supervised-command.js';

// This is a portable wire fixture only. Native process containment has its own
// real guard tests; this fixture never executes an engine or claims isolation.
const fixtureSource = String.raw`
import{createReadStream,renameSync,writeFileSync}from'node:fs';
const options=Object.fromEntries(process.argv.slice(2).reduce((pairs,value,index,all)=>index%2?pairs:[...pairs,[value,all[index+1]]],[]));
const mode=process.env.UD_SUPERVISOR_FIXTURE, sha=options['--executable-sha256'];
if(mode==='native-rejected'){await new Promise(resolve=>process.stderr.write('discarded-prefix:'+'.'.repeat(10000)+'native executable admission refused',resolve));process.exit(1);}
let pending=Buffer.alloc(0), input=[], ended=false, finishing=false;
function frame(kind,body){const head=Buffer.alloc(5);head[0]=kind;head.writeUInt32BE(body.length,1);return Buffer.concat([head,body]);}
async function end(cancelled=false){
 if(finishing)return;finishing=true;
 const result={schema_version:1,exit_code:mode==='nonzero'?7:0,timed_out:mode==='timeout',cancelled,cleanup_verified:mode!=='unclean',executable_sha256:mode==='wrong-identity'?'0'.repeat(64):sha};
 if(mode==='output-limit')result.error='output_limit';
 const out=frame(1,Buffer.concat(input));const err=frame(2,Buffer.from('independent stderr'));
 if(mode==='oversize'){const invalid=Buffer.alloc(5);invalid[0]=1;invalid.writeUInt32BE(1048577,1);process.stdout.write(invalid);process.exit(0);}
 process.stdout.write(out.subarray(0,3));process.stdout.write(out.subarray(3));process.stdout.write(err);
 if(mode!=='missing')process.stdout.write(frame(3,Buffer.from(JSON.stringify(result))));
 if(mode==='suffix')process.stdout.write(frame(1,Buffer.from('forbidden suffix')));
 await new Promise(resolve=>process.stdout.write(Buffer.alloc(0),resolve));process.exit(0);
}
process.stdin.on('data',chunk=>{pending=Buffer.concat([pending,chunk]);while(pending.length>=5){const kind=pending[0],size=pending.readUInt32BE(1);if(pending.length<5+size)return;const body=pending.subarray(5,5+size);pending=pending.subarray(5+size);if(kind===1)input.push(body);else if(kind===2){ended=true;if(mode==='wait'){writeFileSync(process.env.UD_SUPERVISOR_READY+'.new','input-complete');renameSync(process.env.UD_SUPERVISOR_READY+'.new',process.env.UD_SUPERVISOR_READY);}else void end();}else if(kind===3&&mode!=='wait')void end(true);}});
if(mode==='wait'){const control=createReadStream(null,{fd:3,autoClose:false});control.on('data',()=>void end(true));control.on('end',()=>void end(true));}
process.stdin.on('end',()=>{if(!ended)void end(true);});
await new Promise(()=>{});
`;
const node = await realpath(process.execPath);
const hash = `sha256:${createHash('sha256').update(await readFile(node)).digest('hex')}`;
const limits = { timeoutMs: 2000, maxStdoutBytes: 2 * 1024 * 1024, maxStderrBytes: 1024, maxInputBytes: 2 * 1024 * 1024 };
async function fixture<T>(mode: string, test: (environment: NodeJS.ProcessEnv) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ud-supervisor-protocol-'));
  try { const module = path.join(root, 'fixture.mjs'); await writeFile(module, fixtureSource); return await test({ PATH: process.env.PATH, NODE_OPTIONS: `--import=${pathToFileURL(module).href}`, UD_SUPERVISOR_FIXTURE: mode, UD_SUPERVISOR_READY:path.join(root,'ready') }); }
  finally { await rm(root, { recursive: true, force: true }); }
}
async function* input() { yield Buffer.from([0, 1, 2, 255]); yield Buffer.from('full byte-preserving input'); }
const authority = { guard: node, guardSha256: hash, executableSha256: hash };

describe('native guardian wire contract', () => {
  it('retains raw stdout/stderr and actual child exit status only after verified terminal cleanup', async () => {
    for (const mode of ['normal', 'nonzero']) await fixture(mode, async environment => {
      const result = await supervisedCommand(node, ['-e', 'unexecuted fixture'], input(), authority, limits, environment);
      expect(result.code).toBe(mode === 'normal' ? 0 : 7);
      expect(result.stdout).toEqual(Buffer.concat([Buffer.from([0, 1, 2, 255]), Buffer.from('full byte-preserving input')]));
      expect(result.stderr.toString()).toBe('independent stderr');
    });
  });
  it('rejects missing, malformed, oversized, unclean and mismatched terminal outcomes', async () => {
    for (const mode of ['missing', 'unclean', 'wrong-identity', 'suffix', 'oversize']) await fixture(mode, async environment => {
      await expect(supervisedCommand(node, [], input(), authority, limits, environment)).rejects.toThrow(mode === 'missing' ? 'SUPERVISOR_CLEANUP_UNVERIFIED' : 'SUPERVISOR_RESPONSE_INVALID');
    });
  }, 30_000);
  it('retains bounded native refusal diagnostics without replacing the cleanup error or accepting child output', async () => fixture('native-rejected', async environment => {
    const failure = await supervisedCommand(node, [], input(), authority, limits, environment).then(() => undefined, error => error);
    expect(failure?.message).toBe('SUPERVISOR_CLEANUP_UNVERIFIED');
    expect(failure?.code).toBe('SUPERVISOR_CLEANUP_UNVERIFIED');
    expect(failure?.cause).toBeInstanceOf(Error);
    expect(failure.cause.message).toContain('final 8192 retained; exit 1');
    expect(failure.cause.message).toContain('native executable admission refused');
    expect(failure.cause.message).not.toContain('discarded-prefix');
    expect(failure.cause.message.length).toBeLessThan(8350);
  }));
  it('uses the separate lifetime control stream for cancellation after normal input EOF', async () => fixture('wait', async environment => {
    const controller = new AbortController();
    const outcome=supervisedCommand(node, [], input(), authority, limits, environment, controller.signal).then(value=>({value,error:undefined}),error=>({value:undefined,error}));
    try{const deadline=Date.now()+10000;for(;;){try{expect(await readFile(environment.UD_SUPERVISOR_READY!,'utf8')).toBe('input-complete');break;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;if(Date.now()>deadline)throw new Error('Guardian fixture did not acknowledge complete input');await new Promise(resolve=>setTimeout(resolve,5));}}controller.abort();expect((await outcome).error?.message).toBe('SUPERVISED_COMMAND_CANCELLED');}
    finally{controller.abort();await outcome;}
  }));
  it('keeps timeouts and output-limit failures distinct from engine exit codes', async () => {
    for (const [mode, code] of [['timeout', 'SUPERVISED_COMMAND_TIMEOUT'], ['output-limit', 'SUPERVISED_COMMAND_OUTPUT_LIMIT']]) await fixture(mode!, async environment => {
      await expect(supervisedCommand(node, [], input(), authority, limits, environment)).rejects.toThrow(code);
    });
  });
  it('encodes unambiguous bounded data and control frames and checks authority before spawn', async () => {
    expect(supervisorFrame(1, Buffer.from('A'))).toEqual(Buffer.from([1, 0, 0, 0, 1, 65]));
    expect(supervisorFrame(2)).toEqual(Buffer.from([2, 0, 0, 0, 0])); expect(supervisorFrame(3)).toEqual(Buffer.from([3, 0, 0, 0, 0]));
    expect(() => supervisorFrame(4 as any)).toThrow('SUPERVISOR_INPUT_INVALID'); expect(() => supervisorFrame(2, Buffer.from('invalid'))).toThrow('SUPERVISOR_INPUT_INVALID');
    expect(() => supervisorFrame(1)).toThrow('SUPERVISOR_INPUT_INVALID');
    expect(() => supervisorFrame(1, Buffer.alloc(1048577))).toThrow('SUPERVISOR_INPUT_INVALID');
    await expect(supervisedCommand(node, [], input(), { ...authority, guardSha256: 'unbound' }, limits, {})).rejects.toThrow('SUPERVISOR_AUTHORITY_INVALID');
    const controller = new AbortController(); controller.abort(); await expect(supervisedCommand(node, [], input(), authority, limits, {}, controller.signal)).rejects.toThrow('SUPERVISED_COMMAND_CANCELLED');
  });
});
