/** Public acceptance support for the two product-owned userspace routes. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const LEASE=/^\.lease-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

export function userspaceAcceptanceProfile(platform,arch,installer,searchPath){
  assert.ok(['darwin','linux','win32'].includes(platform)&&['arm64','x64'].includes(arch),'Unsupported userspace acceptance target');
  assert.ok(['uv','venv'].includes(installer),'Explicit userspace acceptance installer must be uv or venv');
  const api=platform==='win32'?path.win32:path.posix,delimiter=platform==='win32'?';':':';
  assert.ok(typeof searchPath==='string'&&searchPath.length>0&&searchPath.split(delimiter).every(item=>item&&api.isAbsolute(item)&&!/[\0\r\n]/.test(item)),'An absolute isolated userspace search path is required');
  return{target:platform+'-'+arch,engine:'userspace',worker:platform+'/'+arch,installer,searchPath};
}

/** Git is an explicit read-only host prerequisite, never an ambient installer. */
export async function userspaceGitEvidence(searchPath){
  for(const directory of searchPath.split(path.delimiter)){
    const selected=path.join(directory,process.platform==='win32'?'git.exe':'git');let executable;
    try{executable=await realpath(selected);}catch(error){if(error.code==='ENOENT')continue;throw error;}
    const file=await open(executable,constants.O_RDONLY|(constants.O_NOFOLLOW??0));let before,hash;
    try{before=await file.stat({bigint:true});assert.ok(before.isFile()&&before.size>0n&&before.size<=256n*1024n**2n,'Host Git must be an ordinary bounded executable');
      if(process.platform!=='win32')assert.ok((before.mode&0o022n)===0n&&(before.mode&0o111n)!==0n&&(before.uid===0n||before.uid===BigInt(process.getuid())),'Host Git permissions or owner are unsafe');
      const digest=createHash('sha256'),buffer=Buffer.alloc(1024*1024);let offset=0;
      for(;;){const read=await file.read(buffer,0,buffer.length,offset);if(!read.bytesRead)break;offset+=read.bytesRead;assert.ok(BigInt(offset)<=before.size);digest.update(buffer.subarray(0,read.bytesRead));}
      const after=await file.stat({bigint:true});assert.equal(BigInt(offset),before.size);for(const key of['dev','ino','size','mtimeNs','ctimeNs'])assert.equal(after[key],before[key],'Host Git changed while inspected');hash=digest.digest('hex');
    }finally{await file.close();}
    const result=spawnSync(executable,['--version'],{env:{PATH:path.dirname(executable),LANG:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:process.platform==='win32'?'NUL':'/dev/null',GIT_TERMINAL_PROMPT:'0',...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})},encoding:'utf8',timeout:10000,maxBuffer:65536});
    assert.equal(result.error,undefined,result.stderr);assert.equal(result.status,0,result.stderr);assert.match(result.stdout.trim(),/^git version [0-9]+\.[0-9]+\.[0-9]+[^\r\n]*$/);
    const final=await lstat(executable,{bigint:true});for(const key of['dev','ino','size','mtimeNs','ctimeNs'])assert.equal(final[key],before[key],'Host Git changed during its version probe');
    assert.equal(await realpath(selected),executable,'Host Git selection changed');
    return{kind:'explicit-host-git-read-only-prerequisite',selected_path:selected,executable,sha256:hash,size_bytes:Number(before.size),version:result.stdout.trim(),identity:{device:String(before.dev),inode:String(before.ino)}};
  }
  throw new Error('GIT_SNAPSHOT_PREREQUISITE_MISSING: add an explicitly selected Git executable to the isolated acceptance search path; no installation is performed.');
}

export async function userspaceInstallerEvidence(state,installer,manifest,expectedPython){
  assert.ok(['uv','venv'].includes(installer));assert.match(manifest??'',/^sha256:[a-f0-9]{64}$/);
  assert.ok(expectedPython===undefined||['3.14','3.15'].includes(expectedPython),'Expected userspace Python must be 3.14 or 3.15');
  const name='current-'+manifest.slice(7)+'.json',file=path.join(state,name),info=await lstat(file);
  assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=65536,'Userspace installer marker is not an ordinary bounded file');
  const bytes=await readFile(file),value=JSON.parse(bytes.toString('utf8'));
  assert.equal(value.schema_version,1);assert.equal(value.manifest,manifest);assert.equal(value.installer,installer,'Actual setup took another installer branch');
  assert.match(value.environment??'',/^env-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.match(value.fingerprint??'',/^sha256:[a-f0-9]{64}$/);
  assert.match(value.python_version??'',/^3\.(?:14|15)\.[0-9]+$/);
  if(expectedPython!==undefined)assert.ok(value.python_version.startsWith(expectedPython+'.'),'Actual userspace Python differs from the requested acceptance profile');
  return{path:name,sha256:sha(bytes),installer:value.installer,environment:value.environment,fingerprint:value.fingerprint,python_version:value.python_version};
}

export function requireUserspaceProjectRejection(response){
  assert.equal(response.isError,true);assert.equal(response.structuredContent?.execution?.status,'incomplete');
  const result=response.structuredContent.result;
  assert.equal(result.code,'ENVIRONMENT_NOT_READY');assert.equal(result.environment?.status,'blocked_by_policy');
  assert.deepEqual(result.environment.unsupported_operations,['project_consistency_report']);
  assert.equal(result.environment.runtime?.engine,'userspace');assert.equal(result.environment.runtime?.project_code_allowed,false);
  assert.equal(response.structuredContent.provenance?.worker,undefined);
  return{status:'capability-rejection-verified',execution:response.structuredContent.execution,reason:result};
}

export function operationMatrixSummary(rows,operations,formats,engine){
  const expected=new Set(formats.flatMap(format=>operations.map(operation=>format+'\0'+operation))),seen=new Set();let completed=0,rejections=0;
  let valid=expected.size===formats.length*operations.length;
  for(const row of rows){const key=row.format+'\0'+row.operation;if(!expected.has(key)||seen.has(key))valid=false;seen.add(key);
    if(engine==='userspace'&&row.operation==='project_consistency_report'){if(row.status!=='capability-rejection-verified')valid=false;else rejections++;}
    else if(row.status==='passed')completed++;else valid=false;
  }
  valid&&=seen.size===expected.size&&rows.length===expected.size;
  return{complete:valid,completed_operations:completed,capability_rejections:rejections,scheduled:expected.size};
}

/** Kernel lock contention proves an actual live product lease; a PID file does not. */
export async function activeUserspaceLeases(state,guard){
  let names;try{names=await readdir(state);}catch(error){if(error.code==='ENOENT')return new Map();throw error;}
  assert.ok(names.length<=10000,'Userspace lease inventory exceeds its bound');
  const environment={PATH:process.platform==='win32'?(process.env.SystemRoot??'C:\\Windows')+'\\System32':'/usr/bin:/bin',LANG:'C',...(process.platform==='win32'?{SystemRoot:process.env.SystemRoot??'C:\\Windows'}:{})};
  const invoke=args=>spawnSync(guard,args,{input:'',encoding:'utf8',timeout:30000,maxBuffer:65536,env:environment});
  const identified=invoke(['identity','--root',state]);assert.equal(identified.error,undefined,identified.stderr);assert.equal(identified.status,0,identified.stderr);
  const identity=JSON.parse(identified.stdout);assert.match(identity.device,/^\d+$/);assert.match(identity.inode,/^\d+$/);
  const leases=new Map();
  for(const name of names.filter(name=>LEASE.test(name))){const file=path.join(state,name);let info,bytes;try{info=await lstat(file);assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=4096,'Userspace lease is not an ordinary bounded file');bytes=await readFile(file);}catch(error){if(error.code==='ENOENT')continue;throw error;}
    const value=JSON.parse(bytes.toString('utf8'));assert.equal(value.schema_version,1);assert.ok(Number.isSafeInteger(value.pid)&&value.pid>0);assert.equal(value.kernel_lock,name+'.native');
    const probe=invoke(['state-lock-existing','--root',state,'--path',value.kernel_lock,'--root-device',identity.device,'--root-inode',identity.inode]);assert.equal(probe.error,undefined,probe.stderr);assert.equal(probe.signal,null);
    if(probe.status===0)continue;
    const records=probe.stderr.split('\n').filter(line=>line.startsWith('ud-agent-guard-error: '));assert.equal(records.length,1,probe.stderr);const reason=JSON.parse(records[0].slice('ud-agent-guard-error: '.length));
    if(reason.kind==='NotFound')continue;
    assert.ok(reason.kind==='WouldBlock'||[11,35,32,33].includes(reason.os_code),'Native userspace lease inspection failed: '+probe.stderr);
    leases.set(name,{path:file,record:value,sha256:sha(bytes),kernel_lock_verified:true,root_identity:identity});
  }
  return leases;
}
