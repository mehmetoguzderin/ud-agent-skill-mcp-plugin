/** Original Vitest hooks/metadata calibration; no mutant or model is executed. */
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {posixTest} from '../fixtures/native-scope.mjs';
import {expect,test} from 'vitest';
import {validateSubprocessOpacity} from '../../scripts/quality/stryker-opacity.mjs';
import {prepareNativeAssertionFixture} from '../fixtures/native-assertion-loader.mjs';
import {verifyCompiledSources} from '../../scripts/quality/stryker-assertions.mjs';

posixTest('fixed setup captures collection, whole-file fixtures, test bodies and final aroundAll teardown in actual Vitest metadata',()=>{
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-opacity-hooks-'))),require=createRequire(import.meta.url);
  try{
    mkdirSync(path.join(root,'tests'));mkdirSync(path.join(root,'tmp'));
    symlinkSync(path.dirname(path.dirname(require.resolve('vitest/package.json'))),path.join(root,'node_modules'),'dir');
    writeFileSync(path.join(root,'package.json'),'{"type":"module"}');
    const {setup}=prepareNativeAssertionFixture(root);
    writeFileSync(path.join(root,'reporter.mjs'),`import{writeFileSync}from'node:fs';export default class{onTestRunEnd(modules,errors){writeFileSync(${JSON.stringify(path.join(root,'observations.json'))},JSON.stringify({errors,files:modules.map(module=>({meta:module.task.meta,state:module.task.result.state,ids:module.task.tasks.map(task=>task.id)}))}));}}`);
    writeFileSync(path.join(root,'tests/opaque.test.mjs'),`import{test,expect,beforeAll,afterAll,aroundAll}from'vitest';import{spawnSync}from'node:child_process';const call=()=>spawnSync(process.execPath,['-e','process.exit(0)']);call();beforeAll(()=>{expect(call().status).toBe(0)});afterAll(()=>{expect(call().status).toBe(0)});aroundAll(async(runSuite)=>{await runSuite();expect(call().status).toBe(0)});test('body',()=>{expect(call().status).toBe(0)});`);
    const inventory={'tests/opaque.test.mjs':createHash('sha256').update(readFileSync(path.join(root,'tests/opaque.test.mjs'))).digest('hex')},context={schema_version:1,source_root:root,source_inventory:inventory,kind:'dry-run'};
    writeFileSync(path.join(root,'vitest.config.mjs'),`export default {root:${JSON.stringify(root)},cacheDir:${JSON.stringify(path.join(root,'cache'))},test:{provide:{ud_agent_assertion_context_v1:${JSON.stringify(context)}},include:['tests/opaque.test.mjs'],setupFiles:[${JSON.stringify(setup)}],pool:'threads',maxWorkers:1,reporters:[${JSON.stringify(path.join(root,'reporter.mjs'))}]}};`);
    const result=spawnSync(process.execPath,[path.join(path.dirname(require.resolve('vitest/package.json')),'vitest.mjs'),'run','--config',path.join(root,'vitest.config.mjs'),'--configLoader','runner'],{cwd:root,env:{...process.env,HOME:root,TMPDIR:path.join(root,'tmp'),TMP:path.join(root,'tmp'),TEMP:path.join(root,'tmp')},encoding:'utf8',timeout:20000,maxBuffer:1024**2});
    expect(result.error).toBeUndefined();expect(result.status,result.stdout+'\n'+result.stderr).toBe(0);
    const report=JSON.parse(readFileSync(path.join(root,'observations.json'),'utf8'));expect(report.errors).toEqual([]);expect(report.files).toHaveLength(1);expect(report.files[0].state).toBe('pass');
    const observations=validateSubprocessOpacity(report.files[0].meta.ud_agent_subprocess_opacity_v1);
    expect(observations.records.find(row=>row.scope.kind==='case').scope.id).toBe(report.files[0].ids[0]);
    expect(observations.records.find(row=>row.scope.kind==='file')).toEqual({scope:{kind:'file',path:'tests/opaque.test.mjs'},methods:[{name:'spawnSync',count:3}]});
    expect(observations.records.find(row=>row.scope.kind==='global')).toEqual({scope:{kind:'global'},methods:[{name:'spawnSync',count:1}]});
    const compiled=report.files[0].meta.ud_agent_compiled_sources_v1;
    expect(compiled.child_root).toBe(root);expect(compiled.entries.map(row=>row.source)).toEqual(['tests/opaque.test.mjs']);
    expect(verifyCompiledSources(compiled,compiled,{sourceRoot:root,sourceInventory:inventory})).toBe(true);
  }finally{rmSync(root,{recursive:true,force:true});}
},30000);

if(process.platform==='win32')test('fixed setup refuses missing POSIX immutable authority before collecting or executing application tests',()=>{
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-opacity-refusal-'))),require=createRequire(import.meta.url);
  try{
    mkdirSync(path.join(root,'tests'));mkdirSync(path.join(root,'tmp'));
    symlinkSync(path.dirname(path.dirname(require.resolve('vitest/package.json'))),path.join(root,'node_modules'),'dir');
    writeFileSync(path.join(root,'package.json'),' {"type":"module"}');
    const {setup,runtime}=prepareNativeAssertionFixture(root),receipt=path.join(runtime,'input-receipt.json'),receiptBytes=readFileSync(receipt),marker=path.join(root,'application-ran');
    writeFileSync(path.join(root,'tests/refusal.test.mjs'),`import{test}from'vitest';import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(marker)},'collection executed');test('body',()=>writeFileSync(${JSON.stringify(marker)},'body executed'));`);
    writeFileSync(path.join(root,'vitest.config.mjs'),`export default{root:${JSON.stringify(root)},cacheDir:${JSON.stringify(path.join(root,'cache'))},test:{include:['tests/refusal.test.mjs'],setupFiles:[${JSON.stringify(setup)}],pool:'threads',maxWorkers:1}};`);
    const result=spawnSync(process.execPath,[path.join(path.dirname(require.resolve('vitest/package.json')),'vitest.mjs'),'run','--config',path.join(root,'vitest.config.mjs'),'--configLoader','runner'],{cwd:root,env:{...process.env,HOME:root,TMPDIR:path.join(root,'tmp'),TMP:path.join(root,'tmp'),TEMP:path.join(root,'tmp')},encoding:'utf8',timeout:20000,maxBuffer:1024**2});
    expect(result.error).toBeUndefined();expect(result.status).toBe(1);
    expect(result.stdout+'\n'+result.stderr).toContain('Native assertion loader directory is not immutable authority.');
    expect(existsSync(marker)).toBe(false);expect(readFileSync(receipt)).toEqual(receiptBytes);
  }finally{rmSync(root,{recursive:true,force:true});}
},30000);
