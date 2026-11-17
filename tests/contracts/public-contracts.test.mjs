import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import Ajv2020 from 'ajv/dist/2020.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { loadSavedSelection } from '../../packages/runtime-manager/src/selection.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
const root=path.resolve(import.meta.dirname,'../..');
const json=async file=>JSON.parse(await readFile(path.join(root,file),'utf8'));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const guard=path.join(root,'target/debug/ud-agent-guard'+(process.platform==='win32'?'.exe':''));

test('public generated schemas compile strictly and reject malformed wire/context/state values',async()=>{
  const ajv=new Ajv2020({strict:true,allErrors:true});
  for(const file of ['common/paths','common/refs','common/ids','common/options','common/provenance','annotation-map','ud-context','worker-wire','local-state','results/common/report','results/common/plan','results/common/edit','results/common/build','results/common/environment']) {
    const schema=await json('contracts/schema/'+file+'.schema.json');
    assert.doesNotThrow(()=>ajv.compile(schema),file);
  }
  const wire=ajv.compile(await json('contracts/schema/worker-wire.schema.json'));
  assert.equal(wire({operation:'validation_report',arguments:{}}),true);
  for(const value of [{operation:'invented',arguments:{}},{operation:'validation_report',arguments:{},extra:true},{type:'chunk',path:'../escape',offset:0,bytes_base64:'YQ=='},{type:'chunk',path:'a',offset:0,bytes_base64:'YR=='},{type:'chunk',path:'a',offset:-1,bytes_base64:'YQ=='}])assert.equal(wire(value),false,JSON.stringify(value));
  assert.equal(wire({type:'chunk',path:'a.conllu',offset:0,bytes_base64:'YQ=='}),true);
  const context=ajv.compile(await json('contracts/schema/ud-context.schema.json'));
  const rules=Object.fromEntries(['data.json','deprels.json','edeprels.json','feats.json','tospace.json','udeprels.json','upos.json'].map(file=>[file,'a'.repeat(64)]));
  const legacy={context_sha256:'b'.repeat(64),rule_dir:'rules',rules};
  assert.equal(context(legacy),true);assert.equal(context({...legacy,schema_version:1}),true);
  const missing=structuredClone(legacy);delete missing.rules['upos.json'];assert.equal(context(missing),false);
  assert.equal(context({...legacy,context_sha256:'not-a-hash'}),false);
  const states=await json('contracts/schema/local-state.schema.json'),fixtures=await json('tests/fixtures/compatibility/state-formats-v1.json');
  for(const fixture of fixtures.cases.filter(row=>row.schema)) {
    const validate=ajv.compile({$defs:states.$defs,$ref:'#/$defs/'+fixture.schema});
    assert.equal(validate(fixture.record),true,fixture.id+' '+JSON.stringify(validate.errors));
    const corrupt=structuredClone(fixture.record);delete corrupt[Object.keys(corrupt)[0]];assert.equal(validate(corrupt),false,fixture.id);
  }
});

test('legacy state fixtures pass their real retained readers and corrupt state is refused',async()=>{
  const base=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-contract-state-')));
  try{
    const fixtures=await json('tests/fixtures/compatibility/state-formats-v1.json');
    const selection=path.join(base,'selection');await mkdir(selection,{mode:0o700});
    const record=fixtures.cases.find(row=>row.id==='saved-selection-v1').record;
    // Initialize private ACLs through the same native store on Windows.
    await JournalStore.open(selection,guard);await writeFile(path.join(selection,'selected.json'),JSON.stringify(record),{mode:0o600});
    assert.equal(await loadSavedSelection(selection,{platform:record.platform,arch:record.arch},guard),'docker');
    await mkdir(path.join(base,'transactions'),{mode:0o700});const store=await JournalStore.open(path.join(base,'transactions'),guard);
    for(const [index,fixture]of fixtures.cases.filter(row=>row.schema==='transaction').entries()){
      const value={...fixture.record,id:hash('fixture-'+index),workspace:base};
      await store.create(value);assert.deepEqual(await store.load(value.id),value);
      const file=path.join(store.root,'transactions',value.id,'journal.json');
      await writeFile(file,JSON.stringify({...value,phase:'invented'}));
      await assert.rejects(store.load(value.id),/Transaction journal is invalid/);
    }
    const resources=await ResourceStore.open(path.join(base,'resources'),[base],guard);
    const reference=await resources.put('reports',Buffer.from('{}'),'application/json');
    assert.equal((await resources.bytes(reference.uri,'reports')).toString(),'{}');
    const foreign=await ResourceStore.open(path.join(base,'resources'),[path.join(base,'different-grant')],guard);
    await assert.rejects(foreign.bytes(reference.uri,'reports'),/RESOURCE_ACCESS_DENIED/);
  }finally{await rm(base,{recursive:true,force:true});}
});

test('public snapshots preserve all application identities and intentionally empty optional prompts',async()=>{
  const domain=await json('contracts/ud-interfaces.json'),environment=await json('contracts/environment.json');
  assert.deepEqual(await json('contracts/snapshots/tools.v1.json'),[...domain,...environment]);
  for(const name of ['resources','prompts'])assert.deepEqual(await json('contracts/snapshots/'+name+'.v1.json'),await json('contracts/'+name+'.yaml'));
  assert.deepEqual((await json('contracts/prompts.yaml')).prompts,[]);
  const provenance=await json('contracts/upstream-provenance.json');assert.equal(provenance.operations.length,102);
  for(const row of provenance.operations){const source=await readFile(path.join(root,row.handler.path));assert.equal(hash(source),row.handler.sha256);assert.ok(source.toString().split('\n')[row.handler.line-1].startsWith('def '+row.name+'('));}
  const inventory=await json('tests/fixtures/compatibility/inventory-v1.json');
  assert.equal(new Set(inventory.files).size,inventory.files.length);
  for(const file of inventory.files)await readFile(path.join(root,'tests/fixtures/compatibility',file));
});

test('read-only modern/legacy protocol and CLI transcripts match the frozen compatibility contract',()=>{
  const result=spawnSync(process.execPath,['scripts/generate/compatibility.mjs','--check'],{cwd:root,encoding:'utf8',timeout:45000,maxBuffer:2*1024**2});
  assert.equal(result.error,undefined,result.stderr);assert.equal(result.status,0,result.stderr);
},50000);
