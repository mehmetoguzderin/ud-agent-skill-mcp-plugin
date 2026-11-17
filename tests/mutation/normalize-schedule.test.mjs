import{test,expect}from'vitest';
import{existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync}from'node:fs';
import os from'node:os';import path from'node:path';
import{fileReceipt,sha256,sourceReceipt}from'../../scripts/release/candidate.mjs';
import{canonicalJson}from'../../scripts/release/http-transports.mjs';
import{acceptanceInputHash}from'../../scripts/release/discover-acceptance.mjs';
import{mutationBackendContract,mutationBackendFiles}from'../../scripts/release/mutation-backends.mjs';
import{normalizeSchedule,normalizeScheduleFile,normalizeTests,normalizeStrykerAliases,normalizeStrykerOutcomeAliases}from'../../scripts/quality/normalize-schedule.mjs';
const testPython=process.env.UD_AGENT_PYTHON??path.resolve(process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python');

test('maps pytest, Perl discovery files and Stryker IDs to independent runner identities',()=>{
 const catalog={tests:[{id:'catalog-py',runner:'python',source:'tests/domain/test_rules.py',source_sha256:'a'.repeat(64),name:'test_rules.Rules.test_valid',occurrence:0},{id:'catalog-js',runner:'vitest',source:'tests/rules.test.ts',source_sha256:'b'.repeat(64),name:'rules > valid',occurrence:0}]};
 expect(normalizeTests({tests:[{id:'tests/domain/test_rules.py::Rules::test_valid',source:'tests/domain/test_rules.py',source_sha256:'a'.repeat(64)}]},catalog,{tool:'mutmut'})).toEqual([{id:'tests/domain/test_rules.py::Rules::test_valid',source:'tests/domain/test_rules.py',source_sha256:'a'.repeat(64),discovered_id:'catalog-py'}]);
 expect(normalizeTests({tests:{'tests/domain/test_rules.py':'a'.repeat(64)}},catalog,{tool:'ppi-perl'})[0].discovered_id).toBe('catalog-py');
 expect(normalizeTests({tests:[{id:'tests/rules.test.ts#rules > valid',source:'tests/rules.test.ts',status:'Success'}]},catalog,{tool:'stryker'})).toEqual([{id:'tests/rules.test.ts#rules > valid',source:'tests/rules.test.ts',source_sha256:'b'.repeat(64),discovered_id:'catalog-js'}]);
 expect(normalizeTests({tests:[{id:'tests/rules.test.ts#ud-case-immutable-hash',source:'tests/rules.test.ts',name:'rules > valid',occurrence:0}]},catalog,{tool:'stryker'})[0]).toEqual({id:'tests/rules.test.ts#ud-case-immutable-hash',source:'tests/rules.test.ts',source_sha256:'b'.repeat(64),discovered_id:'catalog-js'});
});

test('binds duplicate display names to explicit independently collected occurrences',()=>{
 const source='tests/parameters.test.ts',source_sha256='c'.repeat(64);
 const catalog={tests:[0,1].map(occurrence=>({id:'catalog-'+occurrence,runner:'vitest',source,source_sha256,name:'same display',occurrence}))};
 const tests=[1,0].map(occurrence=>({id:source+'#case-'+occurrence,source,source_sha256,name:'same display',occurrence}));
 expect(normalizeTests({tests},catalog,{tool:'stryker'}).map(item=>item.discovered_id)).toEqual(['catalog-0','catalog-1']);
 for(const occurrence of[-1,0.5,'0'])expect(()=>normalizeTests({tests:[{...tests[0],occurrence}]},catalog,{tool:'stryker'})).toThrow(/occurrence/);
 expect(()=>normalizeTests({tests:[tests[0],{...tests[0],id:source+'#other'}]},catalog,{tool:'stryker'})).toThrow(/duplicate backend test occurrence/);
});

test('binds process-global Stryker aliases bijectively to independent exact definitions',()=>{
 const file='packages/fixture.mjs',source_sha256='d'.repeat(64);
 const rows=['false','true'].map((replacement,index)=>{const definition={tool:'stryker',version:'10.1.1',operator:'BooleanLiteral',original:replacement==='true'?'false':'true',replacement,location:{start:{line:0,column:index*5},end:{line:0,column:index*5+4}}},definition_sha256=sha256(canonicalJson(definition));return{id:file+'#'+[42,99][index],file,source_sha256,definition,definition_sha256};});
 const generation={backend:{tool:'stryker',version:'10.1.1'},inventory:rows.map(item=>({id:file+'#'+item.definition_sha256,file,source_sha256,definition_sha256:item.definition_sha256}))};
 const plan={tool:'stryker',mutants:[...rows].reverse()},result=normalizeStrykerAliases(plan,generation);
 expect(result.plan.mutants.map(item=>item.id).sort()).toEqual(generation.inventory.map(item=>item.id).sort());
 expect(result.aliases.map(item=>item.raw_id).sort()).toEqual([file+'#42',file+'#99']);
 const raw=rows.map(item=>({id:item.id.slice(file.length+1),file,definition_sha256:item.definition_sha256,status:'Survived',killedBy:[]}));
 expect(normalizeStrykerOutcomeAliases(raw,result.aliases).map(item=>item.status)).toEqual(['Survived','Survived']);
 for(const mutants of[[rows[0]],[rows[0],rows[0]],[rows[0],{...rows[1],source_sha256:'e'.repeat(64)}],[rows[0],{...rows[1],definition:{...rows[1].definition,replacement:'changed'}}],[rows[0],{...rows[1],id:rows[0].id}]])expect(()=>normalizeStrykerAliases({...plan,mutants},generation)).toThrow();
 for(const outcomes of[[raw[0]],[raw[0],raw[0]],[raw[0],{...raw[1],definition_sha256:'f'.repeat(64)}],[raw[0],{...raw[1],file:'packages/foreign.mjs'}]])expect(()=>normalizeStrykerOutcomeAliases(outcomes,result.aliases)).toThrow();
});

test('refuses absent, stale, duplicate and ambiguous independently discovered tests',()=>{
 const one={id:'catalog',runner:'python',source:'tests/test_rules.py',source_sha256:'a'.repeat(64),name:'test_rules.Rules.test_valid',occurrence:0},raw={id:'tests/test_rules.py::Rules::test_valid',source:one.source,source_sha256:one.source_sha256};
 for(const[plan,catalog]of[[{tests:[raw,raw]},{tests:[one]}],[{tests:[{...raw,source_sha256:'b'.repeat(64)}]},{tests:[one]}],[{tests:[raw]},{tests:[]}],[{tests:[raw]},{tests:[one,{...one,id:'other'}]}]])expect(()=>normalizeTests(plan,catalog,{tool:'mutmut'})).toThrow();
});

function fixture(){
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-normalized-schedule-'));
 const put=(name,content)=>{const file=path.join(root,name);mkdirSync(path.dirname(file),{recursive:true});writeFileSync(file,content);};
 put('workers/ud/src/ud_agent/fixture.py','VALUE = 1\n');put('tests/mutation/python_static.py','# unit fixture generator\n');put('pyproject.toml','[tool.mutmut]\nsource_paths=[]\n');put('tests/test_fixture.py','class Case:\n    def test_expected(self): pass\n');put('.artifacts/raw/materialization.json','{"fixture":"read-only generated metadata"}\n');
 const required=mutationBackendFiles({tool:'python-static',version:'1.0.0'});for(const name of[...required.generators,...required.configuration])if(!existsSync(path.join(root,name)))put(name,name.endsWith('.py')?'# independent unit generator fixture\n':'{}\n');
 const backend={tool:'python-static',version:'1.0.0'},source=sourceReceipt(root),input=acceptanceInputHash(source),contract=mutationBackendContract(root,source,backend),file=contract.sources.find(item=>item.path==='workers/ud/src/ud_agent/fixture.py');
 const mutants=Array.from({length:18},(_,index)=>{const definition={tool:'python-static',version:'1.0.0',operator:'module_constant_literal',start:8,end:9,original_hex:'31',replacement:String(index+2)};return{id:'fixture-'+String(index).padStart(2,'0'),file:file.path,source_sha256:file.sha256,definition,definition_sha256:sha256(canonicalJson(definition))};});
 const fingerprints=mutants.map(({id,file,source_sha256,definition_sha256})=>({id,file,source_sha256,definition_sha256})),artifact=fileReceipt(root,'.artifacts/raw/materialization.json');
 const generation={schema_version:1,kind:'mutation-backend-generation',qualification:'complete-backend-generation-no-outcomes',scope_complete:true,input_sha256:input,backend,...contract,raw_artifacts:[artifact],inventory:fingerprints,inventory_sha256:sha256(canonicalJson(fingerprints)),execution:{command:['fixture-generator','discover'],runtime:{kind:'oci',image_id:'sha256:'+'a'.repeat(64)}},source_materializations:contract.sources.map(item=>({source:item.path,source_sha256:item.sha256,mutant_ids:fingerprints.filter(row=>row.file===item.path).map(row=>row.id),artifacts:[artifact]}))};
 put('.artifacts/raw/generation.json',JSON.stringify(generation));
 const test=fileReceipt(root,'tests/test_fixture.py'),catalog={schema_version:1,kind:'acceptance-discovery',qualification:'inventory-only-no-outcomes',input_sha256:input,tests:[{id:'catalog-test',source:test.path,source_sha256:test.sha256,runner:'python',name:'test_fixture.Case.test_expected',occurrence:0}]};
 return{root,catalog,generation:fileReceipt(root,'.artifacts/raw/generation.json'),plan:{tool:'python-static',scheduled:mutants.length,inventory:mutants,tests:[{id:'test_fixture.Case.test_expected',source:test.path,source_sha256:test.sha256} ]}};
}

test('emits bounded shards with exact whole-inventory proof and preserves backend IDs',()=>{
 const value=fixture();try{
  const output=path.join(value.root,'.artifacts/normalized');const report=normalizeSchedule(value.root,{...value,suiteId:'mutation-python',output,maxShardBytes:2048});
  expect(report.scheduled).toBe(18);expect(report.shards.length).toBeGreaterThan(1);expect(report.production_inventory_signature_required).toBe(true);
  const ids=[];for(const receipt of report.shards){expect(receipt.size).toBeLessThanOrEqual(2048);const shard=JSON.parse(readFileSync(path.join(value.root,receipt.path),'utf8'));expect(shard.shard.count).toBe(report.shards.length);expect(shard.shard.scheduled).toBe(18);expect(shard.shard.inventory_sha256).toBe(report.inventory_sha256);expect(shard.tests[0]).toEqual(expect.objectContaining({id:'test_fixture.Case.test_expected',discovered_id:'catalog-test'}));expect(shard.mutants.every(item=>!Object.hasOwn(item,'status'))).toBe(true);ids.push(...shard.mutants.map(item=>item.id));}
  expect(ids).toEqual(value.plan.inventory.map(item=>item.id));
 }finally{rmSync(value.root,{recursive:true,force:true});}
});

test('truncation and supplied outcomes cannot become an acceptance inventory',()=>{
 for(const kind of['truncate','outcomes','damaged-artifact']){
  const value=fixture();try{
   if(kind==='truncate'){value.plan.inventory.pop();value.plan.scheduled--;}
   else if(kind==='outcomes')value.plan.outcomes=[{status:'Killed'}];
   else writeFileSync(path.join(value.root,'.artifacts/raw/materialization.json'),'changed');
   const expected={truncate:/truncated.*full generation/,outcomes:/supplied outcomes/,'damaged-artifact':/Artifact receipt mismatch/}[kind];
   expect(()=>normalizeSchedule(value.root,{...value,suiteId:'mutation-python',output:path.join(value.root,'.artifacts/normalized')})).toThrow(expected);
  }finally{rmSync(value.root,{recursive:true,force:true});}
 }
});

test('streamed plans retain the complete canonical inventory without a whole-plan V8 string',async()=>{
 const value=fixture();try{
  const planFile=path.join(value.root,'.artifacts/plan.json');writeFileSync(planFile,JSON.stringify({...value.plan,inventory:[...value.plan.inventory].reverse()}));
  const result=await normalizeScheduleFile(value.root,{...value,planFile,suiteId:'mutation-python',output:path.join(value.root,'.artifacts/streamed'),maxShardBytes:2048,python:testPython});
  expect(result.scheduled).toBe(18);expect(result.shards.length).toBeGreaterThan(1);
  const ids=result.shards.flatMap(item=>JSON.parse(readFileSync(path.join(value.root,item.path),'utf8')).mutants.map(value=>value.id));
  expect(ids).toEqual(value.plan.inventory.map(item=>item.id));expect(result.shards.every(item=>item.size<=2048)).toBe(true);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});

test('malformed generation streams remain incomplete and never emit a ready manifest',async()=>{
 const value=fixture();try{
  const planFile=path.join(value.root,'.artifacts/plan.json'),output=path.join(value.root,'.artifacts/broken');writeFileSync(planFile,'{"inventory": []}');
  await expect(normalizeScheduleFile(value.root,{...value,planFile,suiteId:'mutation-python',output,python:testPython})).rejects.toThrow(/stream failed/);
  expect(readFileSync(path.join(output,'INCOMPLETE'),'utf8')).toContain('not completed');
 }finally{rmSync(value.root,{recursive:true,force:true});}
});
