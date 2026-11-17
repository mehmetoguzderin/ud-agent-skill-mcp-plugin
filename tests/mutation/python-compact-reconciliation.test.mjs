import { test, expect } from 'vitest';
import { readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { pythonGenerationFixture } from './python-generation-fixture.mjs';
import { reconcilePythonSchedule } from '../../scripts/quality/mutation-inventory.mjs';
import { assessMutmut, canonicalMutmutDefinition, canonicalMutmutGeneration } from '../../scripts/quality/mutation-gate.mjs';
import { mutationBackendContract, verifiedMutationMaterializations } from '../../scripts/release/mutation-backends.mjs';
import { sourceReceipt } from '../../scripts/release/candidate.mjs';

test('compact schedules reconcile every minimal definition only with genuine complete generation authority',()=>{
 const value=pythonGenerationFixture();
 try{
  expect(reconcilePythonSchedule(value.plan,value.report,value.metadata,value.hashes,value.snapshot,value.verified)).toEqual([]);
  for(const proof of[undefined,{...value.verified}])expect(reconcilePythonSchedule(value.plan,value.report,value.metadata,value.hashes,value.snapshot,proof).length).toBeGreaterThan(0);
  for(const plan of[{...value.plan,inventory:[]},{...value.plan,inventory:[{...value.plan.inventory[0],definition_sha256:'0'.repeat(64)}]},{...value.plan,inventory:[{...value.plan.inventory[0],definition:value.definition}]},{...value.plan,inventory:[...value.plan.inventory,...value.plan.inventory],scheduled:2},{...value.plan,definition_representation:'unknown'}])expect(reconcilePythonSchedule(plan,value.report,value.metadata,value.hashes,value.snapshot,value.verified).length).toBeGreaterThan(0);
  expect(reconcilePythonSchedule(value.plan,value.report,value.metadata,{...value.hashes,[value.file]:'0'.repeat(64)},value.snapshot,value.verified).length).toBeGreaterThan(0);
  for(const report of[{...value.report,outcomes:[]},{...value.report,outcomes:[...value.report.outcomes,...value.report.outcomes]},{...value.report,outcomes:[{...value.report.outcomes[0],exit_code:2}]}])expect(reconcilePythonSchedule(value.plan,report,value.metadata,value.hashes,value.snapshot,value.verified).length).toBeGreaterThan(0);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});

test('a reviewed compact survivor expands only its sealed definition and changed shard bytes cannot authorize equivalence',()=>{
 const value=pythonGenerationFixture();
 try{
  expect(canonicalMutmutDefinition(value.verified,value.id)).toEqual(value.definition);
  const metadata={[value.file]:{exit_code_by_key:{[value.id]:0}}},used=new Set();
  const assess=()=>assessMutmut(metadata,[],[value.file],value.hashes,[value.exception],used,value.plan,name=>readFileSync(path.join(value.root,name)),value.verified);
  expect(assess()).toEqual({total:1,killed:0,equivalent:1,errors:[],proven_zero_sources:[]});
  expect(()=>canonicalMutmutDefinition({...value.verified},value.id)).toThrow(/identity/);
  const changed=value.put(value.shardReceipt.path,JSON.stringify({...value.shard,mutants:[{...value.minimal,definition:{...value.definition,replacement_function:'def allowed(x):\n    return False\n'}}]}));
  expect(assess().errors.join('\n')).toMatch(/equivalent definition replay failed/);
  const inventory=value.put('quality/acceptance-inventory.json',JSON.stringify({schema_version:1,state:'frozen',discovery:{schedules:[changed]}}));
  const rebound=canonicalMutmutGeneration(value.root,sourceReceipt(value.root),inventory);
  expect(()=>canonicalMutmutDefinition(rebound,value.id)).toThrow(/full definition differs/);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});

test('v2 ABI review packets are exactly retained in the generation configuration and wrong paths or bytes fail',()=>{
 const value=pythonGenerationFixture();
 try{
  const packets=[['domain_completion','quality/reviews/python-operator-repairs-domain-review-v1.json'],['root','quality/reviews/python-operator-repairs-root-f11.json']].map(([reviewer,name])=>{const receipt=value.put(name,JSON.stringify({reviewer,qualification:'synthetic-configuration-binding-fixture'}));return{path:name,sha256:receipt.sha256,size_bytes:receipt.size,reviewer};});
  const putWrapper=rows=>value.put('quality/reviews/python-operator-repairs-domain-review.json',JSON.stringify({format_revision:2,reviewer:'source-bound-review-packets',packets:rows}));
  putWrapper(packets);
  const contract=()=>mutationBackendContract(value.root,sourceReceipt(value.root),{tool:'mutmut',version:'3.8.1'});
  expect(contract().configuration.filter(row=>packets.some(packet=>packet.path===row.path)).map(row=>row.path)).toEqual(packets.map(row=>row.path).sort());
  for(const rows of[packets.slice(1),[packets[0],packets[0]],[packets[0],{...packets[1],path:'quality/reviews/unapproved.json'}],[packets[0],{...packets[1],sha256:'0'.repeat(64)}]]){putWrapper(rows);expect(contract).toThrow();}
  expect(verifiedMutationMaterializations(value.verified).inventory).toEqual([value.minimal]);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});
