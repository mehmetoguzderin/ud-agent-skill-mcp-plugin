import { test, expect } from 'vitest';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { totalBoundaries, rustAssertionEvidence } from '../../scripts/quality/rust-assertions.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';
const root=process.cwd(),read=name=>JSON.parse(readFileSync(path.join(root,name),'utf8'));
const proof=read('tests/mutation/fixtures/rust-total-boundary-proof.json');
const item={file:proof.source,source_sha256:proof.source_sha256,definition_sha256:proof.definition_sha256,definition:proof.definition};
const rawLogs=read('tests/mutation/fixtures/rust-total-boundary-logs.json');
// The standalone review experiment compiled a copy named policy.rs. Production
// scheduling compiles the canonical source path; an arbitrary same-basename file
// must never inherit that source's contract authorization.
const logs=Object.fromEntries(Object.entries(rawLogs).map(([name,value])=>[name,value.replaceAll(`/owned-proof/${name}/policy.rs`,proof.source)]));
function historical(run){
 const registry=read('quality/reviews/retired-rust-total-boundaries.json'),row=registry.boundaries[0];
 const temporary=mkdtempSync(path.join(os.tmpdir(),'ud-historical-boundary-'));
 try{
  const registryPath=path.join(temporary,'quality/rust-total-boundaries.json');mkdirSync(path.dirname(registryPath),{recursive:true});writeFileSync(registryPath,JSON.stringify({schema_version:1,boundaries:registry.boundaries}));
  for(const [name,original]of [[row.source,'tests/mutation/fixtures/retired-windows-metadata-policy.rs'],[row.test_file,row.test_file],[row.review_file,row.review_file],[row.proof_file,row.proof_file]]){const target=path.join(temporary,name);writableFixtureCopy(path.join(root,original),target,temporary);}
  return run(temporary,row);
 }finally{rmSync(temporary,{recursive:true,force:true});}
}

test('historical contract grading accepts only its exact independently reviewed assertion',()=>historical(historicalRoot=>{
 const contracts=totalBoundaries(historicalRoot,item);
 expect(contracts).toHaveLength(1);
 const result=rustAssertionEvidence(logs.caught,contracts);
 expect(result.valid).toBe(true);
 expect(result.total_boundary_observations).toEqual([expect.objectContaining({boundary:'validate_security',definition_sha256:proof.definition_sha256,source_sha256:proof.source_sha256,test_sha256:proof.test_sha256})]);
 expect(rustAssertionEvidence(logs.caught).valid).toBe(false);
 expect(rustAssertionEvidence(rawLogs.caught,contracts).valid).toBe(false);
 expect(rustAssertionEvidence(logs.caught.replaceAll(proof.source,'/foreign/policy.rs'),contracts).valid).toBe(false);
 expect(totalBoundaries(historicalRoot,{...item,definition_sha256:'a'.repeat(64)})).toEqual([]);
}));

test('uncaught panic, wrong boundary, absent record, stale identity and extra runtime failures remain invalid',()=>historical(historicalRoot=>{
 const contracts=totalBoundaries(historicalRoot,item);
 for(const name of ['uncaught','wrong-boundary','missing-record'])expect(rustAssertionEvidence(logs[name],contracts).valid,name).toBe(false);
 for(const changed of [logs.caught.replace(proof.source_sha256,'a'.repeat(64)),logs.caught.replace(proof.definition_sha256,'b'.repeat(64)),logs.caught.replace('1 failed; 0 ignored','2 failed; 0 ignored'),logs.caught.replace('"input_hex":""','"input_hex":"00"'),logs.caught+'\nthread \'other\' panicked at foreign.rs:1:1:\nindex out of bounds\n',logs.caught.replaceAll('boundary_proof::hostile_empty_security_is_total','other_test')])expect(rustAssertionEvidence(changed,contracts).valid).toBe(false);
 expect(rustAssertionEvidence(logs.baseline,contracts).valid).toBe(false);
}));

test('historical source, immutable test, proof and review fingerprints remain mandatory',()=>historical((temporary,row)=>{
  expect(totalBoundaries(temporary,item)).toHaveLength(1);
  for(const name of [row.source,row.test_file,row.review_file,row.proof_file]){const target=path.join(temporary,name),before=readFileSync(target);writeFileSync(target,Buffer.concat([before,Buffer.from('\n')]));expect(()=>totalBoundaries(temporary,item)).toThrow(/fingerprint/);writeFileSync(target,before);}
  const invalid={...item,definition:{...item.definition,replacement:'||'}};expect(()=>totalBoundaries(temporary,invalid)).toThrow(/scheduling/);
}));

test('defensive production bounds have no active panic-classification authorization',()=>{
 expect(read('quality/rust-total-boundaries.json')).toEqual({schema_version:1,boundaries:[]});
 expect(totalBoundaries(root,item)).toEqual([]);
 expect(rustAssertionEvidence(logs.caught,totalBoundaries(root,item)).valid).toBe(false);
});
