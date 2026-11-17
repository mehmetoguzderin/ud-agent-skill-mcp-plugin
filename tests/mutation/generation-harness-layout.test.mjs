import {test,expect} from 'vitest';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileReceipt} from '../../scripts/release/candidate.mjs';
import {verifyGenerationHarness} from '../../scripts/quality/prove-generation.mjs';

// Original harness bytes are inspected as data; no Python or generated program
// is imported or executed, and these temporary roots claim no SDK authority.
function fixture(){
 const directory=mkdtempSync(path.join(os.tmpdir(),'ud-generation-harness-layout-')),root=path.join(directory,'source'),state=path.join(directory,'state');
 const put=(base,name,bytes)=>{const filename=path.join(base,name);mkdirSync(path.dirname(filename),{recursive:true});writeFileSync(filename,bytes);};
 const records=[['pytest_evidence.py','tests/mutation/pytest_evidence.py'],['secondary-child.py','scripts/quality/secondary-child.py']].map(([name,source])=>{
  const bytes=readFileSync(path.resolve(import.meta.dirname,'../..',source));
  put(root,source,bytes);put(state,'verified-harness/'+name,bytes);
  return {path:name,sha256:fileReceipt(root,source).sha256};
 });
 return {directory,root,state,records,put};
}

test('generation metadata joins the fixed pytest harness only to its actual test source and retains ordinary quality helpers',()=>{
 const value=fixture();try{
  expect(existsSync(path.join(value.root,'scripts/quality/pytest_evidence.py'))).toBe(false);
  expect(()=>verifyGenerationHarness(value.root,value.state,value.records)).not.toThrow();
 }finally{rmSync(value.directory,{recursive:true,force:true});}
});

test('generation harness verification rejects altered source, retained bytes and receipt identities',()=>{
 for(const target of ['source-pytest','source-quality','state-pytest','state-quality','receipt']){
  const value=fixture();try{
   if(target==='source-pytest')value.put(value.root,'tests/mutation/pytest_evidence.py','# altered original\n');
   if(target==='source-quality')value.put(value.root,'scripts/quality/secondary-child.py','# altered original\n');
   if(target==='state-pytest')value.put(value.state,'verified-harness/pytest_evidence.py','# altered retained bytes\n');
   if(target==='state-quality')value.put(value.state,'verified-harness/secondary-child.py','# altered retained bytes\n');
   if(target==='receipt')value.records[0].sha256='0'.repeat(64);
   expect(()=>verifyGenerationHarness(value.root,value.state,value.records)).toThrow('actual image harness differs from its frozen source');
  }finally{rmSync(value.directory,{recursive:true,force:true});}
 }
});

test('a phantom quality alias cannot replace missing pytest source and escaping or missing harness members refuse',()=>{
 for(const target of ['wrong-source-layout','missing-state','escaping']){
  const value=fixture();try{
   if(target==='wrong-source-layout'){
    value.put(value.root,'scripts/quality/pytest_evidence.py',readFileSync(path.join(value.root,'tests/mutation/pytest_evidence.py')));
    rmSync(path.join(value.root,'tests/mutation/pytest_evidence.py'));
   }
   if(target==='missing-state')rmSync(path.join(value.state,'verified-harness/pytest_evidence.py'));
   if(target==='escaping')value.records[0].path='../pytest_evidence.py';
   expect(()=>verifyGenerationHarness(value.root,value.state,value.records)).toThrow(target==='escaping'?'Unsafe relative artifact path.':/ENOENT/);
  }finally{rmSync(value.directory,{recursive:true,force:true});}
 }
});
