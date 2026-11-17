/** Synthetic post-generation transport; never actual discovery or outcomes. */
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sourceReceipt, fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { acceptanceInputHash } from '../../scripts/release/discover-acceptance.mjs';
import { authorityFromGeneration, mutationBackendContract, mutationBackendFiles } from '../../scripts/release/mutation-backends.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { canonicalMutmutGeneration } from '../../scripts/quality/mutation-gate.mjs';

export function pythonGenerationFixture() {
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-python-compact-reconciliation-'));
  const put=(name,value)=>{mkdirSync(path.dirname(path.join(root,name)),{recursive:true});writeFileSync(path.join(root,name),value);return fileReceipt(root,name);};
  const backend={tool:'mutmut',version:'3.8.1'};
  for(const name of Object.values(mutationBackendFiles(backend)).flat())if(!existsSync(path.join(root,name)))put(name,name.endsWith('.json')?'{}':'# Synthetic input identity only\n');
  const file='scripts/example.py',testSource='tests/test_example.py',id='scripts.example.x_allowed__mutmut_1',snapshot='a'.repeat(64);
  put(file,'def allowed(x):\n    return x > 2\n');put(testSource,'# Authored catalog identity only, never executed\n');
  const definition={tool:'mutmut',version:'3.8.1',file,location:{line:1,end_line:2,column:0},original_function:'def allowed(x):\n    return x > 2\n',replacement_function:'def allowed(x):\n    return x >= 2\n',diff:'-    return x > 2\n+    return x >= 2'};
  const reason='For this authored fixture, the independent declared domain admits only integer x values outside the threshold boundary; this is policy transport, not an actual proof of program equivalence.';
  const review={reviewer:'independent-fixture-reviewer',reviews:[{id,equivalent:true,source_sha256:sha256('def allowed(x):\n    return x > 2\n'),definition_sha256:sha256(canonicalJson(definition)),reason,definition}]};
  const reviewReceipt=put('quality/reviews/fixture-equivalent.json',JSON.stringify(review));
  const source=sourceReceipt(root),hashes=Object.fromEntries(source.files.map(row=>[row.path,row.sha256])),input_sha256=acceptanceInputHash(source);
  const minimal={id,file,source_sha256:hashes[file],definition_sha256:sha256(canonicalJson(definition))};
  const raw=put('.artifacts/raw.json',JSON.stringify({qualification:'synthetic-transport-not-actual-control-generation',ids:[id]}));
  const generation={schema_version:1,kind:'mutation-backend-generation',qualification:'complete-backend-generation-no-outcomes',scope_complete:true,input_sha256,backend,...mutationBackendContract(root,source,backend),execution:{command:['synthetic-generator','discover'],runtime:{kind:'oci',image_id:'sha256:'+'b'.repeat(64)}},inventory:[minimal],inventory_sha256:sha256(canonicalJson([minimal])),source_materializations:mutationBackendContract(root,source,backend).sources.map(row=>({source:row.path,source_sha256:row.sha256,mutant_ids:row.path===file?[id]:[],artifacts:[raw]})),raw_artifacts:[raw]};
  const generationReceipt=put('.artifacts/generation.json',JSON.stringify(generation));
  const authorityReceipt=put('.artifacts/authority.json',JSON.stringify(authorityFromGeneration(root,source,input_sha256,generationReceipt)));
  const shard={schema_version:1,inventory_only:true,suite_id:'mutation-python',backend_discovery:authorityReceipt,mutants:[{...minimal,definition}]};
  const shardReceipt=put('.artifacts/shard.json',JSON.stringify(shard));
  const inventoryReceipt=put('quality/acceptance-inventory.json',JSON.stringify({schema_version:1,state:'frozen',discovery:{schedules:[shardReceipt]}}));
  const verified=canonicalMutmutGeneration(root,sourceReceipt(root),inventoryReceipt);
  const item={...minimal,definition_ref:{kind:'mutmut-control-spans-v1',module:file,location:definition.location,generation_repairs:[]}};
  const plan={tool:'mutmut',tool_version:'3.8.1',definition_representation:'mutmut-control-spans-v1',source_tree_sha256:snapshot,scheduled:1,inventory:[item],tests:[{id:'tests/test_example.py::test_allowed',source:testSource,source_sha256:hashes[testSource]}]};
  const metadata={[file]:{exit_code_by_key:{[id]:1}}},report={source_tree_sha256:snapshot,outcomes:[{id,file,exit_code:1,type_check_error:null}]};
  const exception={tool:'mutmut',id,file,source_sha256:hashes[file],definition_sha256:minimal.definition_sha256,author:'fixture-author',reviewed_by:review.reviewer,proof:reason,review:{path:reviewReceipt.path,sha256:reviewReceipt.sha256}};
  return{root,put,file,id,snapshot,definition,minimal,plan,metadata,report,verified,hashes,exception,shard,shardReceipt};
}
