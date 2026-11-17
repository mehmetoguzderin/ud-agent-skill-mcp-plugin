import{test,expect}from'vitest';
import{createHash}from'node:crypto';
import{canonicalJson}from'../../scripts/release/http-transports.mjs';
import{reconcileStrykerGeneration}from'../../scripts/quality/prove-stryker-generation.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const source={sha256:'a'.repeat(64)},files=[{path:'packages/value.mjs',sha256:'b'.repeat(64)},{path:'packages/types.d.ts',sha256:'c'.repeat(64)}],definition={tool:'stryker',version:'10.1.1',operator:'BooleanLiteral',replacement:'false'},digest=sha(canonicalJson(definition));
 const mutant={id:files[0].path+'#'+digest,raw_id:files[0].path+'#9',file:files[0].path,source_sha256:files[0].sha256,definition,definition_sha256:digest};
 const rows=[(({id,raw_id,source_sha256,definition_sha256})=>({id,raw_id,source_sha256,definition_sha256}))(mutant)];
 return{source,contract:{sources:files},raw:{qualification:'complete-operator-discovery-no-outcomes',inventory_only:true,tool:'stryker',tool_version:'10.1.1',source_tree_sha256:source.sha256,options:{excludedMutations:[],ignorers:[]},source_scope:files.map(({path,sha256})=>({path,source_sha256:sha256})),scheduled:1,mutants:[mutant],materialization:files.map((file,index)=>({path:file.path,source_sha256:file.sha256,generated:index?0:1,inventory_sha256:sha(canonicalJson(index?[]:rows))}))}};
}
test('complete actual generation retains aliases and explicit zero-mutant source proofs',()=>{
 const {source,contract,raw}=fixture();expect(reconcileStrykerGeneration(raw,source,contract)).toEqual(raw.mutants.map(({id,file,source_sha256,definition_sha256})=>({id,file,source_sha256,definition_sha256})));
});
test('generation proof rejects omissions, duplicate aliases, forged definitions and filtered operators',()=>{
 const {source,contract,raw}=fixture();
 const changes=[{source_scope:raw.source_scope.slice(0,1)},{mutants:[]},{materialization:raw.materialization.slice(0,1)},{options:{excludedMutations:['BooleanLiteral'],ignorers:[]}},{mutants:[{...raw.mutants[0],definition:{...raw.mutants[0].definition,replacement:'true'}}]},{scheduled:2,mutants:[raw.mutants[0],raw.mutants[0]]},{materialization:raw.materialization.map(item=>({...item,generated:0}))}];
 for(const changed of changes)expect(()=>reconcileStrykerGeneration({...raw,...changed},source,contract)).toThrow();
 const second={...raw.mutants[0],file:contract.sources[1].path,source_sha256:contract.sources[1].sha256};second.id=second.file+'#'+second.definition_sha256;second.raw_id=second.file+'#9';
 const duplicate={...raw,scheduled:2,mutants:[raw.mutants[0],second]};duplicate.materialization=raw.materialization.map(item=>{const rows=duplicate.mutants.filter(row=>row.file===item.path).map(({id,raw_id,source_sha256,definition_sha256})=>({id,raw_id,source_sha256,definition_sha256}));return{...item,generated:rows.length,inventory_sha256:sha(canonicalJson(rows))};});
 expect(()=>reconcileStrykerGeneration(duplicate,source,contract)).toThrow('unique raw alias');
});
