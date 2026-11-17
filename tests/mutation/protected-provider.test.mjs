import{test,expect}from'vitest';
import{assessProtectedProvider}from'../../scripts/quality/mutation-gate.mjs';

test('requires native executed isolation, exact source and verified complete owned cleanup',()=>{
 const source='a'.repeat(64),proof={status:'passed',source_tree_sha256:source};
 const runner={backend:'typescript',source_tree_sha256:source,image:'sha256:'+'b'.repeat(64),worker:{platform:'linux',architecture:'arm64',emulation:false},container_state:{OOMKilled:false,Running:false,ExitCode:0},execution:{status:0,signal:null,error:null},cleanup:[['container','job'],['container','carrier'],['volume','state'],['volume','input']].map(([kind,name])=>({kind,name,status:'removed-owned'}))};
 const evidence={isolation:proof,execution:proof,backendRunner:{status:'executed-not-reconciled',source_tree_sha256:source}};
 expect(assessProtectedProvider(runner,source,'typescript',evidence)).toEqual([]);
 expect(assessProtectedProvider({...runner,inventory_only:true},source,'typescript',evidence).length).toBeGreaterThan(0);
 for(const marker of[{scope_complete:false},{diagnostic_scope:{}},{qualification:'selected-diagnostic'}]){
  expect(assessProtectedProvider({...runner,...marker},source,'typescript',evidence)).toContain('A selected diagnostic cannot satisfy complete protected mutation acceptance.');
  expect(assessProtectedProvider(runner,source,'typescript',{...evidence,backendRunner:{...evidence.backendRunner,...marker}})).toContain('A selected diagnostic cannot satisfy complete protected mutation acceptance.');
 }
 const threshold={...runner,backend:'rust',container_state:{...runner.container_state,ExitCode:2},execution:{...runner.execution,status:2}};
 expect(assessProtectedProvider(threshold,source,'rust',evidence)).toEqual([]);
 expect(assessProtectedProvider({...threshold,backend:'typescript'},source,'typescript',evidence).length).toBeGreaterThan(0);
 const changes=[{worker:{...runner.worker,emulation:true}},{worker:{...runner.worker,architecture:'x64'}},{container_state:{...runner.container_state,OOMKilled:true}},{container_state:{...runner.container_state,Running:true}},{container_state:{...runner.container_state,ExitCode:137}},{execution:{...runner.execution,status:1}},{source_tree_sha256:'c'.repeat(64)},{cleanup:runner.cleanup.slice(1)},{cleanup:runner.cleanup.map((item,index)=>index?item:{...item,status:'failed-or-absent'})},{cleanup:runner.cleanup.map(()=>runner.cleanup[0])}];
 for(const change of changes)expect(assessProtectedProvider({...runner,...change},source,'typescript',evidence).length).toBeGreaterThan(0);
 for(const changed of[{...evidence,isolation:null},{...evidence,execution:{...proof,source_tree_sha256:'d'.repeat(64)}},{...evidence,backendRunner:{...evidence.backendRunner,status:'runner-error'}}])expect(assessProtectedProvider(runner,source,'typescript',changed).length).toBeGreaterThan(0);
});
