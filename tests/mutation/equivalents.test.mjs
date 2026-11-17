import{test}from'vitest';import assert from'node:assert/strict';import{createHash}from'node:crypto';
import{reviewedEquivalent}from'../../scripts/quality/equivalents.mjs';import{canonicalJson}from'../../scripts/release/http-transports.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
for(const tool of['stryker','mutmut','cargo-mutants','python-static'])test(`${tool} equivalents require exact independently reviewed source, definition and proof bytes`,()=>{
 const file='scripts/example.py',definition={tool,version:'fixture',operator:'comparison',original:'x > 0',replacement:'x >= 1'},reviewPath='quality/reviews/fixture.json';
 const item={tool,id:'review-scope-id',file,source_sha256:sha('source'),definition_sha256:sha(canonicalJson(definition)),author:'mutation-author',reviewed_by:'independent-reviewer',proof:'A precise independently checked proof covers all supported inputs and observable effects.'};
 const entry={id:item.id,equivalent:true,source_sha256:item.source_sha256,definition_sha256:item.definition_sha256,definition,reason:item.proof};
 const bytes=Buffer.from(JSON.stringify({reviewer:item.reviewed_by,reviews:[entry]}));item.review={path:reviewPath,sha256:sha(bytes)};
 const hashes={[file]:item.source_sha256,[reviewPath]:sha(bytes)};
 const options={exceptions:[item],used:new Set(),tool,id:'different-full-scope-id',file,hashes,definition,readReview:()=>bytes};
 assert.equal(reviewedEquivalent(options),true);assert.deepEqual([...options.used],[`${tool}\0${item.id}`]);
 for(const change of[{definition:{...definition,replacement:'x >= 0'}},{hashes:{...hashes,[file]:sha('changed')}},{hashes:{...hashes,[reviewPath]:sha('changed')}},{readReview:()=>Buffer.from('changed')},{exceptions:[{...item,author:item.reviewed_by}]},{exceptions:[{...item,proof:item.proof+' changed'}]},{exceptions:[{...item,review:{...item.review,path:'quality/reviews/../outside'}}]},{definition:undefined}])assert.equal(reviewedEquivalent({...options,...change,used:new Set()}),false);
 for(const changed of[{...entry,equivalent:false},{...entry,definition_sha256:sha('wrong')},{...entry,source_sha256:sha('wrong')},{...entry,reason:'different proof'}]){
  const updated=Buffer.from(JSON.stringify({reviewer:item.reviewed_by,reviews:[changed]})),record={...item,review:{path:reviewPath,sha256:sha(updated)}};
  assert.equal(reviewedEquivalent({...options,exceptions:[record],hashes:{...hashes,[reviewPath]:sha(updated)},readReview:()=>updated,used:new Set()}),false);
 }
});
