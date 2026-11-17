import{test,expect}from'vitest';
import{mkdirSync,mkdtempSync,rmSync,writeFileSync}from'node:fs';
import path from'node:path';import os from'node:os';
import{mutationBackendContract,mutationBackendFiles}from'../../scripts/release/mutation-backends.mjs';
import{fileReceipt,sourceReceipt}from'../../scripts/release/candidate.mjs';

test('activated graph revisions add their exact registry and review bytes to authoritative generator configuration',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-active-graph-contract-')),backend={tool:'mutmut',version:'3.8.1'};
 const put=(name,text)=>{mkdirSync(path.dirname(path.join(root,name)),{recursive:true});writeFileSync(path.join(root,name),text);};
 try{
  const required=mutationBackendFiles(backend);for(const name of[...required.generators,...required.configuration])put(name,name.endsWith('.py')?'# synthetic generator fixture\n':'{}\n');
  const registry='quality/python-graph-operator-proposals-v2.json',review='quality/reviews/python-graph-operators-root-review-v2.json';put(registry,'{"fixture":"registry"}\n');put(review,'{"fixture":"review"}\n');
  const activation={schema_version:1,format_revision:2,active:true,registry:{path:registry,sha256:fileReceipt(root,registry).sha256},review:{path:review,sha256:fileReceipt(root,review).sha256}};
  const save=value=>put('quality/python-graph-operators.activation.json',JSON.stringify(value));save(activation);
  const configuration=mutationBackendContract(root,sourceReceipt(root),backend).configuration;
  for(const name of[registry,review])expect(configuration.find(item=>item.path===name)).toEqual(fileReceipt(root,name));
  put(review,'{"fixture":"changed"}\n');expect(()=>mutationBackendContract(root,sourceReceipt(root),backend)).toThrow('bytes differ');
  save({...activation,registry:{path:'quality/../../foreign',sha256:'a'.repeat(64)}});expect(()=>mutationBackendContract(root,sourceReceipt(root),backend)).toThrow();
  save({...activation,active:false});expect(mutationBackendContract(root,sourceReceipt(root),backend).configuration.some(item=>item.path===registry)).toBe(false);
 }finally{rmSync(root,{recursive:true,force:true});}
});
