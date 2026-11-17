/** Discover review candidates; no site becomes behavior by discovery. */
import {createHash}from'node:crypto';import{createRequire}from'node:module';import{constants,openSync,closeSync,fstatSync,readFileSync,readdirSync,writeFileSync}from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{canonicalJson}from'../release/http-transports.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex'),assertions=new Set(['ok','fail','equal','notEqual','strictEqual','notStrictEqual','deepEqual','notDeepEqual','deepStrictEqual','notDeepStrictEqual','partialDeepStrictEqual','throws','doesNotThrow','rejects','doesNotReject','ifError','match','doesNotMatch']);
function property(node){return!node.computed&&node.property.type==='Identifier'?node.property.name:node.computed&&node.property.type==='StringLiteral'?node.property.value:null;}
function origin(p,seen=new Set()){
 if(p.isIdentifier()){const binding=p.scope.getBinding(p.node.name);if(!binding||seen.has(binding))return null;seen.add(binding);const declaration=binding.path;
  if(declaration.isImportSpecifier()||declaration.isImportDefaultSpecifier()||declaration.isImportNamespaceSpecifier()){
   const source=declaration.parentPath.node.source.value;if(declaration.node.importKind==='type'||declaration.parentPath.node.importKind==='type')return null;const name=declaration.isImportDefaultSpecifier()?'default':declaration.isImportNamespaceSpecifier()?'*':declaration.node.imported.name;
   if(['node:assert','node:assert/strict','assert','assert/strict'].includes(source))return['default','*','strict'].includes(name)?'assert-object':assertions.has(name)?'assert-function':null;
   if(['vitest','chai'].includes(source))return name==='*'?'namespace':name==='expect'?'expect':name==='assert'?'assert-object':['it','test'].includes(name)?'test':null;
  }
  if(declaration.isVariableDeclarator()&&binding.constant)return origin(declaration.get('init'),seen);
 }
 if(p.isMemberExpression()){const object=origin(p.get('object'),seen),name=property(p.node);if(object==='namespace')return name==='expect'?'expect':name==='assert'?'assert-object':['test','it'].includes(name)?'test':null;if(object==='assert-object')return'assert-function';if(object==='chain')return'chain';if(object==='expect')return['soft','poll'].includes(name)?'expect':['fail','unreachable','assertions','hasAssertions'].includes(name)?'assert-function':null;if(object==='test')return'test';}
 if(p.isCallExpression()){const value=origin(p.get('callee'),seen);return value==='expect'?'chain':value==='test'?'test':null;}
 return null;
}
export async function discoverAssertionEvidence(root){
 const require=createRequire(import.meta.url);if(require('@babel/parser/package.json').version!=='8.0.10')throw Error('Assertion review requires the pinned parser.');const{parse}=await import('@babel/parser'),{traverse}=await import('@babel/core'),sources=[],sites=[],issues=[];
 function walk(directory){for(const entry of readdirSync(directory,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const filename=path.join(directory,entry.name),name=path.relative(root,filename).split(path.sep).join('/');if(entry.isSymbolicLink())throw Error('Assertion review source is a symlink: '+name);if(entry.isDirectory()){if(!['__pycache__','node_modules','.cache'].includes(entry.name))walk(filename);continue;}if(!entry.isFile()||!/\.(?:[cm]?[jt]sx?)$/.test(name))continue;
  const fd=openSync(filename,constants.O_RDONLY|constants.O_NOFOLLOW);let bytes;try{const before=fstatSync(fd,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size>16n*1024n**2n)throw Error('Assertion review source is not bounded: '+name);bytes=readFileSync(fd);const after=fstatSync(fd,{bigint:true});if(before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs)throw Error('Assertion review source changed: '+name);}finally{closeSync(fd);}
  const fingerprint=sha(bytes),text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),start=sites.length;sources.push({path:name,sha256:fingerprint,size_bytes:bytes.length});
  try{const ast=parse(text,{sourceType:'unambiguous',plugins:[...(/\.(?:ts|tsx|mts|cts)$/.test(name)?['typescript']:[]),...(/\.(?:tsx|jsx)$/.test(name)?['jsx']:[])]});traverse(ast,{CallExpression(p){const kind=origin(p.get('callee'));if(kind!=='assert-function'&&kind!=='chain')return;const expression=text.slice(p.node.start,p.node.end),callee=p.node.callee;let test_name=null;for(let parent=p.parentPath;parent;parent=parent.parentPath)if(parent.isCallExpression()&&origin(parent.get('callee'))==='test'){const argument=parent.node.arguments[0];if(argument?.type==='StringLiteral'){test_name=argument.value;break;}}
   const site={source:name,source_sha256:fingerprint,line:callee.loc.start.line,column:callee.loc.start.column+1,assertion_sha256:sha(expression)};sites.push({...site,id:sha(canonicalJson(site)),classification:'unclassified',test_name,expression,range:{start:p.node.start,end:p.node.end}});
  }});}catch(error){sites.splice(start);issues.push({source:name,error:error.message});}
 }}walk(path.join(root,'tests'));
 return{schema_version:1,qualification:'syntactic-assertion-review-candidates-not-coverage-or-acceptance',grammar:'static-ESM-imported-Node-Chai-Vitest-assertion-calls-and-constant-aliases-v1',discovery_complete_for_declared_grammar:issues.length===0,dynamic_or_unresolved_assertions:'unclassified-at-runtime-replay',test_sources_sha256:sha(canonicalJson(sources)),sources,sites,issues};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==4||process.argv[2]!=='--output')throw Error('Usage: assertion-evidence-inventory.mjs --output OWNED_OUTPUT');const output=path.resolve(process.argv[3]),root=process.cwd();if(!output.startsWith(root+path.sep))throw Error('Assertion review output must remain in the workspace.');const result=await discoverAssertionEvidence(root);writeFileSync(output,JSON.stringify(result,null,2)+'\n');if(result.issues.length)process.exitCode=1;
}
