/** Parent-side classification of independently verified assertion sites.
 * Classification supplements the original outcome; it never turns an error,
 * survivor or integrity check into proof of domain behavior.
 */
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {constants,openSync,closeSync,readFileSync,fstatSync,lstatSync} from 'node:fs';
import path from 'node:path';
import {canonicalJson} from '../release/http-transports.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex'),HASH=/^[a-f0-9]{64}$/;
const file=value=>typeof value==='string'&&value.startsWith('tests/')&&!/[\\\0:]/.test(value)&&!value.split('/').some(part=>!part||part==='.'||part==='..');
const fields=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.sort().join(',');
const insist=(value,message)=>{if(!value)throw new Error('Assertion obligations: '+message);};

export async function createAssertionObligationClassifier({sourceRoot,sourceInventory,obligations,verifyAssertion}){
  insist(typeof sourceRoot==='string'&&path.isAbsolute(sourceRoot)&&sourceInventory&&typeof sourceInventory==='object'&&!Array.isArray(sourceInventory)&&typeof verifyAssertion==='function','frozen source and independently initialized origin verifier are required');
  insist(fields(obligations,['schema_version','sites'])&&obligations.schema_version===1&&Array.isArray(obligations.sites)&&obligations.sites.length<=100000,'complete versioned site declarations are required');
  const require=createRequire(import.meta.url);insist(require('@babel/parser/package.json').version==='8.0.10','pinned original AST parser is required');
  const {parse}=await import('@babel/parser'),sources=new Map(),sites=new Map();
  function source(name){
    const filename=path.join(sourceRoot,name),fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));let bytes;
    try{const before=fstatSync(fd,{bigint:true}),named=lstatSync(filename,{bigint:true});insist(before.isFile()&&before.nlink===1n&&before.size<=16n*1024n**2n&&!named.isSymbolicLink()&&before.dev===named.dev&&before.ino===named.ino,'site source is not an ordinary immutable member');bytes=readFileSync(fd);const after=fstatSync(fd,{bigint:true});insist(before.size===after.size&&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs&&sha(bytes)===sourceInventory[name],'site source differs from frozen bytes');}finally{closeSync(fd);}
    if(sources.has(name))return sources.get(name);
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),ast=parse(text,{sourceType:'unambiguous',plugins:[...(/\.(?:ts|tsx|mts|cts)$/.test(name)?['typescript']:[]),...(/\.(?:tsx|jsx)$/.test(name)?['jsx']:[])]}),calls=[];
    function visit(node,parent){if(!node||typeof node!=='object')return;if(Array.isArray(node)){for(const item of node)visit(item,parent);return;}if(node.type==='CallExpression'){const positions=[node.callee.loc.start,...(parent?.type==='AwaitExpression'?[parent.loc.start]:[])];calls.push({positions,callee:node.callee.loc,sha256:sha(text.slice(node.start,node.end))});}for(const[key,value]of Object.entries(node))if(!['loc','start','end','extra','comments','tokens'].includes(key))visit(value,node);}
    visit(ast,null);const result={calls,sha256:sha(bytes)};sources.set(name,result);return result;
  }
  for(const row of obligations.sites){
    insist(fields(row,['source','source_sha256','line','column','assertion_sha256','classification','requirement','reason'])&&file(row.source)&&HASH.test(row.source_sha256??'')&&sourceInventory[row.source]===row.source_sha256&&Number.isSafeInteger(row.line)&&row.line>=1&&Number.isSafeInteger(row.column)&&row.column>=1&&HASH.test(row.assertion_sha256??'')&&['behavior','source_integrity'].includes(row.classification)&&typeof row.requirement==='string'&&row.requirement.length>0&&row.requirement.length<=512&&typeof row.reason==='string'&&row.reason.length>0&&row.reason.length<=2048,'site declaration is stale, incomplete or invalid');
    const key=`${row.source}:${row.line}:${row.column}`;insist(!sites.has(key),'duplicate source assertion site');
    const matches=source(row.source).calls.filter(call=>call.positions.some(point=>point.line===row.line&&point.column+1===row.column)&&call.sha256===row.assertion_sha256);insist(matches.length===1,'assertion source range does not identify the exact frozen AST call');
    sites.set(key,Object.freeze({...row,callee:matches[0].callee,positions:matches[0].positions}));
  }
  return function classify(test,error,context){
    const origin=verifyAssertion(test,error,context);if(origin?.valid!==true)return{classification:'invalid_assertion',origin};
    const site=origin.assertion_site;insist(site&&file(site.source)&&sourceInventory[site.source]===site.source_sha256,'verified origin is not in the frozen obligation source inventory');
    const declarations=[...sites.values()].filter(row=>row.source===site.source&&(row.positions.some(point=>point.line===site.line&&point.column+1===site.column)||(row.callee.start.line<site.line||row.callee.start.line===site.line&&row.callee.start.column+1<=site.column)&&(row.callee.end.line>site.line||row.callee.end.line===site.line&&row.callee.end.column+1>site.column)));insist(declarations.length<=1,'assertion obligation has ambiguous AST attribution');const declaration=declarations[0];
    if(!declaration)return{classification:'unclassified',assertion_site:site};
    // Revalidate on every classification, including a previously parsed site.
    source(site.source);
    return{classification:declaration.classification,assertion_site:site,assertion_sha256:declaration.assertion_sha256,requirement:declaration.requirement,reason:declaration.reason};
  };
}

export function summarizeAssertionObligations(classifications){
  insist(Array.isArray(classifications)&&classifications.every(row=>row&&['behavior','source_integrity','unclassified','invalid_assertion'].includes(row.classification)),'unknown classification outcome');
  const counts={behavior:0,source_integrity:0,unclassified:0,invalid_assertion:0};for(const row of classifications)counts[row.classification]++;
  return{counts,independent_behavior_detected:counts.behavior>0&&counts.invalid_assertion===0,qualification:counts.invalid_assertion?'invalid-assertion-evidence':counts.behavior?'declared-behavior-assertion':counts.unclassified?'behavior-not-classified':'source-integrity-only'};
}

/** An independent review authorizes exactly these source-bound declarations.
 * It confers no mutation outcome or exemption and cannot classify a new site.
 */
export function verifyAssertionObligationReview(review,{classifierSha256,obligationsSha256,obligations}){

  insist(fields(review,['schema_version','qualification','author','reviewer','classifier','obligations','sites_sha256'])&&review.schema_version===1&&review.qualification==='independent-assertion-obligation-review'&&review.author==='domain_completion'&&typeof review.reviewer==='string'&&review.reviewer.length>0&&review.reviewer!==review.author,'independent review identity is missing');
  insist(fields(review.classifier,['path','sha256'])&&review.classifier.path==='scripts/quality/assertion-obligations.mjs'&&HASH.test(classifierSha256??'')&&review.classifier.sha256===classifierSha256&&fields(review.obligations,['path','sha256'])&&review.obligations.path==='quality/assertion-obligations.json'&&HASH.test(obligationsSha256??'')&&review.obligations.sha256===obligationsSha256,'reviewed classifier or obligation bytes differ');
  insist(obligations?.schema_version===1&&Array.isArray(obligations.sites)&&review.sites_sha256===sha(canonicalJson(obligations.sites)),'reviewed assertion site inventory is incomplete or changed');
  return true;
}
