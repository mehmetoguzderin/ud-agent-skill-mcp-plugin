/** Pure obligation classification fixtures. Origin verification is a separate
 * mandatory supplied boundary; these synthetic callbacks grant no kill proof.
 */
import {test,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createAssertionObligationClassifier,summarizeAssertionObligations} from '../../scripts/quality/assertion-obligations.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
async function fixture(action){const root=mkdtempSync(path.join(os.tmpdir(),'ud-assertion-obligations-')),source='tests/behavior.test.mjs',text="import assert from 'node:assert/strict';\nfunction check(){\n  assert.equal(hash(bytes), expectedSha);\n  assert.deepEqual(actualHeads, [0, 1, 1]);\n}\n",source_sha256=sha(text);mkdirSync(path.join(root,'tests'));writeFileSync(path.join(root,source),text);
 const declarations=[['assert.equal(hash(bytes), expectedSha)','source_integrity','source-byte-provenance'],['assert.deepEqual(actualHeads, [0, 1, 1])','behavior','independent-dependency-head-map']].map(([expression,classification,requirement])=>{const offset=text.indexOf(expression),lines=text.slice(0,offset).split('\n');return{source,source_sha256,line:lines.length,column:lines.at(-1).length+1,assertion_sha256:sha(expression),classification,requirement,reason:classification==='behavior'?'Independent expected dependency heads.':'Source identity binding.'};});
 const options={sourceRoot:root,sourceInventory:{[source]:source_sha256},obligations:{schema_version:1,sites:declarations},verifyAssertion:(_test,error)=>error.proof};
 const proof=index=>({valid:true,assertion_site:{source,source_sha256,line:declarations[index].line,column:declarations[index].column+7,family:'node-assert'}});
 try{return await action({root,source,text,declarations,options,proof});}finally{rmSync(root,{recursive:true,force:true});}}
test('hash-only failures remain integrity evidence and unknown assertions never become behavior by default',async()=>fixture(async({options,proof})=>{
 const classify=await createAssertionObligationClassifier(options),integrity=classify({}, {proof:proof(0)}),behavior=classify({}, {proof:proof(1)});
 expect(integrity.classification).toBe('source_integrity');expect(behavior.classification).toBe('behavior');
 expect(summarizeAssertionObligations([integrity])).toEqual({counts:{behavior:0,source_integrity:1,unclassified:0,invalid_assertion:0},independent_behavior_detected:false,qualification:'source-integrity-only'});
 expect(summarizeAssertionObligations([integrity,behavior]).independent_behavior_detected).toBe(true);
 const unknown=classify({}, {proof:{...proof(0),assertion_site:{...proof(0).assertion_site,line:99}}});expect(unknown.classification).toBe('unclassified');expect(summarizeAssertionObligations([integrity,unknown]).independent_behavior_detected).toBe(false);
 const invalid=classify({}, {proof:{valid:false,reason:'No native origin'}});expect(invalid.classification).toBe('invalid_assertion');expect(summarizeAssertionObligations([behavior,invalid]).independent_behavior_detected).toBe(false);
}));
test('declarations bind exact frozen AST calls rather than neighboring lines, filenames or case names',async()=>fixture(async({options})=>{
 for(const mutate of [value=>value.sites[0].source_sha256='0'.repeat(64),value=>value.sites[0].assertion_sha256='0'.repeat(64),value=>value.sites[0].line++,value=>value.sites.push(value.sites[0]),value=>value.sites[0].classification='anything',value=>value.sites[0].source='../outside',value=>value.sites[0].reason='']){const obligations=structuredClone(options.obligations);mutate(obligations);await expect(createAssertionObligationClassifier({...options,obligations})).rejects.toThrow(/Assertion obligations/);}
 await expect(createAssertionObligationClassifier({...options,verifyAssertion:null})).rejects.toThrow(/origin verifier/);
 expect(()=>summarizeAssertionObligations([{classification:'Killed'}])).toThrow(/unknown classification/);
}));
test('cached classification rechecks source bytes and refuses replaced symbolic-link source paths',async()=>fixture(async({options,proof,root,source,text})=>{
 const classify=await createAssertionObligationClassifier(options);expect(classify({}, {proof:proof(0)}).classification).toBe('source_integrity');writeFileSync(path.join(root,source),text+'// changed\n');expect(()=>classify({}, {proof:proof(0)})).toThrow(/frozen bytes/);
 rmSync(path.join(root,source));writeFileSync(path.join(root,'outside.mjs'),text);symlinkSync(path.join(root,'outside.mjs'),path.join(root,source));expect(()=>classify({}, {proof:proof(0)})).toThrow();
}));

test('independent review binds the exact classifier, metadata and complete declaration inventory',async()=>fixture(async({options})=>{
 const{verifyAssertionObligationReview}=await import('../../scripts/quality/assertion-obligations.mjs'),{canonicalJson}=await import('../../scripts/release/http-transports.mjs');
 const classifierSha256='a'.repeat(64),obligationsSha256=sha(JSON.stringify(options.obligations)),review={schema_version:1,qualification:'independent-assertion-obligation-review',author:'domain_completion',reviewer:'independent-fixture-reviewer',classifier:{path:'scripts/quality/assertion-obligations.mjs',sha256:classifierSha256},obligations:{path:'quality/assertion-obligations.json',sha256:obligationsSha256},sites_sha256:sha(canonicalJson(options.obligations.sites))},binding={classifierSha256,obligationsSha256,obligations:options.obligations};
 expect(verifyAssertionObligationReview(review,binding)).toBe(true);
 for(const change of [value=>value.reviewer=value.author,value=>value.classifier.sha256='0'.repeat(64),value=>value.classifier.path='other.mjs',value=>value.obligations.sha256='0'.repeat(64),value=>value.sites_sha256='0'.repeat(64),value=>delete value.qualification,value=>value.extra=true]){const changed=structuredClone(review);change(changed);expect(()=>verifyAssertionObligationReview(changed,binding)).toThrow(/Assertion obligations/);}
 const obligations=structuredClone(options.obligations);obligations.sites.pop();expect(()=>verifyAssertionObligationReview(review,{...binding,obligations})).toThrow(/incomplete or changed/);
}));
