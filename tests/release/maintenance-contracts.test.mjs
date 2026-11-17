import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import YAML from 'yaml';
import { upstreamCanary } from '../../scripts/quality/upstream-canary.mjs';
import { releasePlatforms } from '../../scripts/release/host-adapters.mjs';
const root=path.resolve(import.meta.dirname,'../..'),read=name=>readFileSync(path.join(root,name)),json=name=>JSON.parse(read(name));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
test('frozen registry schema validates exact published metadata offline and rejects missing transport',()=>{
  const lock=json('registry/schemas.lock.json');assert.equal(lock.schemas.length,1);const row=lock.schemas[0],bytes=read(row.path);assert.equal(bytes.length,row.size_bytes);assert.equal(hash(bytes),row.sha256);
  const ajv=new Ajv({strict:false,allErrors:true});ajv.addFormat('uri',{type:'string',validate:value=>{try{return new URL(value).href===value&&!/\s/.test(value);}catch{return false;}}});
  const validate=ajv.compile(JSON.parse(bytes)),server=json('registry/server.json');assert.equal(server.$schema,row.url);assert.equal(validate(server),true,JSON.stringify(validate.errors));
  const changed=structuredClone(server);delete changed.packages[0].transport;assert.equal(validate(changed),false);
});
test('provider workflow has five explicit actual native profiles and exact action source commits',()=>{
  const workflow=YAML.parse(read('.github/workflows/runtime-matrix.yml').toString()),matrix=workflow.jobs.provider.strategy.matrix.include;
  assert.deepEqual(matrix.map(row=>row.platform).sort(),['darwin-arm64','linux-arm64','linux-x64','win32-arm64','win32-x64']);
  assert.deepEqual(matrix.map(row=>row.platform).sort(),[...releasePlatforms]);
  assert.deepEqual(Object.keys(json('packages/npm-distribution/platforms.json')).sort(),[...releasePlatforms]);
  assert.ok(workflow.jobs.provider['runs-on'].includes('ud-agent-ephemeral'));assert.equal(workflow.on.pull_request,undefined);
  assert.ok(workflow.jobs.provider.steps.some(step=>step.run?.includes('native-provider-acceptance.mjs')));
  const lock=json('.github/actions-source.lock.json');for(const workflow of lock.workflows){assert.equal(hash(read(workflow.path)),workflow.sha256);}
  for(const row of lock.actions)assert.match(row.commit,/^[a-f0-9]{40}$/);
  assert.equal(YAML.parse(read('quality/policy.yaml').toString()).mutation.detection_percent,100);
  assert.deepEqual(YAML.parse(read('quality/deviations.yaml').toString()).deviations,[]);
});
test('retained requirements bind every acceptance suite to actual implementation and original test bytes without claiming execution',()=>{
  const authority=json('contracts/implementation-requirements.json'),audit=json('contracts/implementation-inventory.json'),required=json('quality/requirements.json');
  assert.equal(audit.qualification,'requirements-implementation-test-linkage-not-execution-or-release-certification');
  assert.deepEqual(audit.requirements.map(row=>row.id),authority.requirements.map(row=>row.id));
  assert.equal(new Set(audit.requirements.map(row=>row.id)).size,audit.requirements.length);
  assert.deepEqual(audit.required_suites,required.required_suites);assert.deepEqual(audit.required_artifacts,required.required_artifacts);
  assert.deepEqual([...new Set(audit.requirements.flatMap(row=>row.required_suites))].sort(),[...audit.required_suite_union].sort());assert.ok(required.required_suites.every(suite=>audit.required_suite_union.includes(suite)));
  for(const evidence of [audit.authority,audit.acceptance_authority,...audit.requirements.flatMap(row=>{
    for(const name of ['authorities','implementation','tests'])assert.ok(row[name].length>0,row.id+' '+name);
    assert.equal(Object.hasOwn(row,'status'),false);
    return [...row.authorities,...row.implementation,...row.tests];
  })]){const bytes=read(evidence.path);assert.equal(hash(bytes),evidence.sha256,evidence.path);assert.equal(bytes.length,evidence.size_bytes,evidence.path);}
  assert.equal(audit.requirements.some(row=>JSON.stringify(row).includes('native-quality-exec')),false);
});
test('upstream drift observes all frozen heads, never mutates locks, and rejects incomplete network evidence',async()=>{
  const lock={schema_version:1,sources:[{repository:'Example/One',branch:'main',commit:'a'.repeat(40)},{repository:'Example/Two',branch:'pages/source',commit:'b'.repeat(40)}]},before=JSON.stringify(lock),requests=[];
  const report=await upstreamCanary(lock,{fetcher:async(url,options)=>{requests.push({url,options});return new Response(JSON.stringify({sha:url.includes('/Two/')?'c'.repeat(40):'a'.repeat(40)}),{status:200});}});
  assert.equal(report.status,'review-required');assert.deepEqual(report.rows.map(row=>row.status),['unchanged','drift']);assert.equal(report.upstream_code_executed,false);assert.equal(report.locks_modified,false);assert.equal(JSON.stringify(lock),before);assert.equal(requests[1].url,'https://api.github.com/repos/Example/Two/commits/pages%2Fsource');assert.ok(requests.every(row=>row.options.redirect==='error'&&row.options.signal));
  const failed=await upstreamCanary(lock,{fetcher:async()=>new Response('no',{status:503})});assert.deepEqual(failed.rows.map(row=>row.status),['observation-failed','observation-failed']);assert.equal(failed.status,'review-required');
  await assert.rejects(upstreamCanary({...lock,sources:[{...lock.sources[0],repository:'../bad'}]}));
});
