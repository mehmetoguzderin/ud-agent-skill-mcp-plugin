#!/usr/bin/env node
/** Read-only upstream-head drift signal. Never changes locks or executes new source. */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function upstreamCanary(lock,{fetcher=fetch}={}){
  assert.equal(lock.schema_version,1);assert.ok(Array.isArray(lock.sources)&&lock.sources.length>0);const seen=new Set(),rows=[];
  for(const source of lock.sources){assert.match(source.repository,/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/);assert.match(source.branch,/^[A-Za-z0-9_.\/-]+$/);assert.ok(!source.branch.split('/').includes('..'));assert.match(source.commit,/^[a-f0-9]{40}$/);assert.ok(!seen.has(source.repository));seen.add(source.repository);
    const url='https://api.github.com/repos/'+source.repository+'/commits/'+source.branch.split('/').map(encodeURIComponent).join('%2F');let response;
    try{response=await fetcher(url,{headers:{Accept:'application/vnd.github+json','User-Agent':'ud-agent-upstream-canary'},redirect:'error',signal:AbortSignal.timeout(20000)});assert.equal(response.status,200,'Upstream observation failed');assert.ok(response.body);const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;assert.ok(size<=2*1024**2,'Upstream response exceeds bound');chunks.push(chunk);}const bytes=Buffer.concat(chunks),value=JSON.parse(bytes);assert.match(value.sha,/^[a-f0-9]{40}$/);rows.push({repository:source.repository,branch:source.branch,frozen_commit:source.commit,observed_commit:value.sha,status:value.sha===source.commit?'unchanged':'drift',observation:{url,status:response.status,sha256:hash(bytes),size_bytes:size}});
    }catch(error){await response?.body?.cancel().catch(()=>{});rows.push({repository:source.repository,branch:source.branch,frozen_commit:source.commit,status:'observation-failed',error:error.message});}
  }
  return{schema_version:1,qualification:'read-only-upstream-drift-not-compatibility-or-release-certification',status:rows.every(row=>row.status==='unchanged')?'unchanged':'review-required',rows,locks_modified:false,upstream_code_executed:false,policy:'Drift requires an explicit reviewed lock update and complete ordinary/protected mutation/provider acceptance of the new source. Observing a head never promotes it or claims compatibility.'};
}
if(import.meta.url===pathToFileURL(process.argv[1]??'').href){assert.equal(process.argv.length,4,'Usage: upstream-canary.mjs LOCK_JSON NEW_REPORT_JSON');const bytes=await readFile(process.argv[2]),report=await upstreamCanary(JSON.parse(bytes));await writeFile(process.argv[3],JSON.stringify({...report,lock_sha256:hash(bytes)},null,2)+'\n',{flag:'wx'});if(report.status!=='unchanged')process.exitCode=1;}
