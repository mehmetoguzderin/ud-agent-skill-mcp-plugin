#!/usr/bin/env node
/** Record/check actual read-only protocol and CLI behavior, with private profiles. */
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../release/http-transports.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),check=process.argv.includes('--check');
const hash=value=>createHash('sha256').update(canonicalJson(value)).digest('hex');
const profile=await mkdtemp(path.join(os.tmpdir(),'ud-compatibility-')),files=[];let stale=false;
async function save(name,value){const body=JSON.stringify(value,null,2)+'\n';files.push(name);const destination=path.join(root,'tests/fixtures/compatibility',name);if(check){if(await readFile(destination,'utf8').catch(()=>null)!==body){stale=true;console.error('Compatibility changed: '+name);}}else{await mkdir(path.dirname(destination),{recursive:true});await writeFile(destination,body);}}
try{
  const env={PATH:process.env.PATH??'',HOME:profile,USERPROFILE:profile,LOCALAPPDATA:profile,XDG_DATA_HOME:profile,TMPDIR:profile,TMP:profile,TEMP:profile,...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})};
  for(const era of ['modern','legacy']){
    const client=new Client({name:'ud-compatibility',version:'1'},{versionNegotiation:era==='modern'?{mode:{pin:'2026-07-28'}}:{mode:'legacy'}});
    const transport=new StdioClientTransport({command:process.execPath,args:['--import','tsx',path.join(root,'packages/coordinator/src/entry.ts')],env,stderr:'pipe'});let stderr='';
    try{await client.connect(transport);transport.stderr?.on('data',chunk=>{stderr+=chunk;});const listed=await client.listTools(),resources=await client.listResources(),templates=await client.listResourceTemplates();
      if(listed.tools.length!==104||new Set(listed.tools.map(row=>row.name)).size!==104)throw new Error('Protocol compatibility catalog is incomplete');
      await save('protocol-'+era+'-v1.json',{schema_version:1,era:client.getProtocolEra(),protocol_version:client.getNegotiatedProtocolVersion(),server:client.getServerVersion(),capabilities:client.getServerCapabilities(),tools:listed.tools.map(row=>({name:row.name,input_sha256:hash(row.inputSchema),output_sha256:hash(row.outputSchema),annotations:row.annotations})),resources,resource_templates:templates,prompts:'intentionally-not-advertised',protocol_stderr:stderr});
    }finally{await client.close();}
  }
  const cli=[];
  for(const args of [['--version'],['--help'],['unknown-command']]){const result=spawnSync(process.execPath,['--import','tsx',path.join(root,'packages/coordinator/src/entry.ts'),...args],{cwd:root,env,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});if(result.error||result.signal)throw new Error('CLI compatibility execution failed');cli.push({arguments:args,status:result.status,stdout:result.stdout,stderr:result.stderr});}
  await save('cli-v1.json',{schema_version:1,cases:cli});
  await save('inventory-v1.json',{schema_version:1,scope:'catalog,actual protocol initialization/discovery,successful and rejected CLI behavior,state formats',protocol_revisions:['2026-07-28','2025-11-25'],files:['104-tools-v1.json',...files,'state-formats-v1.json'],required_tests:['tests/contracts/catalog-compatibility.test.ts','tests/contracts/public-contracts.test.mjs','tests/protocol/stdio.test.ts','tests/runtime/selection-state.test.ts','tests/runtime/transactions.test.ts','tests/runtime/runtime-lock.test.ts'],qualification:'compatibility-fixtures-not-native-or-release-certification'});
}finally{await rm(profile,{recursive:true,force:true});}
if(stale)process.exitCode=1;else console.log(check?'Read-only protocol/CLI compatibility is unchanged.':'Protocol/CLI compatibility fixtures captured.');
