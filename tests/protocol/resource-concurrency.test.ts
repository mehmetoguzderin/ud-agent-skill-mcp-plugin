/** Real public MCP dispatch/resource IO with a declared fixture worker. */
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { expect, test, vi } from 'vitest';
import { sha256 } from '../../packages/workspace/src/journal.js';
const fixture=vi.hoisted(()=>({stateRoot:''}));
vi.mock('../../packages/runtime-manager/src/userspace.js',async original=>({...await original<typeof import('../../packages/runtime-manager/src/userspace.js')>(),userspaceStateRoot:()=>fixture.stateRoot}));
vi.mock('../../packages/runtime-manager/src/environment.js',async original=>({...await original<typeof import('../../packages/runtime-manager/src/environment.js')>(),checkEnvironment:async()=>({ready:true,runtime:{engine:'docker',executable:'/fixture/docker'}})}));
vi.mock('../../packages/runtime-manager/src/receipt.js',async original=>({...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(),loadNativeGuardReceipt:async()=>({guard:path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard')})}));
vi.mock('../../packages/coordinator/src/provider-runtime.js',()=>({providerInspection:vi.fn(),providerReadiness:vi.fn(),setupProvider:vi.fn(),resolveAdmittedProvider:async()=>({guard:path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard'),image:{digest:'sha256:'+'a'.repeat(64),contextSha256:'sha256:'+'b'.repeat(64)},stateRoot:'/unused-fixture-state',run:async(input:{arguments:Record<string,unknown>})=>({result:{passed:true,incidents:[],scope:{file_paths:['a.conllu'],sentence_only:false},coverage:{content:'completed'},limitations:[],artifacts:[{filename:'observed.txt',mime_type:'text/plain',content:'artifact for '+path.basename(String(input.arguments.working_tree_path)),size_bytes:Buffer.byteLength('artifact for '+path.basename(String(input.arguments.working_tree_path))),sha256:sha256('artifact for '+path.basename(String(input.arguments.working_tree_path)))}]},snapshot:{sha256:'c'.repeat(64),files:[{path:'a.conllu',sha256:'d'.repeat(64),size:5}]}})})}));
import { createServer } from '../../packages/coordinator/src/server.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
import { executeOperation } from '../../packages/coordinator/src/operations.js';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';

test('concurrent public calls and MCP sessions keep shared resource inventory, bytes and grants isolated',async()=>{
 const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-public-resource-concurrency-')));fixture.stateRoot=path.join(root,'state');
 const clients:Client[]=[],servers:ReturnType<typeof createServer>[]=[];
 try{
  for(const name of['alpha','beta']){const workspace=path.join(root,name);await mkdir(workspace);await writeFile(path.join(workspace,'a.conllu'),'input');const server=createServer(process.cwd(),undefined,[workspace]),client=new Client({name:'resource-concurrency-'+name,version:'1'},{versionNegotiation:{mode:'legacy'}});const[clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();servers.push(server);clients.push(client);await server.connect(serverTransport);await client.connect(clientTransport);}
  const rows=await Promise.all([0,1,0,1].map(async index=>{const name=index?'beta':'alpha',response=await clients[index]!.callTool({name:'validation_report',arguments:{working_tree_path:path.join(root,name),file_paths:['a.conllu'],ud_context_path:'',options:{language_code:'en'}}});expect(response.isError,JSON.stringify(response)).not.toBe(true);const envelope=response.structuredContent as {execution:{status:string};result:{artifacts:{uri:string}[];report_resource:{uri:string}}};expect(envelope.execution.status).toBe('completed');const artifact=envelope.result.artifacts[0]!;const read=await clients[index]!.readResource({uri:artifact.uri});expect(read.contents[0]).toMatchObject({text:'artifact for '+name});return{index,artifact,report:envelope.result.report_resource};}));
  expect(new Set(rows.map(row=>row.artifact.uri)).size).toBe(4);expect(new Set(rows.map(row=>row.report.uri)).size).toBe(4);
  for(const row of rows)await expect(clients[1-row.index]!.readResource({uri:row.artifact.uri})).rejects.toThrow('RESOURCE_ACCESS_DENIED');
  // The same sessions remain usable after the concurrent results were read.
  for(const client of clients)expect((await client.listTools()).tools.length).toBe(104);
 }finally{for(const client of clients)await client.close();for(const server of servers)await server.close();await rm(root,{recursive:true,force:true});}
},30000);

test('a report-storage failure is returned as a structured operation rejection and does not escape dispatch',async()=>{
 const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-resource-failure-')));fixture.stateRoot=path.join(root,'state');
 try{const resources=await ResourceStore.open(path.join(root,'resources'),[root],process.platform==='win32'?path.resolve('target/debug/ud-agent-guard.exe'):undefined);const failure=vi.spyOn(resources,'put').mockRejectedValueOnce(new Error('RESOURCE_CACHE_LIMIT_EXCEEDED'));const{domain}=loadContracts(process.cwd()),contract=domain.find(item=>item.name==='validation_report')!;
  const response=await executeOperation(contract,{working_tree_path:root,file_paths:['a.conllu'],ud_context_path:'',options:{language_code:'en'}},domain,{sourceRoot:process.cwd(),userspaceStateRoot:fixture.stateRoot,allowedRoots:[root]},undefined,{resources});expect(response.isError).toBe(true);expect(response.structuredContent).toMatchObject({execution:{status:'rejected'},result:{code:'REQUEST_REJECTED',reason:'RESOURCE_CACHE_LIMIT_EXCEEDED'}});expect(failure).toHaveBeenCalledOnce();failure.mockRestore();
  const retry=await executeOperation(contract,{working_tree_path:root,file_paths:['a.conllu'],ud_context_path:'',options:{language_code:'en'}},domain,{sourceRoot:process.cwd(),userspaceStateRoot:fixture.stateRoot,allowedRoots:[root]},undefined,{resources});expect(retry.isError,JSON.stringify(retry)).not.toBe(true);
 }finally{await rm(root,{recursive:true,force:true});}
});
