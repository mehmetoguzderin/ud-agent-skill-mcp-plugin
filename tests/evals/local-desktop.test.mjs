/** MIT. Inert native desktop lifecycle contract tests; never starts a GUI or model. */
import { afterEach, describe, expect, it } from 'vitest';
import vm from 'node:vm';
import fs from 'node:fs';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync, existsSync, readlinkSync, unlinkSync } from 'node:fs';
import os from 'node:os';import path from 'node:path';
import { configureDesktopProfile, createDesktopProfileAliases, desktopTranscript, desktopContentIdentity, inspectDesktop, startDesktop } from '../../evals/local/desktop.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';
const roots=[];const temp=(prefix='ud-desktop-')=>{const p=mkdtempSync(path.join(os.tmpdir(),prefix));roots.push(p);return p};
afterEach(()=>roots.splice(0).forEach(p=>rmSync(p,{recursive:true,force:true})));
describe('actual desktop surface mechanics',()=>{
 posixTest('bounds Electron and internal MCP socket paths and retains aliases until process release is verified',()=>{
  const root=temp('u-');const profile=path.join(root,'deep/private/profile'),userData=path.join(profile,'vscode');mkdirSync(userData,{recursive:true});
  const aliases=createDesktopProfileAliases(root,profile,userData);expect(Buffer.byteLength(path.join(aliases.temporaryAlias,'mcp-XXXXXX/mcp.sock'))).toBeLessThanOrEqual(103);expect(readlinkSync(aliases.temporaryAlias)).toBe(path.join(profile,'tmp'));expect(aliases.identities).toHaveLength(2);
  expect(aliases.cleanup(false)).toMatchObject({verified:false,reason:'DESKTOP_PROCESS_RELEASE_UNVERIFIED'});expect(existsSync(aliases.temporaryAlias)).toBe(true);expect(aliases.cleanup(true).verified).toBe(true);expect(existsSync(aliases.temporaryAlias)).toBe(false);expect(existsSync(aliases.userDataAlias)).toBe(false);expect(aliases.cleanup(true).verified).toBe(true);
 });
 posixTest('preserves changed or foreign alias identities instead of deleting them',()=>{
  const root=temp('u-');const profile=path.join(root,'profile'),userData=path.join(profile,'vscode');mkdirSync(userData,{recursive:true});const aliases=createDesktopProfileAliases(root,profile,userData);
  unlinkSync(aliases.temporaryAlias);symlinkSync(userData,aliases.temporaryAlias);expect(aliases.cleanup(true)).toMatchObject({verified:false,reason:'DESKTOP_PROFILE_ALIAS_IDENTITY_CHANGED'});expect(existsSync(aliases.userDataAlias)).toBe(true);expect(readlinkSync(aliases.temporaryAlias)).toBe(userData);
 });
 if(process.platform==='win32') it('Windows refuses native desktop launch before profile preparation or lifecycle callbacks',async()=>{
  const root=temp(),events=[];let callbacks=0;
  await expect(startDesktop({root,harness:{id:'vscode-copilot',status:'mechanically-admitted',driver_available:true},beforeStart:()=>{callbacks++},beforeLaunch:()=>{callbacks++},record:event=>events.push(event)})).rejects.toThrow('DESKTOP_NATIVE_LIFECYCLE_UNVERIFIED:vscode-copilot');
  expect(callbacks).toBe(0);expect(events).toEqual([]);expect(fs.readdirSync(root)).toEqual([]);
 });
 it('configures one loopback model through the installed native customendpoint provider',()=>{
  const profile=temp();const value=configureDesktopProfile({profile,model:'exact/model',endpoint:'http://127.0.0.1:4321',prompt:'Natural request',skillsEnabled:true});
  const groups=JSON.parse(readFileSync(path.join(value.userData,'User/chatLanguageModels.json')));
  expect(groups).toHaveLength(1);expect(groups[0].vendor).toBe('customendpoint');expect(groups[0].models).toHaveLength(1);
  expect(groups[0].models[0]).toMatchObject({id:'exact/model',url:'http://127.0.0.1:4321/v1/chat/completions',contextWindow:16384,maxOutputTokens:512});
  const settings=JSON.parse(readFileSync(path.join(value.userData,'User/settings.json')));expect(settings['chat.agentHost.byokModels.enabled']).toBe(false);expect(settings['chat.defaultToCopilotHarness']).toBe(false);expect(settings['chat.editor.preferCopilotHarness']).toBe(false);expect(settings['chat.byokUtilityModelDefault']).toBe('mainAgent');
  expect(()=>configureDesktopProfile({profile,model:'exact/model',endpoint:'http://127.0.0.1:4321',prompt:'Again',skillsEnabled:true})).toThrow();
 });
 it('rejects remote or credential-bearing endpoint configuration',()=>{
  for(const endpoint of ['https://example.org','http://localhost:1234','http://u:p@127.0.0.1:1234','http://127.0.0.1:1234/api'])expect(()=>configureDesktopProfile({profile:temp(),model:'model',endpoint,prompt:'x',skillsEnabled:false})).toThrow('DESKTOP_PRIVATE_PROVIDER_REQUIRED');
 });
 it('binds all app and extension files, not just the launcher',async()=>{
  const root=temp();mkdirSync(path.join(root,'deep'));writeFileSync(path.join(root,'main'),'same');writeFileSync(path.join(root,'deep/tool'),'before');const before=await desktopContentIdentity(root);
  writeFileSync(path.join(root,'deep/tool'),'after');const after=await desktopContentIdentity(root);expect(before.files).toBe(2);expect(before.sha256).not.toBe(after.sha256);
  symlinkSync('/etc/passwd',path.join(root,'external'));await expect(desktopContentIdentity(root)).rejects.toThrow('DESKTOP_IDENTITY_LINK_ESCAPES_BUNDLE');
 });
 it('cannot certify ChatGPT Desktop from the misnamed Codex bundle',async()=>{
  const root=temp();mkdirSync(path.join(root,'Contents'));writeFileSync(path.join(root,'Contents/Info.plist'),'fixture');
  const runner=async(_cmd,args)=>({stdout:args[1]==='CFBundleIdentifier'?'com.openai.codex':args[1]==='CFBundleExecutable'?'ChatGPT':'1.0'});
  const inspection=await inspectDesktop('chatgpt-desktop',{appPaths:{'chatgpt-desktop':root},runner});expect(inspection.installed).toBe(false);expect(inspection.observed_bundle_id).toBe('com.openai.codex');expect(inspection.status).toBe('interface unsupported');
 });
 it('requires a completed native transcript with exactly one request and no error',()=>{
  const root=temp();expect(desktopTranscript(root).finalAnswer).toBe('');
  writeFileSync(path.join(root,'desktop-result.json'),JSON.stringify({status:'completed'}));writeFileSync(path.join(root,'native-chat.json'),JSON.stringify({requests:[{response:[{value:'Native final.'},{kind:'toolInvocation',value:'not prose'}]}]}));expect(desktopTranscript(root).finalAnswer).toBe('Native final.');
  writeFileSync(path.join(root,'desktop-result.json'),JSON.stringify({status:'completed',response:{errorDetails:{message:'Sign in'}}}));expect(desktopTranscript(root).finalAnswer).toBe('');
  writeFileSync(path.join(root,'desktop-result.json'),JSON.stringify({status:'completed'}));writeFileSync(path.join(root,'native-chat.json'),JSON.stringify({requests:[{response:[{value:'One'}]},{response:[{value:'Two'}]}]}));expect(desktopTranscript(root).finalAnswer).toBe('');
 });
 it('never silently substitutes a CLI for an unavailable UI lifecycle',async()=>{
  await expect(startDesktop({harness:{id:'codex-ide',status:'mechanically-admitted'}})).rejects.toThrow('DESKTOP_NATIVE_LIFECYCLE_UNVERIFIED:codex-ide');
 });
});

async function driveNativeFixture({agent='GitHub.copilot-chat',model='exact/model',requests=1,error}={}){
 const profile=temp();const spec={model:'exact/model',prompt:'Inspect the report.',events:path.join(profile,'events.jsonl'),result:path.join(profile,'result.json'),transcript:path.join(profile,'transcript.json')};
 const configuration=path.join(profile,'driver.json');writeFileSync(configuration,JSON.stringify(spec));const commands=[];
 const vscode={version:'1.146.0',Uri:{file:value=>value},extensions:{getExtension:()=>({id:'GitHub.copilot-chat',packageJSON:{version:'0.74.0'},extensionPath:'/actual/application/copilot',activate:async()=>{}})},lm:{selectChatModels:async()=>[{id:'exact/model',vendor:'customendpoint'}]},commands:{getCommands:async()=>['workbench.action.chat.newLocalChat'],executeCommand:async(command,args)=>{commands.push({command,args});if(command==='workbench.action.chat.export')writeFileSync(spec.transcript,JSON.stringify({requests:Array.from({length:requests},()=>({requestId:'native-request',message:{text:spec.prompt},agent:{id:agent==='GitHub.copilot-chat'?'copilot':'agent-host-copilotcli',extensionId:{value:agent}},modelId:'customendpoint/UD local evaluation/'+model,response:[{value:'Native final.'}],...(error?{result:{errorDetails:{message:error}}}:{})}))}));return error?{errorDetails:{message:error}}:{}}}};
 const exports={};const timer=(callback,delay)=>{const handle=setTimeout(callback,delay);handle.unref();return handle};
 vm.runInNewContext(readFileSync('evals/local/vscode-driver.cjs','utf8'),{exports,require:name=>name==='vscode'?vscode:name==='node:fs'?fs:undefined,process:{env:{UD_EVAL_DESKTOP_DRIVER:configuration}},setTimeout:timer});
 await exports.activate();return{commands,result:JSON.parse(readFileSync(spec.result,'utf8')),events:readFileSync(spec.events,'utf8').trim().split('\n').map(line=>JSON.parse(line))};
}
describe('native local Copilot UI submission',()=>{
 it('creates a fresh local session before exactly one native submission and verifies actual provider/agent',async()=>{
  const result=await driveNativeFixture();expect(result.result.status).toBe('completed');expect(result.commands.map(item=>item.command)).toEqual(['workbench.action.chat.newLocalChat','workbench.action.chat.open','workbench.action.chat.export']);expect(result.commands[1].args.query).toBe('Inspect the report.');expect(result.commands[1].args.blockOnResponse).toBe(true);expect(result.events.find(event=>event.type==='desktop.native_request_observed')).toMatchObject({extension:'GitHub.copilot-chat',model_id:'customendpoint/UD local evaluation/exact/model'});
 });
 it('rejects related agent-host loops, stale conversations and wrong models instead of certifying them',async()=>{
  for(const [fixture,error] of [[{agent:'vscode.agent-host'},'VSCODE_NATIVE_AGENT_SURFACE_MISMATCH'],[{requests:2},'VSCODE_NATIVE_CONVERSATION_NOT_FRESH'],[{model:'foreign/model'},'VSCODE_NATIVE_MODEL_ATTRIBUTION_MISMATCH']]){const result=await driveNativeFixture(fixture);expect(result.result).toMatchObject({status:'failed',error});expect(result.events.some(event=>event.type==='turn.completed')).toBe(false)}
 });
 it('preserves native authentication failures as blockers',async()=>{const result=await driveNativeFixture({error:'Authentication required'});expect(result.result.status).toBe('blocked');expect(result.events.some(event=>event.type==='turn.completed')).toBe(false)});
});
