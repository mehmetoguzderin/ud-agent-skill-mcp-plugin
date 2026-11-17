/** Native Grok catalog installation and discovery; never launches a model. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { sha256, sourceReceipt } from '../release/candidate.mjs';

const args=process.argv.slice(2);
if (args.length!==4 || args[0]!=='--grok' || args[2]!=='--output') throw new Error('Usage: grok-native-smoke.mjs --grok PINNED_BINARY --output NEW_REPORT');
const root=process.cwd(), binary=path.resolve(args[1]), output=path.resolve(args[3]);
if (existsSync(output)) throw new Error('Host fixture evidence requires a new output path.');
const lock=JSON.parse(readFileSync('quality/host-harnesses.lock.json','utf8')).grok;
assert.equal(sha256(readFileSync(binary)),lock.platforms[`${process.platform}/${process.arch}`]?.executable_sha256,'Host harness binary is not pinned.');
const snapshot=sourceReceipt(root);
mkdirSync(path.dirname(output),{recursive:true});
const temporary=mkdtempSync(path.join(path.dirname(output),'grok-native-'));
const marketplace=path.join(temporary,'marketplace'), profile=path.join(temporary,'profile');
mkdirSync(marketplace); mkdirSync(profile);
for (const relative of ['.grok-plugin','packaging/grok']) cpSync(path.join(root,relative),path.join(marketplace,relative),{recursive:true});
const env={PATH:'/usr/bin:/bin:/usr/sbin:/sbin',HOME:profile,GROK_HOME:path.join(profile,'.grok'),LANG:'en_US.UTF-8'};
const report={schema_version:1,qualification:'native-host-install-fixture',status:'failed',source_tree_sha256:snapshot.sha256,
  host:{os:process.platform,architecture:process.arch},harness:{name:'grok',version:lock.version,sha256:sha256(readFileSync(binary))},
  model_requests:false,remote_publication:false,profile:temporary,commands:[]};
function run(arguments_) {
  const result=spawnSync(binary,arguments_,{cwd:profile,env,encoding:'utf8',timeout:45000,maxBuffer:4*1024*1024});
  report.commands.push({arguments:arguments_,status:result.status,signal:result.signal,stdout:result.stdout,stderr:result.stderr,error:result.error?.message??null});
  assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);
  return result.stdout;
}
try {
  assert.match(run(['--version']),new RegExp(`grok ${lock.version.replaceAll('.','\\.')}`));
  run(['plugin','validate',path.join(marketplace,'packaging/grok/ud-agent-skill-mcp-plugin')]);
  run(['plugin','marketplace','add',marketplace]);
  const available=JSON.parse(run(['plugin','list','--json','--available']));
  assert.equal(available.length,1);assert.equal(available[0].skill_count,6);assert.equal(available[0].has_mcp,true);
  run(['plugin','install','ud-agent-skill-mcp-plugin','--trust']);
  const discovered=JSON.parse(run(['inspect','--json']));
  const plugin=discovered.plugins.find(item=>item.name==='ud-agent-skill-mcp-plugin');
  assert.deepEqual(plugin.provides,{skills:6,agents:0,hooks:false,mcpServers:1});assert.equal(plugin.enabled,true);
  assert.deepEqual(discovered.skills.filter(item=>item.source?.plugin_name===plugin.name).map(item=>item.name).sort(),
    ['ud-compare','ud-edit','ud-investigate','ud-release','ud-rules-docs','ud-validate']);
  const servers=discovered.mcpServers.filter(item=>item.source?.plugin_name===plugin.name);
  assert.equal(servers.length,1);assert.equal(servers[0].name,'ud');assert.equal(servers[0].transport,'stdio');assert.equal(servers[0].target,'npx');
  run(['plugin','update','ud-agent-skill-mcp-plugin']);
  run(['plugin','uninstall','ud-agent-skill-mcp-plugin','--confirm']);
  assert.deepEqual(JSON.parse(run(['plugin','list','--json'])),[]);
  run(['plugin','marketplace','remove','marketplace']);
  assert.equal(sourceReceipt(root).sha256,snapshot.sha256,'Source changed during host acceptance.');
  report.status='passed';
} catch(error) {report.error=String(error);process.exitCode=1;}
writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({status:report.status,qualification:report.qualification,evidence:output}));
