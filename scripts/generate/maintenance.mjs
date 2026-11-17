#!/usr/bin/env node
/** Freeze maintenance metadata from actual source declarations, without installing tools. */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),check=process.argv.includes('--check');let stale=false;
const bytes=name=>readFileSync(path.join(root,name)),sha=data=>createHash('sha256').update(data).digest('hex');
const receipt=name=>({path:name,sha256:sha(bytes(name)),size_bytes:bytes(name).length});
function output(name,value){const body=JSON.stringify(value,null,2)+'\n';if(check){if(bytes(name).toString()!==body){console.error('Maintenance metadata is stale: '+name);stale=true;}}else writeFileSync(path.join(root,name),body);}
const workflowFiles=readdirSync(path.join(root,'.github/workflows')).filter(name=>/\.ya?ml$/.test(name)).sort(),actions=new Map();
for(const filename of workflowFiles){const relative='.github/workflows/'+filename,workflow=YAML.parse(bytes(relative).toString(),{uniqueKeys:true});for(const [job,definition]of Object.entries(workflow.jobs??{}))for(const [index,step]of (definition.steps??[]).entries())if(step.uses){const match=/^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.\/-]+)@([a-f0-9]{40})$/.exec(step.uses);if(!match)throw new Error('Workflow action is not pinned to an exact source commit: '+step.uses);const key=step.uses,value=actions.get(key)??{repository:match[1],commit:match[2],uses:[]};value.uses.push({workflow:relative,job,step:index});actions.set(key,value);}}
// GitHub reserves workflows/actions.lock for its own dependency lock format.
output('.github/actions-source.lock.json',{schema_version:1,qualification:'direct-action-source-commit-inventory',actions:[...actions.values()].sort((a,b)=>a.repository<b.repository?-1:a.repository>b.repository?1:a.commit<b.commit?-1:1),workflows:workflowFiles.map(name=>receipt('.github/workflows/'+name)),local_actions_emulation:receipt('quality/act.lock.json'),policy:'Workflow steps use exact source commits. Runner image/emulation identities are recorded separately; no cross-build or act result is native provider certification.'});
const packageJson=JSON.parse(bytes('package.json')),python=bytes('pyproject.toml').toString();
output('quality/toolchain.lock.json',{schema_version:1,qualification:'declared-compiler-and-runner-roles-not-execution-evidence',roles:{bundled_node:bytes('.node-version').toString().trim(),npm_supported_node_majors:[24,26],host_original_rust:'1.99.0',release_and_ci_rust:'1.99.1',protected_linux_mutation_rust:'1.99.1',supported_cpython_minor_versions:['3.14','3.15'],python_requires:python.match(/requires-python\s*=\s*"([^"]+)"/)?.[1],javascript:packageJson.devDependencies},inputs:['.node-version','rust-toolchain.toml','package.json','package-lock.json','pyproject.toml','uv.lock','Cargo.lock','runtime/node-distributions.lock.json','runtime/node-compatibility.lock.json','runtime/userspace-inputs.lock.json','quality/act.lock.json'].map(receipt),policy:'Build/test receipts must additionally bind actual executable bytes, versions, target and source. Declared roles never trigger ambient toolchain acquisition or imply a successful run.'});
if(stale)process.exitCode=1;else console.log(check?'Maintenance metadata is current.':'Maintenance metadata frozen from source.');
