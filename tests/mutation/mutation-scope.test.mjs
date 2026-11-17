import { test, expect } from 'vitest';
import { assertProtectedMutationSources, diagnosticStrykerScope, localDockerAuthority } from '../../scripts/quality/mutation-scope.mjs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('both explicit Rust workspaces admit only closed production source subsets', () => {
  const files=['packages/launcher/src/fs_guard.rs','scripts/quality/rust-assertion-parser/src/main.rs','scripts/quality/rust-assertion-parser/src/cfg_regions.rs'];
  expect(()=>assertProtectedMutationSources('rust',files,files.map(path=>({path})))).not.toThrow();
  for (const path of ['packages/other/src/main.rs','scripts/quality/other/src/main.rs','scripts/quality/rust-assertion-parser/tests/protocol.rs','Cargo.toml']) {
    expect(()=>assertProtectedMutationSources('rust',[path],[{path}])).toThrow(/declared workspace/);
  }
  expect(()=>assertProtectedMutationSources('rust',[files[1]],[])).toThrow(/snapshot/);
});

test('source-transfer admission honors actual Docker precedence and permits only local transports', () => {
  const contexts = [];
  const inspect = name => { contexts.push(name); return 'unix:///private/tmp/owned-docker.sock'; };
  expect(localDockerAuthority({}, inspect)).toEqual({ transport: 'unix', endpoint: 'unix:///private/tmp/owned-docker.sock', selection: 'current-context' });
  expect(contexts).toEqual([undefined]);
  contexts.length = 0;
  expect(localDockerAuthority({ DOCKER_CONTEXT: 'desktop-linux', DOCKER_HOST: 'ssh://remote' }, inspect).selection).toBe('explicit-context');
  expect(contexts).toEqual(['desktop-linux']);
  contexts.length = 0;
  expect(localDockerAuthority({ DOCKER_HOST: 'npipe:////./pipe/docker_engine' }, inspect).transport).toBe('npipe');
  expect(contexts).toEqual([]);
  for (const endpoint of ['ssh://remote', 'tcp://127.0.0.1:2375', 'tcp://remote:2376', 'http://remote', 'npipe:////remote/pipe/docker', 'unix://relative', 'unix:///tmp/../socket', 'unix:///tmp//socket', 'unix:///tmp/socket?host=remote', 'unix:///tmp/%2e%2e/socket', 'unix:///tmp/socket\n', null, {}]) expect(() => localDockerAuthority({}, () => endpoint)).toThrow(/endpoint|local/);
  for (const context of ['--host=ssh://remote', '../remote', 1]) expect(() => localDockerAuthority({ DOCKER_CONTEXT: context }, inspect)).toThrow(/context/);
});

test('Python scopes and canonical path confinement remain explicit', () => {
  for(const path of ['workers/ud/src/ud_agent/wire.py','scripts/quality/rust-literal.py'])expect(()=>assertProtectedMutationSources('python',[path],[{path}])).not.toThrow();
  for(const path of ['../scripts/quality/a.py','/scripts/quality/a.py','scripts//a.py','scripts/./a.py','scripts/../a.py','scripts/a\\b.py','scripts/a\0b.py','scripts/C:drive.py','scripts/e\u0301.py','tests/test_a.py'])expect(()=>assertProtectedMutationSources('python',[path],[{path}])).toThrow();
  expect(()=>assertProtectedMutationSources('python',null,[])).toThrow(/inventory/);
});

test('Stryker diagnostic ranges bind exact source bytes and UTF-16 line bounds without changing tests',()=>{
 const file='packages/example/src/example.ts',bytes=Buffer.from('const x="😀";\r\nexport const y=true;\n'),sha=createHash('sha256').update(bytes).digest('hex'),source='a'.repeat(64),inventory=[{path:file,size:bytes.length,sha256:sha}],range=file+':1:1-2:21';
 const scope=diagnosticStrykerScope(range,inventory,source,()=>bytes);
 expect(scope).toEqual({schema_version:1,kind:'selected-stryker-diagnostic',scope_complete:false,source_tree_sha256:source,range,file,source_sha256:sha,source_size_bytes:bytes.length,start:{line:1,column:1},end:{line:2,column:21}});
 for(const changed of['../'+range,range.replace('packages/','tests/'),file+':01:1-2:21',file+':0:1-2:21',file+':1:0-2:21',file+':1:1-4:1',file+':1:1-2:22',file+':2:2-1:1',file+':2:2-2:2',file+':1:1-2:21?'])expect(()=>diagnosticStrykerScope(changed,inventory,source,()=>bytes)).toThrow(/range/);
 expect(()=>diagnosticStrykerScope(range,[],source,()=>bytes)).toThrow(/snapshot/);
 expect(()=>diagnosticStrykerScope(range,[...inventory,...inventory],source,()=>bytes)).toThrow(/duplicated/);
 expect(()=>diagnosticStrykerScope(range,inventory,source,()=>Buffer.from('changed'))).toThrow(/snapshot/);
 expect(()=>diagnosticStrykerScope(range,inventory,'bad',()=>bytes)).toThrow(/range/);
});

test('diagnostic range CLI rejects foreign backends and mixed selectors before snapshot or engine actions',()=>{
 const temporary=mkdtempSync(path.join(os.tmpdir(),'ud-invalid-stryker-range-'));
 try{
  const output=path.join(temporary,'must-not-create'),range='packages/example.ts:1:1-2:1';
  for(const args of[['--backend','python','--diagnostic-stryker-range',range],['--backend','rust','--diagnostic-stryker-range',range],['--backend','typescript','--file','packages/example.ts','--diagnostic-stryker-range',range],['--backend','typescript','--diagnostic-stryker-range',range,'--diagnostic-stryker-range',range]]){
   const result=spawnSync(process.execPath,[path.resolve('scripts/quality/oci-python-diagnostic.mjs'),output,...args],{env:{PATH:'',HOME:temporary},encoding:'utf8',timeout:10000});
   expect(result.error).toBeUndefined();expect(result.status).toBe(1);expect(result.stderr).toMatch(/exclusive|Repeated/);expect(existsSync(output)).toBe(false);
  }
 }finally{rmSync(temporary,{recursive:true,force:true});}
});
