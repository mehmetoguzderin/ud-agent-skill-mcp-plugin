import { expect, test } from 'vitest';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { mkdtemp, realpath } from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';
import { writableFixtureCopy } from './writable-copy.mjs';

test('native-canonical async fixture roots remain inside the same temporary directory', async () => {
 const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-writable-native-')));
 try {
  const source = path.join(root, 'source'), fixture = path.join(root, 'fixture');
  writeFileSync(source, 'sealed original'); chmodSync(source, 0o444); mkdirSync(fixture);
  writableFixtureCopy(source, path.join(fixture, 'copy'), fixture);
  writeFileSync(path.join(fixture, 'copy'), 'independent edit');
  expect(readFileSync(source, 'utf8')).toBe('sealed original');
  expect(readFileSync(path.join(fixture, 'copy'), 'utf8')).toBe('independent edit');
  expect(() => writableFixtureCopy(source, path.join(root, 'escaped'), fixture)).toThrow(/owned child/);
 } finally { rmSync(root, { recursive: true, force: true }); }
});

test('sealed source stays unchanged while owned copies are writable and independently removable',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-writable-copy-'));const source=path.join(root,'sealed'),fixture=path.join(root,'fixture');mkdirSync(source);mkdirSync(fixture);writeFileSync(path.join(source,'file'),'original');writeFileSync(path.join(source,'tool'),'executable');chmodSync(path.join(source,'file'),0o444);chmodSync(path.join(source,'tool'),0o555);chmodSync(source,0o555);
 try{writableFixtureCopy(source,path.join(fixture,'copy'),fixture);writeFileSync(path.join(fixture,'copy/file'),'edited');expect(readFileSync(path.join(source,'file'),'utf8')).toBe('original');if(process.platform!=='win32'){expect(lstatSync(path.join(source,'file')).mode&0o777).toBe(0o444);expect(lstatSync(path.join(fixture,'copy/file')).mode&0o777).toBe(0o600);expect(lstatSync(path.join(fixture,'copy/tool')).mode&0o777).toBe(0o700);}rmSync(path.join(fixture,'copy'),{recursive:true});}
 finally{chmodSync(source,0o700);chmodSync(path.join(source,'file'),0o600);chmodSync(path.join(source,'tool'),0o700);rmSync(root,{recursive:true,force:true});}
});
test('escaped or symlinked targets and aliased sources never become writable',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-writable-policy-'));mkdirSync(path.join(root,'fixture'));mkdirSync(path.join(root,'foreign'));writeFileSync(path.join(root,'source'),'source');
 try{expect(()=>writableFixtureCopy(path.join(root,'source'),path.join(root,'outside'),path.join(root,'fixture'))).toThrow(/owned child/);symlinkSync(path.join(root,'foreign'),path.join(root,'fixture/link'),process.platform==='win32'?'junction':'dir');expect(()=>writableFixtureCopy(path.join(root,'source'),path.join(root,'fixture/link/file'),path.join(root,'fixture'))).toThrow(/unsafe/);symlinkSync(path.join(root,'source'),path.join(root,'source-link'));expect(()=>writableFixtureCopy(path.join(root,'source-link'),path.join(root,'fixture/file'),path.join(root,'fixture'))).toThrow(/symlink/);expect(readFileSync(path.join(root,'source'),'utf8')).toBe('source');}
 finally{rmSync(root,{recursive:true,force:true});}
});
