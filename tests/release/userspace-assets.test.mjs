import {test,expect}from'vitest';
import{selectedUserspaceFiles}from'../../scripts/release/userspace-assets.mjs';
test('native packages copy only their selected userspace closure while universal npm stays lazy',()=>{
 const shared={path:'runtime/pack/worker/main.py',sha256:'sha256:'+'a'.repeat(64),size:4};
 const arm={path:'runtime/pack/native/darwin-arm64/perl/bin/perl',sha256:'sha256:'+'b'.repeat(64),size:8};
 const x64={path:'runtime/pack/native/win32-x64/perl/bin/perl.exe',sha256:'sha256:'+'c'.repeat(64),size:9};
 const manifest={platforms:{'darwin/arm64':{files:[shared,arm],lazy_core:{url:'pinned'}},'win32/x64':{files:[shared,x64],lazy_core:{url:'pinned'}}}};
 expect(selectedUserspaceFiles(manifest,'darwin-arm64')).toEqual([arm,shared]);
 expect(selectedUserspaceFiles(manifest,'win32-x64')).toEqual([x64,shared]);
 expect(selectedUserspaceFiles(manifest,'all')).toEqual([]);
 expect(()=>selectedUserspaceFiles(manifest,'linux-x64')).toThrow(/absent/);
 delete manifest.platforms['darwin/arm64'].lazy_core;expect(()=>selectedUserspaceFiles(manifest,'all')).toThrow(/lazy core/);
 expect(()=>selectedUserspaceFiles({platforms:{'darwin/arm64':{files:[]}}},'darwin-arm64')).toThrow(/file inventory/);
});
