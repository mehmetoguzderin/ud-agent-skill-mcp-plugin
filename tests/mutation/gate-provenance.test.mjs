import{test,expect}from'vitest';
import{chmodSync,mkdirSync,mkdtempSync,rmSync,writeFileSync}from'node:fs';
import path from'node:path';import os from'node:os';
import{mutationSnapshotIdentity}from'../../scripts/quality/mutation-gate.mjs';
import{captureDiagnosticSnapshot}from'../../scripts/quality/diagnostic-snapshot.mjs';
import{posixTest}from'../fixtures/native-scope.mjs';

test('gate and protected backend share exact source bytes and detect changed content',()=>{
 const temporary=mkdtempSync(path.join(os.tmpdir(),'ud-subject-bytes-'));
 try{
  const root=path.join(temporary,'source');mkdirSync(path.join(root,'scripts'),{recursive:true});const file=path.join(root,'scripts/helper.py');writeFileSync(file,'print(1)\n');
  const first=mutationSnapshotIdentity(root),captured=captureDiagnosticSnapshot(root,path.join(temporary,'first'));
  expect(first.snapshot_sha256).toBe(captured.source_tree_sha256);
  writeFileSync(file,'print(2)\n');
  const second=mutationSnapshotIdentity(root),changed=captureDiagnosticSnapshot(root,path.join(temporary,'second'));
  expect(second.snapshot_sha256).toBe(changed.source_tree_sha256);
  expect(second.snapshot_sha256).not.toBe(first.snapshot_sha256);
  expect(second.inventory_tree_sha256).not.toBe(first.inventory_tree_sha256);
 }finally{rmSync(temporary,{recursive:true,force:true});}
});

posixTest('gate and protected backend share a subject that binds executable permission',()=>{
 const temporary=mkdtempSync(path.join(os.tmpdir(),'ud-subject-'));
 try{
  const root=path.join(temporary,'source');mkdirSync(path.join(root,'scripts'),{recursive:true});const file=path.join(root,'scripts/helper.py');writeFileSync(file,'print(1)\n');chmodSync(file,0o644);
  const first=mutationSnapshotIdentity(root),captured=captureDiagnosticSnapshot(root,path.join(temporary,'first'));
  expect(first.snapshot_sha256).toBe(captured.source_tree_sha256);
  chmodSync(file,0o755);
  const second=mutationSnapshotIdentity(root),executable=captureDiagnosticSnapshot(root,path.join(temporary,'second'));
  expect(second.snapshot_sha256).toBe(executable.source_tree_sha256);
  expect(second.snapshot_sha256).not.toBe(first.snapshot_sha256);
  expect(second.inventory_tree_sha256).toBe(first.inventory_tree_sha256);
 }finally{rmSync(temporary,{recursive:true,force:true});}
});
