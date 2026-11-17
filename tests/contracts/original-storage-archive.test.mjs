// SPDX-License-Identifier: MIT
import { test, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import os from 'node:os';
import { validateLocalEvaluationImageArchive, readLocalEvaluationImageArchive, localEvaluationImageAvailability, localEvaluationImageDependencies } from '../../scripts/quality/original-storage.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex'), digest = bytes => 'sha256:' + sha(bytes), owner = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', label = 'io.github.mehmetoguzderin.ud-agent.local-eval';
const python = process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
function tar(files) {
  const chunks=[];
  for(const [name,value] of Object.entries(files)) {
    const data=Buffer.isBuffer(value)?value:Buffer.from(value), header=Buffer.alloc(512);
    header.write(name);header.write('0000600\0',100);header.write('0000000\0',108);header.write('0000000\0',116);header.write(data.length.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);header.fill(32,148,156);header[156]=48;header.write('ustar\0',257);header.write('00',263);
    const sum=header.reduce((a,b)=>a+b,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148);chunks.push(header,data,Buffer.alloc((512-data.length%512)%512));
  }
  return Buffer.concat([...chunks,Buffer.alloc(1024)]);
}
function fixture(action, kind='docker-config') {
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-client-archive-'))), directory=path.join(root,'.artifacts/local-evals/client-images/fixture'), archives=path.join(root,'.artifacts/local-evals/client-image-archives');
  mkdirSync(directory,{recursive:true,mode:0o700});mkdirSync(archives,{recursive:true,mode:0o700});
  const layer=tar({'probe.txt':'inert client layer\n'}), config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',config:{Labels:{[label]:owner}},rootfs:{type:'layers',diff_ids:[digest(layer)]}}));
  let id=digest(config), files={'config.json':config,'layer.tar':layer,'manifest.json':JSON.stringify([{Config:'config.json',Layers:['layer.tar'],RepoTags:['localhost/fixture:1']}])};
  if(kind!=='docker-config') {
    const packed=gzipSync(layer), manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{digest:digest(config),size:config.length,mediaType:'application/vnd.oci.image.config.v1+json'},layers:[{digest:digest(packed),size:packed.length,mediaType:kind==='docker-gzip'?'application/vnd.docker.image.rootfs.diff.tar.gzip':'application/vnd.oci.image.layer.v1.tar+gzip'}]}));
    id=digest(manifest);files={['blobs/sha256/'+sha(config)]:config,['blobs/sha256/'+sha(manifest)]:manifest,['blobs/sha256/'+sha(packed)]:packed,'oci-layout':JSON.stringify({imageLayoutVersion:'1.0.0'})};
    if(kind==='oci-index') {const index=Buffer.from(JSON.stringify({schemaVersion:2,manifests:[{digest:id,mediaType:'application/vnd.oci.image.manifest.v1+json',platform:{architecture:'arm64',os:'linux'}}]}));id=digest(index);files['blobs/sha256/'+sha(index)]=index;}
    files['index.json']=JSON.stringify({schemaVersion:2,manifests:[{digest:id,mediaType:kind==='oci-index'?'application/vnd.oci.image.index.v1+json':'application/vnd.oci.image.manifest.v1+json'}]});
  }
  const parent='sha256:'+'b'.repeat(64), before={Id:id,Architecture:'arm64',Os:'linux',Size:layer.length,Parent:parent,Config:{Labels:{[label]:owner}},RootFS:{Type:'layers',Layers:[digest(layer)]},...(kind==='docker-config'?{}:{Descriptor:{digest:id}})};
  const receipt={id:'fixture',version:'1',image_id:id,created_by:owner,image_size:layer.length}, receiptBytes=Buffer.from(JSON.stringify(receipt));
  writeFileSync(path.join(directory,'receipt.json'),receiptBytes,{mode:0o600});
  const ancestry={image_id:id,relationship:'immutable-dependencies-of-owned-client-image-not-deletion-authority',images:[{image_id:id,size_bytes:layer.length,parent},{image_id:parent,size_bytes:123,parent:''}]};
  writeFileSync(path.join(directory,'ancestry.json'),JSON.stringify(ancestry),{mode:0o600});
  const archive=path.join(archives,'fixture.tar.gz'), archiveBytes=gzipSync(tar(files));writeFileSync(archive,archiveBytes,{mode:0o400});
  const inspection=path.join(root,'before.json');writeFileSync(inspection,JSON.stringify(before));
  const parsed=spawnSync(python,['-I','-B',path.resolve('scripts/quality/verify-client-image-archive.py'),archive,inspection],{encoding:'utf8',timeout:10000});
  expect(parsed.status,parsed.stderr).toBe(0);const validation=JSON.parse(parsed.stdout);
  const record={schema_version:1,kind:'verified-local-eval-client-image-archive',image_id:id,original_receipt_sha256:sha(receiptBytes),inference:false,archive:{path:path.relative(root,archive),sha256:sha(archiveBytes),size_bytes:archiveBytes.length},before_inspection:before,verified_reload:{image_id:id,architecture:'arm64',os:'linux',owner,cleanup_verified:true,exit_code:0,archive_sha256:sha(archiveBytes)},archive_validation:validation,created_at:new Date().toISOString()};
  const save=()=>{const file=path.join(directory,'archive-availability.json');try{chmodSync(file,0o600)}catch{}writeFileSync(file,JSON.stringify(record),{mode:0o400});chmodSync(file,0o400)};save();
  const absent=imageId=>Object.assign(new Error('exact daemon absence'),{code:'UD_IMAGE_ABSENT',imageId});
  try{return action({root,directory,archive,archiveBytes,record,receipt,ancestry,before,id,parent,save,absent,validation,inspection,files});}finally{rmSync(root,{recursive:true,force:true});}
}

posixTest('private Docker and OCI archives are validated by config and every actual layer',()=>{
  for(const kind of ['docker-config','oci-manifest','oci-index']) fixture(({root,record,id,validation})=>{
    const verified=readLocalEvaluationImageArchive(root,'fixture');expect(verified.image_id).toBe(id);expect(validation.identity_kind).toBe(kind);expect(validation.layers_verified).toBe(true);expect(validation.layers[0].diff_id).toBe(record.before_inspection.RootFS.Layers[0]);
  },kind);
});
test('OCI manifests may contain Docker gzip layers while preserving exact diff IDs',()=>fixture(({validation,record})=>{
  expect(validation.identity_kind).toBe('oci-manifest');expect(validation.layers[0].diff_id).toBe(record.before_inspection.RootFS.Layers[0]);expect(validation.layers[0].blob_digest).not.toBe(validation.layers[0].diff_id);
},'docker-gzip'));

posixTest('a missing selected root needs a valid immutable archive and exact daemon absence',()=>fixture(({root,id,parent,record,save,absent})=>{
  const docker=args=>{if(args[2]===id)throw absent(id);return JSON.stringify([{Id:parent,Architecture:'arm64',Os:'linux',Size:123,Parent:''}]);};
  const missing=[];expect(localEvaluationImageDependencies(root,docker,missing)).toEqual([{image_id:parent,size_bytes:123}]);expect(missing).toEqual([id]);
  expect(localEvaluationImageAvailability(root,'fixture',docker).status).toBe('archived-unavailable');
  delete record.archive_validation;save();expect(()=>localEvaluationImageDependencies(root,docker)).toThrow(/verification absent/);
  expect(()=>localEvaluationImageDependencies(root,()=>{throw new Error('permission denied')})).toThrow(/permission denied/);
}));

posixTest('restored roots may lose implementation Parent metadata while original ancestry stays reconciled',()=>fixture(({root,id,parent,before,absent})=>{
  const live={...before,Parent:''},missing=[];
  const docker=args=>{if(args[2]===parent)throw absent(parent);return JSON.stringify([live]);};
  expect(localEvaluationImageDependencies(root,docker,missing)).toEqual([{image_id:id,size_bytes:before.Size}]);expect(missing).toEqual([parent]);
  live.RootFS={Layers:['sha256:'+'f'.repeat(64)]};expect(()=>localEvaluationImageDependencies(root,docker)).toThrow(/ancestry changed/);
}));
posixTest('archive-restored compressed Size is verified but admission preserves original virtual bytes',()=>fixture(({root,id,parent,before,absent})=>{
  const live={...before,Parent:'',Size:Math.floor(before.Size/2)},docker=args=>{if(args[2]===parent)throw absent(parent);return JSON.stringify([live]);};
  expect(localEvaluationImageDependencies(root,docker)).toEqual([{image_id:id,size_bytes:live.Size,charged_size_bytes:before.Size}]);
  live.RootFS={Layers:['sha256:'+'f'.repeat(64)]};expect(()=>localEvaluationImageDependencies(root,docker)).toThrow(/ancestry changed/);
}));

test('an archive claim cannot replace byte, platform, ownership or reload verification',()=>fixture(({record,receipt,ancestry})=>{
  const context={receipt,receiptSha256:record.original_receipt_sha256,ancestry,archiveSha256:record.archive.sha256,archiveSize:record.archive.size_bytes};
  for(const change of [value=>value.verified_reload.exit_code=1,value=>value.verified_reload.owner='wrong',value=>value.archive_validation.config_digest='not-a-digest',value=>value.archive_validation.diff_ids=['sha256:'+'0'.repeat(64)],value=>value.original_receipt_sha256='0'.repeat(64)]){
    const changed=structuredClone(record);change(changed);expect(()=>validateLocalEvaluationImageArchive(changed,context)).toThrow();
  }
}));

posixTest('private immutable archive admission detects changed bytes after sealing',()=>fixture(({root,archive})=>{
  chmodSync(archive,0o600);writeFileSync(archive,'corrupted archive bytes');chmodSync(archive,0o400);expect(()=>readLocalEvaluationImageArchive(root,'fixture')).toThrow(/byte identity differs/);
}));

if(process.platform==='win32') test('Windows refuses archive admission without verified POSIX private immutable modes and preserves its bytes',()=>fixture(({root,directory,archive,archiveBytes})=>{
  const record=path.join(directory,'archive-availability.json'),before=readFileSync(record);
  expect(()=>readLocalEvaluationImageArchive(root,'fixture')).toThrow('archive file is not private and immutable');
  expect(readFileSync(record)).toEqual(before);expect(readFileSync(archive)).toEqual(archiveBytes);
}));

test('the independent archive parser rejects changed layer payloads and unsafe members',()=>{
  for(const kind of ['docker-config','oci-manifest']) fixture(({archive,files,inspection})=>{
    const layerPath=kind==='docker-config'?'layer.tar':Object.keys(files).find(name=>name.startsWith('blobs/')&&Buffer.isBuffer(files[name])&&files[name][0]===31&&files[name][1]===139);
    files[layerPath]=kind==='docker-config'?tar({'probe.txt':'altered layer'}):gzipSync(tar({'probe.txt':'altered layer'}));
    chmodSync(archive,0o600);writeFileSync(archive,gzipSync(tar(files)));chmodSync(archive,0o400);
    const parsed=spawnSync(python,['-I','-B',path.resolve('scripts/quality/verify-client-image-archive.py'),archive,inspection],{encoding:'utf8',timeout:10000});
    expect(parsed.status).not.toBe(0);expect(parsed.stderr).toMatch(/ARCHIVE_LAYER_/);
    files['../escape']='unsafe';chmodSync(archive,0o600);writeFileSync(archive,gzipSync(tar(files)));chmodSync(archive,0o400);
    const unsafe=spawnSync(python,['-I','-B',path.resolve('scripts/quality/verify-client-image-archive.py'),archive,inspection],{encoding:'utf8',timeout:10000});
    expect(unsafe.status).not.toBe(0);expect(unsafe.stderr).toMatch(/ARCHIVE_MEMBER_INVALID/);
  },kind);
});
