"""Read a verified OCI filesystem through bounded opaque content, never host paths."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import posixpath
import shutil
import subprocess
import tarfile


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe_name(value):
    value=value.removeprefix('./').rstrip('/')
    if not value or value.startswith('/') or '\\' in value or '\0' in value or any(part in ('','.','..') for part in value.split('/')):
        raise ValueError('unsafe OCI layer member')
    return value


class Filesystem:
    def __init__(self,directory,file_observer=None):
        self.directory=Path(directory);self.directory.mkdir();self.inventory={};self.metadata={};self.total=0;self.serial=0;self.file_observer=file_observer

    def add_layer(self,source):
        lower=set(self.inventory);written=set()
        for item in source:
            if item.isdir() and item.name in ('.','./'):continue
            relative=safe_name(item.name);parent,_,base=relative.rpartition('/')
            if base.startswith('.wh.'):
                if base=='.wh.':raise ValueError('empty OCI whiteout target')
                target=parent if base=='.wh..wh..opq' else (parent+'/' if parent else '')+base[4:]
                for existing in lower-written:
                    if ((not target or existing.startswith(target+'/')) if base=='.wh..wh..opq' else existing==target or existing.startswith(target+'/')):
                        self.inventory.pop(existing,None)
                        self.metadata.pop(existing,None)
                continue
            if len(self.inventory)>=500000 or not 0<=item.size<=512*1024**2:raise ValueError('OCI member inventory exceeds bounds')
            if item.isfile():
                self.total+=item.size
                if self.total>4*1024**3:raise ValueError('OCI filesystem exceeds bounds')
                target=self.directory/str(self.serial);self.serial+=1
                with source.extractfile(item) as content,target.open('xb') as output:shutil.copyfileobj(content,output,1024**2)
                self.inventory[relative]=('file',target)
                if self.file_observer is not None:self.file_observer(relative,target,self.serial-1)
            elif item.issym() or item.islnk():
                self.inventory[relative]=('link',item.linkname if item.islnk() or item.linkname.startswith('/') else posixpath.join(parent,item.linkname))
            elif item.isdir():self.inventory[relative]=('dir',None)
            else:self.inventory[relative]=('other',None)
            self.metadata[relative]=(item.mode,item.uid,item.gid)
            written.add(relative)

    def resolve(self,relative,allow_directory=False):
        relative=posixpath.normpath(relative.lstrip('/'))
        for _ in range(64):
            if relative=='..' or relative.startswith('../'):raise ValueError('OCI link escapes its root')
            parts=relative.split('/');rewritten=False
            for index in range(1,len(parts)+1):
                current='/'.join(parts[:index]);kind,value=self.inventory.get(current,('missing',None))
                if kind=='link':
                    relative=posixpath.normpath(str(value).lstrip('/')+('/'+'/'.join(parts[index:]) if index<len(parts) else ''))
                    rewritten=True;break
                if index<len(parts) and kind in ('file','other'):
                    raise ValueError('OCI dependency traverses a non-directory')
            if not rewritten:
                kind,value=self.inventory.get(relative,('missing',None))
                if kind=='dir' and allow_directory:return relative,None
                if kind!='file':raise ValueError('OCI dependency is not a regular file: '+relative)
                return relative,value
        raise ValueError('OCI link cycle')


def verified_filesystem(root,pack,platform,directory,diagnostic_single_platform=False,layer_observer=None,file_observer=None):
    root=Path(root);descriptor=pack['index_transport'];archive=root/safe_name(descriptor['path']);image=pack['images'][platform]
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size!=descriptor['size_bytes'] or 'sha256:'+sha(archive)!=descriptor['sha256']:
        raise ValueError('OCI archive differs from its receipt')
    verifier=(Path(__file__).resolve().parents[1]/'release/oci.mjs').as_uri()
    verify="import{verifyOciArchive}from"+json.dumps(verifier)+";const input=JSON.parse(process.argv[1]);verifyOciArchive(input.file.path,input.pack.index_digest,input.pack.platforms,input.file,input.pack.images,{diagnosticSinglePlatform:input.diagnostic_single_platform});"
    # The archive root is data. It cannot supply executable verifier modules.
    subprocess.run(['node','--input-type=module','-e',verify,json.dumps({'file':{'path':str(archive.resolve()),'sha256':descriptor['sha256'][7:],'size':descriptor['size_bytes']},'pack':pack,'diagnostic_single_platform':diagnostic_single_platform})],check=True,timeout=180)
    filesystem=Filesystem(directory)
    with tarfile.open(archive,'r:') as outer:
        members={item.name:item for item in outer if item.isfile()}
        with outer.extractfile(members['blobs/sha256/'+image['digest'][7:]]) as raw:manifest=json.load(raw)
        for index,layer in enumerate(manifest['layers']):
            filesystem.file_observer=(lambda name,file,serial:file_observer(name,file,serial,layer,index))if file_observer is not None else None
            with outer.extractfile(members['blobs/sha256/'+layer['digest'][7:]]) as raw,tarfile.open(fileobj=raw,mode='r:*') as source:filesystem.add_layer(source)
            if layer_observer is not None:layer_observer(filesystem,layer,index)
    return filesystem
