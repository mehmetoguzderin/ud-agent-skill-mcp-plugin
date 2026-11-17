#!/usr/bin/env python3
"""Derive a private Perl/ELF closure from a cryptographically verified core image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_private_elf',Path(__file__).with_name('elf_dependencies.py'))
elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)


def sha(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def name(value):
    value=value.removeprefix('./').rstrip('/')
    if not value or value.startswith('/')or'\\'in value or'\0'in value or any(x in('','.','..')for x in value.split('/')):raise ValueError('unsafe layer member')
    return value


def prepare(receipt,platform,output):
    if output.exists()or output.is_symlink():raise ValueError('private Perl output must be new')
    pack=receipt['packs']['core'];image=pack['images'][platform]
    descriptor=pack['index_transport'];archive=ROOT/descriptor['path']
    if archive.is_symlink()or archive.stat().st_size!=descriptor['size_bytes']or'sha256:'+sha(archive)!=descriptor['sha256']:raise ValueError('core archive receipt mismatch')
    verify="import{verifyOciArchive}from'./scripts/release/oci.mjs';const input=JSON.parse(process.argv[1]);verifyOciArchive(input.file.path,input.pack.index_digest,input.pack.platforms,input.file,input.pack.images);"
    subprocess.run(['node','--input-type=module','-e',verify,json.dumps({'file':{'path':descriptor['path'],'sha256':descriptor['sha256'][7:],'size':descriptor['size_bytes']},'pack':pack})],cwd=ROOT,check=True,timeout=180)
    machine,triplet=(183,'aarch64-linux-gnu')if platform=='linux/arm64'else(62,'x86_64-linux-gnu')
    prefixes=['etc/perl','usr/share/perl','usr/share/perl5',f'usr/lib/{triplet}/perl',f'usr/lib/{triplet}/perl5',f'usr/lib/{triplet}/perl-base','opt/ud-agent/interset/lib']
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.private-linux-perl-',dir=output.parent)as temporary:
        stage=Path(temporary);filesystem=stage/'image';filesystem.mkdir();inventory={};total=0;serial=0
        with tarfile.open(archive,'r:')as outer:
            members={item.name:item for item in outer if item.isfile()}
            with outer.extractfile(members['blobs/sha256/'+image['digest'][7:]])as stream:manifest=json.load(stream)
            for layer in manifest['layers']:
                lower=set(inventory);written=set()
                with outer.extractfile(members['blobs/sha256/'+layer['digest'][7:]])as raw,tarfile.open(fileobj=raw,mode='r:*')as source:
                    for item in source:
                        if item.isdir()and item.name in('.','./'):continue
                        relative=name(item.name);parent,_,base=relative.rpartition('/')
                        if base.startswith('.wh.'):
                            target = parent if base == '.wh..wh..opq' else (parent + '/' if parent else '') + base[4:]
                            for existing in lower-written:
                                if existing==target or existing.startswith(target+'/'):inventory.pop(existing,None)
                            continue
                        if len(inventory)>500000 or item.size>512*1024*1024:raise ValueError('image member inventory exceeds bounds')
                        if item.isfile():
                            total+=item.size
                            if total>4*1024**3:raise ValueError('core filesystem exceeds bounds')
                            # Keep regular files under opaque content names so a
                            # hostile path/link cannot influence extraction.
                            target=filesystem/str(serial);serial+=1
                            with source.extractfile(item)as content,target.open('xb')as destination:shutil.copyfileobj(content,destination,1024*1024)
                            inventory[relative]=('file',target)
                        elif item.issym()or item.islnk():inventory[relative]=('link',item.linkname if item.islnk()or item.linkname.startswith('/')else posixpath.join(parent,item.linkname))
                        elif item.isdir():inventory[relative]=('dir',None)
                        else:inventory[relative]=('other',None)
                        written.add(relative)
        def resolve(relative, allow_directory=False):
            relative=posixpath.normpath(relative.lstrip('/'))
            if relative.startswith('../')or relative=='..':raise ValueError('image link escapes root')
            for _ in range(64):
                parts=relative.split('/');rewritten=False
                for index in range(1,len(parts)+1):
                    current='/'.join(parts[:index]);kind,value=inventory.get(current,('missing',None))
                    if kind=='link':relative=posixpath.normpath(str(value).lstrip('/')+('/'+'/'.join(parts[index:])if index<len(parts)else''));rewritten=True;break
                if not rewritten:
                    kind,value=inventory.get(relative,('missing',None))
                    if kind=='dir' and allow_directory:return relative,None
                    if kind!='file':raise ValueError('image dependency is not a regular file: '+relative)
                    return relative,value
            raise ValueError('image link cycle')
        packroot=stage/'pack';packroot.mkdir();modules=packroot/'modules';selected=[];roots=set()
        for relative,(kind,_)in sorted(inventory.items()):
            if kind not in('file','link')or not any(relative==prefix or relative.startswith(prefix+'/')for prefix in prefixes):continue
            resolved,source=resolve(relative,True)
            if source is None:continue
            target=modules/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);target.chmod(0o444);selected.append(target)
            for prefix in prefixes:
                if relative.startswith(prefix+'/'):
                    roots.add('modules/'+prefix)
                    child=relative[len(prefix)+1:].split('/',1)[0]
                    if re.fullmatch(r'\d+(?:\.\d+){1,2}',child):roots.add('modules/'+prefix+'/'+child)
        if not selected:raise ValueError('Perl module closure is empty')
        _,perl=resolve('usr/bin/perl');binary=packroot/'bin/perl';binary.parent.mkdir();shutil.copyfile(perl,binary);binary.chmod(0o555)
        def is_elf(file):
            with file.open('rb')as stream:return stream.read(4)==b'\x7fELF'
        candidates=[binary,*[file for file in selected if is_elf(file)]];pending=list(candidates);processed=set();libraries={};interpreter=None
        while pending:
            current=pending.pop();fingerprint=sha(current)
            if fingerprint in processed:continue
            processed.add(fingerprint);info=elf.inspect(current.read_bytes())
            if info['machine']!=machine or info['search_paths']:raise ValueError('ELF architecture or embedded search path violates the private runtime contract')
            if current==binary:
                if not info['interpreter']:raise ValueError('private Perl has no explicit ELF loader')
                _,loader=resolve(info['interpreter']);interpreter=packroot/'loader'/Path(info['interpreter']).name;interpreter.parent.mkdir();shutil.copyfile(loader,interpreter);interpreter.chmod(0o555);pending.append(interpreter)
            for dependency in info['needed']:
                if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,255}',dependency):raise ValueError('ELF dependency name is not confined')
                matches=[]
                for folder in[f'lib/{triplet}',f'usr/lib/{triplet}','lib64','usr/lib64','lib','usr/lib']:
                    try:matches.append(resolve(folder+'/'+dependency)[1])
                    except ValueError:continue
                if not matches or len({sha(file)for file in matches})!=1:raise ValueError('ELF dependency is missing or ambiguous: '+dependency)
                source=matches[0];target=packroot/'lib'/dependency;target.parent.mkdir(exist_ok=True)
                if dependency not in libraries:shutil.copyfile(source,target);target.chmod(0o555);libraries[dependency]=sha(target);pending.append(target)
                elif libraries[dependency]!=sha(source):raise ValueError('ELF library identity collision')
        if interpreter is None:raise ValueError('private ELF loader is unavailable')
        roots=sorted(value for value in roots if(packroot/value).is_dir())
        files=[{'path':file.relative_to(packroot).as_posix(),'sha256':'sha256:'+sha(file),'size':file.stat().st_size}for file in sorted(packroot.rglob('*'))if file.is_file()]
        record={'schema_version':1,'state':'frozen-inputs','platform':platform,'source':{'image_manifest':image['digest'],'image_index':pack['index_digest'],'archive_sha256':descriptor['sha256']},'executable':'bin/perl','library_dirs':roots,'loader':{'executable':interpreter.relative_to(packroot).as_posix(),'library_dirs':['lib']},'files':files,'probe':{'status':'pending','reason':'Run private loader and complete module closure on the selected architecture.'}}
        os.rename(packroot,output)
    (output.parent/(output.name+'-receipt.json')).write_text(json.dumps(record,indent=2)+'\n');return record


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workers',type=Path,required=True);parser.add_argument('--platform',choices=['linux/arm64','linux/amd64'],required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps({'files':len(prepare(json.loads(args.workers.read_text()),args.platform,args.output)['files'])}))


if __name__=='__main__':main()
