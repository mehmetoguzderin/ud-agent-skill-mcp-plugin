#!/usr/bin/env python3
"""Verify actual OCI layer contents against build inputs without executing an image."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def digest(stream):
    return hashlib.file_digest(stream,'sha256').hexdigest()


def safe(name):
    name=name.removeprefix('./').rstrip('/')
    if not name or name.startswith('/') or '\\' in name or '\0' in name or any(part in ('','.','..') for part in name.split('/')):
        raise ValueError('unsafe image layer path')
    return name


def verify(archive, manifest_digest, context, render=False):
    expected=json.loads((context/'input-manifest.json').read_text())
    files={};payloads={};total=0
    with tarfile.open(archive,'r:') as outer:
        members={member.name:member for member in outer if member.isfile()}
        def blob(identifier):
            if not identifier.startswith('sha256:') or len(identifier)!=71:raise ValueError('invalid OCI content digest')
            stream=outer.extractfile(members['blobs/sha256/'+identifier[7:]])
            if digest(stream)!=identifier[7:]:raise ValueError('OCI content digest mismatch')
            stream.seek(0);return stream
        with blob(manifest_digest) as stream: manifest=json.load(stream)
        with blob(manifest['config']['digest']) as stream: configuration=json.load(stream)
        for layer in manifest['layers']:
            with blob(layer['digest']) as raw,tarfile.open(fileobj=raw,mode='r:*') as source:
                lower=set(files);written=set()
                for member in source:
                    if member.isdir() and member.name in ('.','./'):continue
                    name=safe(member.name)
                    if len(name)>4096 or len(files)>500000 or member.size<0 or member.size>8*1024**3:raise ValueError('image content inventory exceeds bounds')
                    parent,_,base=name.rpartition('/')
                    if base.startswith('.wh.'):
                        target=parent if base=='.wh..wh..opq' else (parent+'/' if parent else '')+base[4:]
                        for existing in lower-written:
                            if existing==target or existing.startswith(target+'/'):files.pop(existing,None);payloads.pop(existing,None)
                    elif member.isfile():
                        total+=member.size
                        if total>32*1024**3:raise ValueError('image content closure exceeds bounds')
                        with source.extractfile(member) as content:
                            if name in ('opt/ud-agent/input-manifest.json','opt/ud-agent/render/manifest.json'):
                                if member.size>8*1024**2:raise ValueError('image receipt exceeds bounds')
                                data=content.read();fingerprint=hashlib.sha256(data).hexdigest();payloads[name]=data
                            else:fingerprint=digest(content)
                        files[name]={'sha256':fingerprint,'size_bytes':member.size,'type':'file'};written.add(name)
                    else:
                        files[name]={'type':'directory' if member.isdir() else 'link' if member.issym() or member.islnk() else 'other'};written.add(name);payloads.pop(name,None)
    def regular(name):
        parts=name.split('/')
        if any(files.get('/'.join(parts[:index]),{}).get('type','directory')!='directory' for index in range(1,len(parts))):raise ValueError('image source has a linked or special ancestor')
        return files.get(name,{})
    source_manifest=context/'input-manifest.json'
    if regular('opt/ud-agent/input-manifest.json').get('sha256')!=hashlib.sha256(source_manifest.read_bytes()).hexdigest():raise ValueError('image build-input manifest differs from supplied context')
    checked=0
    for name,fingerprint in expected['files'].items():
        if name.split('/',1)[0] in ('worker','upstream','docs','docs-automation','context','licenses'):
            actual=regular('opt/ud-agent/'+name)
            if actual.get('type')!='file' or actual.get('sha256')!=fingerprint:raise ValueError('image source bytes differ: '+name)
            checked+=1
        elif name.startswith('perl/'+configuration['architecture']+'/'):
            relative=name.removeprefix('perl/'+configuration['architecture']+'/')
            actual=regular('opt/ud-agent/perl/'+relative)
            if actual.get('type')!='file'or actual.get('sha256')!=fingerprint:raise ValueError('image private Perl bytes differ: '+relative)
            checked+=1
    if not checked:raise ValueError('image source inventory is empty')
    if render:
        raw=payloads.get('opt/ud-agent/render/manifest.json')
        if raw is None:raise ValueError('render image has no browser receipt')
        receipt=json.loads(raw)
        if receipt.get('schema_version')!=1 or not receipt.get('fonts') or not receipt.get('files'):raise ValueError('render inventory is incomplete')
        for item in receipt['files']:
            actual=regular(safe(item['path'].removeprefix('/')))
            if actual.get('type')!='file' or actual.get('sha256')!=item['sha256'] or actual.get('size_bytes')!=item['size_bytes']:raise ValueError('image browser or font bytes differ: '+item['path'])
            checked+=1
    return {'schema_version':1,'status':'passed','manifest':manifest_digest,'source_files_verified':checked,'input_manifest_sha256':hashlib.sha256(source_manifest.read_bytes()).hexdigest(),'qualification':'offline-image-content-evidence'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--archive',type=Path,required=True);parser.add_argument('--manifest',required=True);parser.add_argument('--context',type=Path,required=True);parser.add_argument('--render',action='store_true');args=parser.parse_args()
    print(json.dumps(verify(args.archive,args.manifest,args.context,args.render)))


if __name__=='__main__':main()
