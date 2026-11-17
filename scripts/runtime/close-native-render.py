#!/usr/bin/env python3
"""Close a pinned Linux browser pack over a fully verified OCI ELF inventory."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
oci=load('ud_render_oci',Path(__file__).with_name('oci_filesystem.py'))
elf=load('ud_render_elf',Path(__file__).with_name('elf_dependencies.py'))
paths=load('ud_render_paths',ROOT/'workers/ud/src/ud_agent/unicode_paths.py')


def close(base_receipt,worker_receipt,output,transport):
    if output.exists() or output.is_symlink() or transport.exists() or transport.is_symlink():raise ValueError('closed render outputs must be new')
    platform=base_receipt['platform'];machine,triplet=(183,'aarch64-linux-gnu') if platform=='linux/arm64' else (62,'x86_64-linux-gnu') if platform=='linux/x64' else (None,None)
    if machine is None:raise ValueError('Linux render closure requires a supported Linux platform')
    engine_platform='linux/arm64' if machine==183 else 'linux/amd64'
    source=ROOT/paths.validate_path(base_receipt['root']);records={}
    for record in base_receipt['files']:
        name=paths.validate_path(record['path']);file=source/name
        if name in records or file.is_symlink() or not file.is_file() or file.stat().st_size!=record['size'] or 'sha256:'+oci.sha(file)!=record['sha256']:raise ValueError('native browser base receipt differs from its files')
        records[name]=record
    actual={file.relative_to(source).as_posix() for file in source.rglob('*') if file.is_file()}
    if actual!=set(records):raise ValueError('native browser base inventory is not closed')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.close-native-render-',dir=output.parent) as temporary:
        temporary=Path(temporary);pack=temporary/'pack';pack.mkdir()
        for name in records:
            target=pack/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target);target.chmod(0o555 if (source/name).stat().st_mode&0o111 else 0o444)
        manifest=json.loads((pack/'manifest.json').read_text());executable=pack/paths.validate_path(manifest['executable'])
        if not executable.is_file():raise ValueError('native browser executable is missing')
        filesystem=oci.verified_filesystem(ROOT,worker_receipt['packs']['render'],engine_platform,temporary/'image')
        def is_elf(path):
            with path.open('rb') as stream:return stream.read(4)==b'\x7fELF'
        candidates=[pack/name for name in records if is_elf(pack/name)]
        transformations=[]
        def normalized_copy(source,target):
            before=source.read_bytes();info=elf.inspect(before)
            if info['machine']!=machine:raise ValueError('native browser closure contains a foreign ELF architecture')
            after=elf.without_search_paths(before)
            if source!=target:
                target.parent.mkdir(parents=True,exist_ok=True)
            target.chmod(0o600) if target.exists() else None
            target.write_bytes(after);target.chmod(0o555)
            if after!=before:transformations.append({'path':target.relative_to(pack).as_posix(),'operation':'remove-rpath-runpath','before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()})
            return hashlib.sha256(after).hexdigest()
        for file in candidates:normalized_copy(file,file)
        locals_by_name={}
        for file in candidates:locals_by_name.setdefault(file.name,[]).append(file)
        pending=list(candidates);processed=set();libraries={};interpreter=None;origins={} 
        while pending:
            file=pending.pop();original=file.read_bytes();fingerprint=hashlib.sha256(original).hexdigest()
            if fingerprint in processed:continue
            processed.add(fingerprint);info=elf.inspect(original)
            if info['machine']!=machine:raise ValueError('native browser closure contains a foreign ELF architecture')
            if info['search_paths']:raise ValueError('native browser dependency retained an ambient search path')
            if file==executable:
                if not info['interpreter']:raise ValueError('native browser has no ELF interpreter')
                loader_path,loader_source=filesystem.resolve(info['interpreter']);interpreter=pack/'elf/loader'/Path(info['interpreter']).name;interpreter.parent.mkdir(parents=True);normalized_copy(loader_source,interpreter);pending.append(interpreter)
                origins[interpreter.relative_to(pack).as_posix()]={'image_path':loader_path,'sha256':oci.sha(loader_source)}
            for dependency in info['needed']:
                if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,255}',dependency):raise ValueError('ELF dependency has an unsafe name')
                matches=[];origin=None
                if dependency in locals_by_name:
                    matches=locals_by_name[dependency];origin={'browser_path':matches[0].relative_to(pack).as_posix()}
                else:
                    for folder in [f'lib/{triplet}',f'usr/lib/{triplet}','lib64','usr/lib64','lib','usr/lib']:
                        try:
                            resolved,found=filesystem.resolve(folder+'/'+dependency);matches.append(found);origin={'image_path':resolved}
                        except ValueError:continue
                if not matches or len({oci.sha(found) for found in matches})!=1:raise ValueError('ELF dependency is missing or ambiguous: '+dependency)
                found=matches[0];source_sha=oci.sha(found);fingerprint=hashlib.sha256(elf.without_search_paths(found.read_bytes())).hexdigest();target=pack/'elf/lib'/dependency;target.parent.mkdir(parents=True,exist_ok=True)
                if dependency not in libraries:
                    normalized_copy(found,target);libraries[dependency]=fingerprint;pending.append(target);origins[target.relative_to(pack).as_posix()]={**origin,'source_sha256':source_sha,'sha256':fingerprint}
                elif libraries[dependency]!=fingerprint:raise ValueError('ELF dependency identity collision')
        if interpreter is None:raise ValueError('native browser ELF loader is unavailable')
        for relative,(kind,_) in sorted(filesystem.inventory.items()):
            if relative.startswith('usr/share/doc/') and relative.endswith('/copyright') and kind in ('file','link'):
                _,file=filesystem.resolve(relative);target=pack/'licenses/oci'/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o444)
        image=worker_receipt['packs']['render']['images'][engine_platform]
        identity={'schema_version':1,'source':{'browser_transport':base_receipt['transport'],'image_index':worker_receipt['packs']['render']['index_digest'],'image_manifest':image['digest']},'libraries':origins,'transformations':transformations}
        (pack/'elf-closure.json').write_text(json.dumps(identity,sort_keys=True,indent=2)+'\n')
        manifest['loader']={'executable':interpreter.relative_to(pack).as_posix(),'library_dirs':['elf/lib']}
        manifest['files']=[{'path':file.relative_to(pack).as_posix(),'sha256':oci.sha(file),'size_bytes':file.stat().st_size} for file in sorted(pack.rglob('*')) if file.is_file() and file!=pack/'manifest.json']
        (pack/'manifest.json').chmod(0o600);(pack/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n');(pack/'manifest.json').chmod(0o444)
        transport.parent.mkdir(parents=True,exist_ok=True)
        with transport.open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as target:
            for file in sorted(pack.rglob('*')):
                if not file.is_file():continue
                member=target.gettarinfo(str(file),arcname=file.relative_to(pack).as_posix());member.uid=member.gid=member.mtime=0;member.uname=member.gname=''
                with file.open('rb') as content:target.addfile(member,content)
        os.rename(pack,output)
    record={'schema_version':1,'state':'frozen-inputs','platform':platform,'root':output.relative_to(ROOT).as_posix(),'manifest':'manifest.json','files':[{'path':file.relative_to(output).as_posix(),'sha256':'sha256:'+oci.sha(file),'size':file.stat().st_size} for file in sorted(output.rglob('*')) if file.is_file()],'transport':{'path':transport.relative_to(ROOT).as_posix(),'sha256':'sha256:'+oci.sha(transport),'size':transport.stat().st_size},'probe':{'status':'pending','reason':'Run private browser closure on the actual selected architecture.'}}
    (output.parent/(output.name+'-receipt.json')).write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base',type=Path,required=True);parser.add_argument('--workers',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--transport',type=Path,required=True);args=parser.parse_args()
    result=close(json.loads(args.base.read_text()),json.loads(args.workers.read_text()),args.output.resolve(),args.transport.resolve());print(json.dumps({'files':len(result['files']),'transport':result['transport']}))
