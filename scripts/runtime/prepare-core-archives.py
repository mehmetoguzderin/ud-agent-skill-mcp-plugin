#!/usr/bin/env python3
"""Create reproducible per-host userspace core transports without foreign execution."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_core_transport_paths',ROOT/'workers/ud/src/ud_agent/unicode_paths.py');paths=importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)

def digest(path):
    with path.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()

def prepare(source,output):
    source=source.resolve(strict=True);output=output.resolve()
    if output.exists()or output.is_relative_to(source):raise ValueError('lazy core output must be a new separate pack directory')
    manifest=json.loads((source/'runtime/userspace.lock.json').read_text())
    if manifest.get('schema_version')!=1 or manifest.get('format_revision')!=2 or manifest.get('state')!='frozen'or not manifest.get('platforms'):raise ValueError('lazy core transports require a complete frozen userspace manifest')
    copied={};assets=[]
    output.mkdir(parents=True)
    (output/'INCOMPLETE').write_text('Core transport assembly has not completed.\n')
    for host,item in manifest['platforms'].items():
        if host not in ['darwin/arm64','darwin/x64','linux/arm64','linux/x64','win32/arm64','win32/x64']or not item.get('files'):raise ValueError('userspace platform inventory is missing')
        seen=set();total=0
        for entry in item['files']:
            name=entry['path']
            paths.validate_path(name);key=paths.path_key(name)
            if key in seen or len(seen)>=50000:raise ValueError('core inventory contains an unsafe or duplicate file')
            seen.add(key);file=source/name;total+=entry['size']
            if total>2*1024**3:raise ValueError('core transport exceeds its bounded expanded size')
            if file.is_symlink()or not file.is_file()or file.stat().st_size!=entry['size']or'sha256:'+digest(file)!=entry['sha256']:raise ValueError('core input does not match the selected platform inventory')
            if name in copied:
                if copied[name]!=entry['sha256']:raise ValueError('core platform inventories conflict')
            else:
                destination=output/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,destination);destination.chmod(0o555 if file.stat().st_mode&0o111 else 0o444);copied[name]=entry['sha256']
        relative='.artifacts/release-inputs/ud-agent-userspace-'+host.replace('/','-')+'.tar.gz';archive=output/relative;archive.parent.mkdir(parents=True,exist_ok=True)
        with archive.open('xb')as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0)as zipped,tarfile.open(fileobj=zipped,mode='w|',format=tarfile.USTAR_FORMAT)as target:
            for entry in sorted(item['files'],key=lambda value:value['path']):
                name=entry['path'];file=output/name;info=tarfile.TarInfo(name);info.size=entry['size'];info.mode=0o555 if file.stat().st_mode&0o111 else 0o444;info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
                with file.open('rb')as content:target.addfile(info,content)
        descriptor={'url':'https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/'+archive.name,'sha256':'sha256:'+digest(archive),'size':archive.stat().st_size}
        item['lazy_core']=descriptor;assets.append({'id':'userspace-core-'+host.replace('/','-'),'platform':host.replace('/','-'),'path':relative,'sha256':descriptor['sha256'],'size_bytes':descriptor['size'],'url':descriptor['url']})
    for item in manifest.get('bootstrap_assets',[]):
        file=source/item['path']
        if file.is_symlink()or not file.is_file()or'sha256:'+digest(file)!=item['sha256']or file.stat().st_size!=item['size']:raise ValueError('core bootstrap asset is stale')
        target=output/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o555 if file.stat().st_mode&0o111 else 0o444)
    (output/'runtime/userspace.lock.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    (output/'runtime/core-artifacts.json').write_text(json.dumps({'schema_version':1,'assets':assets},indent=2)+'\n');(output/'INCOMPLETE').unlink()
    return {'schema_version':1,'platforms':list(manifest['platforms']),'userspace_sha256':'sha256:'+digest(output/'runtime/userspace.lock.json'),'assets':assets}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--userspace',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(prepare(args.userspace,args.output)))
if __name__=='__main__':main()
