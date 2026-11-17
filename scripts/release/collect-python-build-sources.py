#!/usr/bin/env python3
"""Collect exact runtime source inputs declared by the frozen managed-Python build."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_source_acquisition',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)


def collect(build_source,output,download):
    proof=json.loads((build_source/'receipt.json').read_bytes());archive=build_source/'source.tar.gz'
    if proof.get('repository')!='astral-sh/python-build-standalone'or proof.get('tag')!='20261026'or proof.get('commit')!='fa506e0858ac9f2cc5b289c137b888a2aa24d1ee'or acquisition.digest(archive)!=proof['source']['sha256']:raise ValueError('managed interpreter build source differs from the frozen release')
    downloads=None;notices=[]
    output.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive,'r:gz')as source:
        for member in source:
            if not member.isfile():continue
            if member.name.endswith('/pythonbuild/downloads.json'):
                if downloads is not None or not 0<member.size<=2*1024**2:raise ValueError('managed interpreter source table is duplicate or oversized')
                downloads=json.load(source.extractfile(member))
            if '/licenses/'in member.name or member.name.rsplit('/',1)[-1].startswith('LICENSE.')or member.name.rsplit('/',1)[-1]=='LICENSE':
                body=source.extractfile(member).read(8*1024**2+1)
                if len(body)>8*1024**2:raise ValueError('managed interpreter notice exceeds bound')
                fingerprint=hashlib.sha256(body).hexdigest();target=output/'notices'/fingerprint;target.parent.mkdir(exist_ok=True)
                if not target.exists():target.write_bytes(body);target.chmod(0o444)
                notices.append({'source_path':member.name,'path':target.relative_to(output).as_posix(),'sha256':fingerprint,'size_bytes':len(body)})
    if not isinstance(downloads,dict)or downloads.get('cpython-3.14',{}).get('version')!='3.14.10'or downloads.get('cpython-3.15',{}).get('version')!='3.15.2':raise ValueError('managed interpreter sources name different Python releases')
    selected={name:value for name,value in downloads.items()if 'library_names'in value or name in('cpython-3.14','cpython-3.15','pip','setuptools','linux-uapi','musl','musl-static','zstd')}
    def obtain(pair):
        name,item=pair;target=output/'blobs'/item['sha256']
        if download:acquisition.acquire(item['url'],target,item['size'],item['sha256'])
        if target.exists()and(target.is_symlink()or target.stat().st_size!=item['size']or acquisition.digest(target)!=item['sha256']):raise ValueError('managed interpreter runtime source differs from its declared build hash')
        return {'name':name,'version':item['version'],'url':item['url'],'sha256':item['sha256'],'size_bytes':item['size'],'path':target.relative_to(output).as_posix(),'acquired':target.is_file(),'upstream_licenses':item.get('licenses',[]),'upstream_public_domain':item.get('license_public_domain',False),'upstream_license_file':item.get('license_file')}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:records=list(pool.map(obtain,sorted(selected.items())))
    build_target=output/'build-recipe.tar.gz'
    if build_target.exists():
        if build_target.is_symlink()or acquisition.digest(build_target)!=proof['source']['sha256']:raise ValueError('managed interpreter source recipe cache is corrupt')
    else:
        __import__('shutil').copyfile(archive,build_target);build_target.chmod(0o444)
    records.append({'name':'python-build-standalone','version':proof['commit'],'url':proof['source']['url'],'sha256':proof['source']['sha256'],'size_bytes':archive.stat().st_size,'path':build_target.name,'acquired':True,'role':'exact-managed-interpreter-build-recipe'})
    report={'schema_version':1,'qualification':'frozen-managed-interpreter-runtime-source-subinventory','status':'passed'if all(row['acquired']for row in records)else'incomplete','coverage':'Runtime source overapproximation across selected Python3.14/3.15 platform builds; compiler/tool binaries are not included.','build_source':proof,'files':records,'notices':notices}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build-source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--download',action='store_true');args=parser.parse_args();report=collect(args.build_source,args.output,args.download);print(json.dumps({'status':report['status'],'files':len(report['files']),'notices':len(report['notices'])}));raise SystemExit(0 if report['status']=='passed'else 1)
