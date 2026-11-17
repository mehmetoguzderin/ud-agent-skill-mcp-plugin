#!/usr/bin/env python3
"""Acquire lock-bound npm/Cargo source archives and their original notices."""
from __future__ import annotations
import argparse
import base64
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tarfile
import tomllib

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_source_acquire',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)
NOTICE=re.compile(r'^(license|licence|copying|notice|copyright)(?:[._-].*)?$',re.I)


def plan(root,additional_cargo=()):
    """The locks, rather than an input list of desired packages, define scope."""
    root=Path(root);items={};bindings={}
    npm_file=root/'package-lock.json';npm=json.loads(npm_file.read_bytes());bindings[str(npm_file.resolve())]=acquisition.digest(npm_file)
    for location,item in sorted(npm.get('packages',{}).items()):
        if not location:continue
        name=item.get('name')or location.rsplit('node_modules/',1)[-1];version=item.get('version');url=item.get('resolved');integrities=[]
        if not isinstance(name,str)or not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+',name)or not isinstance(version,str)or not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*',version)or not isinstance(url,str)or not url.startswith('https://registry.npmjs.org/'):
            raise ValueError('npm lock has a non-registry or unversioned source')
        for sri in item.get('integrity','').split():
            algorithm,separator,value=sri.partition('-')
            if separator and algorithm in('sha256','sha512'):
                decoded=base64.b64decode(value,validate=True)
                if len(decoded)!=hashlib.new(algorithm).digest_size:raise ValueError('npm integrity digest has an invalid length')
                integrities.append({'algorithm':algorithm,'hex':decoded.hex()})
        if not integrities:raise ValueError('npm source has no frozen strong integrity contract')
        row={'family':'npm','name':name,'version':version,'url':url,'integrities':integrities,'license_declared':item.get('license'),'consumers':[location]};identity='npm:'+name+'@'+version
        if identity in items:
            previous=items[identity]
            if any(previous[key]!=row[key]for key in('url','integrities','license_declared')):raise ValueError('npm identities have conflicting source contracts')
            previous['consumers'].append(location)
        else:items[identity]=row
    locks=[root/'Cargo.lock',root/'scripts/quality/rust-assertion-parser/Cargo.lock',*map(Path,additional_cargo)]
    for file in locks:
        if not file.is_file():raise ValueError('required Rust source lock is missing')
        bindings[str(file.resolve())]=acquisition.digest(file)
        for item in tomllib.loads(file.read_text())['package']:
            if 'source'not in item:continue
            if item['source']!='registry+https://github.com/rust-lang/crates.io-index'or not re.fullmatch('[a-f0-9]{64}',item.get('checksum',''))or not re.fullmatch('[A-Za-z0-9_-]+',item['name'])or not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*',item['version']):
                raise ValueError('Cargo source needs a supported exact registry checksum')
            name,version=item['name'],item['version'];row={'family':'cargo','name':name,'version':version,'url':f'https://static.crates.io/crates/{name}/{name}-{version}.crate','sha256':item['checksum'],'consumers':[str(file.resolve())]};identity='cargo:'+name+'@'+version
            if identity in items:
                if items[identity]['sha256']!=row['sha256']:raise ValueError('Cargo locks disagree on source content')
                items[identity]['consumers'].append(str(file.resolve()))
            else:items[identity]=row
    if not items:raise ValueError('source locks are empty')
    return [items[key]for key in sorted(items)],bindings


def inspect_archive(file,output):
    """Inspect opaque archives and copy notice bytes without extracting paths."""
    notices=[];seen=set();total=0
    with tarfile.open(file,'r:*')as source:
        for member in source:
            name=member.name.removeprefix('./').rstrip('/')
            if not name or name.startswith('/')or'\\'in name or any(part in('','.','..')for part in name.split('/'))or name in seen or len(seen)>=200000:raise ValueError('package source archive has unsafe or duplicate paths')
            seen.add(name);total+=member.size
            if member.size>512*1024**2 or total>4*1024**3:raise ValueError('package source archive expansion exceeds bound')
            if not member.isfile()or not NOTICE.fullmatch(name.rsplit('/',1)[-1]):continue
            if member.size>8*1024**2:raise ValueError('package notice exceeds bound')
            body=source.extractfile(member).read(member.size+1)
            if len(body)!=member.size:raise ValueError('package notice is truncated')
            digest=hashlib.sha256(body).hexdigest();target=output/'notices'/digest;target.parent.mkdir(exist_ok=True)
            if target.exists():
                if target.is_symlink()or target.read_bytes()!=body:raise ValueError('cached notice is corrupt')
            else:target.write_bytes(body);target.chmod(0o444)
            notices.append({'source_path':name,'path':target.relative_to(output).as_posix(),'sha256':digest,'size_bytes':len(body)})
    return notices


def collect(root,output,download,additional_cargo=(),reuse=None):
    items,bindings=plan(root,additional_cargo);output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    def obtain(item):
        key=item.get('sha256')or hashlib.sha256(item['url'].encode()).hexdigest();target=output/'blobs'/key
        if reuse is not None and not target.exists():
            previous=Path(reuse)/'blobs'/key
            if previous.is_file():
                if previous.is_symlink():raise ValueError('source reuse cache contains a link')
                target.parent.mkdir(exist_ok=True);shutil.copyfile(previous,target);target.chmod(0o444)
        if download:acquisition.acquire(item['url'],target,sha256=item.get('sha256'),maximum=512*1024**2)
        row={**item,'path':target.relative_to(output).as_posix(),'acquired':target.is_file()}
        if row['acquired']:
            if target.is_symlink()or not target.is_file():raise ValueError('source cache contains a linked or nonordinary object')
            for expected in item.get('integrities',[]):
                with target.open('rb')as stream:actual=hashlib.file_digest(stream,expected['algorithm']).hexdigest()
                if actual!=expected['hex']:raise ValueError('npm source differs from frozen SRI integrity')
            digest=acquisition.digest(target)
            if item.get('sha256',digest)!=digest:raise ValueError('Cargo source differs from frozen checksum')
            row.update(sha256=digest,size_bytes=target.stat().st_size,notices=inspect_archive(target,output))
        return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:records=list(pool.map(obtain,items))
    if any(acquisition.digest(Path(name))!=expected for name,expected in bindings.items()):raise ValueError('package source locks changed during collection')
    report={'schema_version':1,'qualification':'complete-locked-npm-cargo-source-and-notice-subinventory','status':'passed'if all(row['acquired']for row in records)else'incomplete','target_execution':False,'locks':bindings,'files':records,'scope':'Every package in the source npm lock and all explicit Cargo locks, including zero-native-execution platform dependencies; additional source lock closures are identified exactly.'}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cargo-lock',type=Path,action='append',default=[]);parser.add_argument('--download',action='store_true');parser.add_argument('--reuse',type=Path);args=parser.parse_args();report=collect(args.root,args.output,args.download,args.cargo_lock,args.reuse);print(json.dumps({'status':report['status'],'files':len(report['files'])}));raise SystemExit(0 if report['status']=='passed'else 1)
