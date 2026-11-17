#!/usr/bin/env python3
"""Acquire exact already-locked Perl, UD, Node and Python package source archives."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_source_acquire',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)


def plan(root, assets_root=None):
    assets_root = root if assets_root is None else assets_root
    items=[];bindings={}
    def lock(name):
        file=root/name;bindings[name]=acquisition.digest(file);return json.loads(file.read_bytes())
    perl=lock('runtime/native-perl-source.lock.json');items.append({'family':'perl','name':perl['name'],'version':perl['version'],'url':perl['url'],'sha256':perl['sha256'],'cached':str(root/'.artifacts/native-perl/cache'/(perl['name']+'.tar.gz'))})
    modules=lock('runtime/native-perl-modules.lock.json')
    for record in modules['releases'].values():items.append({'family':'cpan','name':record['name'],'version':record['version'],'url':record['url'],'sha256':record['sha256'],'cached':str(root/'.artifacts/native-perl/cache'/(record['name']+'.tar.gz'))})
    for record in lock('runtime/ud-sources.lock.json')['sources']:
        name=record['repository'].rsplit('/',1)[1];items.append({'family':'ud','name':record['repository'],'version':record['commit'],'url':'https://codeload.github.com/'+record['repository']+'/tar.gz/'+record['commit'],'sha256':record['archive_sha256'],'cached':str(root/'.artifacts/sources'/(name+'-'+record['commit']+'.tar.gz'))})
    interset=lock('runtime/perl-deps.lock.json')['interset'];items.append({'family':'ud','name':'dan-zeman/interset','version':interset['commit'],'url':'https://codeload.github.com/dan-zeman/interset/tar.gz/'+interset['commit'],'sha256':interset['archive_sha256'],'size_bytes':interset['archive_size'],'cached':str(root/'.artifacts/perl-sources'/interset['archive'])})
    node=lock('runtime/node-distributions.lock.json');signed=assets_root/'.artifacts/node/SHASUMS256.txt.asc';keyring=assets_root/'.artifacts/node/nodejs-release-keys.kbx'
    if acquisition.digest(signed)!=node['signed_manifest_sha256']or acquisition.digest(keyring)!=node['release_keyring_sha256']:raise ValueError('Node signed source checksum roots differ from their release lock')
    verified=subprocess.run(['gpgv','--status-fd','1','--keyring',str(keyring.resolve()),str(signed.resolve())],capture_output=True,timeout=30)
    if verified.returncode or ('[GNUPG:] VALIDSIG '+node['checksum_signer_fingerprint']+' ').encode()not in verified.stdout:raise ValueError('Node source checksum signature verification failed')
    raw=signed.read_bytes();start=raw.index(b'\n\n')+2;end=raw.index(b'\n-----BEGIN PGP SIGNATURE-----');manifest=raw[start:end].decode();filename='node-v'+node['version']+'.tar.xz';matches=[line.split()[0]for line in manifest.splitlines()if line.split()[-1:]==[filename]]
    if len(matches)!=1 or not re.fullmatch('[0-9a-f]{64}',matches[0]):raise ValueError('Node signed manifest omits its exact source archive')
    items.append({'family':'node','name':'Node.js','version':node['version'],'url':'https://nodejs.org/dist/v'+node['version']+'/'+filename,'sha256':matches[0],'signature_receipt':{'signed_manifest_sha256':node['signed_manifest_sha256'],'keyring_sha256':node['release_keyring_sha256'],'signer':node['checksum_signer_fingerprint']}})
    uv=root/'uv.lock';bindings['uv.lock']=acquisition.digest(uv)
    for record in tomllib.loads(uv.read_text())['package']:
        source=record.get('sdist')
        if source:items.append({'family':'python-package','name':record['name'],'version':record['version'],'url':source['url'],'sha256':source['hash'].removeprefix('sha256:'),'size_bytes':source['size']})
    definitions=set()
    for item in items:
        key=item['family']+'\0'+item['name']+'\0'+item['version']
        if key in definitions or not re.fullmatch('[0-9a-f]{64}',item['sha256']):raise ValueError('source plan has a duplicate or malformed identity')
        definitions.add(key)
    return items,bindings


def source_notices(archive):
    records=[];seen=set();total=0
    if hasattr(archive,'read'):
        archive.seek(0);opened=tarfile.open(fileobj=archive,mode='r:*')
    else:opened=tarfile.open(archive,'r:*')
    with opened as source:
        for member in source:
            name=member.name.removeprefix('./').rstrip('/')
            if not name or name.startswith('/')or'\\'in name or any(part in('','.','..')for part in name.split('/'))or name in seen or len(seen)>100000:raise ValueError('locked source archive has unsafe or duplicate names')
            seen.add(name);total+=member.size
            if member.size>512*1024**2 or total>4*1024**3:raise ValueError('locked source expansion exceeds its bound')
            if not member.isfile():continue # Links remain opaque archive bytes, never host paths.
            leaf=name.rsplit('/',1)[-1].lower()
            if not re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$',leaf):continue
            body=source.extractfile(member).read(8*1024**2+1)
            if len(body)>8*1024**2:raise ValueError('source notice exceeds its bound')
            records.append({'path':name,'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)})
    return records


def collect(root,output,download):
    items,bindings=plan(root);output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    def obtain(item):
        target=output/'blobs'/item['sha256'];cached=Path(item.get('cached','/nonexistent'))
        if not target.exists()and cached.is_file()and not cached.is_symlink():
            if acquisition.digest(cached)!=item['sha256']:raise ValueError('cached locked source archive is corrupt')
            target.parent.mkdir(exist_ok=True);shutil.copyfile(cached,target);target.chmod(0o444)
        if download:acquisition.acquire(item['url'],target,item.get('size_bytes'),item['sha256'])
        record={key:value for key,value in item.items()if key!='cached'};record['path']=target.relative_to(output).as_posix();record['acquired']=target.is_file()
        if record['acquired']:
            if target.is_symlink()or acquisition.digest(target)!=item['sha256']:raise ValueError('locked source archive differs from its exact contract')
            record['size_bytes']=target.stat().st_size;record['notice_files']=source_notices(target)
        return record
    with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:records=list(pool.map(obtain,items))
    if any(acquisition.digest(root/name)!=fingerprint for name,fingerprint in bindings.items()):raise ValueError('source dependency locks changed during collection')
    report={'schema_version':1,'qualification':'exact-locked-source-subinventory','families':sorted({row['family']for row in records}),'status':'passed'if all(row['acquired']for row in records)else'incomplete','locks':bindings,'files':records,'scope_limitation':'This is not the complete product corresponding-source inventory; OCI/guest/Go/provider/managed-interpreter/runtime-C source closures are separate.'}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--download',action='store_true');args=parser.parse_args();report=collect(args.root.resolve(),args.output,args.download);print(json.dumps({'status':report['status'],'files':len(report['files']),'families':report['families']}));raise SystemExit(0 if report['status']=='passed'else 1)
