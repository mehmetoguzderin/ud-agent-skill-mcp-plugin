#!/usr/bin/env python3
"""Acquire exact corresponding Debian sources from authenticated publisher indexes."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import io
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import quote,urlsplit
from urllib.request import urlopen
import uuid

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_materials',Path(__file__).with_name('source_materials.py'));materials=importlib.util.module_from_spec(spec);spec.loader.exec_module(materials)


def digest(file):
    with file.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()


def acquire(url,target,size=None,sha256=None,maximum=8*1024**3):
    if target.is_symlink():raise ValueError('source material target is a link')
    if target.exists():
        if size is not None and target.stat().st_size!=size or sha256 is not None and digest(target)!=sha256:raise ValueError('cached source material differs from its authenticated receipt')
        return
    target.parent.mkdir(parents=True,exist_ok=True);temporary=target.with_name(target.name+'.'+uuid.uuid4().hex+'.part')
    try:
        with urlopen(url,timeout=60)as source,temporary.open('xb')as output:
            count=0
            while chunk:=source.read(1024**2):
                count+=len(chunk)
                if count>(size if size is not None else maximum):raise ValueError('source download exceeds its bound')
                output.write(chunk)
            output.flush();os.fsync(output.fileno())
        if size is not None and count!=size or sha256 is not None and digest(temporary)!=sha256:raise ValueError('source download differs from its authenticated receipt')
        temporary.chmod(0o444);temporary.replace(target)
    finally:temporary.unlink(missing_ok=True)


def release_indexes(raw,suite):
    start=raw.find(b'\n\n');end=raw.find(b'\n-----BEGIN PGP SIGNATURE-----')
    if not raw.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n')or start<0 or end<=start:raise ValueError('signed publisher release framing is invalid')
    body=b'\n'.join(line[2:]if line.startswith(b'- ')else line for line in raw[start+2:end].split(b'\n'))
    records=materials.control_records(body)
    if len(records)!=1 or suite not in(records[0].get('Suite'),records[0].get('Codename')):raise ValueError('signed publisher release names another suite')
    indexes={}
    for line in records[0].get('SHA256','').splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch('[0-9a-f]{64}',fields[0])and fields[1].isdigit()and re.fullmatch(r'(main|universe|restricted|multiverse)/source/Sources.xz',fields[2]):
            if fields[2]in indexes or not 0<int(fields[1])<=128*1024**2:raise ValueError('publisher source index is duplicated or oversized')
            indexes[fields[2]]={'sha256':fields[0],'size_bytes':int(fields[1])}
    if not indexes:raise ValueError('publisher release contains no source indexes')
    return indexes


def collect(inventories,bases,suites,output,download,gpgv,keyring,signer,repositories=None,publisher="ubuntu"):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    keyring=keyring.resolve(strict=True);gpgv=gpgv.resolve(strict=True)
    if publisher not in('ubuntu','debian'):raise ValueError('unsupported source publisher')
    if publisher=='ubuntu':
        lock=json.loads((ROOT/'runtime/lima-guest.lock.json').read_bytes())['package_authentication']
        if digest(keyring)!=lock['keyring_sha256'].removeprefix('sha256:')or signer!=lock['signer_fingerprint']:raise ValueError('publisher archive signing authority differs from the frozen root')
    subjects=[];packages=[]
    for file in inventories:
        data=json.loads(file.read_bytes())
        if data.get('status')!='passed'or data.get('qualification')!=('image-bound-publisher-package-and-notice-inventory'if publisher=='ubuntu'else'oci-bound-publisher-package-and-notice-inventory')or data.get('guest_execution'if publisher=='ubuntu'else'target_execution')is not False or data.get('emulation')is not False or not data.get('packages')or any(row.get('status')not in('removed-owned','absent')for row in data.get('cleanup',[])):raise ValueError('complete image-bound package inventory and cleanup are required')
        for package in data['packages']:
            notice=file.parent/package['notice']['path']
            if notice.is_symlink()or digest(notice)!=package['notice']['sha256']or notice.stat().st_size!=package['notice']['size_bytes']:raise ValueError('package notice differs from its image receipt')
        if publisher=='debian'and digest(keyring)!=data['archive_keyring']['sha256']:raise ValueError('Debian archive signing keyring differs from the verified OCI image')
        packages.extend(data['packages']);subjects.append({'path':str(file.resolve()),'sha256':digest(file),'image_sha256':data['image']['sha256']if publisher=='ubuntu'else data['oci_image_digest'],'architecture':data['guest_architecture']if publisher=='ubuntu'else data['platform']})
    requirements=materials.source_requirements(packages);catalog={};metadata=[]
    for base,suite in (repositories if repositories is not None else [(base,suite)for base in bases for suite in suites]):
        parsed=urlsplit(base)
        if parsed.scheme!='https'or parsed.netloc!=('snapshot.ubuntu.com'if publisher=='ubuntu'else'snapshot.debian.org')or not re.fullmatch('/ubuntu/[0-9]{8}T[0-9]{6}Z'if publisher=='ubuntu'else'/archive/debian(?:-security)?/[0-9]{8}T[0-9]{6}Z',parsed.path)or parsed.query or parsed.fragment:raise ValueError('exact Ubuntu snapshot source base required')
        if not re.fullmatch('(resolute|questing|plucky|oracular|noble)(?:-updates|-security)?'if publisher=='ubuntu'else'(trixie|bookworm)(?:-updates|-security)?',suite):raise ValueError('unsupported publisher source suite')
        prefix=output/'metadata'/materials.sha((base+'/'+suite).encode());release=prefix/'InRelease'
        acquire(base+'/dists/'+suite+'/InRelease',release,maximum=2*1024**2)
        result=subprocess.run([str(gpgv),'--status-fd','1','--keyring',str(keyring),str(release)],capture_output=True,timeout=30)
        if result.returncode or (('[GNUPG:] VALIDSIG '+signer+' ').encode()not in result.stdout if publisher=='ubuntu'else b'[GNUPG:] VALIDSIG 'not in result.stdout):raise ValueError('publisher release signature verification failed')
        metadata.append({'url':base+'/dists/'+suite+'/InRelease','path':release.relative_to(output).as_posix(),'sha256':digest(release),'size_bytes':release.stat().st_size,'signature':result.stdout.decode()})
        for name,item in release_indexes(release.read_bytes(),suite).items():
            target=prefix/name.replace('/','_');url=base+'/dists/'+suite+'/'+name.rsplit('/',1)[0]+'/by-hash/SHA256/'+item['sha256'];acquire(url,target,item['size_bytes'],item['sha256'])
            metadata.append({'url':url,'path':target.relative_to(output).as_posix(),**item})
            with lzma.open(target,'rb')as compressed:expanded=compressed.read(128*1024**2+1)
            if len(expanded)>128*1024**2:raise ValueError('publisher source index expansion exceeds its bound')
            for identity,component in materials.source_index(expanded).items():
                component={**component,'files':[{**value,'url':base+'/'+quote(value['path'],safe='/+~.-_')}for value in component['files']]}
                if identity in catalog and sorted((Path(item['path']).name,item['sha256'],item['size_bytes'])for item in catalog[identity]['files'])!=sorted((Path(item['path']).name,item['sha256'],item['size_bytes'])for item in component['files']):raise ValueError('publisher indexes disagree on exact source bytes: '+identity.replace('\0','@'))
                catalog[identity]=component
    selected=[];missing=[];files={}
    for required in requirements:
        entry=catalog.get(required['name']+'\0'+required['version'])
        if entry is None:missing.append(required);continue
        selected.append({**entry,'consumers':required['consumers']})
        for file in entry['files']:
            if file['sha256']in files and files[file['sha256']]['size_bytes']!=file['size_bytes']:raise ValueError('source digest has inconsistent sizes')
            files[file['sha256']]=file
    if download:
        def obtain(item):acquire(item['url'],output/'blobs'/item['sha256'],item['size_bytes'],item['sha256'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:list(pool.map(obtain,files.values()))
    records=[{**item,'path':'blobs/'+item['sha256'],'acquired':(output/'blobs'/item['sha256']).is_file()}for item in files.values()]
    report={'schema_version':1,'qualification':'publisher-authenticated-exact-corresponding-source-closure','publisher':publisher,'status':'passed'if not missing and all(item['acquired']for item in records)else'incomplete','subjects':subjects,'metadata':metadata,'signer':signer,'keyring_sha256':digest(keyring),'gpgv_sha256':digest(gpgv),'required_sources':len(requirements),'sources':selected,'files':records,'missing':missing,'license_conclusions':'Package notices retained exactly; no inferred SPDX license conclusions.'}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inventory',action='append',type=Path,required=True);parser.add_argument('--base',action='append',default=[]);parser.add_argument('--repository',action='append',help='exact snapshot HTTPS base followed by |suite');parser.add_argument('--suite',action='append',default=[]);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--download',action='store_true');parser.add_argument('--publisher',choices=['ubuntu','debian'],default='ubuntu');parser.add_argument('--gpgv',type=Path,default=shutil.which('gpgv'));parser.add_argument('--keyring',type=Path,default=ROOT/'.artifacts/lima-product/ubuntu/ubuntu-archive-keyring.gpg');args=parser.parse_args()
    signer=json.loads((ROOT/'runtime/lima-guest.lock.json').read_bytes())['package_authentication']['signer_fingerprint']
    repositories=[tuple(value.split('|'))for value in args.repository]if args.repository else None
    if not args.base and not repositories:parser.error('--base or --repository is required')
    report=collect(args.inventory,args.base,args.suite or['resolute','resolute-updates','resolute-security'],args.output,args.download,args.gpgv,args.keyring,signer,repositories,args.publisher);print(json.dumps({'status':report['status'],'required_sources':report['required_sources'],'found':len(report['sources']),'missing':len(report['missing']),'files':len(report['files'])}));raise SystemExit(0 if report['status']=='passed'else 1)
