#!/usr/bin/env python3
"""Inspect shipped Go binaries as data and verify their exact module source ZIPs."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
from urllib.parse import quote
from urllib.request import urlopen
import zipfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_sources',Path(__file__).with_name('source_materials.py'));materials=importlib.util.module_from_spec(spec);spec.loader.exec_module(materials)
spec=importlib.util.spec_from_file_location('ud_source_acquisition',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)
PROGRAMS=['bin/nerdctl','bin/containerd','bin/containerd-shim-runc-v2','bin/runc','bin/rootlesskit','bin/rootlessctl','bin/ctr']


def escaped(value):
    if not isinstance(value,str)or not re.fullmatch(r'[A-Za-z0-9./+_~-]+',value)or any(part in('','.','..')for part in value.split('/')):raise ValueError('unsafe Go module identity')
    return ''.join('!'+character.lower()if character.isupper()else character for character in value)


def collect(inputs,output,go,go_sha,download,derived=None,derived_inputs=None,reuse=None):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True);locked=json.loads((ROOT/'runtime/lima-inputs.lock.json').read_bytes());binaries=[];modules={};mains=[];standards=set()
    derivation=None
    if derived is not None:
        spec=importlib.util.spec_from_file_location('ud_derived_lima',ROOT/'scripts/runtime/prepare-lima-assets.py');lima=importlib.util.module_from_spec(spec);spec.loader.exec_module(lima)
        derivation=json.loads((derived/'derived-runtimes.json').read_bytes())
    for architecture in('arm64','amd64'):
        replacements=lima.derived_members(derived,architecture)[0]if derived is not None else {}
        name='nerdctl-full-2.4.2-linux-'+architecture+'.tar.gz';record=next(row for row in locked['assets']if row['name']==name);archive=inputs/name
        if archive.is_symlink()or archive.stat().st_size!=record['size']or acquisition.digest(archive)!=record['sha256']:raise ValueError('Go runtime source subject archive differs from its provider lock')
        with tarfile.open(archive,'r:gz')as source:
            found=set()
            for member in source:
                if member.name not in PROGRAMS:continue
                if member.name in found or not member.isfile()or not 0<member.size<=256*1024**2:raise ValueError('shipped Go executable is duplicate, linked or oversized')
                found.add(member.name);original=source.extractfile(member).read(member.size+1)
                if len(original)!=member.size:raise ValueError('source subject archive member is truncated')
                body=replacements.get(member.name,(original,None))[0]
                if not body or body[:6]!=b'\x7fELF\x02\x01'or int.from_bytes(body[18:20],'little')!=({'arm64':183,'amd64':62}[architecture]):raise ValueError('Go source subject architecture differs')
                binary=output/'subjects'/architecture/member.name;binary.parent.mkdir(parents=True,exist_ok=True)
                if binary.exists():
                    if binary.is_symlink()or binary.stat().st_size!=len(body)or acquisition.digest(binary)!=materials.sha(body):raise ValueError('cached source subject bytes differ from its provider archive')
                else:binary.write_bytes(body);binary.chmod(0o444)
                info=materials.go_build_info(binary,go,go_sha);binaries.append({'path':binary.relative_to(output).as_posix(),'sha256':materials.sha(body),'size_bytes':len(body),'architecture':architecture,'provider_archive':record,'binary_origin':'controlled-source-derivation'if member.name in replacements else'original-upstream-release','build_info':info})
                standards.add(info['go_version']);settings={row['Key']:row.get('Value','')for row in info['build_settings']}
                main=info['main'];commit=settings.get('vcs.revision');version=main['Version']
                if member.name in replacements:
                    proof=derivation['runc_derivation']if member.name=='bin/runc'else derivation['containerd_derivation'];commit=proof['commit'];version='v'+proof['version']
                mains.append({'path':main['Path'],'version':version,'commit':commit,'cgo':settings.get('CGO_ENABLED'),'consumers':[binary.relative_to(output).as_posix()]})
                for module in info['dependencies']:
                    key=module['path']+'\0'+module['version']
                    if key in modules and modules[key]['h1']is not None and module['h1']is not None and modules[key]['h1']!=module['h1']:raise ValueError('binary module metadata disagrees on exact source bytes')
                    selected=modules.setdefault(key,{**module,'consumers':[]});selected['consumers'].append(binary.relative_to(output).as_posix())
            if found!=set(PROGRAMS):raise ValueError('provider archive omits a shipped Go executable')
    source_mains={};source_sums={}
    for main in mains:
        if not main['path'].startswith('github.com/')or not re.fullmatch('[0-9a-f]{40}',main.get('commit')or''):
            raise ValueError('Go main source lacks an exact supported repository commit')
        repository='/'.join(main['path'].split('/')[1:3]);key=repository+'@'+main['commit']
        if key in source_mains:continue
        target=output/'main-sources'/materials.sha(key.encode());url='https://codeload.github.com/'+repository+'/tar.gz/'+main['commit']
        if reuse is not None and not target.exists():
            candidate=reuse/'main-sources'/target.name
            if candidate.is_file()and not candidate.is_symlink():target.parent.mkdir(parents=True,exist_ok=True);__import__('shutil').copyfile(candidate,target);target.chmod(0o444)
        if download:acquisition.acquire(url,target,maximum=1024**3)
        record={'repository':repository,'commit':main['commit'],'url':url,'path':target.relative_to(output).as_posix(),'acquired':False}
        if target.exists():
            sums=None;notices=[]
            with tarfile.open(target,'r:gz')as source:
                seen=set();total=0
                for member in source:
                    if len(seen)>100_000 or member.name in seen or member.name.startswith('/')or any(part in('','.','..')for part in member.name.split('/')):raise ValueError('main source archive has unsafe or duplicate names')
                    seen.add(member.name)
                    if member.isdir():continue
                    if member.issym()or member.islnk():continue # Preserve archive bytes; never extract repository links.
                    if not member.isfile()or not 0<=member.size<=512*1024**2:raise ValueError('main source contains an oversized or special member')
                    total+=member.size
                    if total>4*1024**3:raise ValueError('main source expansion exceeds its bound')
                    parts=member.name.split('/')
                    if len(parts)==2 and parts[-1]=='go.sum':
                        if sums is not None or member.size>32*1024**2:raise ValueError('main source go.sum is duplicated or oversized')
                        sums=source.extractfile(member).read().decode('utf-8')
                    if len(parts)==2 and re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$',parts[-1].lower()):
                        body=source.extractfile(member).read(8*1024**2+1)
                        if len(body)>8*1024**2:raise ValueError('main source notice exceeds bound')
                        notices.append({'path':member.name,'sha256':materials.sha(body),'size_bytes':len(body)})
            if sums is None:raise ValueError('main source has no module content contract')
            for line in sums.splitlines():
                fields=line.split()
                if len(fields)!=3 or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=',fields[2]):raise ValueError('main source go.sum entry is malformed')
                if fields[1].endswith('/go.mod'):continue
                identity=fields[0]+'\0'+fields[1]
                if identity in source_sums and source_sums[identity]!=fields[2]:raise ValueError('main sources disagree on module content')
                source_sums[identity]=fields[2]
            record.update(acquired=True,sha256=acquisition.digest(target),size_bytes=target.stat().st_size,license_files=notices)
        source_mains[key]=record
    for identity,module in modules.items():
        contracted=source_sums.get(identity)
        if contracted is not None and module['h1']is not None and module['h1']!=contracted:raise ValueError('module hash differs between binary metadata and exact main source')
        if module['h1']is None:module['h1']=contracted;module['hash_origin']='exact-main-source-go.sum'
        else:module['hash_origin']='embedded-binary-module-metadata'
    def obtain(module):
        target=output/'modules'/materials.sha((module['path']+'@'+module['version']).encode())
        url='https://proxy.golang.org/'+escaped(module['path'])+'/@v/'+escaped(module['version'])+'.zip'
        if reuse is not None and not target.exists():
            candidate=reuse/'modules'/target.name
            if candidate.is_file()and not candidate.is_symlink():target.parent.mkdir(parents=True,exist_ok=True);__import__('shutil').copyfile(candidate,target);target.chmod(0o444)
        if download and module['h1']is not None:acquisition.acquire(url,target,maximum=512*1024**2)
        record={**module,'url':url,'archive':{'path':target.relative_to(output).as_posix()},'acquired':False}
        if target.exists():
            if materials.go_zip_hash(target,module['path'],module['version'])!=module['h1']:raise ValueError('Go source ZIP differs from the hash embedded in shipped binary')
            licenses=[]
            with zipfile.ZipFile(target)as source:
                for item in source.infolist():
                    if re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$',item.filename.rsplit('/',1)[-1].lower()):
                        body=source.read(item)
                        if len(body)>8*1024**2:raise ValueError('Go source notice exceeds bound')
                        licenses.append({'path':item.filename,'sha256':materials.sha(body),'size_bytes':len(body)})
            record.update(acquired=True,archive={**record['archive'],'sha256':acquisition.digest(target),'size_bytes':target.stat().st_size},license_files=licenses)
        return record
    with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:records=list(pool.map(obtain,[modules[key]for key in sorted(modules)]))
    standard_records=[];go_catalog=output/'metadata/go-releases.json'
    if download:acquisition.acquire('https://go.dev/dl/?mode=json&include=all',go_catalog,maximum=32*1024**2)
    if go_catalog.exists():
        releases=json.loads(go_catalog.read_bytes())
        for version in sorted(standards):
            matches=[asset for release in releases if release.get('version')==version for asset in release.get('files',[])if asset.get('kind')=='source']
            if len(matches)!=1:raise ValueError('exact Go standard-library source is missing or ambiguous')
            item=matches[0]
            if not re.fullmatch(r'go[0-9]+\.[0-9]+\.[0-9]+\.src\.tar\.gz',item.get('filename',''))or not re.fullmatch('[0-9a-f]{64}',item.get('sha256',''))or not 0<item.get('size',0)<=256*1024**2:raise ValueError('official Go source descriptor is invalid')
            target=output/'standard-libraries'/item['filename'];url='https://go.dev/dl/'+item['filename']
            if download:acquisition.acquire(url,target,item['size'],item['sha256'])
            standard_records.append({'version':version,'url':url,'path':target.relative_to(output).as_posix(),'sha256':item['sha256'],'size_bytes':item['size'],'acquired':target.exists(),'publisher_catalog':{'path':go_catalog.relative_to(output).as_posix(),'sha256':acquisition.digest(go_catalog),'url':'https://go.dev/dl/?mode=json&include=all'}})
    runtime_sources=[]
    if derived is not None:
        if derived_inputs is None:raise ValueError('derived runtime needs its actual source archive input root')
        for item in derivation['source_inputs']['files']:
            if item['role']not in('go-source','zig-source','libseccomp-source'):continue
            candidate=derived_inputs/item['path']
            if candidate.is_symlink()or candidate.stat().st_size!=item['size_bytes']or acquisition.digest(candidate)!=item['sha256']:raise ValueError('derived C/runtime source differs from its build-input contract')
            target=output/'runtime-sources'/item['sha256'];target.parent.mkdir(exist_ok=True)
            if not target.exists():__import__('shutil').copyfile(candidate,target);target.chmod(0o444)
            runtime_sources.append({**item,'path':target.relative_to(output).as_posix(),'acquired':True})
        if {row['role']for row in runtime_sources}!={'go-source','zig-source','libseccomp-source'}:raise ValueError('derived runtime source closure is incomplete')
    cgo_pending=[row for row in mains if row['cgo']=='1'and not(derivation is not None and row['commit']==derivation['runc_derivation']['commit'])]
    complete=all(row['acquired']for row in records)and all(row['acquired']for row in source_mains.values())and standards=={row['version']for row in standard_records if row['acquired']}and not cgo_pending
    # C/static dependencies need actual build-input receipts. Their absence
    # remains explicit even after every Go module/source archive is acquired.
    # Main modules and C/static dependencies need their own commit/source
    # receipts. Their absence is never mistaken for complete source closure.
    report={'schema_version':1,'qualification':'binary-bound-go-module-source-inventory','status':'passed'if complete else'incomplete','target_execution':False,'emulation':False,'go_inspector':{'path':str(go.resolve()),'sha256':go_sha},'binaries':binaries,'modules':records,'main_sources':list(source_mains.values()),'main_modules':mains,'module_hashes_pending':[row for row in records if row['h1']is None],'standard_libraries':standard_records,'standard_libraries_pending':sorted(standards-set(item['version']for item in standard_records if item['acquired'])),'derived_runtime_sources':runtime_sources,'derivation':derivation,'static_c_dependencies_pending':cgo_pending}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--go',type=Path,required=True);parser.add_argument('--go-sha256',required=True);parser.add_argument('--download',action='store_true');parser.add_argument('--derived-runtime',type=Path);parser.add_argument('--derived-inputs',type=Path);parser.add_argument('--reuse',type=Path);args=parser.parse_args()
    report=collect(args.inputs,args.output,args.go,args.go_sha256,args.download,args.derived_runtime,args.derived_inputs,args.reuse);print(json.dumps({'binaries':len(report['binaries']),'modules':len(report['modules']),'acquired':sum(row['acquired']for row in report['modules']),'status':report['status']}))
