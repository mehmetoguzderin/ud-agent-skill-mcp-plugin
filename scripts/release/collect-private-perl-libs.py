#!/usr/bin/env python3
"""Bind privately shipped Perl ELF bytes to exact provider-image dpkg sources."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import uuid

ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
owned=module('ud_private_elf_owned','extract-guest-materials.py');materials=module('ud_private_elf_materials','source_materials.py')
SCRIPT=r'''
import base64,hashlib,json,pathlib,re,subprocess,sys
expected=json.loads(sys.argv[1]);mappings=[];notices={}
if not expected or len(expected)>64:raise ValueError('bounded library inventory required')
for leaf,fingerprint in sorted(expected.items()):
 if not re.fullmatch(r'[A-Za-z0-9+_.-]+',leaf)or not re.fullmatch('[0-9a-f]{64}',fingerprint):raise ValueError('unsafe library identity')
 found={}
 for prefix in('/lib/aarch64-linux-gnu/','/usr/lib/aarch64-linux-gnu/','/lib/'):
  candidate=pathlib.Path(prefix+leaf)
  if candidate.exists():
   resolved=candidate.resolve(strict=True)
   if not str(resolved).startswith(('/lib/','/usr/lib/'))or not resolved.is_file():raise ValueError('library escapes image data roots')
   raw=resolved.read_bytes()
   if len(raw)>32*1024**2:raise ValueError('library exceeds bound')
   if hashlib.sha256(raw).hexdigest()==fingerprint:found.setdefault(str(resolved),set()).add(str(candidate))
 if len(found)!=1:raise ValueError('library has no unique byte-exact image origin: '+leaf)
 resolved,aliases=next(iter(found.items()));aliases.add(resolved)
 for alias in list(aliases):
  if alias.startswith('/usr/lib/'):aliases.add(alias.removeprefix('/usr'))
  elif alias.startswith('/lib/'):aliases.add('/usr'+alias)
 owners=set();lists=[]
 for alias in sorted(aliases):
  result=subprocess.run(['/usr/bin/dpkg-query','--search',alias],capture_output=True,timeout=10)
  if result.returncode not in(0,1)or len(result.stdout)>1024**2:raise ValueError('bounded package ownership query failed')
  for line in result.stdout.decode('utf-8').splitlines():
   owner,separator,path=line.partition(': ')
   if separator and path==alias and re.fullmatch(r'[a-z0-9+.-]+(?::arm64)?',owner):owners.add(owner)
 if len(owners)!=1:raise ValueError('ELF package owner is missing or ambiguous: '+leaf)
 owner=next(iter(owners));name=owner.split(':')[0]
 list_candidates=[pathlib.Path('/var/lib/dpkg/info/'+owner+'.list'),pathlib.Path('/var/lib/dpkg/info/'+name+'.list')]
 actual_lists=[file for file in list_candidates if file.is_file()]
 if len({file.resolve()for file in actual_lists})!=1:raise ValueError('package file list is missing or ambiguous')
 filelist=actual_lists[0].read_bytes()
 if len(filelist)>8*1024**2 or not aliases.intersection(filelist.decode('utf-8').splitlines()):raise ValueError('package file list does not independently contain its library')
 copyright=pathlib.Path('/usr/share/doc/'+name+'/copyright').resolve(strict=True)
 if not str(copyright).startswith(('/usr/share/doc/','/usr/share/common-licenses/'))or not copyright.is_file():raise ValueError('notice escapes controlled image data roots')
 notice=copyright.read_bytes()
 if not 0<len(notice)<=8*1024**2:raise ValueError('notice exceeds bound')
 notices[name]={'resolved_path':str(copyright),'bytes_base64':base64.b64encode(notice).decode()}
 mappings.append({'library':leaf,'sha256':fingerprint,'resolved_image_path':resolved,'aliases':sorted(aliases),'package':name,'package_list_path':str(actual_lists[0]),'package_list_base64':base64.b64encode(filelist).decode()})
status=pathlib.Path('/var/lib/dpkg/status').read_bytes()
if len(status)>16*1024**2:raise ValueError('package status exceeds bound')
print(json.dumps({'schema_version':1,'mappings':mappings,'notices':notices,'status_base64':base64.b64encode(status).decode()},separators=(',',':')))
'''


def derive(status,mappings,notices,expected,output):
    names={row['package']for row in mappings}
    if len(mappings)!=len(expected)or {row['library']for row in mappings}!=set(expected):raise ValueError('ELF source mapping is incomplete or duplicate')
    records=[row for row in materials.control_records(status)if row.get('Status')=='install ok installed'and row.get('Package')in names]
    manifest=''.join(row['Package']+'\t'+row['Version']+'\n'for row in records).encode();packages=materials.installed_packages(b'\n\n'.join('\n'.join(key+': '+value.replace('\n','\n ') for key,value in row.items()).encode()for row in records),manifest,'arm64')
    if {row['name']for row in packages}!=names:raise ValueError('ELF package status omits an independently observed owner')
    for row in mappings:
        if row['sha256']!=expected[row['library']]:raise ValueError('private ELF bytes differ from their source mapping')
        aliases=row.get('aliases',[])
        if not isinstance(aliases,list)or not aliases or len(set(aliases))!=len(aliases)or row.get('resolved_image_path')not in aliases or any(not re.fullmatch(r'/(?:usr/)?lib/(?:aarch64-linux-gnu/)?[A-Za-z0-9+_.-]+',name)for name in aliases):raise ValueError('ELF image aliases are invalid')
        body=base64.b64decode(row.pop('package_list_base64'),validate=True)
        if not set(aliases).intersection(body.decode('utf-8').splitlines())or len(body)>8*1024**2:raise ValueError('ELF package file list does not contain its exact library')
        file=output/'package-lists'/hashlib.sha256(body).hexdigest();file.parent.mkdir(exist_ok=True);file.write_bytes(body);row['package_list']={'path':file.relative_to(output).as_posix(),'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)}
    for package in packages:
        notice=notices[package['name']];body=base64.b64decode(notice['bytes_base64'],validate=True);file=output/'copyright'/hashlib.sha256(body).hexdigest();file.parent.mkdir(exist_ok=True);file.write_bytes(body);package['notice']={'path':file.relative_to(output).as_posix(),'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body),'resolved_image_path':notice['resolved_path']}
    return packages


def collect(pack_root,receipt_file,output):
    if output.exists():raise ValueError('new private ELF source inventory output required')
    definition=json.loads(receipt_file.read_bytes());origin=definition.get('elf_origin',{});provider=origin.get('provider','')
    if definition.get('platform')!='linux/arm64'or origin.get('machine')!=183 or not re.fullmatch(r'ghcr\.io/catthehacker/ubuntu@sha256:[0-9a-f]{64}',provider)or not origin.get('libraries'):raise ValueError('private ELF provider receipt is missing or unsupported')
    expected=origin['libraries']
    for leaf,fingerprint in expected.items():
        matches=[row for row in definition['files']if row['path'].rsplit('/',1)[-1]==leaf and row['sha256'].removeprefix('sha256:')==fingerprint]
        if not matches:raise ValueError('ELF origin is absent from the private runtime inventory')
        for row in matches:
            file=pack_root/row['path']
            if file.is_symlink()or file.stat().st_size!=row['size']or owned.digest(file)!=fingerprint:raise ValueError('private runtime ELF input is corrupt')
    inspection=json.loads(owned.command(['docker','image','inspect',provider]))
    if len(inspection)!=1 or inspection[0]['Id']!=provider.split('@')[1]or inspection[0]['Architecture']!='arm64'or inspection[0]['Os']!='linux':raise ValueError('private ELF source provider is not the exact native ARM image')
    output.mkdir(parents=True,mode=0o700);owner=uuid.uuid4().hex;name='ud-source-metadata-'+owner+'-status';label='io.github.mehmetoguzderin.ud-agent.source-metadata='+owner
    resources=[{'kind':'container','name':'ud-source-metadata-'+owner+'-'+suffix}for suffix in('status','notices','lookup')]+[{'kind':'volume','name':'ud-source-metadata-'+owner}]
    report={'schema_version':1,'qualification':'image-bound-publisher-package-and-notice-inventory','status':'failed','guest_execution':False,'target_execution':False,'emulation':False,'guest_architecture':'arm64','image':{'sha256':inspection[0]['Id'],'kind':'private-library-origin-container'},'host':{'os':platform.system(),'architecture':platform.machine()},'owner':owner,'resources':resources,'cleanup':[],'private_runtime_receipt_sha256':owned.digest(receipt_file),'reader_sha256':hashlib.sha256(SCRIPT.encode()).hexdigest(),'provider_diff_ids':inspection[0]['RootFS']['Layers']};owned.persist(output,report)
    try:
        owned.command(['docker','create','--name',name,'--label',label,'--pull','never','--platform','linux/arm64','--user','65534:65534','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','1','--pids-limit','32','--entrypoint','/usr/bin/python3',provider,'-I','-B','-c',SCRIPT,json.dumps(expected)],timeout=30)
        current=owned.inspect_owned('container',name,owner);host=current['HostConfig']
        if current['Image']!=inspection[0]['Id']or current['Config']['User']!='65534:65534'or host['NetworkMode']!='none'or not host['ReadonlyRootfs']or host['CapDrop']!=['ALL']or current.get('Mounts')or host['Memory']!=256*1024**2 or host['NanoCpus']!=10**9:raise ValueError('source reader containment differs')
        raw=owned.command(['docker','start','--attach',name],timeout=60);(output/'reader-output.json').write_bytes(raw);report['reader_output']={'path':'reader-output.json','sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)};observed=json.loads(raw)
        if observed.get('schema_version')!=1:raise ValueError('source reader framing differs')
        status=base64.b64decode(observed['status_base64'],validate=True);(output/'status').write_bytes(status);report['packages']=derive(status,observed['mappings'],observed['notices'],expected,output);report['library_mappings']=observed['mappings'];report['status_file']={'path':'status','sha256':hashlib.sha256(status).hexdigest(),'size_bytes':len(status)};report['status']='passed'
    finally:owned.cleanup(output,report)
    owned.persist(output,report);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pack',type=Path,required=True);parser.add_argument('--receipt',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();result=collect(args.pack,args.receipt,args.output);print(json.dumps({'status':result['status'],'libraries':len(result['library_mappings']),'packages':len(result['packages'])}))
