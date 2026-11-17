#!/usr/bin/env python3
"""Extract publisher dpkg/notice bytes from frozen qcow data without guest boot."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import struct
import subprocess
import tarfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('ud_material_inventory',Path(__file__).with_name('source_materials.py'))
inventory=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(inventory)
ROOT_TYPES={'arm64':'b921b045-1df0-41c3-af44-4c6f280d3fae','amd64':'4f68bce3-e8cd-4db1-96e7-fbcaf984b709'}


def digest(file):
    with Path(file).open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()


def command(arguments,timeout=120,input=None):
    result=subprocess.run(arguments,input=input,capture_output=True,timeout=timeout,check=False)
    if result.returncode or len(result.stdout)>16*1024**2 or len(result.stderr)>16*1024**2:
        raise ValueError('metadata tool failed: '+str(arguments[0])+' '+result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


def persist(output, report):
    temporary=output/'receipt.new'
    with temporary.open('w')as target:
        json.dump(report,target,indent=2);target.write('\n');target.flush();os.fsync(target.fileno())
    temporary.replace(output/'receipt.json')
    if os.name=='nt':
        spec=importlib.util.spec_from_file_location('ud_guest_windows_storage',ROOT/'scripts/quality/windows-storage-acl.py')
        storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage);native=storage.WindowsStorage()
        handle=native.kernel.CreateFileW(str(output),0x80000000|0x40000000,1|2,None,3,0x02000000|0x00200000,None)
        if handle==storage.ctypes.c_void_p(-1).value:raise storage.ctypes.WinError(storage.ctypes.get_last_error())
        try:
            native.inspect_handle(handle,str(output),'directory',True)
            native.require(native.kernel.FlushFileBuffers(handle))
        finally:native.kernel.CloseHandle(handle)
        return
    descriptor=os.open(output,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def inspect_owned(kind,name,owner):
    result=subprocess.run(['docker',*(['volume']if kind=='volume'else[]),'inspect',name],capture_output=True,timeout=30)
    if result.returncode:
        text=result.stderr.decode(errors='replace')
        if result.returncode==1 and result.stdout.strip()==b'[]' and any(value in text.lower() for value in('no such object: '+name,'no such container: '+name,'no such volume: '+name,'get '+name+': no such volume')):
            return None
        raise ValueError('source metadata resource inspection failed')
    values=json.loads(result.stdout)
    if len(values)!=1:raise ValueError('source metadata resource identity is ambiguous')
    labels=values[0].get('Labels')if kind=='volume'else values[0].get('Config',{}).get('Labels')
    if not isinstance(labels,dict)or labels.get('io.github.mehmetoguzderin.ud-agent.source-metadata')!=owner:
        raise ValueError('source metadata resource ownership changed')
    return values[0]


def cleanup(output,report):
    owner=report.get('owner')
    if not isinstance(owner,str)or len(owner)!=32 or any(c not in'0123456789abcdef'for c in owner):
        raise ValueError('source metadata recovery owner is invalid')
    expected=[{'kind':'container','name':'ud-source-metadata-'+owner+'-'+suffix}for suffix in('status','notices','lookup')]+[{'kind':'volume','name':'ud-source-metadata-'+owner}]
    if report.get('resources')!=expected:raise ValueError('source metadata recovery resources differ from the owner-bound contract')
    failures=[]
    for resource in expected:
        kind,name=resource['kind'],resource['name']
        try:
            current=inspect_owned(kind,name,owner)
            if current is not None:
                command(['docker',*(['volume','rm']if kind=='volume'else['rm','--force']),name],timeout=30)
                if inspect_owned(kind,name,owner)is not None:raise ValueError('source metadata resource remains after removal')
            report['cleanup'].append({**resource,'status':'removed-owned'if current is not None else'absent'})
        except Exception as error:
            failures.append({**resource,'error':str(error)});report['cleanup'].append({**resource,'status':'failed','error':str(error)})
        persist(output,report)
    if failures:raise ValueError('owned source metadata cleanup failed: '+json.dumps(failures))


def copy_partition(raw,partition,target):
    with raw.open('rb')as source,target.open('xb')as destination:
        source.seek(partition['offset']);remaining=partition['size']
        while remaining:
            chunk=source.read(min(8*1024**2,remaining))
            if not chunk:raise ValueError('guest partition is truncated')
            if chunk.count(0)==len(chunk):destination.seek(len(chunk),1)
            else:destination.write(chunk)
            remaining-=len(chunk)
        destination.truncate(partition['size'])
    target.chmod(0o444)


def extract(architecture,image_file,output,qemu_img=None,lock_file=None,tool_receipt=None):
    output=output.resolve();image_file=image_file.resolve(strict=True)
    if output.exists()or architecture not in ROOT_TYPES:raise ValueError('new output and supported source architecture required')
    lock_file=lock_file or ROOT/'runtime/lima-guest.lock.json';tool_receipt=tool_receipt or ROOT/'runtime/materials/lima-ubuntu/nsenter-extraction.json'
    locked=json.loads(lock_file.read_bytes());tools=json.loads(tool_receipt.read_bytes());image=locked['images'][architecture]
    if image_file.stat().st_size!=image['size_bytes']or digest(image_file)!=image['sha256'].removeprefix('sha256:'):
        raise ValueError('guest source image differs from its exact release lock')
    with image_file.open('rb')as source:header=source.read(104)
    if len(header)<104 or header[:4]!=b'QFI\xfb'or struct.unpack_from('>I',header,4)[0]not in(2,3)or any(header[8:20])or struct.unpack_from('>Q',header,72)[0]&4:
        raise ValueError('guest qcow has external backing/data or an unsupported header')
    qemu=Path(qemu_img or tools['qemu_img']['path']).resolve(strict=True)
    if digest(qemu)!=tools['qemu_img']['sha256'].removeprefix('sha256:'):
        raise ValueError('native image decoder differs from its frozen tool receipt')
    if platform.machine().lower()not in('arm64','aarch64'):raise ValueError('this frozen source decoder is native ARM64; no target emulation is allowed')
    host=os.environ.get('DOCKER_HOST')
    if host and not host.startswith('unix:///'):raise ValueError('source metadata extraction requires a local Unix container endpoint')
    if not host:
        contexts=json.loads(command(['docker','context','inspect']))
        if len(contexts)!=1 or not contexts[0].get('Endpoints',{}).get('docker',{}).get('Host','').startswith('unix:///'):
            raise ValueError('source metadata extraction requires a verified local endpoint')
    tool_image=tools['extraction']['tool_image'];inspected=json.loads(command(['docker','image','inspect',tool_image]))
    if len(inspected)!=1 or inspected[0]['Id']!=tool_image or inspected[0]['Architecture']!='arm64'or inspected[0]['Os']!='linux':
        raise ValueError('metadata extractor image is not the frozen native ARM64 tool')
    output.mkdir(parents=True,mode=0o700);(output/'INCOMPLETE').write_text('Source metadata extraction is not complete.\n')
    raw=output/'guest.raw';command([str(qemu),'convert','-f','qcow2','-O','raw',str(image_file),str(raw)],timeout=300)
    partition=inventory.guest_partition(raw)
    if partition['type_guid']!=ROOT_TYPES[architecture]:raise ValueError('guest root partition has the wrong architecture-specific identity')
    rootfs=output/'rootfs.ext4';copy_partition(raw,partition,rootfs);raw.unlink()
    owner=uuid.uuid4().hex;label='io.github.mehmetoguzderin.ud-agent.source-metadata='+owner;volume='ud-source-metadata-'+owner;containers=[]
    report={'schema_version':1,'qualification':'image-bound-publisher-package-and-notice-inventory','status':'failed','guest_execution':False,'emulation':False,
            'guest_architecture':architecture,'host':{'os':platform.system(),'architecture':platform.machine()},'tool_process_architecture':'arm64','image':image,
            'image_lock_sha256':digest(lock_file),'decoder':{'sha256':digest(qemu),'version':command([str(qemu),'--version']).decode().splitlines()[0]},
            'extractor_image':tool_image,'partition':partition,'rootfs_sha256':digest(rootfs),'owner':owner,'cleanup':[],'resources':[{'kind':'container','name':'ud-source-metadata-'+owner+'-'+suffix}for suffix in('status','notices','lookup')]+[{'kind':'volume','name':volume}]}
    persist(output,report)
    def create(suffix,arguments,extra=()):
        name='ud-source-metadata-'+owner+'-'+suffix
        command(['docker','create','--name',name,'--label',label,'--platform','linux/arm64','--user','10001:10001','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','1','--pids-limit','32','--mount','type=bind,src='+str(rootfs)+',dst=/input/rootfs.ext4,readonly','--mount','type=volume,src='+volume+',dst=/output',*extra,'--entrypoint','/usr/sbin/debugfs',tool_image,*arguments]);containers.append(name);return name
    def start(name):
        result=command(['docker','start','--attach',name],timeout=120);return result
    try:
        command(['docker','volume','create','--label',label,volume])
        first=create('status',['-R','dump /var/lib/dpkg/status /output/data/status','/input/rootfs.ext4'])
        payload=io.BytesIO()
        with tarfile.open(fileobj=payload,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name in('data','data/copyright'):
                entry=tarfile.TarInfo(name);entry.type=tarfile.DIRTYPE;entry.mode=0o700;entry.uid=entry.gid=10001;archive.addfile(entry)
        command(['docker','cp','--archive','-',first+':/output'],input=payload.getvalue());start(first)
        command(['docker','cp',first+':/output/data/status',str(output/'status')])
        manifest=ROOT/'runtime/materials/lima-ubuntu'/(architecture+'.manifest')
        if manifest.stat().st_size!=image['manifest']['size_bytes']or digest(manifest)!=image['manifest']['sha256'].removeprefix('sha256:'):
            raise ValueError('publisher guest package manifest differs from its lock')
        packages=inventory.installed_packages((output/'status').read_bytes(),manifest.read_bytes(),architecture)
        script=output/'commands';script.write_text(''.join('dump '+item['notice_guest_path']+' /output/data/copyright/'+item['notice_basename']+'\n'for item in packages));script.chmod(0o444)
        second=create('notices',['-f','/input/commands','/input/rootfs.ext4'],['--mount','type=bind,src='+str(script)+',dst=/input/commands,readonly'])
        start(second);command(['docker','cp',second+':/output/data/copyright',str(output/'copyright')])
        # debugfs dump does not follow a final symlink. Resolve only the
        # image's own bounded notice links; never expose host filesystem links.
        def lookup(arguments):
            name=create('lookup',arguments)
            result=start(name)
            if inspect_owned('container',name,owner)is None:raise ValueError('source notice reader disappeared')
            command(['docker','rm',name]);return result.decode('utf-8',errors='strict')
        for item in packages:
            target=output/'copyright'/item['notice_basename']
            if target.exists()and target.stat().st_size:continue
            current=item['notice_guest_path'];chain=[]
            for attempt in range(32):
                if current in chain:raise ValueError('image notice symlink cycle')
                chain.append(current)
                text=lookup(['-R','stat '+current,'/input/rootfs.ext4'])
                kind=re.search(r'^Inode: [0-9]+ +Type: ([A-Za-z]+) ',text,re.M)
                if kind is None:raise ValueError('image notice is missing')
                if kind[1]=='regular':
                    destination='/output/data/copyright/'+item['notice_basename']
                    lookup(['-R','dump '+current+' '+destination,'/input/rootfs.ext4'])
                    command(['docker','cp',first+':'+destination,str(target)])
                    item['notice_link_chain']=chain
                    break
                match=re.search(r'^Fast link dest: "([^"\r\n]+)"$',text,re.M)
                if kind[1]!='symlink'or match is None:raise ValueError('notice is not a bounded regular file or short link')
                link=match[1]
                if not re.fullmatch(r'[A-Za-z0-9_./+-]+',link):raise ValueError('unsafe image notice link')
                current=posixpath.normpath(posixpath.join(posixpath.dirname(current),link))
                if not any(current.startswith(prefix)for prefix in('/usr/share/doc/','/usr/share/common-licenses/')):raise ValueError('image notice link escapes its data roots')
            else:raise ValueError('image notice link chain exceeds its bound')
        expected={item['notice_basename']for item in packages};actual={file.name for file in(output/'copyright').iterdir()}
        if actual!=expected:raise ValueError('guest copyright closure is missing or has extra notices')
        for item in packages:
            file=output/'copyright'/item['notice_basename']
            if file.is_symlink()or not file.is_file()or file.stat().st_nlink!=1 or not 0<file.stat().st_size<=8*1024**2:raise ValueError('guest copyright is not bounded ordinary data')
            item['notice']={'path':'copyright/'+file.name,'sha256':digest(file),'size_bytes':file.stat().st_size};file.chmod(0o444)
        if digest(image_file)!=image['sha256'].removeprefix('sha256:'):raise ValueError('guest source image changed during extraction')
        report.update(status='passed',packages=packages,status_file={'path':'status','sha256':digest(output/'status'),'size_bytes':(output/'status').stat().st_size})
    except BaseException as error:
        report['status']='failed';report['error']=type(error).__name__+': '+str(error);persist(output,report)
        raise
    finally:
        cleanup(output,report)
    if report['status']!='passed':raise ValueError('guest source metadata did not complete')
    rootfs.unlink();script.unlink();(output/'INCOMPLETE').unlink();return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--architecture',choices=ROOT_TYPES,required=True);parser.add_argument('--image',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--qemu-img',type=Path);parser.add_argument('--recover',action='store_true');args=parser.parse_args()
    if args.recover:
        cleanup(args.output.resolve(strict=True),json.loads((args.output/'receipt.json').read_bytes()));print(json.dumps({'cleanup':'verified'}));raise SystemExit(0)
    result=extract(args.architecture,args.image,args.output,args.qemu_img);print(json.dumps({'status':result['status'],'packages':len(result['packages']),'architecture':args.architecture,'guest_execution':False}))
