"""Derive a verifier-only PBS prefix inventory; never approve or execute it."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('verifier_runtime_paths', ROOT/'workers/ud/src/ud_agent/unicode_paths.py')
paths = importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)


def digest(file):
    with file.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


@contextmanager
def verified_tar(archive,asset):
    if archive.is_symlink():raise ValueError('verifier archive cannot be a link')
    with archive.open('rb')as held:
        before=os.fstat(held.fileno())
        if before.st_size!=asset['size']or 'sha256:'+hashlib.file_digest(held,'sha256').hexdigest()!=asset['digest']:raise ValueError('verifier archive bytes differ from frozen publisher asset')
        held.seek(0)
        with tarfile.open(fileobj=held,mode='r:gz')as bundle:yield bundle
        after=os.fstat(held.fileno())
        state=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if state(before)!=state(after):raise ValueError('verifier archive changed during same-FD inspection')


def native_slices(body):
    cpus={0x100000c:'darwin-arm64',0x1000007:'darwin-x64'}
    if body[:4]==b'\xcf\xfa\xed\xfe':
        if len(body)<32:raise ValueError('truncated verifier Mach-O header')
        cpu=struct.unpack_from('<I',body,4)[0]
        if cpu not in cpus:raise ValueError('unsupported verifier Mach-O CPU')
        return [(cpus[cpu],body)]
    fat={b'\xca\xfe\xba\xbe':('>',20),b'\xca\xfe\xba\xbf':('>',32),b'\xbe\xba\xfe\xca':('<',20),b'\xbf\xba\xfe\xca':('<',32)}
    if body[:4]in fat:
        endian,width=fat[body[:4]]
        if len(body)<8:raise ValueError('truncated verifier fat header')
        count=struct.unpack_from(endian+'I',body,4)[0]
        if not 1<=count<=8 or 8+count*width>len(body):raise ValueError('invalid verifier fat slice count')
        slices=[];ranges=[];seen=set()
        for index in range(count):
            start=8+index*width;cpu=struct.unpack_from(endian+'I',body,start)[0]
            offset,size=struct.unpack_from(endian+('II'if width==20 else'QQ'),body,start+8)
            if cpu not in cpus or cpu in seen or not size or offset<8+count*width or offset+size>len(body)or any(offset<end and begin<offset+size for begin,end in ranges):raise ValueError('invalid verifier fat slice bounds or CPU')
            if body[offset:offset+4]!=b'\xcf\xfa\xed\xfe':raise ValueError('verifier fat slice is not a supported thin Mach-O')
            inner=native_slices(body[offset:offset+size])
            if len(inner)!=1 or inner[0][0]!=cpus[cpu]:raise ValueError('verifier fat slice CPU differs from its thin header')
            slices.extend(inner);seen.add(cpu);ranges.append((offset,offset+size))
        return slices
    if body[:4]in(b'\xfe\xed\xfa\xcf',b'\xfe\xed\xfa\xce',b'\xce\xfa\xed\xfe'):raise ValueError('unsupported verifier Mach-O encoding')
    return []


def macho_dependencies(body):
    if body[:4] != b'\xcf\xfa\xed\xfe':return [],[]
    if len(body)<32:raise ValueError('truncated verifier native header')
    count,size=struct.unpack_from('<II',body,16)
    if count>4096 or size>len(body)-32:raise ValueError('invalid verifier native commands')
    result=[];rpaths=[];offset=32
    for _ in range(count):
        if offset+8>32+size:raise ValueError('truncated verifier native command')
        command,length=struct.unpack_from('<II',body,offset)
        if length<8 or offset+length>32+size:raise ValueError('invalid verifier native command size')
        if command in (12,14,0x80000018,0x8000001f,0x80000023,0x8000001c):
            if length<12:raise ValueError('truncated verifier native dependency command')
            start=offset+struct.unpack_from('<I',body,offset+8)[0]
            if not offset+12<=start<offset+length:raise ValueError('invalid verifier native dependency string')
            end=body.find(b'\0',start,offset+length)
            if end<0:raise ValueError('unterminated verifier dependency')
            (rpaths if command==0x8000001c else result).append(body[start:end].decode('utf-8','strict'))
        offset+=length
    return result,rpaths


def derive(root,archive,asset_name,platform):
    generator_sha256=digest(Path(__file__))
    if platform not in ('darwin-arm64','darwin-x64'):raise ValueError('other verifier platforms are not provisioned by this producer')
    receipt_file=root/'runtime/receipts/userspace-python-release.json';release=json.loads(receipt_file.read_bytes())
    rows=[row for row in release['assets']if row['name']==asset_name]
    if len(rows)!=1 or release['tag_name']!='20261026':raise ValueError('verifier archive is not in the frozen publisher release')
    asset=rows[0]
    files={};links={};seen=set();excluded=[];total=0;dependencies=[];native_files=[];support=[]
    with verified_tar(archive,asset)as bundle:
        for row in bundle:
            name=paths.validate_path(row.name.rstrip('/')if row.isdir()else row.name);key=paths.path_key(name)
            if not name.startswith('python/')or key in seen or len(seen)>=100000:raise ValueError('verifier archive path is foreign or duplicate')
            seen.add(key);name=name[7:]
            if row.isdir():continue
            if not name or not 0<=row.size<=512*1024**2:raise ValueError('verifier member size is invalid')
            total+=row.size
            if total>2*1024**3:raise ValueError('verifier archive expansion exceeds bound')
            if '__pycache__'in name.split('/')or name.endswith('.pyc'):excluded.append(name);continue
            if row.issym()or row.islnk():
                target=posixpath.normpath(posixpath.join(posixpath.dirname('python/'+name),row.linkname)if row.issym()else row.linkname)
                if not target.startswith('python/'):raise ValueError('verifier alias leaves its prefix')
                links[name]={'path':name,'linkname':row.linkname,'target':target[7:]};continue
            if not row.isfile():raise ValueError('verifier archive has a special member')
            body=bundle.extractfile(row).read(row.size+1)
            if len(body)!=row.size:raise ValueError('verifier member is truncated')
            files[name]={'path':name,'sha256':hashlib.sha256(body).hexdigest(),'size':len(body),'executable':bool(row.mode&0o111)}
            slices=native_slices(body)
            if slices:
                architectures=sorted(architecture for architecture,_ in slices)
                if platform not in architectures:raise ValueError('verifier Mach-O CPU differs from the selected platform')
                native_files.append({'path':name,'architectures':architectures})
                for architecture,native_body in slices:
                    native,rpaths=macho_dependencies(native_body)
                    for dependency in native:dependencies.append({'consumer':name,'architecture':architecture,'path':dependency,'rpaths':rpaths})
            elif body.startswith(b'!<arch>\n'):
                support.append({'path':name,'format':'static-linker-archive','reason':'Original link-time support archive, not an executable or dynamically loaded runtime library.'})
            elif body[:2]==b'MZ'or body[:4]in(b'\x7fELF',b'\0asm'):
                if '/site-packages/'not in '/'+name:raise ValueError('unclassified foreign verifier binary outside disabled site packages')
                if body[:2]!=b'MZ'or len(body)<64:raise ValueError('unsupported foreign verifier support binary')
                offset=struct.unpack_from('<I',body,60)[0]
                if offset+6>len(body)or body[offset:offset+4]!=b'PE\0\0':raise ValueError('invalid foreign verifier PE support header')
                cpu=struct.unpack_from('<H',body,offset+4)[0];architecture={0x14c:'win32-x86',0x8664:'win32-x64',0xaa64:'win32-arm64'}.get(cpu)
                if architecture is None:raise ValueError('unsupported foreign verifier PE CPU')
                support.append({'path':name,'format':'PE','architecture':architecture,'reason':'Original foreign packaging support bytes; site initialization is disabled and no such binary is loaded.'})
    for name,row in links.items():
        target=row['target'];visited={name}
        while target in links:
            if target in visited or len(visited)>32:raise ValueError('verifier alias cycle')
            visited.add(target);target=links[target]['target']
        if target not in files:raise ValueError('verifier alias has no inventoried ordinary target')
        row['resolved_target']=target
    version=asset_name.split('+',1)[0].removeprefix('cpython-');entry='bin/python'+'.'.join(version.split('.')[:2])
    if entry not in files:raise ValueError('verifier executable is missing')
    if not any(row['path']==entry and platform in row['architectures']for row in native_files):raise ValueError('verifier entrypoint has no matching native Mach-O CPU')
    unresolved=[]
    for row in dependencies:
        value=row['path']
        if value.startswith(('/usr/lib/','/System/Library/')):row['classification']='host-readonly-system-loader-or-library'
        elif value.startswith('@loader_path/'):
            target=posixpath.normpath(posixpath.join(posixpath.dirname(row['consumer']),value[13:]))
            if target not in files and target not in links:unresolved.append(row)
            else:row.update(classification='inventoried-private-runtime-library',target=target)
        elif value.startswith('@rpath/'):
            targets=[]
            for rpath in row['rpaths']:
                if rpath.startswith('@loader_path/'):
                    target=posixpath.normpath(posixpath.join(posixpath.dirname(row['consumer']),rpath[13:],value[7:]))
                    if target in files or target in links:targets.append(target)
            if len(set(targets))!=1:unresolved.append(row)
            else:row.update(classification='inventoried-private-runtime-library',target=targets[0])
        else:unresolved.append(row)
    if digest(Path(__file__))!=generator_sha256:raise ValueError('verifier inventory producer changed during inspection')
    return {'schema_version':1,'qualification':'publisher-archive-verifier-prefix-inventory-not-approval','platform':platform,'version':version,'entrypoint':entry,'files':[files[key]for key in sorted(files)],'links':[links[key]for key in sorted(links)],'excluded_original_pycache':sorted(excluded),'site_initialization':'disabled-with-S','pycache_policy':'private-empty-prefix-with-B','native_files':native_files,'disabled_foreign_support_payloads':support,'native_dependencies':dependencies,'unresolved_dependencies':unresolved,'origin':{'release_receipt':{'path':receipt_file.relative_to(root).as_posix(),'sha256':digest(receipt_file),'size':receipt_file.stat().st_size},'archive':{'name':asset_name,'sha256':asset['digest'][7:],'size':asset['size'],'url':asset['browser_download_url']}},'generator':{'path':Path(__file__).resolve().relative_to(root).as_posix(),'sha256':generator_sha256}}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','asset-name','platform','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();output=Path(args.output)
    if output.exists():raise ValueError('new verifier inventory output required')
    value=derive(ROOT,Path(args.archive),args.asset_name,args.platform);output.write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({'files':len(value['files']),'links':len(value['links']),'unresolved_dependencies':len(value['unresolved_dependencies'])}))
