#!/usr/bin/env python3
"""Read signed-package binaries and released dSYMs; never execute provider code.

Joins compilation-unit file names to exact frozen source archive members. A
UUID match binds symbols to binary bytes, not to a reproduced compiler build.
Imported SDK module metadata is distinguished from file compilation units.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile
import uuid
import zipfile
from contextlib import contextmanager

ROOT=Path(__file__).resolve().parents[2]


class PrivateInputChanged(ValueError):
    """An inspection workspace must remain available after ownership changes."""


@contextmanager
def inspection_directory(parent):
    temporary=tempfile.TemporaryDirectory(prefix='ud-apple-dsym-',dir=parent,delete=False)
    try:yield temporary.name
    except PrivateInputChanged:raise
    except BaseException:
        temporary.cleanup();raise
    else:temporary.cleanup()


def verify_private_input(file, expected, body, temporary):
    try:
        current=file.lstat()
        if file.is_symlink()or current.st_nlink!=1 or(current.st_dev,current.st_ino)!=expected or file.read_bytes()!=body:
            raise PrivateInputChanged('Private dSYM inspection input changed; preserved workspace: '+temporary)
    except OSError as error:
        raise PrivateInputChanged('Private dSYM inspection input unavailable; preserved workspace: '+temporary)from error


def sha(data):return hashlib.sha256(data).hexdigest()
def receipt(file):
    with file.open('rb')as stream:value=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'sha256':value,'size_bytes':file.stat().st_size}
def ordinary(file,expected=None):
    if file.is_symlink()or not file.is_file():raise ValueError('Provenance input is not an ordinary file')
    before=file.stat();data=file.read_bytes();after=file.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('Provenance bytes changed while read')
    if expected and {'sha256':sha(data),'size_bytes':len(data)}!={k:expected[k]for k in ('sha256','size_bytes')}:raise ValueError('Frozen provenance input differs')
    return data


def macho(data):
    if len(data)<32 or data[:4]!=b'\xcf\xfa\xed\xfe'or struct.unpack_from('<I',data,4)[0]!=0x100000c:raise ValueError('Expected native ARM64 Mach-O metadata')
    count,extent=struct.unpack_from('<II',data,16)
    if not 1<=count<=1024 or extent>16*1024**2 or 32+extent>len(data):raise ValueError('Invalid bounded Mach-O load commands')
    offset=32;result={'uuid':None,'dylibs':[],'rpaths':[],'build_versions':[]}
    def string(command,at):
        start=struct.unpack_from('<I',command,at)[0]
        if start<at+4 or start>=len(command):raise ValueError('Invalid Mach-O command string offset')
        end=command.find(b'\0',start)
        if end<0:raise ValueError('Unterminated Mach-O command string')
        return command[start:end].decode('utf-8','strict')
    for _ in range(count):
        if offset+8>32+extent:raise ValueError('Truncated Mach-O command')
        kind,size=struct.unpack_from('<II',data,offset)
        if size<8 or size%8 or offset+size>32+extent:raise ValueError('Invalid Mach-O command extent')
        command=data[offset:offset+size]
        if kind==0x1b:
            if size!=24 or result['uuid']is not None:raise ValueError('Invalid or duplicate Mach-O UUID')
            result['uuid']=str(uuid.UUID(bytes=command[8:24])).upper()
        elif kind in(0xc,0x80000018,0x8000001f,0x80000023):
            if size<24:raise ValueError('Truncated dylib command')
            result['dylibs'].append({'name':string(command,8),'weak':kind==0x80000018})
        elif kind==0x8000001c:
            if size<16:raise ValueError('Truncated rpath command')
            result['rpaths'].append(string(command,8))
        elif kind==0x32:
            if size<24:raise ValueError('Truncated build-version command')
            platform,minimum,sdk,tools=struct.unpack_from('<IIII',command,8)
            if tools>1024 or 24+tools*8!=size:raise ValueError('Invalid build-version tools')
            version=lambda value:'.'.join(str(n)for n in(value>>16,(value>>8)&255,value&255))
            result['build_versions'].append({'platform':platform,'minimum_os':version(minimum),'sdk':version(sdk),'tools':[{'tool':struct.unpack_from('<I',command,24+i*8)[0],'version':version(struct.unpack_from('<I',command,28+i*8)[0])}for i in range(tools)]})
        offset+=size
    if offset!=32+extent or result['uuid']is None:raise ValueError('Incomplete Mach-O identity')
    return result


def compilation_units(text):
    units=[]
    for block in text.split('DW_TAG_compile_unit')[1:]:
        row={}
        for field in ('name','producer','comp_dir'):
            values=re.findall(r'DW_AT_'+field+r'\s+\(("(?:[^"\\]|\\.)*")\)',block)
            if len(values)>1:raise ValueError('Ambiguous root compilation-unit attribute')
            if values:row[field]=json.loads(values[0])
        if 'name'not in row or 'producer'not in row:raise ValueError('Compilation unit omits actual name/producer')
        units.append(row)
    if not units:raise ValueError('Released dSYM has no compilation units')
    return units


def source_members(file):
    files={};payloads={};total=0;prefix=None
    with tarfile.open(file,'r:gz')as archive:
        for index,member in enumerate(archive):
            if index>200000:raise ValueError('Source archive member count exceeds bound')
            parts=member.name.rstrip('/').split('/')
            if len(parts)<1 or '\\'in member.name or any(part in('','.','..')for part in parts):raise ValueError('Unsafe source member name')
            if prefix is None:prefix=parts[0]
            if parts[0]!=prefix:raise ValueError('Source archive has multiple roots')
            if not member.isfile():continue
            total+=member.size
            if len(parts)<2 or member.size<0 or member.size>128*1024**2 or total>1024**3:raise ValueError('Source archive expansion exceeds bound')
            relative='/'.join(parts[1:])
            if relative in files:raise ValueError('Duplicate source member')
            data=archive.extractfile(member).read(member.size+1)
            if len(data)!=member.size:raise ValueError('Truncated source member')
            files[relative]={'sha256':sha(data),'size_bytes':len(data)}
            if relative=='Package.resolved':payloads[relative]=data
    return files,payloads


def source_location(name):
    marker='/.build/checkouts/'
    if marker in name:
        suffix=name.split(marker,1)[1];parts=suffix.split('/',1)
        if len(parts)!=2:raise ValueError('Compilation-unit checkout path lacks source member')
        return parts[0].lower(),parts[1]
    marker='/container/container/'
    if marker in name:return 'apple/container',name.split(marker,1)[1]
    return None


def collect(provider,source_root,debug_archive,lock,dwarfdump,output):
    ordinary(debug_archive,lock['archive']);source_receipt=json.loads(ordinary(source_root/'receipt.json'));records=source_receipt['files'];source_cache={}
    def source(repository,commit):
        key=(repository.lower(),commit)
        if key not in source_cache:
            rows=[row for row in records if row['name'].lower()==key[0]and row['version']==commit]
            if len(rows)!=1:raise ValueError('Exact compiled source archive is absent: '+repository+'@'+commit)
            row=rows[0];relative=Path(row['path'])
            if relative.is_absolute()or '..'in relative.parts:raise ValueError('Unsafe source receipt path')
            ordinary(source_root/relative,row);members,metadata=source_members(source_root/relative);source_cache[key]=(row,members,metadata)
        return source_cache[key]
    original,root_members,metadata=source(lock['repository'],lock['source_commit']);pins=json.loads(metadata['Package.resolved'])['pins'];sources={'apple/container':(lock['repository'],lock['source_commit'])}
    for pin in pins:
        match=re.fullmatch(r'https://github.com/([^/]+/[^/]+?)(?:\.git)?',pin['location'])
        if not match or pin['identity'].lower()in sources:raise ValueError('Unsupported or duplicate exact Swift source pin')
        sources[pin['identity'].lower()]=(match[1],pin['state']['revision'])
    tool=dwarfdump.resolve(strict=True);macho(ordinary(tool));tool_identity=receipt(tool);rows=[];debugged=set();unresolved=[]
    with zipfile.ZipFile(debug_archive)as symbols,inspection_directory(output.parent)as temporary:
        infos=symbols.infolist()
        if len(infos)>1000 or sum(row.file_size for row in infos)>2*1024**3 or len({row.filename for row in infos})!=len(infos):raise ValueError('Released dSYM archive is not bounded and unique')
        by_name={row.filename:row for row in infos}
        for file in sorted(provider.rglob('*')):
            if not file.is_file()or file.is_symlink():continue
            with file.open('rb')as stream:magic=stream.read(4)
            if magic!=b'\xcf\xfa\xed\xfe':continue
            data=ordinary(file);identity=macho(data);relative=file.relative_to(provider).as_posix();name=file.name;product={'builder':'container-builder','build':'container-build'}.get(name,name);member=f'container-dSYM/{product}.dSYM/Contents/Resources/DWARF/{product}'
            row={'path':relative,'sha256':sha(data),'size_bytes':len(data),'macho':identity,'debug_evidence':'not-in-official-symbol-archive','embedded_release_commit':lock['source_commit']if lock['source_commit'].encode()in data else None,'embedded_release_version':lock['version']if lock['version'].encode()in data else None}
            if member in by_name:
                info=by_name[member]
                if not 0<info.file_size<128*1024**2:raise ValueError('Released dSYM image exceeds bound')
                debug=symbols.read(info)
                if macho(debug)['uuid']!=identity['uuid']:raise ValueError('Released dSYM does not match actual shipped Mach-O UUID')
                local=Path(temporary)/'image'
                with local.open('xb')as created:
                    created.write(debug);local.chmod(0o400);opened=os.fstat(created.fileno());created_identity=(opened.st_dev,opened.st_ino)
                dump=Path(temporary)/'units'
                try:
                    with dump.open('wb')as stream:result=subprocess.run([str(tool),'--debug-info','--recurse-depth=0',str(local)],stdout=stream,stderr=subprocess.PIPE,timeout=60)
                finally:verify_private_input(local,created_identity,debug,temporary)
                if result.returncode or result.stderr or dump.stat().st_size>64*1024**2:raise ValueError('Released dSYM metadata parser failed')
                raw=dump.read_bytes();prefix=(str(local)+':\tfile format Mach-O arm64\n').encode()
                if not raw.startswith(prefix):raise ValueError('Released dSYM parser has an unexpected diagnostic header')
                canonical=(identity['uuid']+':\tfile format Mach-O arm64\n').encode()+raw[len(prefix):]
                if os.name=='nt':
                    spec=importlib.util.spec_from_file_location('ud_dsym_windows_storage',ROOT/'scripts/quality/windows-storage-acl.py')
                    storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)
                    try:storage.WindowsStorage().unlink_readonly(str(local),created_identity)
                    except (ValueError,OSError)as error:raise PrivateInputChanged('Private dSYM cleanup refused; preserved workspace: '+temporary)from error
                else:local.unlink()
                units=compilation_units(canonical.decode('utf-8','strict'));joined=[];imports=[]
                for unit in units:
                    name=unit['name']
                    if '/'not in name:imports.append(unit);continue
                    location=source_location(name)
                    if location is None or location[0]not in sources:unresolved.append({'binary':relative,'unit':unit,'reason':'unmapped-compilation-unit-source'});continue
                    repository,commit=sources[location[0]];source_row,members,_=source(repository,commit);source_file=members.get(location[1])
                    if source_file is None:unresolved.append({'binary':relative,'unit':unit,'reason':'declared-source-archive-omits-member'});continue
                    joined.append({**unit,'repository':repository,'commit':commit,'member':location[1],**source_file})
                row.update({'debug_evidence':'uuid-matched-official-symbols','debug_member':{'path':member,'sha256':sha(debug),'size_bytes':len(debug)},'metadata_sha256':sha(canonical),'metadata_normalization':'Replace only the diagnostic input filename in the first line with the verified Mach-O UUID; preserve all compilation-unit attribute bytes.','producers':dict(collections.Counter(unit['producer']for unit in units)),'source_units':joined,'imported_module_metadata':imports});debugged.add(member)
            rows.append(row)
    if not rows or len(debugged)!=9:raise ValueError('Released Apple symbol/binary inventory is incomplete')
    output_receipt={'schema_version':1,'qualification':'uuid-and-source-member-attribution-not-reproduced-build','provider_files':rows,'sources':[{'repository':repository,'commit':commit,'archive':row}for(repository,commit),(row,_,_)in sorted(source_cache.items())],'unresolved_source_units':unresolved,'debug_archive':lock['archive'],'debug_lock_sha256':sha(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()),'parser_tool':{'path':str(tool),**tool_identity},'source_receipt':receipt(source_root/'receipt.json'),'generator':receipt(Path(__file__)),'limitations':['dSYM compile-unit paths identify source members; they do not prove a bit-identical rebuild or source-byte checksum in the original compiler.','Imported SDK module metadata is not classified as statically shipped runtime code.','Two release payload plugins have no official dSYM and remain scoped to signed-release/source-commit attribution.','OS dynamic libraries and weak Swift compatibility imports are host prerequisites; no Swift runtime dylib is present in this provider payload.','Compiler-generated/runtime components and publisher redistribution authority require independent component/license review.']}
    output.write_text(json.dumps(output_receipt,indent=2)+'\n');return output_receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--provider',type=Path,required=True);parser.add_argument('--sources',type=Path,required=True);parser.add_argument('--debug-archive',type=Path,required=True);parser.add_argument('--debug-lock',type=Path,default=ROOT/'runtime/materials/apple-binary-debug.lock.json');parser.add_argument('--dwarfdump',type=Path,default=Path('/opt/homebrew/opt/llvm/bin/llvm-dwarfdump'));parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();result=collect(args.provider,args.sources,args.debug_archive,json.loads(args.debug_lock.read_text()),args.dwarfdump,args.output);print(json.dumps({'binaries':len(result['provider_files']),'debugged':sum(row['debug_evidence']=='uuid-matched-official-symbols'for row in result['provider_files']),'sources':len(result['sources']),'unresolved':len(result['unresolved_source_units'])}))
if __name__=='__main__':main()
