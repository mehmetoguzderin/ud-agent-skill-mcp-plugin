#!/usr/bin/env python3
"""Bind actual Windows Perl PEs/PDBs and reproduced XS link members as data.

No target is executed. Compiler library bytes remain local inspection inputs;
this receipt does not establish a publisher redistribution grant.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
pdb=module('ud_perl_pdb','scripts/release/node-windows-components.py')
builder=module('ud_perl_builder','scripts/runtime/prepare-windows-perl.py')


def archive_members(data):
    if not isinstance(data,bytes)or len(data)>256*1024**2 or data[:8]!=b'!<arch>\n':raise ValueError('Invalid bounded COFF archive')
    rows=[];offset=8;long_names=None;symbols=None
    while offset<len(data):
        if offset+60>len(data)or data[offset+58:offset+60]!=b'`\n':raise ValueError('Truncated COFF header')
        raw=data[offset:offset+16].decode('ascii').strip();size_text=data[offset+48:offset+58].decode('ascii').strip()
        if not re.fullmatch('[0-9]+',size_text):raise ValueError('Invalid COFF member size')
        size=int(size_text);end=offset+60+size
        if size>64*1024**2 or end>len(data)or len(rows)>100000:raise ValueError('COFF member exceeds bounds')
        body=data[offset+60:end]
        if raw=='//':
            if long_names is not None:raise ValueError('Duplicate long-name table')
            long_names=body
        elif raw=='/'and symbols is None:symbols=body
        elif raw!='/':rows.append({'offset':offset,'raw':raw,'bytes':body})
        offset=end
        if size%2:
            # Microsoft's COFF format requires an even next header address;
            # native SDK archives use NUL padding, LLVM archives use LF.
            if offset>=len(data):raise ValueError('Missing COFF alignment byte')
            offset+=1
    for row in rows:
        raw=row.pop('raw')
        if re.fullmatch('/[0-9]+',raw):
            start=int(raw[1:])
            if long_names is None or start>=len(long_names):raise ValueError('Invalid COFF long-name offset')
            end=long_names.find(b'\0',start);newline=long_names.find(b'\n',start)
            if end<0 or 0<=newline<end:end=newline
            if end<0:raise ValueError('Unterminated COFF long name')
            row['name']=long_names[start:end].decode('utf-8').removesuffix('/')
        else:row['name']=raw.removesuffix('/')
    if symbols is None or len(symbols)<4:raise ValueError('COFF symbol index is missing')
    count=struct.unpack_from('>I',symbols)[0];at=4+4*count
    if count>2000000 or at>len(symbols):raise ValueError('COFF symbol index exceeds bounds')
    by_offset={row['offset']:row for row in rows};index=collections.defaultdict(set)
    for number in range(count):
        end=symbols.find(b'\0',at)
        if end<0:raise ValueError('Truncated COFF symbol name')
        name=symbols[at:end].decode('utf-8');selected=struct.unpack_from('>I',symbols,4+4*number)[0]
        if selected not in by_offset:raise ValueError('COFF index points outside member headers')
        index[name].add(selected);at=end+1
    if any(symbols[at:]):raise ValueError('Trailing COFF symbol-index data')
    return rows,index


def map_rows(text):
    result=[]
    pattern=re.compile(r'^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8,16})\s+(\S+)\s+([0-9a-fA-F]{8,16})\s+(?:[fi]\s+)*(.+?)\s*$')
    for line in text.splitlines():
        match=pattern.fullmatch(line)
        if not match:continue
        label=match[5];split=re.fullmatch(r'([A-Za-z0-9_.-]+):(.+)',label)
        if split:result.append({'symbol':match[3],'library':split[1].lower(),'member':split[2],'section':int(match[1],16),'offset':int(match[2],16),'address':int(match[4],16)})
    if not result:raise ValueError('Actual link map has no archive contributions')
    return result


def resolve_members(data,rows):
    members,index=archive_members(data);output={}
    for row in rows:
        named=[item for item in members if item['name'].casefold()==row['member'].casefold()]
        if not named:raise ValueError('Link-map member is absent from its exact library')
        if len(named)>1:
            offsets=index.get(row['symbol'],set());named=[item for item in named if item['offset']in offsets]
        if len(named)!=1:raise ValueError('Link-map member/symbol is ambiguous in its exact library')
        item=named[0];key=item['offset'];body=item['bytes']
        if key not in output:output[key]={'name':item['name'],'archive_header_offset':key,'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body),'map_symbols':[],'member_kind':'short-COFF-import'if body[:4]==b'\0\0\xff\xff'and len(body)>=20 and body[4:6]==b'\0\0'else'COFF-object'}
        if row['symbol']not in output[key]['map_symbols']:output[key]['map_symbols'].append(row['symbol'])
    return sorted(output.values(),key=lambda row:row['archive_header_offset'])


def library_identity(file):
    """Preserve xwin's case aliases while binding the actual ordinary archive."""
    parent=file.parent.resolve(strict=True);resolved=file.resolve(strict=True)
    if resolved.parent!=parent:raise ValueError('Contributing library alias escapes its admitted directory')
    result={'path':str(file.relative_to(ROOT)),'resolved_path':str(resolved.relative_to(ROOT)),**pdb.fingerprint(resolved)}
    if file.is_symlink():result['alias_target']=str(file.readlink())
    return resolved,result


def source_supplier_members(archive,architecture,wanted):
    result={};prefix='Library/'if architecture=='arm64'else''
    for stream,member in builder.entries(archive):
        name=member.name
        if name.startswith('/')or'\\'in name or'\0'in name or any(part in('.','..')for part in name.rstrip('/').split('/')):raise ValueError('Unsafe original supplier member')
        relative=name[len(prefix):]if name.startswith(prefix)else None
        if relative not in wanted:continue
        if not member.isfile()or relative in result or member.size>32*1024**2:raise ValueError('Supplier member is special, duplicate or oversized')
        with stream.extractfile(member)as body:fingerprint=hashlib.file_digest(body,'sha256').hexdigest()
        result[relative]={'member':name,'sha256':fingerprint,'size_bytes':member.size}
    if set(result)!=set(wanted):raise ValueError('Supplier archive omits an actual shipped PE/PDB')
    return result


def collect(output,pdbutil,readobj):
    if output.exists():raise ValueError('A new Windows Perl component output is required')
    for tool in(pdbutil,readobj):
        with tool.resolve(strict=True).open('rb')as stream:
            if stream.read(8)!=bytes.fromhex('cffaedfe0c000001'):raise ValueError('A native ARM64 metadata reader is required')
    output.mkdir(parents=True,mode=0o700);provider_lock=json.loads((ROOT/'runtime/windows-perl-distributions.lock.json').read_text());results=[]
    for architecture in('arm64','x64'):
        raw=ROOT/f'.artifacts/native-perl/win32-{architecture}-deferred-2';live=ROOT/f'.artifacts/native-perl/win32-{architecture}-runtime-only-3';rebuilt=ROOT/f'.artifacts/native-perl/win32-{architecture}-linkage-rebuild-2';receipt_file=rebuilt.with_name(rebuilt.name+'-receipt.json');build=json.loads(receipt_file.read_text());linkage=Path(build['linkage_root']);folder=output/architecture;folder.mkdir(mode=0o700)
        if build['producer_sha256']!=builder.digest(ROOT/'scripts/runtime/prepare-windows-perl.py')or build['platform']!='win32/'+architecture:raise ValueError('Authored source-build receipt is stale')
        expected={(name,f'lib/perl5/auto/{module.replace("::","/")}/{module.split("::")[-1]}.dll')for name,(module,*_)in builder.XS.items()}
        if {(r['release'],r['binary'])for r in build['compiled_xs']}!=expected:raise ValueError('Authored XS inventory is incomplete')
        authored={r['binary']:r for r in build['compiled_xs']};binaries=sorted([*raw.rglob('*.exe'),*raw.rglob('*.dll')]);symbols=sorted(raw.rglob('*.pdb'));wanted={p.relative_to(raw).as_posix()for p in symbols}|{p.relative_to(raw).as_posix()for p in binaries if p.relative_to(raw).as_posix()not in authored}
        supplier=provider_lock['platforms'][architecture]['perl'];archive=builder.verified(ROOT/'.artifacts/native-perl/cache/windows'/supplier['filename'],supplier);members=source_supplier_members(archive,architecture,wanted)
        def supplier_file(file):
            key=file.relative_to(raw).as_posix();identity=pdb.fingerprint(file)
            if identity!={k:members[key][k]for k in('sha256','size_bytes')}:raise ValueError('Actual supplier byte differs from original archive')
            return identity
        pdb_rows=[];guid={};module_rows={}
        for index,file in enumerate(symbols):
            identity=supplier_file(file);metadata=folder/f'pdb-{index}.txt';text=pdb.run(pdbutil,['dump','--summary','--modules','--files','--section-contribs','--section-headers',str(file)],metadata);debug=pdb.parse_guid(text,True);modules=pdb.parse_modules(text)
            if supplier_file(file)!=identity:raise ValueError('Supplier PDB changed during inspection')
            row={'path':file.relative_to(raw).as_posix(),**identity,'source_member':members[file.relative_to(raw).as_posix()],'debug_identity':debug,'metadata':{'path':metadata.relative_to(output).as_posix(),**pdb.fingerprint(metadata)},'modules':list(modules.values())};pdb_rows.append(row);key=(debug['guid'],debug['age'])
            if key in guid and guid[key]['sha256']!=row['sha256']:raise ValueError('PDB debug identity has conflicting contents')
            guid[key]=row;module_rows[key]=modules
        pe_rows=[]
        for index,file in enumerate(binaries):
            relative=file.relative_to(raw).as_posix();data=file.read_bytes();identity=pdb.fingerprint(file)
            if pdb.fingerprint(live/relative)!=identity:raise ValueError('Current runtime PE differs from audited original')
            sections=pdb.pe_sections(data,architecture);metadata=folder/f'pe-{index}.txt';text=pdb.run(readobj,['--file-headers','--sections','--coff-debug-directory',str(file)],metadata)
            if relative in authored:
                if data!=(rebuilt/relative).read_bytes()or builder.digest(file)!=authored[relative]['sha256']:raise ValueError('Authored XS reproduction differs from shipped bytes')
                row=authored[relative];map_file=linkage/row['map']['path']
                if builder.digest(map_file)!=row['map']['sha256']or map_file.stat().st_size!=row['map']['size_bytes']:raise ValueError('Actual XS map differs')
                contributions=map_rows(map_file.read_text());libraries=[];arch='aarch64'if architecture=='arm64'else'x86_64';search=[rebuilt/'lib/CORE',rebuilt/'lib/perl5/5.44/core_perl/CORE',ROOT/f'.artifacts/xwin-cache/xwin/crt/lib/{arch}',ROOT/f'.artifacts/xwin-cache/xwin/sdk/lib/ucrt/{arch}',ROOT/f'.artifacts/xwin-cache/xwin/sdk/lib/um/{arch}']
                for name in sorted({r['library']for r in contributions}):
                    selected=[directory/(name+'.lib')for directory in search if(directory/(name+'.lib')).is_file()]
                    if len(selected)!=1:raise ValueError('Contributing library path is missing or ambiguous: '+name)
                    archive_file,archive_identity=library_identity(selected[0]);body=archive_file.read_bytes();selected_rows=[r for r in contributions if r['library']==name];objects=resolve_members(body,selected_rows)
                    if library_identity(selected[0])!=(archive_file,archive_identity)or pdb.fingerprint(archive_file)!= {'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)}:raise ValueError('Contributing archive changed')
                    libraries.append({'library':name,'archive':archive_identity,'members':objects})
                for item in row['objects']:
                    if builder.digest(linkage/item['coff']['path'])!=item['coff']['sha256']:raise ValueError('Authored COFF input changed')
                pe_rows.append({'path':relative,**identity,'origin':'authored-reproduced-XS','reproduction':row,'libraries':libraries,'target_execution':False});continue
            supplier_file(file);debug=pdb.parse_guid(text);key=(debug['guid'],debug['age'])
            if key not in guid:raise ValueError('Shipped supplier PE has no matching original PDB')
            runtime=[]
            for value in module_rows[key].values():
                library=value['library'];component=library.replace('\\','/').casefold()
                if 'microsoft visual studio'not in component and 'windows kits'not in component:continue
                runtime.append({**value,'contributions':[pdb.contribution_bytes(data,sections,item)for item in value['contributions']]})
            pe_rows.append({'path':relative,**identity,'origin':'supplier','source_member':members[relative],'debug_identity':debug,'pdb_path':guid[key]['path'],'runtime_compilands':runtime,'target_execution':False})
        live_pes={p.relative_to(live).as_posix()for pattern in('*.exe','*.dll')for p in live.rglob(pattern)}
        if live_pes!={p.relative_to(raw).as_posix()for p in binaries}:raise ValueError('Actual shipped PE inventory differs')
        results.append({'platform':'win32/'+architecture,'supplier_archive':supplier,'pdbs':pdb_rows,'binaries':pe_rows,'rebuild_receipt':{'path':str(receipt_file.relative_to(ROOT)),**pdb.fingerprint(receipt_file)},'native_execution':'pending_native'})
    generators=['scripts/release/windows-perl-components.py','scripts/release/node-windows-components.py','scripts/runtime/prepare-windows-perl.py','scripts/runtime/windows_pe.py']
    result={'schema_version':1,'qualification':'exact-PE-PDB-archive-and-reproduced-XS-member-attribution-not-native-acceptance','records':results,'generators':{name:pdb.fingerprint(ROOT/name)for name in generators},'tools':[{'path':str(tool.resolve()),**pdb.fingerprint(tool.resolve())}for tool in(pdbutil,readobj)],'publisher_redistribution_authority':'unverified-external','limitations':['Supplier PDB contributions hash linked image bytes, not reconstructed original COFF members.','Authored XS DLLs reproduce the shipped bytes; selected library members are bound through actual maps and COFF linker indexes.','Corresponding-source, original Microsoft SDK/CRT terms and publisher authority remain separate reviewed requirements.','No Windows target execution occurred.']}
    (output/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    args=argparse.ArgumentParser(description=__doc__);args.add_argument('--output',type=Path,required=True);args.add_argument('--pdbutil',type=Path,default=Path('/opt/homebrew/opt/llvm/bin/llvm-pdbutil'));args.add_argument('--readobj',type=Path,default=Path('/opt/homebrew/opt/llvm/bin/llvm-readobj'));selected=args.parse_args();result=collect(selected.output,selected.pdbutil,selected.readobj);print(json.dumps({'records':[{'platform':r['platform'],'pdbs':len(r['pdbs']),'pes':len(r['binaries'])}for r in result['records']]}))
