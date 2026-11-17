#!/usr/bin/env python3
"""Bind signed Node Windows PDB compiler/runtime facts to actual PE byte ranges.

PDB section contributions identify linked image bytes, not complete original
COFF objects. Original libraries are not reconstructed or claimed as supplied.
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
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_windows_pe',ROOT/'scripts/runtime/windows_pe.py');pe=importlib.util.module_from_spec(spec);spec.loader.exec_module(pe)


def fingerprint(file):
    before=file.stat()
    if file.is_symlink()or not file.is_file():raise ValueError('Provenance input is not ordinary')
    with file.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    after=file.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('Provenance input changed while read')
    return {'sha256':digest,'size_bytes':after.st_size}
def checked(file,row):
    if fingerprint(file)!={k:row[k]for k in ('sha256','size_bytes')}:raise ValueError('Frozen provenance bytes differ')
    return file


def section(text,name,next_name=None):
    pattern=r'^\s*'+re.escape(name)+r'\s*\n=+\s*\n';matches=list(re.finditer(pattern,text,re.M))
    if len(matches)!=1:raise ValueError('PDB metadata section is missing or ambiguous: '+name)
    start=matches[0].end()
    if next_name is None:return text[start:]
    end=re.search(r'^\s*'+re.escape(next_name)+r'\s*\n=+\s*\n',text[start:],re.M)
    if end is None:raise ValueError('PDB metadata terminal section is missing')
    return text[start:start+end.start()]


def parse_modules(text):
    data=section(text,'Modules','Files');rows={}
    for match in re.finditer(r'^\s*Mod (\d+) \| `(.*?)`:\s*\n(.*?)(?=^\s*Mod \d+ \||\Z)',data,re.M|re.S):
        index=int(match[1]);body=match[3];objects=re.findall(r'^\s*Obj: `(.*?)`:',body,re.M);streams=re.findall(r'debug stream: (\d+), # files: (\d+)',body)
        if index in rows or len(objects)!=1 or len(streams)!=1:raise ValueError('PDB compiland inventory is ambiguous')
        rows[index]={'id':index,'object':match[2],'library':objects[0],'debug_stream':int(streams[0][0]),'expected_source_files':int(streams[0][1]),'source_files':[],'contributions':[]}
    if not rows or set(rows)!=set(range(len(rows))):raise ValueError('PDB compiland inventory is incomplete')
    files=section(text,'Files','Section Headers');current=None
    for line in files.splitlines():
        match=re.fullmatch(r'\s*Mod (\d+) \| `(.*?)`:\s*',line)
        if match:
            current=int(match[1])
            if current not in rows or rows[current]['object']!=match[2]:raise ValueError('PDB source-file inventory changed compiland identity')
        elif line.startswith('- '):
            absent=re.fullmatch(r'- \(None: \) (.+)',line)
            if absent:
                if current is None:raise ValueError('PDB source file is not attributed to a compiland')
                rows[current]['source_files'].append({'path':absent[1],'algorithm':'none','checksum':None});continue
            match=re.fullmatch(r'- \((SHA-256|MD5|SHA-1): ([A-Fa-f0-9]+)\) (.+)',line)
            if match is None or current is None:raise ValueError('Unrecognized PDB source-checksum record')
            algorithm=match[1].lower().replace('-','');expected={'sha256':64,'sha1':40,'md5':32}[algorithm]
            if len(match[2])!=expected:raise ValueError('Invalid PDB source checksum extent')
            rows[current]['source_files'].append({'path':match[3],'algorithm':algorithm,'checksum':match[2].lower()})
    for row in rows.values():
        if len(row['source_files'])!=row['expected_source_files']:raise ValueError('PDB source-file inventory is incomplete')
    contributions=section(text,'Section Contributions')
    for line in contributions.splitlines():
        if 'SC['not in line:continue
        match=re.fullmatch(r'\s*SC\[(.*?)\]\s*\| mod = (\d+), (\d+):(\d+), size = (\d+), data crc = (\d+), reloc crc = (\d+)\s*',line)
        if match is None or int(match[2])not in rows:raise ValueError('PDB section contribution is unrecognized or unattributed')
        rows[int(match[2])]['contributions'].append({'section_name':match[1],'section':int(match[3]),'offset':int(match[4]),'size_bytes':int(match[5]),'data_crc':int(match[6]),'relocation_crc':int(match[7])})
    if not any(row['contributions']for row in rows.values()):raise ValueError('PDB contains no section contributions')
    return rows


def parse_guid(text,pdb=False):
    guid=re.findall(r'^\s*'+('GUID'if pdb else'PDBGUID')+r': \{([A-Fa-f0-9-]{36})\}\s*$',text,re.M);age=re.findall(r'^\s*'+('Age'if pdb else'PDBAge')+r': (\d+)\s*$',text,re.M)
    if len(guid)!=1 or len(age)!=1:raise ValueError('PDB/PE debug identity is missing or ambiguous')
    return {'guid':guid[0].upper(),'age':int(age[0])}


def pe_sections(data,architecture):
    pe.inspect_pe(data,architecture);start=struct.unpack_from('<I',data,60)[0];count=struct.unpack_from('<H',data,start+6)[0];optional=struct.unpack_from('<H',data,start+20)[0];rows={}
    for index in range(count):
        at=start+24+optional+40*index;name=data[at:at+8].split(b'\0',1)[0].decode('ascii','strict');virtual_size,rva,raw_size,raw=struct.unpack_from('<4I',data,at+8);rows[index+1]={'name':name,'virtual_size':virtual_size,'rva':rva,'raw_size':raw_size,'raw_offset':raw}
    return rows


def contribution_bytes(data,sections,value):
    if value['size_bytes']==0:return {**value,'file_bytes':0,'zero_fill_bytes':0,'linked_image_sha256':hashlib.sha256(b'').hexdigest()}
    target=sections.get(value['section']);size=value['size_bytes'];offset=value['offset']
    if not target or target['name']!=value['section_name']or offset+size>max(target['virtual_size'],target['raw_size']):raise ValueError('PDB section contribution escapes the actual PE section')
    count=min(size,max(0,target['raw_size']-offset));at=target['raw_offset']+offset
    if count and at+count>len(data):raise ValueError('PDB section contribution escapes PE file bytes')
    digest=hashlib.sha256(data[at:at+count]);remaining=size-count
    while remaining:part=min(remaining,65536);digest.update(b'\0'*part);remaining-=part
    return {**value,'file_bytes':count,'zero_fill_bytes':size-count,'linked_image_sha256':digest.hexdigest()}


def run(tool,args,file):
    with file.open('wb')as stdout:result=subprocess.run([str(tool),*args],stdout=stdout,stderr=subprocess.PIPE,timeout=180)
    if result.returncode or result.stderr or file.stat().st_size>256*1024**2:raise ValueError('Original LLVM provenance parser failed or exceeded its bound')
    return file.read_bytes().decode('latin1')


def collect(root,assets,debug_root,output,pdbutil,readobj):
    if output.exists():raise ValueError('A new Node provenance output is required')
    for tool in(pdbutil,readobj):
        with tool.resolve(strict=True).open('rb')as stream:header=stream.read(8)
        if header!=bytes.fromhex('cffaedfe0c000001'):raise ValueError('A native macOS ARM64 LLVM inspection utility is required; no Windows/amd64 execution')
    node=json.loads((root/'runtime/node-distributions.lock.json').read_text());lock=json.loads((root/'runtime/materials/node-windows-debug.lock.json').read_text());signed=assets/'SHASUMS256.txt.asc';keys=assets/'nodejs-release-keys.kbx'
    if node['version']!=lock['version']or fingerprint(signed)['sha256']!=node['signed_manifest_sha256']or fingerprint(keys)['sha256']!=node['release_keyring_sha256']:raise ValueError('Node signed checksum authority differs')
    signature=subprocess.run(['gpgv','--status-fd','1','--keyring',str(keys.resolve()),str(signed.resolve())],capture_output=True,timeout=30)
    if signature.returncode or ('[GNUPG:] VALIDSIG '+node['checksum_signer_fingerprint']+' ').encode()not in signature.stdout:raise ValueError('Node publisher checksum signature failed')
    lines=signed.read_text().splitlines();output.mkdir(mode=0o700,parents=True);rows=[]
    for architecture in('arm64','x64'):
        folder=output/architecture;folder.mkdir(mode=0o700);archive=lock['archives'][architecture];platform='win32-'+architecture;binary_archive=node['platforms'][platform];zip_file=checked(debug_root/('win-'+architecture+'.zip'),archive)
        for digest,name in[(archive['sha256'],archive['filename']),(binary_archive['sha256'],binary_archive['filename'])]:
            if lines.count(digest+'  '+name)!=1:raise ValueError('Node input is not uniquely covered by signed checksums')
        binary_zip=assets/binary_archive['filename']
        if fingerprint(binary_zip)['sha256']!=binary_archive['sha256']:raise ValueError('Original Node binary archive differs')
        with zipfile.ZipFile(zip_file)as symbols:
            if symbols.namelist()!=['node.pdb']or not 0<symbols.getinfo('node.pdb').file_size<1024**3:raise ValueError('Official Node PDB ZIP has an unexpected inventory')
            with symbols.open('node.pdb')as source,(folder/'node.pdb').open('wb')as target:
                while chunk:=source.read(1024*1024):target.write(chunk)
        with zipfile.ZipFile(binary_zip)as binaries:data=binaries.read('node-v'+node['version']+'-win-'+architecture+'/node.exe')
        binary=folder/'node.exe';binary.write_bytes(data);raw_sha=hashlib.sha256(data).hexdigest()
        if lines.count(raw_sha+'  win-'+architecture+'/node.exe')!=1:raise ValueError('Node PE differs from independently signed raw executable')
        metadata=run(pdbutil,['dump','--summary','--modules','--files','--section-contribs','--section-headers',str(folder/'node.pdb')],folder/'pdb.txt');pe_metadata=run(readobj,['--file-headers','--sections','--coff-debug-directory',str(binary)],folder/'pe.txt');identity=parse_guid(metadata,True)
        if identity!=parse_guid(pe_metadata):raise ValueError('Official PDB GUID/age does not match shipped Node PE')
        modules=parse_modules(metadata);sections=pe_sections(data,architecture);runtime=[];other_libraries=collections.Counter();source_files={}
        for index,module in modules.items():
            library=module['library'];name=library.rsplit('\\',1)[-1].lower()
            if name not in('libcmt.lib','libcpmt.lib','libucrt.lib','libvcruntime.lib','oldnames.lib','legacy_stdio_definitions.lib','libconcrt.lib'):
                other_libraries[library]+=1;continue
            if 'microsoft visual studio'not in library.lower()and'windows kits'not in library.lower():raise ValueError('CRT name is not bound to actual vendor library provenance')
            contributions=[contribution_bytes(data,sections,item)for item in module['contributions']]
            symbols_file=folder/f'module-{index}.txt';symbols=run(pdbutil,['dump','--symbols','--modi='+str(index),str(folder/'node.pdb')],symbols_file);producers=[]
            for match in re.finditer(r'machine = ([^,]+), Ver = ([^\r\n]+), language = ([^\r\n]+)\r?\n\s*frontend = ([0-9.]+), backend = ([0-9.]+)',symbols):producers.append({'machine':match[1],'producer':match[2],'language':match[3],'frontend':match[4],'backend':match[5]})
            for source in module['source_files']:source_files[(source['path'],source['algorithm'],source['checksum'])]=source
            runtime.append({**module,'contributions':contributions,'producer_records':producers,'symbol_metadata':fingerprint(symbols_file),'linked_file_bytes':sum(item['file_bytes']for item in contributions),'attribution':'official-PDB-compiland-and-linked-image-ranges-not-original-COFF-object-hash'})
        if not runtime:raise ValueError('Official PDB has no identifiable compiler runtime modules')
        canonical_pe=pe_metadata.replace('File: '+str(binary),'File: '+identity['guid'],1).encode('latin1')
        rows.append({'platform':'win32/'+architecture,'binary':{'sha256':raw_sha,'size_bytes':len(data)},'binary_archive':binary_archive,'pdb_archive':archive,'pdb':fingerprint(folder/'node.pdb'),'debug_identity':identity,'total_compilands':len(modules),'runtime_compilands':runtime,'runtime_source_checksums':list(source_files.values()),'other_library_compiland_counts':dict(other_libraries),'rust_compiler_commits':sorted(set(value.decode()for value in re.findall(rb'/rustc/([a-f0-9]{40})/',data))),'pdb_metadata':fingerprint(folder/'pdb.txt'),'canonical_pe_metadata_sha256':hashlib.sha256(canonical_pe).hexdigest(),'target_execution':False})
    result={'schema_version':1,'qualification':'signed-PDB-linked-byte-attribution-not-reproduced-build','version':node['version'],'records':rows,'signature_authority':{'signed_manifest_sha256':node['signed_manifest_sha256'],'release_keyring_sha256':node['release_keyring_sha256'],'signer':node['checksum_signer_fingerprint']},'tools':[{'path':str(file.resolve()),**fingerprint(file.resolve())}for file in(pdbutil,readobj)],'generator':fingerprint(Path(__file__)),'pe_parser':fingerprint(ROOT/'scripts/runtime/windows_pe.py'),'publisher_redistribution_authority':'unverified-external','limitations':['Section contributions hash linked PE image bytes and explicit zero fill, not complete original COFF archive members.','PDB source checksums identify producer inputs; retained source bytes and original license terms must be joined independently.','Linker folding can give multiple original compilands the same linked byte ranges.','No Windows or AMD64 target was executed, and no publisher redistribution grant is inferred.']}
    (output/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--assets',type=Path,default=ROOT/'.artifacts/node');parser.add_argument('--debug-root',type=Path,default=ROOT/'.artifacts/node/windows-pdb');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--pdbutil',type=Path,default=Path('/opt/homebrew/opt/llvm/bin/llvm-pdbutil'));parser.add_argument('--readobj',type=Path,default=Path('/opt/homebrew/opt/llvm/bin/llvm-readobj'));args=parser.parse_args();result=collect(args.root,args.assets,args.debug_root,args.output,args.pdbutil,args.readobj);print(json.dumps({'records':[{'platform':r['platform'],'runtime_compilands':len(r['runtime_compilands'])}for r in result['records']]}))
if __name__=='__main__':main()
