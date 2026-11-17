#!/usr/bin/env python3
"""Create deterministic bounded shards of verified corresponding-source inputs.

Only explicitly selected source archives, notices and verification metadata enter
the tar stream. Executable subjects used for data inspection never enter it.
The index proves the provided subinventories, not complete product coverage.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

SHA=re.compile('[0-9a-f]{64}\\Z')
MAX_PART=2*1024**3-1


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()


def safe(name):
    if not isinstance(name,str)or not name or name.startswith('/')or'\\'in name or':'in name or'\0'in name or any(part in('','.','..')for part in name.split('/')):raise ValueError('unsafe source-material path')
    return name


def file_state(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def verify_held_path(stream, file, identity):
    """Bind a pathname to the held original using the same native stat API.

    Windows CPython 3.15 reports ChangeTime in fstat.st_ctime but birthtime in
    lstat.st_ctime. Compare both descriptors with fstat; keep the full file ID,
    size, write time and change time, and separately reject pathname aliases.
    """
    before = file.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400:
        raise ValueError('source-material path is not an ordinary file')
    descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        named = os.fstat(descriptor); after = file.lstat()
        if (not stat.S_ISREG(after.st_mode) or getattr(after, 'st_file_attributes', 0) & 0x400
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
                or file_state(named) != identity or file_state(os.fstat(stream.fileno())) != identity):
            raise ValueError('source-material changed during same-FD inspection')
    finally: os.close(descriptor)


def opened(root,record):
    """Open the same no-follow ordinary file whose bytes will enter the bundle."""
    name=safe(record.get('path'));expected=record.get('sha256');size=record.get('size_bytes',record.get('size'))
    if not isinstance(expected,str)or not SHA.fullmatch(expected)or size is not None and(type(size)is not int or not 0<=size<=8*1024**3):raise ValueError('invalid source-material content receipt')
    file=root
    for part in name.split('/'):
        file=file/part
        if file.is_symlink():raise ValueError('source-material path contains a link')
    fd=os.open(file,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0));stream=os.fdopen(fd,'rb')
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode)or size is not None and before.st_size!=size:raise ValueError('source-material size or kind differs')
        fingerprint=hashlib.file_digest(stream,'sha256').hexdigest();after=os.fstat(fd)
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if fingerprint!=expected or identity(before)!=identity(after):raise ValueError('source-material hash or identity differs')
        verify_held_path(stream,file,identity(before))
        stream.seek(0);yielded={'sha256':expected,'size_bytes':before.st_size,'path':name};return stream,identity(before),yielded
    except BaseException:stream.close();raise


def selected(data):
    provider_metadata=data.get('qualification')=='immutable-publisher-oci-source-build-metadata-not-reproduced-build'and data.get('target_execution')is False and data.get('emulation')is False and SHA.fullmatch(data.get('index_digest','').removeprefix('sha256:'))
    if data.get('schema_version')!=1 or data.get('status')!='passed'and not provider_metadata:raise ValueError('source subinventory has not passed its own integrity checks')
    kind=data.get('qualification');rows=[]
    def add(record):
        if not isinstance(record,dict):raise ValueError('source subinventory has a malformed content record')
        rows.append(record)
    if provider_metadata:
        # These are immutable original manifests/config/build metadata. The
        # component replayer separately authenticates their locked OCI chain;
        # selecting bytes for a bundle does not assert binary reproduction.
        for row in data['files']:add(row)
    elif kind=='publisher-authenticated-exact-corresponding-source-closure':
        for row in [*data['files'],*data['metadata']]:add(row)
        if data.get('missing'):raise ValueError('publisher source closure is incomplete')
    elif kind=='binary-bound-go-module-source-inventory':
        if data.get('static_c_dependencies_pending')or data.get('module_hashes_pending')or data.get('standard_libraries_pending'):raise ValueError('Go source inventory still has missing dependencies')
        for row in data['modules']:add(row['archive'])
        for key in('main_sources','standard_libraries','derived_runtime_sources'):
            for row in data.get(key,[]):
                add(row)
                if 'publisher_catalog'in row:add(row['publisher_catalog'])
        # Deliberately do not select binaries/subjects, tool executables or the
        # original full runtime archives. They are verification subjects only.
    elif kind in('exact-locked-source-subinventory','frozen-managed-interpreter-runtime-source-subinventory','complete-locked-npm-cargo-source-and-notice-subinventory','pinned-source-and-notices'):
        for row in data['files']:
            if row.get('family')=='rust-stdlib-crate' and not row.get('supported_target_consumers'):continue
            add(row)
            for notice in row.get('notices',[]):add(notice)
        for row in data.get('notices',[]):add(row)
    elif kind=='pinned-apple-kernel-corresponding-source-inputs':
        add(data['kernel_source']);add(data['kernel_source']['developer_signature']);add(data['kernel_config']);add(data['kata_source'])
        for row in data['kernel_source']['key_certificates']:add(row)
    elif kind=='oci-bound-publisher-package-and-notice-inventory':
        for row in data['packages']:
            for notice in row.get('notices',[row['notice']]):add(notice)
        for key in('common_licenses','status_files'):
            for row in data[key]:add(row)
        add(data['archive_keyring'])
    elif kind=='image-bound-publisher-package-and-notice-inventory':
        for row in data['packages']:add(row['notice'])
        add(data['status_file'])
        for row in data.get('library_mappings', []):add(row['package_list'])
        if data.get('reader_output'):add(data['reader_output'])
    else:raise ValueError('unsupported source subinventory qualification: '+str(kind))
    return rows


class Parts:
    def __init__(self,output,limit):
        if type(limit)is not int or not 1024<=limit<=MAX_PART:raise ValueError('source shard bound must be between1KiB and the GitHub asset limit')
        self.output=output;self.limit=limit;self.part=None;self.size=0;self.parts=[];self.digest=hashlib.sha256();self.current=None;self.total=0
    def write(self,data):
        view=memoryview(data);self.digest.update(view);self.total+=len(view);original=len(view)
        while view:
            if self.part is None:
                self.name=f'ud-agent-corresponding-source-{len(self.parts):04d}.tar.part';self.part=(self.output/self.name).open('xb');self.current=hashlib.sha256();self.size=0
            amount=min(len(view),self.limit-self.size);chunk=view[:amount];self.part.write(chunk);self.current.update(chunk);self.size+=amount;view=view[amount:]
            if self.size==self.limit:self.finish_part()
        return original
    def finish_part(self):
        if self.part is None:return
        self.part.flush();os.fsync(self.part.fileno());self.part.close();self.parts.append({'id':f'corresponding-source-{len(self.parts):04d}','path':self.name,'sha256':self.current.hexdigest(),'size':self.size});self.part=None
    def flush(self):
        if self.part:self.part.flush()
    def close(self):self.finish_part()


def bundle(receipts,output,limit=256*1024**2,required_materials=None,component_coverage=None):
    output=Path(output)
    if output.exists():raise ValueError('new source bundle output required')
    output.mkdir(parents=True);(output/'INCOMPLETE').write_text('Source bundle has not completed.\n')
    blobs={};collections=[];seen=set();required=None
    if required_materials is not None:
        required={}
        for row in required_materials:
            key=row.get('sha256');size=row.get('size_bytes')
            if not isinstance(key,str)or not SHA.fullmatch(key)or type(size)is not int or not 0<=size<=8*1024**3 or key in required:raise ValueError('component source material selection is invalid or duplicate')
            required[key]=size
        if not required:raise ValueError('actual component source requirements are empty')
    for identifier,file in sorted(receipts):
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,80}',identifier)or identifier in seen:raise ValueError('source collection ID is invalid or duplicate')
        seen.add(identifier);file=Path(file)
        if file.is_symlink()or not file.is_file()or file.stat().st_size>64*1024**2:raise ValueError('source collection receipt is linked or oversized')
        raw=file.read_bytes();data=json.loads(raw);members=[]
        for row in selected(data):
            if required is not None and row.get('sha256')not in required:continue
            stream,identity,record=opened(file.parent,row)
            try:
                if required is not None and required[record['sha256']]!=record['size_bytes']:raise ValueError('selected component source size differs')
                key=record['sha256'];previous=blobs.get(key)
                if previous is not None and previous['record']['size_bytes']!=record['size_bytes']:raise ValueError('source digests have inconsistent sizes')
                blobs.setdefault(key,{'root':file.parent,'record':record})
                entry={'original_path':record['path'],'path':'blobs/'+key,'sha256':key,'size_bytes':record['size_bytes']}
                if entry not in members:members.append(entry)
            finally:stream.close()
        if not members:continue
        collections.append({'id':identifier,'qualification':data['qualification'],'receipt_path':'receipts/'+identifier+'.json','receipt_sha256':hashlib.sha256(raw).hexdigest(),'receipt_size_bytes':len(raw),'members':sorted(members,key=lambda row:(row['original_path'],row['sha256'])),'raw':raw})
    if not collections or not blobs:raise ValueError('source bundle inventories are empty')
    if required is not None and set(blobs)!=set(required):raise ValueError('source collections omit actual shipped component source materials')
    complete=False
    if component_coverage is not None:
        if required is None or component_coverage.get('qualification')!='replayed-actual-shipped-component-source-license-closure'or component_coverage.get('complete_available_shipped_component_coverage')is not True or component_coverage.get('required_materials')!=required_materials:raise ValueError('source selection does not match its replayed component model')
        complete=component_coverage.get('complete_product_coverage')is True
    manifest={'schema_version':1,'qualification':'verified-corresponding-source-subinventories','complete_product_coverage':complete,'collections':[{key:value for key,value in row.items()if key!='raw'}for row in collections],'files':[{'path':'blobs/'+key,'sha256':key,'size_bytes':value['record']['size_bytes']}for key,value in sorted(blobs.items())]}
    if required is not None:manifest['material_selection']='exact-replayed-shipped-component-requirements-no-unshipped-tool-binaries'
    manifest_bytes=canonical(manifest);parts=Parts(output,limit)
    try:
        with tarfile.open(fileobj=parts,mode='w|',format=tarfile.USTAR_FORMAT)as target:
            def add(name,stream,size):
                entry=tarfile.TarInfo(name);entry.size=size;entry.mode=0o644;entry.mtime=0;entry.uid=entry.gid=0;entry.uname=entry.gname='';target.addfile(entry,stream)
            add('MATERIALS.json',io.BytesIO(manifest_bytes),len(manifest_bytes))
            for row in collections:add(row['receipt_path'],io.BytesIO(row['raw']),len(row['raw']))
            for key,value in sorted(blobs.items()):
                stream,before,record=opened(value['root'],value['record'])
                try:
                    add('blobs/'+key,stream,record['size_bytes']);after=os.fstat(stream.fileno())
                    if before!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('source material changed while archiving')
                finally:stream.close()
    finally:parts.close()
    index={'schema_version':1,'qualification':'verified-corresponding-source-subinventories','complete_product_coverage':complete,'format':'concatenated-ustar','reassembly':'Concatenate parts in listed order, verify stream_sha256, then inspect/extract the ordinary-file USTAR archive.','manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),'stream_sha256':parts.digest.hexdigest(),'stream_size_bytes':parts.total,'parts':parts.parts,'collections':[{'id':row['id'],'sha256':row['receipt_sha256']}for row in collections],'unique_source_files':len(blobs)}
    if required is not None:index['material_selection']='exact-replayed-shipped-component-requirements-no-unshipped-tool-binaries'
    (output/'ud-agent-corresponding-source-index.json').write_bytes(canonical(index));(output/'INCOMPLETE').unlink();return index


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--receipt',action='append',required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--part-bytes',type=int,default=256*1024**2);args=parser.parse_args();pairs=[]
    for value in args.receipt:
        identifier,separator,file=value.partition('=')
        if not separator:parser.error('receipt must be ID=PATH')
        pairs.append((identifier,Path(file)))
    result=bundle(pairs,args.output,args.part_bytes);print(json.dumps({'qualification':result['qualification'],'complete_product_coverage':False,'parts':len(result['parts']),'bytes':result['stream_size_bytes']}))
