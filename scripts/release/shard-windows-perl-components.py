#!/usr/bin/env python3
"""Losslessly shard the complete Perl attribution; no contributor is omitted."""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('ud_windows_perl_shard_inputs',ROOT/'scripts/release/node-windows-components.py');INPUTS=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(INPUTS)
MAX_PART=4*1024**2
MAX_TOTAL=512*1024**2
MAX_PARTS=8192


def original_bytes(value):return (json.dumps(value,indent=2)+'\n').encode()
def encoded(value):return (json.dumps(value,separators=(',',':'))+'\n').encode()
def digest(body):return {'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)}
def generators():return {name:INPUTS.fingerprint(ROOT/name)for name in('scripts/release/shard-windows-perl-components.py','scripts/release/node-windows-components.py')}


def shard(source,output,*,max_part=MAX_PART):
    if not isinstance(max_part,int)or isinstance(max_part,bool)or not 256<=max_part<=MAX_PART:raise ValueError('Invalid bounded evidence-part limit')
    if output.exists():raise ValueError('A new sharded attribution directory is required')
    source_id=INPUTS.fingerprint(source)
    if not 0<source_id['size_bytes']<=MAX_TOTAL:raise ValueError('Complete source attribution exceeds its bound')
    value=json.loads(source.read_bytes())
    if value.get('schema_version')!=1 or not isinstance(value.get('records'),list)or not value['records']:raise ValueError('Incomplete source attribution')
    if original_bytes(value)!=source.read_bytes()or INPUTS.fingerprint(source)!=source_id:raise ValueError('Source attribution is noncanonical or changed')
    output.mkdir(parents=True,mode=0o700);(output/'parts').mkdir(mode=0o700);document=copy.deepcopy(value);parts=[]
    def pack(rows):
        if not isinstance(rows,list):raise ValueError('Evidence contributor list is missing')
        current=[];batches=[];current_size=3
        for row in rows:
            row_size=len(encoded(row))-1
            if row_size+3>max_part:raise ValueError('A complete contributor exceeds evidence-part bound')
            if current and current_size+1+row_size>max_part:batches.append(current);current=[];current_size=3
            current_size+=row_size+(1 if current else 0);current.append(row)
        if current:batches.append(current)
        result=[]
        for batch in batches:
            name=f'parts/{len(parts):05d}.json';body=encoded(batch);(output/name).write_bytes(body);item={'path':name,**digest(body),'items':len(batch)};parts.append(item);result.append(item)
        return {'schema_version':1,'kind':'closed-contributor-list','count':len(rows),'parts':result}
    for record in document['records']:
        for pdb in record['pdbs']:pdb['modules']=pack(pdb['modules'])
        for binary in record['binaries']:
            if binary['origin']=='supplier':binary['runtime_compilands']=pack(binary['runtime_compilands'])
    if len(parts)>MAX_PARTS:raise ValueError('Evidence-part inventory exceeds its bound')
    index={'schema_version':1,'qualification':'lossless-sharded-Windows-Perl-attribution-not-native-acceptance','source_receipt':source_id,'source_canonical_sha256':hashlib.sha256(encoded(value)).hexdigest(),'max_part_bytes':max_part,'parts':parts,'document':document,'generators':generators()}
    body=encoded(index)
    if len(body)>16*1024**2:raise ValueError('Attribution index exceeds its bound')
    (output/'index.json').write_bytes(body);verify(output/'index.json');return index


def verify(file):
    index_id=INPUTS.fingerprint(file)
    if not 0<index_id['size_bytes']<=16*1024**2:raise ValueError('Invalid attribution-index bound')
    index=json.loads(file.read_bytes());expected={'schema_version','qualification','source_receipt','source_canonical_sha256','max_part_bytes','parts','document','generators'}
    if set(index)!=expected or index['schema_version']!=1 or index['qualification']!='lossless-sharded-Windows-Perl-attribution-not-native-acceptance':raise ValueError('Invalid attribution-index contract')
    if index['generators']!=generators():raise ValueError('Attribution sharder source binding is stale')
    if not isinstance(index['max_part_bytes'],int)or isinstance(index['max_part_bytes'],bool)or not 256<=index['max_part_bytes']<=MAX_PART:raise ValueError('Invalid evidence-part limit')
    parts=index['parts']
    if not isinstance(parts,list)or len(parts)>MAX_PARTS:raise ValueError('Invalid complete part inventory')
    by_name={};total=0
    for number,item in enumerate(parts):
        name=f'parts/{number:05d}.json'
        if not isinstance(item,dict)or set(item)!={'path','sha256','size_bytes','items'}or item['path']!=name or not re.fullmatch('[0-9a-f]{64}',item['sha256'])or not isinstance(item['items'],int)or isinstance(item['items'],bool)or item['items']<1 or not isinstance(item['size_bytes'],int)or isinstance(item['size_bytes'],bool)or not 0<item['size_bytes']<=index['max_part_bytes']:raise ValueError('Invalid bounded part descriptor')
        body_file=file.parent/name
        if INPUTS.fingerprint(body_file)!={key:item[key]for key in('sha256','size_bytes')}:raise ValueError('Evidence part differs from frozen index')
        body=body_file.read_bytes();rows=json.loads(body)
        if not isinstance(rows,list)or len(rows)!=item['items']or encoded(rows)!=body:raise ValueError('Evidence-part row inventory differs')
        by_name[name]=rows;total+=len(body)
    if total>MAX_TOTAL:raise ValueError('Complete attribution evidence exceeds bound')
    actual={path.relative_to(file.parent).as_posix()for path in file.parent.rglob('*')if path.is_file()or path.is_symlink()}
    if actual!={'index.json',*by_name}:raise ValueError('Unexpected or omitted attribution payload')
    used=[];document=copy.deepcopy(index['document'])
    def unpack(value):
        if not isinstance(value,dict)or set(value)!={'schema_version','kind','count','parts'}or value['schema_version']!=1 or value['kind']!='closed-contributor-list'or not isinstance(value['count'],int)or isinstance(value['count'],bool)or value['count']<0:raise ValueError('Incomplete contributor-list contract')
        result=[]
        for item in value['parts']:
            name=item.get('path')
            if name not in by_name or item!=parts[int(name[6:11])]:raise ValueError('Contributor-list evidence is not declared')
            used.append(name);result.extend(by_name[name])
        if len(result)!=value['count']:raise ValueError('Contributor count differs from source inventory')
        return result
    for record in document['records']:
        for pdb in record['pdbs']:pdb['modules']=unpack(pdb['modules'])
        for binary in record['binaries']:
            if binary['origin']=='supplier':binary['runtime_compilands']=unpack(binary['runtime_compilands'])
    if len(used)!=len(parts)or set(used)!=set(by_name):raise ValueError('Evidence parts are missing, duplicated or unconsumed')
    if digest(original_bytes(document))!=index['source_receipt']or hashlib.sha256(encoded(document)).hexdigest()!=index['source_canonical_sha256']:raise ValueError('Lossless source attribution reconstruction failed')
    if INPUTS.fingerprint(file)!=index_id:raise ValueError('Attribution index changed while verified')
    return {'schema_version':1,'qualification':index['qualification'],'index':index_id,'source_receipt':index['source_receipt'],'parts':len(parts),'total_part_bytes':total,'records':[{'platform':row['platform'],'pdbs':len(row['pdbs']),'binaries':len(row['binaries'])}for row in document['records']]}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group(required=True);group.add_argument('--source',type=Path);group.add_argument('--verify',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
    if args.source:
        if args.output is None:parser.error('--source requires --output')
        shard(args.source,args.output);print(json.dumps(verify(args.output/'index.json')))
    else:
        if args.output is not None:parser.error('--verify does not write output')
        print(json.dumps(verify(args.verify)))
