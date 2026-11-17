#!/usr/bin/env python3
"""Assemble original, receipt-bound notice bytes for every coordinator layout."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('ud_source_bundle',Path(__file__).with_name('source-bundle.py'));source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)


def assemble(receipts,output):
    output=Path(output)
    if output.exists():raise ValueError('new notice output required')
    output.mkdir(parents=True);records=[];files={};bindings=[]
    for identifier,file in sorted(receipts):
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,80}',identifier):raise ValueError('invalid notice source ID')
        file=Path(file);raw=file.read_bytes();data=json.loads(raw)
        if data.get('status')!='passed':raise ValueError('notice source subinventory is incomplete')
        bindings.append({'id':identifier,'sha256':hashlib.sha256(raw).hexdigest()})
        for component in data.get('files',[]):
            for notice in component.get('notices',[]):
                stream,identity,record=source.opened(file.parent,notice)
                try:
                    body=stream.read(8*1024**2+1)
                    if len(body)!=record['size_bytes']or len(body)>8*1024**2:raise ValueError('notice exceeds bound')
                finally:stream.close()
                name=record['sha256']+'.txt';target=output/name
                if name not in files:target.write_bytes(body);target.chmod(0o644);files[name]={'path':name,'sha256':record['sha256'],'size_bytes':len(body)}
                records.append({'collection':identifier,'component':component.get('name'),'version':component.get('version'),'archive_sha256':component['sha256'],'source_path':notice['source_path'],'notice':name})
    if not files:raise ValueError('notice inventory is empty')
    result={'schema_version':1,'qualification':'original-upstream-notices-no-license-conclusion','sources':bindings,'files':[files[key]for key in sorted(files)],'components':records,'scope':'These exact upstream notice bytes accompany all layouts. Dependency declarations and corresponding-source coverage remain separately verified; absence from this subinventory never implies permission or public-domain status.'}
    (output/'INDEX.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--receipt',action='append',required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();pairs=[]
    for item in args.receipt:
        identifier,separator,file=item.partition('=')
        if not separator:parser.error('receipt must be ID=PATH')
        pairs.append((identifier,Path(file)))
    result=assemble(pairs,args.output);print(json.dumps({'files':len(result['files']),'component_notices':len(result['components'])}))
