#!/usr/bin/env python3
"""Freeze native browser objects from the already reviewed stable CfT receipt."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
import os
import tempfile

ROOT=Path(__file__).resolve().parents[2]
PLATFORMS={'darwin/arm64':'mac-arm64','darwin/x64':'mac-x64','linux/arm64':'linux-arm64','linux/x64':'linux64','win32/x64':'win64'}

def acquire(platform):
    metadata_file=ROOT/'.artifacts/userspace-inputs/chrome-stable-release.json'
    metadata=json.loads(metadata_file.read_text());stable=metadata['channels']['Stable'];slug=PLATFORMS[platform]
    record=next(item for item in stable['downloads']['chrome-headless-shell']if item['platform']==slug)
    expected=f'https://storage.googleapis.com/chrome-for-testing-public/{stable["version"]}/{slug}/chrome-headless-shell-{slug}.zip'
    if record['url']!=expected:raise ValueError('browser publisher receipt has an unexpected URL')
    lock=ROOT/'runtime'/('native-browser-'+platform.replace('/','-')+'.lock.json')
    archive=ROOT/'.artifacts/userspace-inputs'/('chrome-headless-shell-'+slug+'.zip')
    frozen=json.loads(lock.read_text())if lock.exists()else None
    if archive.exists():
        data=archive.read_bytes();digest=hashlib.sha256(data).hexdigest();size=len(data)
        if frozen is not None and(frozen['sha256']!=digest or frozen['size_bytes']!=size or frozen['url']!=expected):raise ValueError('cached native browser differs from its frozen receipt')
    else:
        with tempfile.NamedTemporaryFile(prefix='.browser-download-',dir=archive.parent,delete=False)as target:
            temporary=Path(target.name);digest=hashlib.sha256();size=0
            try:
                with urlopen(Request(expected,headers={'User-Agent':'ud-agent-build/1'}),timeout=60)as source:
                    if source.url!=expected:raise ValueError('browser acquisition redirected away from its fixed publisher object')
                    while chunk:=source.read(1024*1024):
                        size+=len(chunk)
                        if size>256*1024*1024:raise ValueError('native browser archive exceeds its bound')
                        target.write(chunk);digest.update(chunk)
                target.flush();os.fsync(target.fileno());digest=digest.hexdigest()
                if frozen is not None and(frozen['sha256']!=digest or frozen['size_bytes']!=size):raise ValueError('downloaded browser differs from its frozen receipt')
                os.link(temporary,archive)
            finally:temporary.unlink(missing_ok=True)
    receipt={'schema_version':1,'state':'frozen-inputs','version':stable['version'],'platform':platform,'url':expected,'sha256':digest,'size_bytes':size,'publisher_metadata_sha256':hashlib.sha256(metadata_file.read_bytes()).hexdigest()}
    if frozen is None:
        with lock.open('x')as target:target.write(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return {'platform':platform,'archive':str(archive),'receipt':str(lock),'sha256':digest,'size_bytes':size}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--platform',choices=sorted(PLATFORMS),action='append',required=True);args=parser.parse_args()
    with ThreadPoolExecutor(max_workers=4)as pool:
        for item in pool.map(acquire,args.platform):print(json.dumps(item),flush=True)
if __name__=='__main__':main()
