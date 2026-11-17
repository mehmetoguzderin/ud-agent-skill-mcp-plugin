#!/usr/bin/env python3
"""Check exact cross-architecture assets without executing foreign binaries."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[2]
HOSTS=['darwin/arm64','darwin/x64','linux/arm64','linux/x64','win32/arm64','win32/x64']
def digest(file):
    with file.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()
def read(file):return json.loads(file.read_text())
def hash_value(value):return str(value).removeprefix('sha256:')


def binary_architecture(file):
    with file.open('rb')as source:
        data=source.read(4096)
        if data[:6]==b'\x7fELF\x02\x01':return {62:'amd64',183:'arm64'}.get(struct.unpack_from('<H',data,18)[0],'unknown')
        if data[:4]==b'\xcf\xfa\xed\xfe':return {0x1000007:'amd64',0x100000C:'arm64'}.get(struct.unpack_from('<I',data,4)[0],'unknown')
        if data[:2]==b'MZ'and len(data)>=64:
            offset=struct.unpack_from('<I',data,60)[0]
            if offset>1024*1024:raise ValueError('PE header exceeds inspection bound')
            source.seek(offset);header=source.read(6)
            if header[:4]!=b'PE\0\0':raise ValueError('invalid PE signature')
            return {0x8664:'amd64',0xAA64:'arm64'}.get(struct.unpack_from('<H',header,4)[0],'unknown')
    raise ValueError('unsupported native executable format')


def lima_assets(root):
    lock = read(root / 'runtime/lima-inputs.lock.json')
    rows = []
    expected = {'lima': ('v2.3.0', '800a96b14e96b5d2ceb20ab2602147c1e79224ea'), 'nerdctl': ('v2.4.2', '94bc03df5247ece1781c4b115a44ef3d4b1e0e65')}
    for name, (tag, commit) in expected.items():
        if lock['sources'][name]['tag'] != tag or lock['sources'][name]['commit'] != commit:
            raise ValueError('Lima provider source identity differs from its exact maintained head')
    for asset in lock['assets']:
        file = root / '.artifacts/lima-product' / asset['name']
        if file.is_symlink() or not file.is_file() or file.stat().st_size != asset['size'] or digest(file) != asset['sha256']:
            raise ValueError('Lima provider input bytes differ from their frozen receipt')
        architecture = 'arm64' if '-arm64.tar.gz' in asset['name'] else 'amd64'
        required = ['bin/limactl'] if asset['name'].startswith('lima-') else ['bin/nerdctl', 'bin/containerd', 'bin/runc']
        binaries = []
        with tarfile.open(file, 'r:gz') as archive:
            members = {item.name.removeprefix('./'): item for item in archive}
            for name in required:
                item = members.get(name)
                if item is None or not item.isfile() or item.size < 20 or item.size > 512 * 1024**2:
                    raise ValueError('Lima provider native binary is missing from the exact archive')
                with archive.extractfile(item) as binary:
                    data = binary.read(4096)
                if data[:6] == b'\x7fELF\x02\x01':
                    machine = {62: 'amd64', 183: 'arm64'}.get(struct.unpack_from('<H', data, 18)[0])
                elif data[:4] == b'\xcf\xfa\xed\xfe':
                    machine = {0x1000007: 'amd64', 0x100000C: 'arm64'}.get(struct.unpack_from('<I', data, 4)[0])
                else:
                    raise ValueError('Lima provider native binary has an unsupported format')
                if machine != architecture:
                    raise ValueError('Lima provider binary architecture differs from selected asset')
                binaries.append({'path': name, 'architecture': machine, 'size_bytes': item.size})
        rows.append({'component': 'lima-provider-input', 'platform': 'darwin/' + ('x64' if architecture == 'amd64' else 'arm64'),
                     'status': 'bytes-verified', 'asset': asset, 'binaries': binaries, 'executed': False,
                     'execution': 'deferred-user-request' if architecture == 'amd64' else 'pending-provider'})
    if len(rows) != 4:
        raise ValueError('Lima provider must include both architectures of Lima and its complete nerdctl closure')
    return rows


def build(root,network=False):
    rows=[];errors=[]
    def asset(component,host,version,record,candidates):
        expected=hash_value(record.get('sha256'));size=record.get('size_bytes',record.get('size'));url=record.get('url')
        if not re.fullmatch('[a-f0-9]{64}',expected)or size is not None and(not isinstance(size,int)or size<=0):raise ValueError('invalid locked asset identity')
        existing=next((file for file in candidates if file.exists()),None)
        item={'component':component,'platform':host,'version':version,'sha256':'sha256:'+expected,'url':url,'size_bytes':size}
        if existing:
            if existing.is_symlink()or not existing.is_file()or digest(existing)!=expected or size is not None and existing.stat().st_size!=size:raise ValueError('asset integrity mismatch: '+str(existing))
            item.update(status='bytes-verified',path=existing.relative_to(root).as_posix(),size_bytes=existing.stat().st_size)
        elif network and isinstance(url,str)and url.startswith('https://'):
            with urlopen(Request(url,method='HEAD',headers={'User-Agent':'ud-agent-availability/1'}),timeout=30)as response:
                actual=response.headers.get('Content-Length')
                if response.status!=200 or size is not None and actual is not None and int(actual)!=size:raise ValueError('publisher availability metadata mismatch: '+url)
                item.update(status='publisher-object-available',http_status=response.status,content_length=int(actual)if actual else None)
        else:raise ValueError('required locked asset is not locally available: '+component+'/'+host)
        return item
    pending=[]
    for lock_name,folder in [('node-distributions','node'),('node-compatibility','node24')]:
        node=read(root/'runtime'/f'{lock_name}.lock.json');signed=root/'.artifacts'/folder/'SHASUMS256.txt.asc';keyring=root/'.artifacts/node/nodejs-release-keys.kbx'
        if digest(signed)!=node['signed_manifest_sha256']or digest(keyring)!=node['release_keyring_sha256']:raise ValueError('Node publisher signature inputs are stale')
        proof=subprocess.run(['gpgv','--keyring',str(keyring),'--status-fd','1',str(signed)],capture_output=True,text=True,timeout=30,check=True)
        if '[GNUPG:] VALIDSIG '+node['checksum_signer_fingerprint']+' 'not in proof.stdout:raise ValueError('Node publisher signer differs from its exact receipt')
        signed_lines=signed.read_text().splitlines()
        for host in HOSTS:
            item=node['platforms'][host.replace('/','-')]
            if item['sha256']+'  '+item['filename']not in signed_lines:raise ValueError('Node platform asset is absent from the signed publisher inventory')
            record={**item,'url':f'https://nodejs.org/dist/v{node["version"]}/'+item['filename']};pending.append(('node',host,node['version'],record,[root/'.artifacts'/folder/item['filename']]))
    inputs=read(root/'runtime/userspace-inputs.lock.json')
    for host in HOSTS:
        item=inputs['platforms'][host]
        for key,version in [('uv_archive',inputs['uv_version']),('python_download',item['python_download']['version'])]:
            record=item[key];paths=[root/'.artifacts/userspace-inputs/cache'/hash_value(record['sha256'])]
            if key=='python_download':paths.append(root/'.artifacts'/record['url'].rsplit('/',1)[-1].replace('%2B','+'))
            pending.append(('uv'if key=='uv_archive'else'python',host,version,record,paths))
    for slug,host,archive in [('macos-arm64','darwin/arm64','mac-arm64'),('darwin-x64','darwin/x64','mac-x64'),('linux-arm64','linux/arm64','linux-arm64'),('linux-x64','linux/x64','linux64'),('win32-x64','win32/x64','win64')]:
        record=read(root/'runtime'/f'native-browser-{slug}.lock.json');pending.append(('browser',host,record['version'],record,[root/'.artifacts/userspace-inputs'/f'chrome-headless-shell-{archive}.zip']))
    edge=read(root/'runtime/native-browser-windows-arm64.lock.json');pending.append(('browser','win32/arm64',edge['version'],edge['archive'],[root/'.artifacts/browser-windows-arm64/MicrosoftEdgeEnterpriseARM64.msi']))
    def checked(arguments):
        try:return asset(*arguments)
        except(Exception)as error:return {'component':arguments[0],'platform':arguments[1],'status':'failed','error':str(error)}
    with ThreadPoolExecutor(max_workers=8)as pool:rows.extend(pool.map(checked,pending))
    perl=read(root/'runtime/native-perl-source.lock.json');archive=root/'.artifacts/native-perl/cache'/(perl['name']+'.tar.gz')
    rows.append(checked(('perl-source','all',perl['version'],{'sha256':perl['sha256'],'url':perl['url']},[archive])))
    modules=read(root/'runtime/native-perl-modules.lock.json')
    for name,record in modules['releases'].items():
        candidates=[root/'.artifacts/perl-mutation/cache'/(hash_value(record['sha256'])+'.tar.gz')]
        rows.append(checked(('perl-module','all',name,record,candidates)))
    cross=read(root/'.artifacts/cross-build-receipt.json')
    for host in HOSTS:
        for component,record in cross['platforms'][host.replace('/','-')].items():
            file=root/record['path'];architecture='amd64'if host.endswith('/x64')else'arm64'
            try:
                if digest(file)!=record['sha256']or binary_architecture(file)!=architecture:raise ValueError('native helper hash or machine mismatch')
                rows.append({'component':component,'platform':host,'status':'cross-built-bytes-verified','sha256':'sha256:'+record['sha256'],'execution':'deferred-user-request'if architecture=='amd64'else'pending-native'if host.startswith('win32/')else'locally-applicable'})
            except(Exception)as error:rows.append({'component':component,'platform':host,'status':'failed','error':str(error)})
    for host in HOSTS:
        slug=host.replace('/','-');file=root/'.artifacts/native-perl'/(slug+('-source'if host=='linux/arm64'else'')+'-receipt.json')
        if host=='linux/x64':
            rows.append({'component':'private-perl-build','platform':host,'status':'deferred-user-request','source_version':perl['version'],'recipe':'scripts/runtime/build-linux-perl.py','reason':'Source build requires amd64 execution; exact source/module assets are checked above.'});continue
        if not file.is_file():rows.append({'component':'private-perl-build','platform':host,'status':'failed','error':'compiled private dependency receipt is missing'});continue
        record=read(file);rows.append({'component':'private-perl-build','platform':host,'status':'dependency-receipt-available','receipt':file.relative_to(root).as_posix(),'receipt_sha256':'sha256:'+digest(file),'files':len(record.get('files',[])),'execution':'deferred-user-request'if host.endswith('/x64')else'pending-native'if host.startswith('win32/')else'locally-applicable'})
    provider_root=root/'.artifacts/provider-assets/export-v4';provider_file=provider_root/'provider-receipts.json'
    if provider_file.is_file():
        provider=read(provider_file)
        for entry in provider['files']:
            file=provider_root/entry['path']
            if file.is_symlink()or not file.is_file()or digest(file)!=hash_value(entry['sha256'])or file.stat().st_size!=entry['size_bytes']:raise ValueError('provider asset inventory is damaged')
        for name,receipt in provider['provider_receipts'].items():
            record=next((item for item in provider['files']if item['sha256']==receipt['executable_sha256']),None)
            if record is None:raise ValueError('provider CLI is absent from its closed inventory')
            architecture='amd64'if name.endswith('/x64')else'arm64'
            if binary_architecture(provider_root/record['path'])!=architecture:raise ValueError('provider CLI machine differs from its selected architecture')
            rows.append({'component':'runtime-provider','platform':name,'status':'bytes-verified','receipt':str(provider_file.relative_to(root)),'executable_sha256':receipt['executable_sha256'],'execution':'deferred-user-request'if architecture=='amd64'else'pending-provider'})
    else:rows.append({'component':'runtime-provider','platform':'all','status':'failed','error':'complete Apple/WSLc provider asset closure is missing'})
    rows.extend(lima_assets(root))
    for item in rows:
        if item['status']=='failed':errors.append(item['component']+'/'+item['platform']+': '+item['error'])
    return {'schema_version':1,'qualification':'architecture-availability-only','executed_foreign_binaries':False,'heavy_amd64_execution':'deferred-user-request','status':'passed'if not errors else'failed','rows':rows,'errors':errors}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--check-network',action='store_true');args=parser.parse_args();report=build(ROOT,args.check_network);args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'rows':len(report['rows']),'errors':report['errors']}));return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
