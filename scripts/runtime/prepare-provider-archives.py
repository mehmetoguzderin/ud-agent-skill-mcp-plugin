#!/usr/bin/env python3
"""Create lazy provider asset packs without starting any provider or VM."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_provider_transport_paths',ROOT/'workers/ud/src/ud_agent/unicode_paths.py');paths=importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)

def sha(file):
    with file.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()

def ordinary(root,name):
    paths.validate_path(name);current=root
    for index,part in enumerate(name.split('/')):
        current/=part
        if current.is_symlink()or(index<len(name.split('/'))-1 and not current.is_dir()):raise ValueError('provider asset parent is not an ordinary directory')
    if not current.is_file():raise ValueError('provider asset is not an ordinary file')
    return current

def verify_reused_archive(file,selected,root):
    expected={item['path']:item for item in selected};seen=set()
    with tarfile.open(file,'r:gz')as archive:
        for member in archive:
            name=member.name;paths.validate_path(name)
            if name in seen or name not in expected or not member.isfile()or member.pax_headers:raise ValueError('reused provider archive has undeclared or unsafe members')
            seen.add(name);item=expected[name]
            mode=0o555 if(root/name).stat().st_mode&0o111 else 0o444
            if member.size!=item['size_bytes']or member.mode!=mode or member.uid!=0 or member.gid!=0 or member.mtime!=0:raise ValueError('reused provider archive metadata differs')
            with archive.extractfile(member)as stream:
                if'sha256:'+hashlib.file_digest(stream,'sha256').hexdigest()!=item['sha256']:raise ValueError('reused provider archive member bytes differ')
    if seen!=set(expected):raise ValueError('reused provider archive is incomplete')

def prepare(source,output,reuse=None,reuse_unchanged=False):
    source=source.resolve(strict=True);output=output.resolve()
    if output.exists()or output.is_relative_to(source):raise ValueError('provider archive output must be a new separate directory')
    receipt=json.loads((source/'provider-receipts.json').read_text())
    reused=json.loads(ordinary(reuse.resolve(strict=True),'provider-receipts.json').read_text())if reuse is not None else None
    if receipt.get('schema_version')!=1 or not receipt.get('provider_receipts')or not receipt.get('files'):raise ValueError('provider source receipt is incomplete')
    inventory={};keys=set();assets=[];output.mkdir(parents=True);(output/'INCOMPLETE').write_text('Provider archives have not completed.\n')
    for item in receipt['files']:
        name=item['path']
        paths.validate_path(name);key=paths.path_key(name)
        if key in keys or len(keys)>=50000:raise ValueError('provider asset path is unsafe or duplicate')
        keys.add(key)
        file=ordinary(source,name)
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=item['size_bytes']or'sha256:'+sha(file)!=item['sha256']:raise ValueError('provider source bytes differ from their frozen receipt')
        inventory[name]=item;target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o555 if file.stat().st_mode&0o111 else 0o444)
    for name,item in receipt['provider_receipts'].items():
        parts=name.split('/')
        if len(parts)!=3 or parts[0]not in('apple-container','wslc','lima-nerdctl')or parts[1]not in('darwin','win32','linux')or parts[2]not in('arm64','x64'):raise ValueError('provider identity is unsupported')
        engine,platform,architecture=parts;prefix=f'runtime/providers/{engine}/{platform}-{architecture}/';selected=[value for path,value in inventory.items()if path.startswith(prefix)or engine=='apple-container'and path=='runtime/images/init-linux-arm64.tar']
        if not selected:raise ValueError('provider selected inventory is empty')
        slug='-'.join(parts);relative=f'.artifacts/release-inputs/ud-agent-provider-{slug}.tar.gz';archive=output/relative;archive.parent.mkdir(parents=True,exist_ok=True)
        previous=None;previous_asset=None
        if reused is not None:
            previous=reused.get('provider_receipts',{}).get(name,{}).get('lazy_assets')
            previous_asset=next((value for value in reused.get('lazy_archive_assets',[])if value['id']=='provider-assets-'+slug),None)
        can_reuse=previous and previous_asset and previous_asset['path']==relative and json.dumps(previous['files'],sort_keys=True)==json.dumps(selected,sort_keys=True)
        if reused is not None and not can_reuse and not reuse_unchanged:raise ValueError('provider archive reuse requires the exact unchanged selected inventory')
        if can_reuse:
            existing=ordinary(reuse.resolve(),relative)
            if existing.stat().st_size!=previous['size']or'sha256:'+sha(existing)!=previous['sha256']or previous_asset['sha256']!=previous['sha256']or previous_asset['size_bytes']!=previous['size']:raise ValueError('reused provider archive receipt differs')
            verify_reused_archive(existing,selected,output);shutil.copyfile(existing,archive)
            if archive.stat().st_size!=previous['size']or'sha256:'+sha(archive)!=previous['sha256']:raise ValueError('reused provider archive changed during copy')
        else:
            with archive.open('xb')as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0)as zipped,tarfile.open(fileobj=zipped,mode='w|',format=tarfile.USTAR_FORMAT)as target:
                for entry in sorted(selected,key=lambda value:value['path']):
                    file=output/entry['path'];header=tarfile.TarInfo(entry['path']);header.size=entry['size_bytes'];header.mode=0o555 if file.stat().st_mode&0o111 else 0o444;header.uid=header.gid=header.mtime=0;header.uname=header.gname=''
                    with file.open('rb')as content:target.addfile(header,content)
        url='https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/'+archive.name;fingerprint='sha256:'+sha(archive);size=archive.stat().st_size
        item['lazy_assets']={'url':url,'sha256':fingerprint,'size':size,'files':selected}
        assets.append({'id':'provider-assets-'+slug,'platform':slug,'path':relative,'url':url,'sha256':fingerprint,'size_bytes':size})
    receipt['lazy_archive_assets']=assets
    (output/'provider-receipts.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');(output/'INCOMPLETE').unlink();return receipt

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--assets',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);group=parser.add_mutually_exclusive_group();group.add_argument('--reuse-archives',type=Path);group.add_argument('--reuse-unchanged-archives',type=Path);args=parser.parse_args();result=prepare(args.assets,args.output,args.reuse_archives or args.reuse_unchanged_archives,args.reuse_unchanged_archives is not None);print(json.dumps({'providers':list(result['provider_receipts']),'assets':result['lazy_archive_assets']}))
if __name__=='__main__':main()
