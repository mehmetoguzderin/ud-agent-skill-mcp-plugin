#!/usr/bin/env python3
"""Build the frozen original Rust AST helper in a protected native ARM job."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'scripts/quality/rust-assertion-parser'
SOURCES = ('Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/cfg_regions.rs')
CHILD = r'''
import hashlib,importlib.util,json,os,stat,shutil
from pathlib import Path
spec=importlib.util.spec_from_file_location('owned_boundary','/opt/mutation/harness/oci-exec.py');boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)
receipt=json.loads(Path('/input/source.json').read_bytes())
owned=Path('/state/parser-source');owned.mkdir(mode=0o755)
expected={'Cargo.toml','Cargo.lock','src/main.rs','src/cfg_regions.rs'}
if {row['path']for row in receipt['files']}!=expected:raise ValueError('Parser source inventory is not closed')
for row in receipt['files']:
 file=Path('/input/source')/row['path'];info=file.lstat()
 if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or info.st_size!=row['size']or info.st_size>1024**2:raise ValueError('Parser source is not bounded ordinary input')
 raw=file.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('Parser source hash differs')
 target=owned/row['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o444)
for directory in sorted([owned,*[path for path in owned.rglob('*')if path.is_dir()]],key=lambda path:len(path.parts),reverse=True):directory.chmod(0o555)
workspace={'root':str(owned),'files':[{**row,'mode':0o444}for row in receipt['files']],'readonly_links':[],'readonly_tree':True}
program=r"""
import os,stat,subprocess,sys
from pathlib import Path
source,result=map(Path,sys.argv[1:]);cache=Path(os.environ['TMPDIR']);home=cache/'cargo-home';home.mkdir();target=cache/'target'
env={'PATH':'/opt/mutation/rust/bin:/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(cache),'TMPDIR':str(cache),'CARGO_HOME':str(home),'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','SOURCE_DATE_EPOCH':'315532800','RUSTC':'/opt/mutation/rust/bin/rustc'}
command=['/opt/mutation/rust/bin/cargo','build','--release','--locked','--offline','--jobs','2','--manifest-path',str(source/'Cargo.toml'),'--target','aarch64-unknown-linux-gnu','--config','source.crates-io.replace-with="verified-vendor"','--config','source.verified-vendor.directory="/opt/mutation/rust/vendor"']
result_code=subprocess.run(command,cwd=source,env=env).returncode
if result_code:raise SystemExit(result_code)
compiled=target/'aarch64-unknown-linux-gnu/release/ud-rust-assertion-parser';info=compiled.lstat()
assert stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and info.st_size<32*1024**2
result.write_bytes(compiled.read_bytes())
"""
outcome=boundary.execute(['/opt/mutation/python/bin/python3','-I','-B','-c',program,'{workspace}','{result}'],state='/state',environment={'PATH':'/opt/mutation/rust/bin:/usr/bin:/bin','LANG':'C.UTF-8'},timeout=240,workspace=workspace,result={'basename':'parser.bin','max_bytes':32*1024**2})
raw=outcome.pop('result_bytes',None)
if outcome['status']!=0 or outcome['timed_out'] or outcome.get('cancelled')or outcome['owned_descendants_cancelled']or raw is None:raise RuntimeError(json.dumps(outcome))
if raw[:6]!=b'\x7fELF\x02\x01'or int.from_bytes(raw[18:20],'little')!=183:raise RuntimeError('compiled parser is not native ARM64 ELF')
Path('/state/ud-rust-assertion-parser').write_bytes(raw)
print(json.dumps({'schema_version':1,'qualification':'development-assertion-parser-build','sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),'source_inventory':receipt['source_inventory'],'execution':outcome}))
'''


def digest(file):
    with file.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def source_inputs(root):
    entries=[];inventory={}
    for name in SOURCES:
        file=root/SOURCE/name
        for parent in file.parents:
            if parent==root:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('parser source parent is an alias')
        info=file.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or info.st_size>1024**2:raise ValueError('parser source is not bounded ordinary data')
        raw=file.read_bytes();expected=hashlib.sha256(raw).hexdigest();entries.append({'path':name,'sha256':expected,'size':len(raw),'mode':0o644});inventory[SOURCE+'/'+name]=expected
    return {'schema_version':1,'files':entries,'source_inventory':inventory}


def verify_sdk(root,receipt):
    if receipt.get('qualification')!='development-mutation-toolchain'or receipt.get('platform')!='linux/arm64'or receipt.get('links')!=[]:raise ValueError('Rust SDK authority is invalid')
    expected=set()
    for item in receipt['files']:
        name=item['path']
        if not isinstance(name,str)or name.startswith('/')or any(part in('','.','..')for part in name.split('/'))or'\\'in name or name in expected:raise ValueError('Rust SDK member is unsafe or duplicate')
        expected.add(name);file=root/name
        for parent in file.parents:
            if parent==root:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('Rust SDK parent is aliased')
        info=file.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_size!=item['size']or stat.S_IMODE(info.st_mode)!=item['mode']or digest(file)!=item['sha256']:raise ValueError('Rust SDK bytes or metadata differ from receipt')
    if {file.relative_to(root).as_posix()for file in root.rglob('*')if file.is_file()}!=expected or any(file.is_symlink()for file in root.rglob('*')):raise ValueError('Rust SDK closure has unlisted members')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--sdk',type=Path,default=ROOT/'.artifacts/mutation-rust-assets');parser.add_argument('--image',default='localhost/ud-agent-mutation-runtime:arm64-final1');parser.add_argument('--harness-snapshot',type=Path,default=ROOT/'scripts/quality');args=parser.parse_args()
    if platform.machine().lower()not in('arm64','aarch64'):raise ValueError('This build requires a native ARM host; emulation is disabled')
    output=args.output.resolve();output.mkdir(mode=0o700,parents=True);sdk=args.sdk.resolve();receipt=json.loads((sdk/'rust-input-receipt.json').read_bytes());verify_sdk(sdk/'export',receipt)
    source=source_inputs(ROOT);input_root=output/'input';(input_root/'source').mkdir(parents=True)
    for item in source['files']:
        target=input_root/'source'/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/SOURCE/item['path'],target);target.chmod(0o644)
    (input_root/'source.json').write_text(json.dumps(source)+'\n')
    identifier=uuid.uuid4().hex;name='ud-assertion-parser-'+identifier;volume=name+'-state';label='io.github.mehmetoguzderin.ud-agent.parser-build='+identifier
    def docker(arguments,**options):
        result=subprocess.run(['docker',*arguments],capture_output=True,text=True,timeout=options.pop('timeout',120),**options)
        if result.returncode:raise RuntimeError('Docker command failed: '+result.stderr[-4000:])
        return result.stdout
    # This builder is local-only; do not copy any source to an SSH/TCP daemon.
    context=os.environ.get('DOCKER_CONTEXT')
    endpoint=docker(['context','inspect','--format','{{.Endpoints.docker.Host}}',*([context]if context else [])]).strip()if context or not os.environ.get('DOCKER_HOST')else os.environ['DOCKER_HOST']
    if not endpoint.startswith('unix:///') and endpoint!='npipe:////./pipe/docker_engine':raise ValueError('Parser source builds require a local Docker endpoint')
    image=json.loads(docker(['image','inspect',args.image]))[0]
    if image.get('Os')!='linux'or image.get('Architecture')!='arm64':raise ValueError('Parser image is not native Linux ARM64')
    command=['create','--pull=never','--name',name,'--label',label,'--platform','linux/arm64','--user','0:0','--init','--network','none','--read-only','--cpus','2','--memory','2g','--pids-limit','128','--cap-drop','ALL']
    for capability in ['SETUID','SETGID','CHOWN','DAC_OVERRIDE','KILL','SETPCAP']:command+=['--cap-add',capability]
    command+=['--security-opt','no-new-privileges','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=512m','--mount','type=volume,src='+volume+',dst=/state','--mount','type=volume,src='+volume+'-input,dst=/input,readonly','--entrypoint','/opt/mutation/python/bin/python3',image['Id'],'-I','-B','-c',CHILD]
    created=False;volume_created=False;input_created=False;carrier_created=False;proof=None
    carrier=name+'-input';inputs=volume+'-input'
    journal={'schema_version':1,'qualification':'original-parser-build','image':image['Id'],'docker_endpoint':endpoint,'owner':identifier,'source_inventory':source['source_inventory'],'resources':{'job':name,'carrier':carrier,'state':volume,'input':inputs},'cleanup':[]}
    def save(): (output/'setup-journal.json').write_text(json.dumps(journal,indent=2)+'\n')
    save()
    try:
        docker(['volume','create','--label',label,volume]);volume_created=True
        docker(['volume','create','--label',label,inputs]);input_created=True
        docker(['create','--pull=never','--name',carrier,'--label',label,'--network','none','--mount','type=volume,src='+inputs+',dst=/input','--entrypoint','/bin/true',image['Id']]);carrier_created=True
        docker(['cp',str(input_root/'source'),carrier+':/input/source']);docker(['cp',str(input_root/'source.json'),carrier+':/input/source.json'])
        docker(['cp',carrier+':/opt/mutation/input-receipt.json',str(output/'image-input-receipt.json')]);runtime=json.loads((output/'image-input-receipt.json').read_text())
        if runtime.get('rust',{}).get('sha256')!=digest(sdk/'rust-input-receipt.json'):raise ValueError('Parser image SDK differs from verified base receipt')
        for name_needed in ('oci-exec.py','oci-isolation.py'):
            expected=next((row for row in runtime['harness']if row['path']==name_needed),None)
            if expected is None or expected['sha256']!=digest(args.harness_snapshot/name_needed):raise ValueError('Parser image execution boundary is stale')
        docker(command);created=True
        log=docker(['start','--attach',name],timeout=300);(output/'build.log').write_text(log)
        state=json.loads(docker(['inspect',name]))[0]['State']
        if state['ExitCode']!=0 or state['OOMKilled']:raise ValueError('Parser compile failed or exhausted memory')
        proof=json.loads(log.splitlines()[-1]);docker(['cp',name+':/state/ud-rust-assertion-parser',str(output/'parser.bin')])
        if digest(output/'parser.bin')!=proof['sha256']or(output/'parser.bin').stat().st_size!=proof['size_bytes']:raise ValueError('Parser export differs from harvested proof')
        if source_inputs(ROOT)!=source:raise ValueError('Parser sources changed during compilation')
        shutil.copytree(sdk/'export',output/'export');binary=output/'export/bin/ud-rust-assertion-parser';binary.parent.mkdir(exist_ok=True,parents=True)
        if binary.exists():binary.chmod(0o644)
        shutil.copyfile(output/'parser.bin',binary);binary.chmod(0o555)
        receipt['assertion_parser']={'schema_version':1,'source_inventory':source['source_inventory']};receipt['files']=[item for item in receipt['files']if item['path']!='bin/ud-rust-assertion-parser'];receipt['files'].append({'path':'bin/ud-rust-assertion-parser','sha256':proof['sha256'],'size':proof['size_bytes'],'mode':0o555});receipt['files'].sort(key=lambda item:item['path'])
        verify_sdk(output/'export',receipt);(output/'rust-input-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    finally:
        if created:
            current=json.loads(docker(['inspect',name]))[0]
            if current['Config'].get('Labels',{}).get('io.github.mehmetoguzderin.ud-agent.parser-build')!=identifier:raise ValueError('Parser container cleanup ownership changed')
            docker(['rm','--force',name]);journal['cleanup'].append(name);save()
        if carrier_created:
            current=json.loads(docker(['inspect',carrier]))[0]
            if current['Config'].get('Labels',{}).get('io.github.mehmetoguzderin.ud-agent.parser-build')!=identifier:raise ValueError('Parser carrier cleanup ownership changed')
            docker(['rm',carrier]);journal['cleanup'].append(carrier);save()
        if input_created:
            current=json.loads(docker(['volume','inspect',inputs]))[0]
            if current.get('Labels',{}).get('io.github.mehmetoguzderin.ud-agent.parser-build')!=identifier:raise ValueError('Parser input cleanup ownership changed')
            docker(['volume','rm',inputs]);journal['cleanup'].append(inputs);save()
        if volume_created:
            current=json.loads(docker(['volume','inspect',volume]))[0]
            if current.get('Labels',{}).get('io.github.mehmetoguzderin.ud-agent.parser-build')!=identifier:raise ValueError('Parser volume cleanup ownership changed')
            docker(['volume','rm',volume]);journal['cleanup'].append(volume);save()
    if proof is not None:
        (output/'build-receipt.json').write_text(json.dumps({'schema_version':1,'image':image['Id'],'host':{'os':platform.system(),'architecture':platform.machine()},'worker':{'os':'linux','architecture':'arm64','emulation':False},'source_inventory':source['source_inventory'],'harness_snapshot':str(args.harness_snapshot.resolve()),'harness_inputs':{name:digest(args.harness_snapshot/name)for name in('oci-exec.py','oci-isolation.py')},'execution':proof,'cleanup':'owned-container-removed','recipe_sha256':digest(Path(__file__))},indent=2)+'\n')
        print(json.dumps({'output':str(output),'receipt_sha256':digest(output/'rust-input-receipt.json'),'parser_sha256':proof['sha256']}))


if __name__=='__main__':main()
