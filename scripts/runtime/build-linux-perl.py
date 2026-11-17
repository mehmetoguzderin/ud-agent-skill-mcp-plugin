#!/usr/bin/env python3
"""Build the shared pinned Perl source/module contract in an owned offline Linux job."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[2]

def sha(file):
    with file.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def acquire(url,target,digest,download):
    # Explicit --download fetches only frozen inputs from their locked public
    # origins and admits them only by their locked SHA-256; offline runs keep
    # requiring the verified cache.
    if target.is_file()and not target.is_symlink():return
    if not download:return
    from urllib.parse import urlsplit
    from urllib.request import Request,urlopen
    parsed=urlsplit(url)
    if parsed.scheme!='https'or parsed.hostname not in{'cpan.metacpan.org','codeload.github.com'}or parsed.query or parsed.fragment:raise ValueError('untrusted Perl input URL')
    with urlopen(Request(url,headers={'User-Agent':'ud-agent-perl-inputs/0.1'}),timeout=120)as response:data=response.read(64*1024*1024+1)
    if len(data)>64*1024*1024 or hashlib.sha256(data).hexdigest()!=digest:raise ValueError('downloaded Perl input differs from its lock: '+target.name)
    target.parent.mkdir(parents=True,exist_ok=True);temporary=target.with_name('.'+target.name+'.'+uuid.uuid4().hex);temporary.write_bytes(data);temporary.replace(target)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--platform',choices=['linux/arm64','linux/amd64'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--compiled-input',type=Path,help='Resume ELF closure from a source-receipted private compiled pack');parser.add_argument('--docker-host',help='Explicit product-owned local Docker Unix endpoint');parser.add_argument('--download',action='store_true',help='explicitly acquire missing locked public source inputs and the pinned builder image');args=parser.parse_args();output=args.output.resolve();
    if output.exists():raise ValueError('Linux Perl output must be new')
    lock=json.loads((ROOT/'quality/act.lock.json').read_text());image=lock['linux_runner']['nonroot_image'];source=json.loads((ROOT/'runtime/native-perl-source.lock.json').read_text());modules=json.loads((ROOT/'runtime/native-perl-modules.lock.json').read_text());interset=json.loads((ROOT/'runtime/perl-deps.lock.json').read_text())['interset']
    acquire(source['url'],ROOT/'.artifacts/native-perl/cache'/(source['name']+'.tar.gz'),source['sha256'],args.download)
    acquire('https://codeload.github.com/dan-zeman/interset/tar.gz/'+interset['commit'],ROOT/'.artifacts/perl-sources'/interset['archive'],interset['archive_sha256'],args.download)
    for item in modules['releases'].values():acquire(item['url'],ROOT/'.artifacts/perl-mutation/cache'/(item['sha256']+'.tar.gz'),item['sha256'],args.download)
    owner=uuid.uuid4().hex;context=ROOT/'.artifacts/linux-perl-source-inputs'/owner;context.mkdir(parents=True,mode=0o755)
    inputs=['scripts/runtime/prepare-native-perl.py','scripts/runtime/perl_build.py','scripts/runtime/elf_dependencies.py','workers/ud/src/ud_agent/elf_runtime.py','scripts/runtime/close-linux-elf.py','scripts/quality/prepare-perl-parser.py','runtime/native-perl-source.lock.json','runtime/native-perl-modules.lock.json','runtime/perl-deps.lock.json','.artifacts/native-perl/cache/'+source['name']+'.tar.gz','.artifacts/perl-sources/'+interset['archive']]
    inputs+=['.artifacts/perl-mutation/cache/'+item['sha256']+'.tar.gz'for item in modules['releases'].values()]
    source_inputs=[]
    for relative in inputs:
        original=ROOT/relative
        if original.is_symlink()or not original.is_file():raise ValueError('source-built Perl offline input is missing')
        target=context/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target);target.chmod(0o444);source_inputs.append({'path':relative,'sha256':sha(target),'size_bytes':target.stat().st_size})
    if args.compiled_input:
        compiled=args.compiled_input.resolve(strict=True);receipt_path=compiled.parent/(compiled.name+'-receipt.json');receipt=json.loads(receipt_path.read_text())
        contract_sha=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if receipt['source_sha256']!=contract_sha(source)or receipt['modules_sha256']!=contract_sha(modules)or receipt['interset_commit']!=interset['commit']:raise ValueError('compiled Perl inputs differ from the frozen dependency contract')
        for item in receipt['files']:
            relative=item['path'];original=compiled/relative
            if relative.startswith('/')or'\\'in relative or any(part in('', '.', '..')for part in relative.split('/'))or original.is_symlink()or'sha256:'+sha(original)!=item['sha256']or original.stat().st_size!=item['size']:raise ValueError('compiled Perl input inventory is damaged')
            target=context/'compiled/perl'/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original,target);source_inputs.append({'path':target.relative_to(context).as_posix(),'sha256':sha(target),'size_bytes':target.stat().st_size})
        shutil.copyfile(receipt_path,context/'compiled/perl-receipt.json');source_inputs.append({'path':'compiled/perl-receipt.json','sha256':sha(receipt_path),'size_bytes':receipt_path.stat().st_size})
    for directory in context.rglob('*'):
        if directory.is_dir():directory.chmod(0o755)
    (context/'input-manifest.json').write_text(json.dumps(source_inputs,indent=2)+'\n')
    volume='ud-perl-build-'+owner;input_volume=volume+'-inputs';name=volume;container=None;input_container=None;created=False;input_created=False;report={'schema_version':1,'qualification':'development-source-built-runtime','platform':args.platform,'provider_image':image,'host':{'os':platform.system(),'architecture':platform.machine()},'inputs_sha256':hashlib.sha256(json.dumps(source_inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'status':'failed'}
    environment=dict(os.environ)
    if args.docker_host:
        if not args.docker_host.startswith('unix://')or not Path(args.docker_host[7:]).resolve().is_relative_to(ROOT/'.artifacts'):raise ValueError('alternate Docker endpoint must be an owned local Unix socket')
        environment.pop('DOCKER_CONTEXT',None);environment['DOCKER_HOST']=args.docker_host;report['docker_endpoint']=args.docker_host
    def run(arguments,timeout=60):return subprocess.run(['docker',*arguments],check=True,capture_output=True,timeout=timeout,env=environment)
    if args.download and subprocess.run(['docker','image','inspect',image],capture_output=True,env=environment).returncode:run(['pull','--platform',args.platform,image],1800)
    try:
        run(['volume','create','--label','io.ud-agent.perl-build='+owner,volume]);created=True
        run(['volume','create','--label','io.ud-agent.perl-build='+owner,input_volume]);input_created=True
        staged=run(['create','--name',name+'-inputs','--label','io.ud-agent.perl-build='+owner,'--pull=never','--platform',args.platform,'--network','none','--read-only','--user','0:0','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=volume,src='+input_volume+',dst=/input','--entrypoint','true',image]);input_container=staged.stdout.decode().strip()
        run(['cp',str(context)+'/.',input_container+':/input'],180)
        run(['rm',input_container]);input_container=None
        run(['run','--rm','--pull=never','--platform',args.platform,'--network','none','--read-only','--user','0:0','--cap-drop','ALL','--cap-add','CHOWN','--security-opt','no-new-privileges','--mount','type=volume,src='+volume+',dst=/output','--entrypoint','chown',image,'10001:10001','/output'])
        host='linux/x64'if args.platform=='linux/amd64'else'linux/arm64'
        prepare=['python3','-c','import shutil;shutil.copytree("/input/compiled/perl","/output/perl");shutil.copyfile("/input/compiled/perl-receipt.json","/output/perl-receipt.json")']if args.compiled_input else['python3','/input/scripts/runtime/prepare-native-perl.py','--target',host,'--output','/output/perl','--build-timeout','3600']
        commands=[prepare,['python3','/input/scripts/runtime/close-linux-elf.py','--root','/output/perl','--receipt','/output/perl-receipt.json','--platform',args.platform,'--provider',image]]
        code='import subprocess,json,hashlib,pathlib;root=pathlib.Path("/input");inventory=json.loads((root/"input-manifest.json").read_text());assert all(not(root/item["path"]).is_symlink()and(root/item["path"]).stat().st_size==item["size_bytes"]and hashlib.sha256((root/item["path"]).read_bytes()).hexdigest()==item["sha256"]for item in inventory);commands='+repr(commands)+';[subprocess.run(command,check=True)for command in commands]'
        start=run(['create','--name',name,'--label','io.ud-agent.perl-build='+owner,'--pull=never','--platform',args.platform,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','4294967296','--cpus','2','--pids-limit','256','--env','HOME=/tmp','--env','PATH=/usr/local/bin:/usr/bin:/bin','--env','LANG=C','--env','LC_ALL=C','--env','QEMU_CPU=max','--tmpfs','/tmp:rw,nosuid,nodev,size=536870912,uid=10001,gid=10001','--mount',f'type=volume,src={input_volume},dst=/input,readonly','--mount',f'type=volume,src={volume},dst=/output','--entrypoint','python3',image,'-c',code]);container=start.stdout.decode().strip()
        result=run(['start','--attach',container],7200);(context/'build.log').write_bytes(result.stdout+b'\n'+result.stderr)
        output.parent.mkdir(parents=True,exist_ok=True);run(['cp',container+':/output/perl',str(output)],180);run(['cp',container+':/output/perl-receipt.json',str(output.parent/(output.name+'-receipt.json'))],60)
        receipt=json.loads((output.parent/(output.name+'-receipt.json')).read_text())
        if receipt['probe'].get('status')!='passed'or receipt['probe'].get('ambient_elf')is not False:raise ValueError('private Perl closure was not proven')
        report['status']='passed';report['output']=str(output);print(json.dumps({'status':'passed','platform':args.platform,'files':len(receipt['files']),'output':str(output)}))
    except subprocess.CalledProcessError as error:
        (context/'build.log').write_bytes((error.stdout or b'')+b'\n'+(error.stderr or b''));report['error']=str(error)
        if container:
            # Preserve owned diagnostic output before cleanup; a failed closure
            # is never placed at the accepted output path or admitted as ready.
            failed=context/'failed-output';failed.mkdir()
            subprocess.run(['docker','cp',container+':/output/.',str(failed)],capture_output=True,timeout=120,check=False,env=environment)
        raise
    finally:
        if input_container:
            actual=json.loads(run(['inspect',input_container]).stdout)[0]
            if actual['Config'].get('Labels',{}).get('io.ud-agent.perl-build')!=owner:raise ValueError('Linux Perl input handoff ownership changed')
            run(['rm','--force',input_container])
        if container:
            actual=json.loads(run(['inspect',container]).stdout)[0]
            if actual['Config'].get('Labels',{}).get('io.ud-agent.perl-build')!=owner:raise ValueError('Linux Perl build ownership changed')
            run(['rm','--force',container])
        if created:
            actual=json.loads(run(['volume','inspect',volume]).stdout)[0]
            if actual.get('Labels',{}).get('io.ud-agent.perl-build')!=owner:raise ValueError('Linux Perl cache ownership changed')
            run(['volume','rm',volume]);report['cleanup']='verified'
        if input_created:
            actual=json.loads(run(['volume','inspect',input_volume]).stdout)[0]
            if actual.get('Labels',{}).get('io.ud-agent.perl-build')!=owner:raise ValueError('Linux Perl input volume ownership changed')
            run(['volume','rm',input_volume])
        (context/'run.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
