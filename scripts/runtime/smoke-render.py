#!/usr/bin/env python3
"""Run repeated offline exports from an immutable local image without injection."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time
import uuid

CODE = r'''import hashlib,json,time
from ud_agent.render_browser import browser_export
outputs=[]
html='<!doctype html><html><head><meta charset="utf-8"></head><body><h1>UD offline render</h1><p>English العربية 日本語</p></body></html>'.encode()
for fmt in ['png','pdf','png','pdf']:
 started=time.monotonic(); data,receipt=browser_export(html,fmt,800,600)
 outputs.append({'format':fmt,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'seconds':time.monotonic()-started})
print(json.dumps({'status':'passed','outputs':outputs,'renderer_receipt_sha256':receipt}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--platform', choices=['linux/arm64', 'linux/amd64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Render evidence must have a new output path')
    root = Path(__file__).resolve().parents[2]
    policy = root / 'runtime/policies/render-seccomp.json'
    image = json.loads(subprocess.check_output(['docker','image','inspect',args.image]))[0]
    if image['Os']+'/'+image['Architecture'] != args.platform:
        raise ValueError('Render image platform mismatch')
    name = 'ud-render-acceptance-' + uuid.uuid4().hex
    label = 'io.ud-agent.acceptance=' + name
    container = None
    report = {'schema_version':1,'qualification':'development-runtime-evidence','provider':'docker','host':{'os':platform.system(),'architecture':platform.machine()},
        'worker_platform':args.platform,'image_id':image['Id'],'source_injection':False,'render_policy_sha256':hashlib.sha256(policy.read_bytes()).hexdigest(),'status':'failed'}
    def command(arguments, **options):
        return subprocess.run(['docker',*arguments],check=True,capture_output=True,**options)
    try:
        created=command(['create','--name',name,'--label',label,'--platform',args.platform,'--pull=never','--user','10001:10001','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--security-opt','seccomp='+str(policy),'--memory','2147483648','--cpus','2','--pids-limit','128','--ulimit','nofile=1024:1024',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=67108864','--workdir','/tmp','--entrypoint','python',image['Id'],'-B','-c',CODE],timeout=30)
        container=created.stdout.decode().strip()
        inspected=json.loads(command(['inspect',container],timeout=30).stdout)[0]
        host=inspected['HostConfig']; config=inspected['Config']
        if (config['User']!='10001:10001' or host['Privileged'] or not host['ReadonlyRootfs'] or host['NetworkMode']!='none'
            or host['Memory']!=2147483648 or host['NanoCpus']!=2000000000 or host['PidsLimit']!=128 or host['CapAdd']
            or host['CapDrop']!=['ALL'] or config.get('Labels',{}).get('io.ud-agent.acceptance')!=name or inspected['Image']!=image['Id']):
            raise ValueError('Created render containment does not match the requested bounds')
        report['inspection']=inspected
        execution=command(['start','--attach',container],timeout=180)
        report['worker']=json.loads(execution.stdout)
        if report['worker'].get('status')!='passed' or len(report['worker'].get('outputs',[]))!=4:
            raise ValueError('Repeated rendering did not complete')
        final=json.loads(command(['inspect',container],timeout=30).stdout)[0]
        if final['State']['Running'] or final['State']['ExitCode']!=0 or final['State']['OOMKilled']:
            raise ValueError('Render job did not exit cleanly')
        report['status']='passed'
    except Exception as error:
        report['error']=str(error)
        if isinstance(error,subprocess.CalledProcessError): report['stderr']=error.stderr.decode(errors='replace')[-8192:]
    finally:
        if container:
            current=json.loads(command(['inspect',container],timeout=30).stdout)[0]
            if current['Config'].get('Labels',{}).get('io.ud-agent.acceptance')!=name:
                raise ValueError('Refusing to clean an unowned render container')
            command(['rm','--force',container],timeout=30)
            remaining=subprocess.run(['docker','inspect',container],capture_output=True,timeout=30)
            report['cleanup_verified']=remaining.returncode!=0 and b'no such object:' in remaining.stderr.lower() and container.encode() in remaining.stderr
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='passed' or not report.get('cleanup_verified'):
        raise SystemExit(1)
    print(json.dumps({'status':'passed','evidence':str(args.output),'image_id':image['Id'],'worker_platform':args.platform}))


if __name__=='__main__': main()
