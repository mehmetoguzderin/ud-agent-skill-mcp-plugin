#!/usr/bin/env python3
"""Probe a private Perl/ELF closure and prove loaded files remain product-owned."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import uuid


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--receipt',type=Path,required=True);parser.add_argument('--image',required=True);args=parser.parse_args()
    root=args.root.resolve(strict=True);receipt=json.loads(args.receipt.read_text());base='/private/ud-perl'
    for item in receipt['files']:
        file=root/item['path']
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=item['size']or'sha256:'+hashlib.sha256(file.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('private Perl probe inputs are stale')
    libraries=[base+'/'+value for value in receipt['library_dirs']]
    script='BEGIN { @INC = splice(@ARGV,0,'+str(len(libraries))+'); } use Moose; use MooseX::SemiAffordanceAccessor; use namespace::autoclean; use List::MoreUtils; use YAML; use JSON::Parse; use File::Which; use LWP::Simple; use Lingua::Interset; require Exporter::Easy; use JSON::PP; open my $maps,"<","/proc/self/maps" or die "maps unavailable"; my @maps=<$maps>; print JSON::PP->new->canonical->encode({inc=>\\%INC,maps=>\\@maps,version=>"$^V"});'
    name='ud-perl-closure-'+uuid.uuid4().hex;container=None
    def run(arguments):return subprocess.run(['docker',*arguments],check=True,capture_output=True,timeout=60)
    try:
        created=run(['create','--name',name,'--label','io.ud-agent.perl-probe='+name,'--platform',receipt['platform'],'--pull=never','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','2147483648','--cpus','2','--pids-limit','128','--env','LANG=C','--env','LC_ALL=C','--env','PATH=/usr/bin:/bin','--mount',f'type=bind,src={root},dst={base},readonly','--entrypoint',base+'/'+receipt['loader']['executable'],args.image,'--inhibit-cache','--library-path',':'.join(base+'/'+value for value in receipt['loader']['library_dirs']),base+'/'+receipt['executable'],'-f','-e',script,*libraries]);container=created.stdout.decode().strip()
        output=run(['start','--attach',container]);proof=json.loads(output.stdout)
        virtual={key:value for key,value in proof['inc'].items()if value=='(set by Moose)'and(key in('Class/MOP/Class/Immutable/Class/MOP/Class.pm','main.pm')or re.fullmatch(r'Moose/Meta/Class/__ANON__/SERIAL/[1-9][0-9]*\.pm',key))}
        loaded={key:value for key,value in proof['inc'].items()if key not in virtual}
        if not loaded or any(not isinstance(value,str)or not value.startswith(base+'/')for value in loaded.values()):raise ValueError('Perl loaded ambient module code')
        paths={line.split(None,5)[5].strip()for line in proof['maps']if len(line.split(None,5))==6 and line.split(None,5)[5].strip().startswith('/')}
        if not paths or any(not value.startswith(base+'/')for value in paths):raise ValueError('Perl loaded ambient ELF or mapped data: '+repr(paths))
        receipt['probe']={'status':'passed','provider':'docker','worker_platform':receipt['platform'],'host':{'os':platform.system(),'architecture':platform.machine()},'ambient_modules':False,'ambient_elf':False,'module_files':loaded,'virtual_classes':virtual,'mapped_files':sorted(paths),'version':proof['version']}
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'passed','platform':receipt['platform'],'modules':len(proof['inc']),'mapped_files':len(paths)}))
    finally:
        if container:
            actual=json.loads(run(['inspect',container]).stdout)[0]
            if actual['Config'].get('Labels',{}).get('io.ud-agent.perl-probe')!=name:raise ValueError('Perl probe ownership changed')
            run(['rm','--force',container])
            remaining=subprocess.run(['docker','inspect',container],capture_output=True,timeout=30)
            if remaining.returncode==0 or b'no such object:'not in remaining.stderr.lower():raise ValueError('Perl probe cleanup was not verified')


if __name__=='__main__':main()
