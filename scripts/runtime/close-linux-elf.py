#!/usr/bin/env python3
"""Close a source-built private Perl's ELF dependencies inside a pinned Linux builder."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

spec=importlib.util.spec_from_file_location('ud_close_elf',Path(__file__).with_name('elf_dependencies.py'));elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
def sha(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def close(root,receipt_path,platform,provider):
    if sys.platform!='linux'or not re.fullmatch(r'.+@sha256:[a-f0-9]{64}',provider):raise ValueError('a pinned Linux build provider is required')
    root=root.resolve(strict=True);receipt=json.loads(receipt_path.read_text());machine,triplet=(183,'aarch64-linux-gnu')if platform=='linux/arm64'else(62,'x86_64-linux-gnu')
    binary=root/receipt['executable'];pending=[binary];libraries={};processed=set();loader=None;relocations=[]
    for item in receipt['files']:
        file=root/item['path']
        if file.is_symlink()or'sha256:'+sha(file)!=item['sha256']or file.stat().st_size!=item['size']:raise ValueError('source-built Perl receipt is stale')
        with file.open('rb')as stream:
            if stream.read(4)==b'\x7fELF':pending.append(file)
    while pending:
        current=pending.pop();fingerprint=sha(current)
        if current in processed:continue
        processed.add(current);data=current.read_bytes();info=elf.inspect(data)
        if info['machine']!=machine:raise ValueError('private ELF contains an unexpected architecture: '+str(current))
        if info['search_paths']:
            mode=current.stat().st_mode&0o777;current.chmod(mode|0o200)
            current.write_bytes(elf.without_search_paths(data));current.chmod(mode)
            relocations.append({'path':current.relative_to(root).as_posix(),'source_sha256':fingerprint,'removed_search_paths':info['search_paths'],'sha256':sha(current)});info=elf.inspect(current.read_bytes())
        if current==binary:
            original=Path(info['interpreter']).resolve(strict=True);loader=root/'loader'/original.name;loader.parent.mkdir(exist_ok=True);shutil.copyfile(original,loader);loader.chmod(0o555);pending.append(loader)
        for dependency in info['needed']:
            if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,255}',dependency):raise ValueError('unconfined ELF dependency name')
            matches=[(Path(folder)/dependency).resolve(strict=True)for folder in[f'/lib/{triplet}',f'/usr/lib/{triplet}','/lib64','/usr/lib64','/lib','/usr/lib']if(Path(folder)/dependency).is_file()]
            if not matches or len({sha(path)for path in matches})!=1:raise ValueError('missing or ambiguous ELF dependency: '+dependency)
            target=root/'lib/elf'/dependency;target.parent.mkdir(parents=True,exist_ok=True)
            if dependency not in libraries:shutil.copyfile(matches[0],target);target.chmod(0o555);libraries[dependency]=sha(target);pending.append(target)
            elif libraries[dependency]!=sha(matches[0]):raise ValueError('ELF dependency collision')
    if loader is None:raise ValueError('source Perl has no private ELF loader')
    receipt['loader']={'executable':loader.relative_to(root).as_posix(),'library_dirs':['lib/elf']};receipt['platform']=platform;receipt['elf_origin']={'provider':provider,'machine':machine,'libraries':libraries,'relocations':relocations};receipt['files']=[{'path':path.relative_to(root).as_posix(),'sha256':'sha256:'+sha(path),'size':path.stat().st_size}for path in sorted(root.rglob('*'))if path.is_file()]
    libraries=[str(root/value)for value in receipt['library_dirs']]
    code='BEGIN{@INC=splice(@ARGV,0,'+str(len(libraries))+');} use Moose;use MooseX::SemiAffordanceAccessor;use namespace::autoclean;use List::MoreUtils;use YAML;use JSON::Parse;use File::Which;use LWP::Simple;use Lingua::Interset;require Exporter::Easy;use JSON::PP;open my $maps,"<","/proc/self/maps" or die "maps unavailable";my @maps=<$maps>;print JSON::PP->new->canonical->encode({inc=>\\%INC,maps=>\\@maps,version=>"$^V"});'
    result=subprocess.run([str(loader),'--inhibit-cache','--library-path',str(root/'lib/elf'),str(binary),'-f','-e',code,*libraries],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},capture_output=True,timeout=30,check=True);proof=json.loads(result.stdout)
    virtual={key:value for key,value in proof['inc'].items()if value=='(set by Moose)'and(key in('Class/MOP/Class/Immutable/Class/MOP/Class.pm','main.pm')or re.fullmatch(r'Moose/Meta/Class/__ANON__/SERIAL/[1-9][0-9]*\.pm',key))}
    # The pinned B::Hooks::EndOfScope contract intentionally supports its PP
    # implementation without the optional Variable::Magic accelerator. Perl
    # retains a null %INC entry for that failed optional XS require. Admit only
    # this exact marker when its owned PP implementation actually loaded.
    optional={key:value for key,value in proof['inc'].items()if key=='B/Hooks/EndOfScope/XS.pm'and value is None and isinstance(proof['inc'].get('B/Hooks/EndOfScope/PP.pm'),str)and proof['inc']['B/Hooks/EndOfScope/PP.pm'].startswith(str(root)+'/')}
    virtual.update(optional)
    loaded={key:value for key,value in proof['inc'].items()if key not in virtual}
    mapped={line.split(None,5)[5].strip()for line in proof['maps']if len(line.split(None,5))==6 and line.split(None,5)[5].strip().startswith('/')}
    invalid_modules={key:value for key,value in loaded.items()if not isinstance(value,str)or not value.startswith(str(root)+'/')}
    invalid_mappings=[value for value in mapped if not value.startswith(str(root)+'/')]
    if not loaded or invalid_modules or not mapped or invalid_mappings:raise ValueError('private Perl probe used an ambient module or ELF mapping: '+repr({'modules':invalid_modules,'mappings':invalid_mappings}))
    receipt['probe']={'status':'passed','ambient_modules':False,'ambient_elf':False,'module_count':len(loaded),'mapped_files':sorted(mapped),'virtual_classes':virtual,'version':proof['version'],'provider':provider}
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n');return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--receipt',type=Path,required=True);parser.add_argument('--platform',choices=['linux/arm64','linux/amd64'],required=True);parser.add_argument('--provider',required=True);args=parser.parse_args();r=close(args.root,args.receipt,args.platform,args.provider);print(json.dumps({'files':len(r['files']),'probe':r['probe']}))
if __name__=='__main__':main()
