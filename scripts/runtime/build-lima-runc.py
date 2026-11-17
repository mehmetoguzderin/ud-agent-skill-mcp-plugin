#!/usr/bin/env python3
"""Cross-build the same runc release with a source-closed musl/libseccomp closure."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[2]
RUNC_COMMIT='29dd3dc2b13b4123162e5fe132504bb4b15569f1'


def digest(file):
    with file.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()


def execute(args,cwd,env,log,timeout=600):
    with log.open('ab')as target:
        target.write((json.dumps(args)+'\n').encode());target.flush()
        result=subprocess.run(args,cwd=cwd,env=env,stdout=target,stderr=subprocess.STDOUT,timeout=timeout)
    if result.returncode:raise ValueError('controlled source build failed; see '+str(log))


def extract(archive,output):
    if output.exists():raise ValueError('source/tool extraction directory must be new')
    output.mkdir()
    with tarfile.open(archive,'r:*')as source:
        entries=source.getmembers();total=0;seen=set()
        for item in entries:
            parts=item.name.rstrip('/').split('/')
            if not item.name or item.name.startswith('/')or'\\'in item.name or any(part in('','.','..')for part in parts)or item.name in seen or len(seen)>=100_000 or not(item.isfile()or item.isdir()or item.issym()or item.islnk()):raise ValueError('source/tool archive has an unsafe member')
            seen.add(item.name);total+=item.size
            if item.size>1024**3 or total>4*1024**3:raise ValueError('source/tool archive expansion exceeds its bound')
        source.extractall(output,filter='data')
    roots=list(output.iterdir())
    if len(roots)!=1 or not roots[0].is_dir()or roots[0].is_symlink():raise ValueError('source/tool archive has no single ordinary root')
    return roots[0]


def elf(data,architecture):
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01'or struct.unpack_from('<H',data,18)[0]!=({'arm64':183,'amd64':62}[architecture]):raise ValueError('derived runtime architecture differs')
    offset=struct.unpack_from('<Q',data,32)[0];width,count=struct.unpack_from('<HH',data,54)
    if width<56 or offset+width*count>len(data):raise ValueError('derived runtime has malformed ELF headers')
    if any(struct.unpack_from('<I',data,offset+width*i)[0]==3 for i in range(count)):raise ValueError('derived runc must use its verified static libc closure')


def build(inputs,sources,output):
    if platform.system()!='Darwin'or platform.machine().lower()not in('arm64','aarch64'):raise ValueError('this exact frozen compiler profile requires native macOS ARM64')
    output=output.resolve()
    if output.exists():raise ValueError('controlled source build output must be new')
    output.mkdir(parents=True);(output/'INCOMPLETE').write_text('No candidate until both cross-builds and source receipts are verified.\n')
    inputs=inputs.resolve();receipt=json.loads((inputs/'input-receipt.json').read_bytes())
    expected={'zig-tool','zig-source','go-tool','go-source','libseccomp-source'}
    if receipt.get('go_version')!='1.27.1'or receipt.get('zig_version')!='0.17.1'or receipt.get('libseccomp_version')!='2.6.1'or {row['role']for row in receipt['files']}!=expected or len(receipt['files'])!=len(expected):raise ValueError('cross-build inputs are incomplete or select another release')
    files={}
    for row in receipt['files']:
        name=row['path']
        if not name.startswith('inputs/')or any(part in('','.','..')for part in name.split('/')):raise ValueError('cross-build input path is unsafe')
        file=inputs/name
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=row['size_bytes']or digest(file)!=row['sha256']:raise ValueError('cross-build source/tool input differs from its verified receipt')
        files[row['role']]=file
    source_receipt=json.loads((sources/'receipt.json').read_bytes());main=next((row for row in source_receipt['main_sources']if row['repository']=='opencontainers/runc'and row['commit']==RUNC_COMMIT),None)
    if main is None or not main['acquired']or digest(sources/main['path'])!=main['sha256']:raise ValueError('exact embedded runc source commit is unavailable')
    go=extract(files['go-tool'],output/'go');zig=extract(files['zig-tool'],output/'zig');runc=extract(sources/main['path'],output/'runc')
    if not(runc/'vendor/modules.txt').is_file():raise ValueError('runc source requires its complete vendored module closure')
    environment={'PATH':str(go/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(output/'home'),'TMPDIR':str(output/'tmp'),'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOENV':'off','GOCACHE':str(output/'cache/go'),'GOMODCACHE':str(output/'cache/modules'),'ZIG_GLOBAL_CACHE_DIR':str(output/'cache/zig'),'ZIG_LOCAL_CACHE_DIR':str(output/'cache/zig-local'),'SOURCE_DATE_EPOCH':'315532800','ZERO_AR_DATE':'1','LANG':'C','LC_ALL':'C'}
    for name in('home','tmp','cache'): (output/name).mkdir()
    tools={'go':{'sha256':digest(go/'bin/go'),'version':'1.27.1'},'zig':{'sha256':digest(zig/'zig'),'version':'0.17.1'}}
    results={}
    for arch,target in [('arm64','aarch64-linux-musl'),('amd64','x86_64-linux-musl')]:
        work=output/arch;work.mkdir();source=extract(files['libseccomp-source'],work/'source');prefix=work/'libseccomp';bin=work/'bin';bin.mkdir()
        for name,command in [('cc',[str(zig/'zig'),'cc','-target',target]),('ar',[str(zig/'zig'),'ar']),('ranlib',[str(zig/'zig'),'ranlib'])]:
            wrapper=bin/name;wrapper.write_text('#!/bin/sh\nexec '+' '.join(shlex.quote(arg)for arg in command)+' "$@"\n');wrapper.chmod(0o555)
        pkg=bin/'pkg-config';pkg.write_text('#!/bin/sh\ncase "$*" in\n"--cflags -- libseccomp") printf "%s\\n" '+shlex.quote('-I'+str(prefix/'include'))+';;\n"--libs -- libseccomp") printf "%s\\n" '+shlex.quote('-L'+str(prefix/'lib')+' -lseccomp')+';;\n*) echo "unsupported pkg-config contract" >&2; exit 1;;\nesac\n');pkg.chmod(0o555)
        env={**environment,'CC':str(bin/'cc'),'AR':str(bin/'ar'),'RANLIB':str(bin/'ranlib'),'CFLAGS':'-O2 -g0 -fPIC -ffile-prefix-map='+str(output)+'=.','LDFLAGS':'-static'}
        log=work/'build.log'
        execute([str(source/'configure'),'--build=aarch64-apple-darwin','--host='+target,'--prefix='+str(prefix),'--disable-shared','--enable-static','--disable-dependency-tracking'],source,env,log)
        execute(['/usr/bin/make','-j2'],source,env,log);execute(['/usr/bin/make','install'],source,env,log)
        binary=work/'runc';env.update(GOOS='linux',GOARCH=arch,CGO_ENABLED='1',PKG_CONFIG=str(pkg),CGO_CFLAGS='-O2 -g0',CGO_LDFLAGS='-static')
        flags='-s -w -buildid= -linkmode external -extldflags=-static -X main.version=1.5.2 -X main.gitCommit='+RUNC_COMMIT
        execute([str(go/'bin/go'),'build','-p','2','-mod=vendor','-trimpath','-tags','seccomp,netgo,osusergo','-ldflags',flags,'-o',str(binary),'.'],runc,env,log)
        elf(binary.read_bytes(),arch);binary.chmod(0o555)
        results[arch]={'path':binary.relative_to(output).as_posix(),'sha256':digest(binary),'size_bytes':binary.stat().st_size,'target':target,'execution':'not-executed','libseccomp_archive_sha256':digest(prefix/'lib/libseccomp.a'),'build_log_sha256':digest(log)}
    for row in receipt['files']:
        if digest(inputs/row['path'])!=row['sha256']:raise ValueError('cross-build input changed during compilation')
    report={'schema_version':1,'qualification':'locally-derived-same-source-runc-crossbuild-not-upstream-signature','status':'cross-built','version':'1.5.2','commit':RUNC_COMMIT,'target_execution':False,'emulation':False,'build_host':{'os':platform.system(),'architecture':platform.machine()},'inputs_receipt_sha256':digest(inputs/'input-receipt.json'),'main_source':main,'tools':tools,'runtime_c_source_closure':['zig-source','libseccomp-source'],'binaries':results,'builder_sha256':digest(Path(__file__))}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink();return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--sources',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(build(args.inputs,args.sources,args.output)['binaries']))
