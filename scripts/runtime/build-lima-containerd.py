#!/usr/bin/env python3
"""Derive the same containerd release with the profile's source-closed pure-Go build."""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import os

spec=importlib.util.spec_from_file_location('ud_derived_runc',Path(__file__).with_name('build-lima-runc.py'));shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
COMMIT='b7a25261e029d68978bbf290df0a62fc819b3c51'
TARGETS={'containerd':'./cmd/containerd','containerd-shim-runc-v2':'./cmd/containerd-shim-runc-v2','ctr':'./cmd/ctr'}


def build(toolchain,sources,output):
    if platform.system()!='Darwin'or platform.machine().lower()not in('arm64','aarch64'):raise ValueError('this compiler profile requires native macOS ARM64')
    output=output.resolve();toolchain=toolchain.resolve();sources=sources.resolve()
    if output.exists():raise ValueError('derived containerd output must be new')
    tool_receipt=json.loads((toolchain/'receipt.json').read_bytes());go=toolchain/'go/go/bin/go'
    if tool_receipt.get('status')!='cross-built'or tool_receipt.get('tools',{}).get('go',{}).get('version')!='1.27.1'or shared.digest(go)!=tool_receipt['tools']['go']['sha256']:raise ValueError('verified source-closed Go toolchain is unavailable')
    source_receipt=json.loads((sources/'receipt.json').read_bytes());main=next((row for row in source_receipt['main_sources']if row['repository']=='containerd/containerd'and row['commit']==COMMIT),None)
    if main is None or not main['acquired']or shared.digest(sources/main['path'])!=main['sha256']:raise ValueError('exact containerd source commit is unavailable')
    output.mkdir(parents=True);(output/'INCOMPLETE').write_text('Derived provider acceptance has not run.\n');source=shared.extract(sources/main['path'],output/'source')
    if not(source/'vendor/modules.txt').is_file():raise ValueError('complete containerd vendor source is required')
    for name in('home','tmp','cache'):(output/name).mkdir()
    env={'PATH':str(go.parent)+':/usr/bin:/bin','HOME':str(output/'home'),'TMPDIR':str(output/'tmp'),'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOENV':'off','GOCACHE':str(output/'cache/go'),'GOMODCACHE':str(output/'cache/modules'),'SOURCE_DATE_EPOCH':'315532800','CGO_ENABLED':'0','GOOS':'linux','LANG':'C','LC_ALL':'C'}
    results={};flags='-s -w -buildid= -X github.com/containerd/containerd/v2/version.Version=v2.4.2 -X github.com/containerd/containerd/v2/version.Revision='+COMMIT+' -X github.com/containerd/containerd/v2/version.Package=github.com/containerd/containerd/v2'
    for architecture in('arm64','amd64'):
        work=output/architecture;work.mkdir();records={}
        for name,package in TARGETS.items():
            binary=work/name;log=work/(name+'.log');shared.execute([str(go),'build','-p','2','-mod=vendor','-trimpath','-tags','urfave_cli_no_docs,osusergo,netgo,static_build','-ldflags',flags,'-o',str(binary),package],source,{**env,'GOARCH':architecture},log)
            shared.elf(binary.read_bytes(),architecture);binary.chmod(0o555);records[name]={'path':binary.relative_to(output).as_posix(),'sha256':shared.digest(binary),'size_bytes':binary.stat().st_size,'execution':'not-executed','build_log_sha256':shared.digest(log)}
        results[architecture]=records
    report={'schema_version':1,'qualification':'locally-derived-same-source-containerd-crossbuild-not-upstream-signature','status':'cross-built','version':'2.4.2','commit':COMMIT,'target_execution':False,'emulation':False,'cgo':False,'required_snapshotter_profiles':['overlayfs','native'],'capability_acceptance':'pending-actual-arm64-provider; amd64-native-user-deferred','main_source':main,'toolchain_receipt_sha256':shared.digest(toolchain/'receipt.json'),'go':tool_receipt['tools']['go'],'binaries':results,'builder_sha256':shared.digest(Path(__file__))}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink();return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--toolchain',type=Path,required=True);parser.add_argument('--sources',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(build(args.toolchain,args.sources,args.output)['binaries']))
