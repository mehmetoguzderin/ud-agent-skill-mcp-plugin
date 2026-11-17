#!/usr/bin/env python3
"""Cross-build exact original uv0.13.7 with static CRT and data-only provenance.

No Windows/amd64 executable runs. Original vendor binaries remain separate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import tomllib

ROOT=Path(__file__).resolve().parents[2]
UV_COMMIT='316c827e058c16b71d5c507a20729c2995a7bcce'
UV_VERSION='0.13.7'


def digest(file):
    with file.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def checked(root,row):
    name=row['path']
    if not isinstance(name,str)or name.startswith('/')or'\\'in name or any(part in('','.','..')for part in name.split('/')):raise ValueError('Unsafe frozen source path')
    file=root/name
    if file.is_symlink()or not file.is_file()or file.stat().st_size!=row['size_bytes']or digest(file)!=row['sha256']:raise ValueError('Frozen source bytes differ')
    return file


def crate_members(archive,name,version):
    files=set();total=0
    with tarfile.open(archive,'r:gz')as source:
        for member in source:
            parts=member.name.rstrip('/').split('/')
            if '\\'in member.name or parts[0]!=name+'-'+version or any(part in('','.','..')for part in parts)or member.issym()or member.islnk()or member.isdev():raise ValueError('Cargo source archive has foreign or special paths')
            if member.isdir():continue
            if not member.isfile()or len(parts)<2 or member.size<0 or member.size>128*1024**2 or(total:=total+member.size)>512*1024**2:raise ValueError('Cargo source archive exceeds its bound')
            relative='/'.join(parts[1:])
            if relative in files or relative=='.cargo-checksum.json':raise ValueError('Cargo source archive has duplicate/checksum member')
            data=source.extractfile(member).read(member.size+1)
            if len(data)!=member.size:raise ValueError('Cargo source archive is truncated')
            files.add(relative);yield relative,data,0o444|(member.mode&0o111)
    if not files:raise ValueError('Cargo source archive is empty')


def extract_crate(archive,destination,name,version,checksum):
    if destination.exists():raise ValueError('Vendor destination already exists')
    destination.mkdir(parents=True);files={};total=0
    for relative,data,mode in crate_members(archive,name,version):
        target=destination/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);target.chmod(mode);files[relative]=hashlib.sha256(data).hexdigest();total+=len(data)
    (destination/'.cargo-checksum.json').write_text(json.dumps({'files':files,'package':checksum},sort_keys=True,separators=(',',':'))+'\n')
    return {'name':name,'version':version,'package_sha256':checksum,'files':len(files),'bytes':total}


def verify_vendor(output,package_sources):
    """Replay every original crate archive, including files the compiler ignores."""
    receipt=json.loads((output/'source-receipt.json').read_text())
    if digest(package_sources/'receipt.json')!=receipt['source_receipts']['dependencies']:raise ValueError('uv dependency source receipt changed')
    available={(row['name'],row['version']):row for row in json.loads((package_sources/'receipt.json').read_text())['files']if row['family']=='cargo'}
    inventory=[];expected_directories=set()
    for item in receipt['dependencies']:
        name,version=item['name'],item['version'];directory=output/'vendor'/(name+'-'+version);expected_directories.add(directory.name)
        row=available.get((name,version))
        if not row or row['sha256']!=item['package_sha256']:raise ValueError('uv dependency original archive binding changed')
        archive=checked(package_sources,row);expected={};rows=[]
        for relative,data,mode in crate_members(archive,name,version):
            expected[relative]=hashlib.sha256(data).hexdigest();rows.append({'path':directory.name+'/'+relative,'sha256':expected[relative],'size_bytes':len(data)})
            file=directory/relative
            if file.is_symlink()or not file.is_file()or file.stat().st_size!=len(data)or digest(file)!=expected[relative]:raise ValueError('uv dependency source bytes changed')
        manifest=json.dumps({'files':expected,'package':item['package_sha256']},sort_keys=True,separators=(',',':'))+'\n'
        file=directory/'.cargo-checksum.json'
        if file.is_symlink()or file.read_text()!=manifest:raise ValueError('uv dependency checksum manifest changed')
        actual=set()
        for file in directory.rglob('*'):
            if file.is_symlink()or not(file.is_file()or file.is_dir()):raise ValueError('uv dependency source has a special member')
            if file.is_file():actual.add(file.relative_to(directory).as_posix())
        if actual!=set(expected)|{'.cargo-checksum.json'}:raise ValueError('uv dependency source inventory is not closed')
        inventory.extend(rows)
    if {file.name for file in(output/'vendor').iterdir()}!=expected_directories:raise ValueError('uv dependency directory inventory is not closed')
    encoded=json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()
    return {'sha256':hashlib.sha256(encoded).hexdigest(),'files':len(inventory),'crates':len(expected_directories)}


def prepare(output,provider_sources,package_sources):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    receipts={key:json.loads((root/'receipt.json').read_text())for key,root in [('upstream',provider_sources),('dependencies',package_sources)]}
    rows=[row for row in receipts['upstream']['files']if row['name']=='astral-sh/uv'and row['version']==UV_COMMIT]
    if len(rows)!=1:raise ValueError('Exact original uv release source is absent')
    declarations=json.loads((ROOT/'runtime/materials/provider-source-mappings.lock.json').read_text())['sources'];declared=[row for row in declarations if row['name']=='astral-sh/uv'and row['version']==UV_COMMIT]
    if len(declared)!=1 or rows[0]['sha256']!=declared[0]['sha256'] or rows[0]['size_bytes']!=declared[0]['size_bytes']:raise ValueError('uv source is not bound to the original source-tree release declaration')
    archive=checked(provider_sources,rows[0]);source=output/'source'
    if source.exists():raise ValueError('Original uv source destination already exists')
    with tarfile.open(archive,'r:gz')as tar:
        members=tar.getmembers()
        if len(members)>100000 or sum(member.size for member in members)>512*1024**2 or any(member.size<0 or member.size>128*1024**2 for member in members):raise ValueError('uv source archive expansion exceeds its bound')
        # Python's data filter confines all archive paths and supported links.
        tar.extractall(output/'extract',filter='data')
    roots=list((output/'extract').iterdir())
    if len(roots)!=1 or not roots[0].is_dir()or roots[0].is_symlink():raise ValueError('uv source root is not closed')
    roots[0].rename(source);(output/'extract').rmdir()
    lockfile=source/'Cargo.lock';lock=tomllib.loads(lockfile.read_text());expected={}
    for row in lock['package']:
        if 'source'not in row:continue
        if row['source']!='registry+https://github.com/rust-lang/crates.io-index'or len(row.get('checksum',''))!=64:raise ValueError('uv has a non-registry dependency without a frozen source contract')
        expected[(row['name'],row['version'])]=row['checksum']
    available={(row['name'],row['version']):row for row in receipts['dependencies']['files']if row['family']=='cargo'}
    vendor=output/'vendor';vendor.mkdir();closure=[]
    for(name,version),checksum in sorted(expected.items()):
        row=available.get((name,version))
        if not row or row['sha256']!=checksum:raise ValueError('uv source closure omits exact Cargo lock entry: '+name+'@'+version)
        file=checked(package_sources,row);closure.append(extract_crate(file,vendor/(name+'-'+version),name,version,checksum))
    package=tomllib.loads((source/'crates/uv/Cargo.toml').read_text())
    version=package['package']['version']
    if version!=UV_VERSION or package['package']['name']!='uv':raise ValueError('uv source package/version differs')
    report={'schema_version':1,'qualification':'original-source-offline-crossbuild-inputs','source_commit':UV_COMMIT,'source':rows[0],'cargo_lock_sha256':digest(lockfile),'dependencies':closure,'source_tree':source_inventory(source),'source_receipts':{name:digest(root/'receipt.json')for name,root in [('upstream',provider_sources),('dependencies',package_sources)]}}
    (output/'source-receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


def source_inventory(root):
    rows=[]
    for file in sorted(root.rglob('*')):
        relative=file.relative_to(root).as_posix()
        if file.is_symlink():rows.append({'path':relative,'link':os.readlink(file)})
        elif file.is_file():rows.append({'path':relative,'sha256':digest(file),'size_bytes':file.stat().st_size})
        elif not file.is_dir():raise ValueError('Original source has a special file')
    return rows


def header_overlay(sdk, destination):
    """Model Windows ASCII header lookup without altering original SDK files.

    LLVM's documented VFS overlay is data only. Conflicting case-folded names
    are rejected; byte-identical SDK aliases have one deterministic spelling.
    """
    roots=[];inventory=[]
    def visit(directory):
        contents=[];names={}
        for file in sorted(directory.iterdir()):
            if not file.name.isascii():raise ValueError('Windows SDK header name is not ASCII')
            key=file.name.lower()
            if file.is_dir():
                if file.is_symlink():raise ValueError('Windows SDK header directory is a symlink')
                row={'type':'directory','name':file.name,'contents':visit(file)}
            elif file.is_file():
                resolved=file.resolve()
                if not resolved.is_relative_to(sdk.resolve()):raise ValueError('Windows SDK header escapes frozen SDK')
                entry={'path':file.relative_to(sdk).as_posix(),'sha256':digest(resolved),'size_bytes':resolved.stat().st_size}
                inventory.append(entry);row={'type':'file','name':file.name,'external-contents':str(resolved)}
                if key in names:
                    if names[key].get('external-contents') is None or digest(Path(names[key]['external-contents']))!=entry['sha256']:raise ValueError('Windows SDK header has ambiguous case aliases')
                    continue
            else:raise ValueError('Windows SDK header is not ordinary')
            if key in names:raise ValueError('Windows SDK header has ambiguous case aliases')
            names[key]=row;contents.append(row)
        return contents
    for name in ['crt/include','sdk/include/ucrt','sdk/include/um','sdk/include/shared','sdk/include/winrt']:
        root=sdk/name
        roots.append({'type':'directory','name':str(root.resolve()),'contents':visit(root)})
    destination.write_text(json.dumps({'version':0,'case-sensitive':False,'roots':roots},sort_keys=True,separators=(',',':'))+'\n')
    return {'path':destination.name,'sha256':digest(destination),'size_bytes':destination.stat().st_size,'headers':inventory,'format':'llvm-vfs-overlay-v0','documentation':'https://llvm.org/docs/doxygen/classllvm_1_1vfs_1_1RedirectingFileSystem.html'}


def prepare_host_tools(output,tools):
    """Only native ARM LLVM utilities may satisfy lld's Windows tool names."""
    directory=output/'tools';directory.mkdir(exist_ok=True);records={}
    for name,source in tools.items():
        if name not in('mt.exe','rc.exe'):raise ValueError('Unsupported native Windows resource-tool alias')
        source=source.resolve(strict=True)
        with source.open('rb')as stream:header=stream.read(8)
        if not source.is_file()or source.stat().st_size>64*1024**2 or len(header)!=8 or header[:4]!=b'\xcf\xfa\xed\xfe'or struct.unpack('<I',header[4:8])[0]!=0x0100000c:raise ValueError('Resource utility must be a native macOS ARM64 Mach-O, never a Windows/amd64 executable')
        target=directory/name
        if target.exists()or target.is_symlink():
            if not target.is_symlink()or target.resolve()!=source:raise ValueError('Owned native resource-tool alias changed')
        else:target.symlink_to(source)
        records[name]={'path':'tools/'+name,'source':str(source),'sha256':digest(source),'size_bytes':source.stat().st_size,'execution_architecture':'darwin-arm64'}
    return records


def build(output,targets,package_sources):
    if platform.system()!='Darwin' or platform.machine().lower() not in('arm64','aarch64'):raise ValueError('This original-source crossbuilder requires native macOS arm64; no emulation')
    producer_sha256=digest(Path(__file__))
    output=output.resolve();receipt=json.loads((output/'source-receipt.json').read_text());source=output/'source';vendor=output/'vendor';toolchain=ROOT/'.artifacts/rustup/toolchains/1.99.1-aarch64-apple-darwin';xwin=ROOT/'.artifacts/cargo/bin/cargo-xwin'
    if source_inventory(source)!=receipt['source_tree']:raise ValueError('uv original source tree changed')
    if digest(source/'Cargo.lock')!=receipt['cargo_lock_sha256']:raise ValueError('uv source lock changed')
    vendor_identity=verify_vendor(output,package_sources)
    (output/'cargo-home').mkdir(exist_ok=True);(output/'home').mkdir(exist_ok=True);(output/'tmp').mkdir(exist_ok=True)
    overlay=header_overlay(ROOT/'.artifacts/xwin-cache/xwin',output/'windows-headers.vfs.json')
    host_tools=prepare_host_tools(output,{'mt.exe':Path('/opt/homebrew/opt/llvm/bin/llvm-mt')})
    environment={'HOME':str(output/'home'),'TMPDIR':str(output/'tmp'),'CARGO_HOME':str(output/'cargo-home'),'LANG':'C','LC_ALL':'C','PATH':':'.join([str(output/'tools'),str(toolchain/'bin'),str(toolchain/'lib/rustlib/aarch64-apple-darwin/bin'),str(ROOT/'.artifacts/cargo/bin'),'/opt/homebrew/bin','/usr/bin','/bin']),'RUSTC':str(toolchain/'bin/rustc'),'RUSTUP_TOOLCHAIN':'1.99.1','DYLD_LIBRARY_PATH':str(toolchain/'lib'),'CARGO_PROFILE_RELEASE_STRIP':'none','XWIN_CACHE_DIR':str(ROOT/'.artifacts/xwin-cache'),'CARGO_TARGET_DIR':str(output/'target'),'CARGO_NET_OFFLINE':'true','SOURCE_DATE_EPOCH':'1793577600','CL_FLAGS':' '.join(shlex.quote(flag)for flag in ['/clang:-ivfsoverlay','/clang:'+str(output/overlay['path'])])}
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET']:environment.pop(key,None)
    records=[]
    for target in targets:
        if target not in ['aarch64-pc-windows-msvc','x86_64-pc-windows-msvc']:raise ValueError('Unsupported uv Windows target')
        mapfile=output/(target+'.map');command=[str(xwin),'xwin','rustc','--locked','--offline','--release','--jobs','2','-p','uv','--bin','uv','--xwin-version','18','--target',target,'--config','source.crates-io.replace-with="verified-vendor"','--config','source.verified-vendor.directory='+json.dumps(str(vendor)),'--config',f'target.{target}.rustflags=["-C","target-feature=+crt-static"]','--','-C','link-arg=/DEBUG:NONE','-C','link-arg=/Brepro','-C','link-arg=/MAP:'+str(mapfile)]
        with(output/(target+'.log')).open('wb')as log:result=subprocess.run(['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',*command],cwd=source,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
        if result.returncode:raise RuntimeError('uv original source crossbuild failed: '+target)
        if source_inventory(source)!=receipt['source_tree']:raise ValueError('uv build modified original source inputs')
        if verify_vendor(output,package_sources)!=vendor_identity:raise ValueError('uv build modified dependency source inputs')
        if digest(Path(__file__))!=producer_sha256:raise ValueError('uv source-build recipe changed during execution')
        binary=output/'target'/target/'release/uv.exe';records.append({'target':target,'path':str(binary.relative_to(output)),'sha256':digest(binary),'size_bytes':binary.stat().st_size,'map':{'path':mapfile.name,'sha256':digest(mapfile),'size_bytes':mapfile.stat().st_size},'command':command,'target_execution':False})
        (output/'build-receipt.json').write_text(json.dumps({'schema_version':1,'qualification':'locally-built-original-uv-unaccepted','producer_sha256':producer_sha256,'source_receipt_sha256':digest(output/'source-receipt.json'),'source_commit':UV_COMMIT,'version':UV_VERSION,'rust':'1.99.1','vendor_inventory':vendor_identity,'header_overlay':overlay,'host_tools':host_tools,'records':records,'publisher_redistribution_authority':'unverified-external'},indent=2)+'\n')
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--prepare-only',action='store_true');parser.add_argument('--build-only',action='store_true');parser.add_argument('--target',action='append',choices=['aarch64-pc-windows-msvc','x86_64-pc-windows-msvc']);parser.add_argument('--provider-sources',type=Path,default=ROOT/'.artifacts/source-materials-data/provider-sources-binary-v2');parser.add_argument('--package-sources',type=Path,default=ROOT/'.artifacts/source-materials-data/package-sources-uv');args=parser.parse_args()
    if args.prepare_only and args.build_only:raise ValueError('Choose one build stage')
    if not args.build_only:prepare(args.output,args.provider_sources,args.package_sources)
    if not args.prepare_only:build(args.output,args.target or ['aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'],args.package_sources)
if __name__=='__main__':main()
