#!/usr/bin/env python3
"""Cross-build the locked Windows Perl/XS closure without a Windows interpreter.

The resulting PE identities, dependencies and sources are verified locally;
loading/behavior on Windows remains an explicit native acceptance requirement.
"""
from __future__ import annotations
import argparse
from compression.zstd import ZstdFile
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/filename);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
PE=module('ud_windows_pe','scripts/runtime/windows_pe.py')
XS={
 'Class-Load-XS-0.10':('Class::Load::XS','0.10',['XS.xs'],[]),
 'Clone-0.51':('Clone','0.51',['Clone.xs'],[]),
 'HTML-Parser-3.86':('HTML::Parser','3.86',['Parser.xs'],['MARKED_SECTION']),
 'JSON-Parse-0.62':('JSON::Parse','0.62',['Parse.xs'],[]),
 'List-MoreUtils-XS-0.430':('List::MoreUtils::XS','0.430',['XS.xs'],[]),
 'Moose-2.4001':('Moose','2.4001',['xs/Attribute.xs','xs/AttributeCore.xs','xs/Class.xs','xs/Generated.xs','xs/HasAttributes.xs','xs/HasMethods.xs','xs/Inlined.xs','xs/Instance.xs','xs/MOP.xs','xs/Method.xs','xs/Moose.xs','xs/Package.xs','xs/ToInstance.xs','mop.c'],[]),
 'Package-Stash-XS-0.32':('Package::Stash::XS','0.32',['XS.xs'],[]),
 'Params-SomeUtil-1.12':('Params::SomeUtil','1.12',['SomeUtil.xs'],[]),
 'Params-Util-1.102':('Params::Util','1.102',['Util.xs'],[]),
}

def digest(path):return 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()
def verified(path,receipt):
    if path.is_symlink() or not path.is_file() or path.stat().st_size!=receipt['size_bytes'] or digest(path)!=receipt['sha256']:raise ValueError('frozen Windows build input mismatch: '+str(path))
    return path

def entries(archive):
    if archive.name.endswith('.conda'):
        with zipfile.ZipFile(archive) as container:
            names=container.namelist()
            if len(names)!=len(set(names)) or any('/' in name or '\\' in name for name in names):raise ValueError('unsafe conda ZIP inventory')
            for name in names:
                if not re.fullmatch(r'(?:pkg|info)-[A-Za-z0-9_.-]+\.tar\.zst',name):
                    if name!='metadata.json':raise ValueError('unknown conda member')
                    continue
                info=container.getinfo(name)
                if info.file_size>256*1024*1024 or info.flag_bits&1:raise ValueError('oversized or encrypted conda member')
                with container.open(name) as compressed,ZstdFile(compressed) as expanded,tarfile.open(fileobj=expanded,mode='r|') as tar:
                    for member in tar:yield tar,member
    else:
        with tarfile.open(archive,'r:*') as tar:
            for member in tar:yield tar,member

def extract(archive,destination,strip=None):
    seen=set();total=0
    for tar,member in entries(archive):
        raw=member.name;parts=PurePosixPath(raw).parts
        if raw.startswith('/') or '\\' in raw or ':' in raw or any(part in ('','..','.') for part in parts) or len(parts)>64:raise ValueError('unsafe Windows input archive path')
        if strip is not None:
            if not parts or parts[0]!=strip:raise ValueError('archive root differs from locked release')
            parts=parts[1:]
            if not parts and member.isdir():continue
        relative='/'.join(parts);key=relative.casefold()
        if not relative or key in seen or len(seen)>=50000:raise ValueError('duplicate or excessive Windows input inventory')
        seen.add(key);target=destination.joinpath(*parts)
        if member.isdir():target.mkdir(parents=True,exist_ok=True)
        elif member.isfile() and member.size<=32*1024*1024:
            total+=member.size
            if total>512*1024*1024:raise ValueError('Windows input expanded size exceeded')
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as out:shutil.copyfileobj(tar.extractfile(member),out)
            if target.stat().st_size!=member.size:raise ValueError('Windows input file size changed')
            target.chmod(0o644)
        else:raise ValueError('Windows input contains links or special files')

def copy_tree(source,destination):
    for item in sorted(source.rglob('*')):
        target=destination/item.relative_to(source)
        if item.is_symlink():raise ValueError('Windows private assets cannot contain links')
        if item.is_dir():target.mkdir(parents=True,exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True,exist_ok=True)
            if target.exists() and target.read_bytes()!=item.read_bytes():raise ValueError('Windows runtime content collision: '+str(target))
            if not target.exists():shutil.copyfile(item,target)
        else:raise ValueError('Windows private asset is not regular')

def build(architecture,output,host_perl,llvm=None,sdk=None,*,open_toolchain=False):
    if architecture not in ('arm64','x64') or output.exists() or output.is_symlink():raise ValueError('Windows target output must be new')
    producer_sha256=digest(Path(__file__));linkage=output.absolute().parent/(output.name+'-linkage')
    if linkage.exists() or linkage.is_symlink():raise ValueError('Windows linkage evidence output must be new')
    linkage.mkdir(mode=0o700,parents=True)
    lock=json.loads((ROOT/'runtime/windows-perl-distributions.lock.json').read_text())
    if lock.get('schema_version')!=1 or lock.get('state')!='frozen-inputs' or lock.get('upstream_perl')!='5.44.0':raise ValueError('Windows Perl inputs are not frozen')
    selected=lock['platforms'][architecture];cache=ROOT/'.artifacts/native-perl/cache/windows'
    perl_archive=verified(cache/selected['perl']['filename'],selected['perl'])
    host_perl=host_perl.resolve(strict=True)
    env={'PATH':'/usr/bin:/bin','HOME':str(output.parent.resolve()),'LC_ALL':'C'}
    host_version=subprocess.check_output([str(host_perl),'-e','print $^V'],env=env,text=True,timeout=10)
    if host_version!='v5.44.0':raise ValueError('cross XS generation requires the exact host Perl5.44 ABI')
    host_core=Path(subprocess.check_output([str(host_perl),'-MConfig','-e','print $Config{privlibexp}'],env=env,text=True,timeout=10))
    xsubpp=host_core/'ExtUtils/xsubpp';xsubpp.resolve(strict=True)
    target='aarch64' if architecture=='arm64' else 'x86_64'
    opensource_lock = ROOT / 'runtime/materials/windows-open-toolchain.lock.json'
    if open_toolchain:
        opensource = json.loads(opensource_lock.read_text())
        source_directory = ROOT / '.artifacts/llvm-mingw-inputs'
        for item in [opensource['archive'], *opensource['sources']]:
            checked = {**item, 'sha256': 'sha256:' + item['sha256']}
            verified(source_directory / item['filename'], checked)
    else:
        llvm=llvm.resolve(strict=True);sdk=sdk.resolve(strict=True)
        compiler=llvm/'clang-cl';linker=ROOT/'.artifacts/rustup/toolchains/1.99.1-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/gcc-ld/lld-link'
        if not compiler.is_file() or not linker.is_file():raise ValueError('locked LLVM Windows tools are absent')
    module_lock=json.loads((ROOT/'runtime/native-perl-modules.lock.json').read_text());commands=[];compiled=[]
    with tempfile.TemporaryDirectory(prefix='.windows-perl-',dir=output.parent) as temporary:
        work=Path(temporary);package=work/'core';package.mkdir();extract(perl_archive,package)
        about=json.loads((package/'info/about.json').read_text());recipe=(package/'info/recipe/meta.yaml').read_text()
        if 'perl-5.44.0.tar.xz' not in recipe or '505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91' not in recipe:raise ValueError('Windows provider source is not the frozen stable Perl5.44')
        runtime=work/'runtime';runtime.mkdir()
        if architecture=='arm64':copy_tree(package/'Library',runtime);core=runtime/'lib/CORE';core_library='lib'
        else:
            for name in ['bin','lib']:copy_tree(package/name,runtime/name)
            core=runtime/'lib/perl5/5.44/core_perl/CORE';core_library='lib/perl5/5.44/core_perl'
        libraries=['lib/perl5',core_library]
        providers=[]
        for index,receipt in enumerate(selected['redistributables']):
            archive=verified(cache/receipt['filename'],receipt);directory=work/f'redist-{index}';directory.mkdir();extract(archive,directory);providers.append(directory/'Library/bin')
            copy_tree(directory/'info/licenses',runtime/f'share/licenses/redistributable-{index}')
        info_licenses=package/'info/licenses'
        if info_licenses.is_dir():copy_tree(info_licenses,runtime/'share/licenses/perl-provider')
        definitions=['WIN32','_CONSOLE','NO_STRICT','WIN64','_CRT_SECURE_NO_DEPRECATE','_CRT_NONSTDC_NO_DEPRECATE','_WINSOCK_DEPRECATED_NO_WARNINGS','PERL_TEXTMODE_SCRIPTS','MULTIPLICITY','PERL_IMPLICIT_SYS']
        if open_toolchain:
            archive = source_directory / opensource['archive']['filename']
            subprocess.run(['/usr/bin/tar', '-xf', str(archive), '-C', str(work)], env=env, check=True, timeout=120)
            toolchain = work / archive.name.removesuffix('.tar.xz')
            compiler = toolchain / 'bin' / (target + '-w64-mingw32-clang')
            linker = toolchain / 'bin/ld.lld'
            windows_flags = ['-O2', '-g0', '-ffile-prefix-map=' + str(work) + '=/ud-agent/build', *['-D' + name for name in definitions]]
        else:
            windows_flags=['/nologo','/O2','/MD',*['/D'+name for name in definitions]]
            include=[core,sdk/'crt/include',sdk/'sdk/include/ucrt',sdk/'sdk/include/shared',sdk/'sdk/include/um']
            libdirs=[core,sdk/f'crt/lib/{target}',sdk/f'sdk/lib/ucrt/{target}',sdk/f'sdk/lib/um/{target}']
            for directory in include+libdirs:
                if not directory.is_dir():raise ValueError('Windows SDK directory is absent: '+str(directory))
            def overlay_directory(directory):
                values=[]
                for item in sorted(directory.iterdir()):
                    if item.is_symlink():raise ValueError('Windows SDK includes contain unexpected links')
                    values.append({'type':'directory','name':item.name,'contents':overlay_directory(item)} if item.is_dir() else {'type':'file','name':item.name,'external-contents':str(item)})
                return values
            overlay=work/'windows-sdk-vfs.json';overlay.write_text(json.dumps({'version':0,'case-sensitive':False,'roots':[{'type':'directory','name':str(directory),'contents':overlay_directory(directory)} for directory in include[1:]]}))
            windows_flags.extend(['/clang:-ivfsoverlay','/clang:'+str(overlay),'/clang:-ffile-prefix-map='+str(work)+'=/ud-agent/build'])
        def run(args,cwd):
            commands.append(args);process=subprocess.run(args,cwd=cwd,env=env,capture_output=True,timeout=120)
            with (output.parent/(output.name+'-cross-build.log')).open('ab') as log:log.write(('COMMAND '+json.dumps(args)+'\n').encode()+process.stdout+process.stderr)
            if process.returncode:raise ValueError('Windows XS cross-build failed: '+process.stderr.decode(errors='replace')[-3000:])
            return process.stdout
        for release,receipt in module_lock['releases'].items():
            archive=ROOT/'.artifacts/perl-mutation/cache'/(receipt['sha256']+'.tar.gz')
            if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest()!=receipt['sha256']:raise ValueError('pinned CPAN source changed')
            source=work/release;source.mkdir();extract(archive,source,release)
            if (source/'lib').is_dir():copy_tree(source/'lib',runtime/'lib/perl5')
            if release=='Clone-0.51':shutil.copyfile(source/'Clone.pm',runtime/'lib/perl5/Clone.pm')
            for item in source.iterdir():
                if item.is_file() and re.fullmatch(r'(?:LICENSE(?:\.[A-Za-z0-9_-]+)?|COPYING(?:\.[A-Za-z0-9_-]+)?|Artistic|README(?:\.[A-Za-z0-9_-]+)?)',item.name,re.I):
                    target_license=runtime/'share/licenses'/release/item.name;target_license.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(item,target_license)
            actual_xs=sorted(item.relative_to(source).as_posix() for item in source.rglob('*.xs') if item.parts[len(source.parts)] not in ('t','xt','inc'))
            if actual_xs and release not in XS:raise ValueError('unmapped XS distribution: '+release)
            if release not in XS:continue
            name,version,sources,defines=XS[release]
            if release=='List-MoreUtils-XS-0.430':
                features={'HAVE_TIME_H':'#include <time.h>\nint f(void){return 0;}', 'HAVE_SYS_TIME_H':'#include <sys/time.h>\nint f(void){return 0;}', 'HAVE_SIZE_T':'#include <stddef.h>\nsize_t f(void){return 0;}', 'HAVE_SSIZE_T':'#include <sys/types.h>\nssize_t f(void){return 0;}', 'HAVE_BUILTIN_EXPECT':'int f(int x){return __builtin_expect(x,0);}', 'HAVE_FEATURE_STATEMENT_EXPRESSION':'int f(void){return ({1;});}', 'HAVE_TIME':'#include <time.h>\ntime_t f(void){return time(0);}'}
                settings=[]
                for feature,code in features.items():
                    probe=source/(feature+'.c');probe.write_text(code+'\n')
                    if open_toolchain:
                        arguments=[str(compiler),*windows_flags,'-Werror','-fsyntax-only',str(probe)]
                    else:
                        arguments=[str(compiler),'--target='+target+'-pc-windows-msvc',*windows_flags,*['/I'+str(directory) for directory in include[1:]],'/WX','/Zs','/Tc'+str(probe)]
                    commands.append(arguments);result=subprocess.run(arguments,cwd=source,env=env,capture_output=True,timeout=30)
                    if result.returncode not in (0,1):raise ValueError('cross compiler feature probe failed to run')
                    settings.append(('#define '+feature+' 1') if result.returncode==0 else ('/* '+feature+' unavailable */'))
                sizes=source/'abi-sizes.c';sizes.write_text('_Static_assert(sizeof(void*)==8,"ptr");_Static_assert(sizeof(long long)==8,"long long");_Static_assert(sizeof(long)==4,"long");_Static_assert(sizeof(int)==4,"int");\n')
                if open_toolchain:
                    run([str(compiler),*windows_flags,'-fsyntax-only',str(sizes)],source)
                else:
                    run([str(compiler),'--target='+target+'-pc-windows-msvc',*windows_flags,'/Zs','/Tc'+str(sizes)],source)
                (source/'LMUconfig.h').write_text('\n'.join(settings+['#define SIZEOF_PTR 8','#define SIZEOF_LONG_LONG 8','#define SIZEOF_LONG 4','#define SIZEOF_INT 4'])+'\n')
            if sorted(item for item in sources if item.endswith('.xs'))!=actual_xs:raise ValueError('XS source inventory changed: '+release)
            objects=[];object_receipts=[];module_evidence=linkage/name.replace('::','_');module_evidence.mkdir(mode=0o700)
            for filename in sources:
                original=source/filename;generated=original.with_suffix('.c')
                if original.suffix=='.xs':
                    args=[str(host_perl),str(xsubpp),'-typemap',str(host_core/'ExtUtils/typemap')]
                    if (source/'typemap').is_file():args+=['-typemap',str(source/'typemap')]
                    generated.write_bytes(run([*args,str(original)],source))
                else:generated=original
                object_file=original.with_suffix('.obj');objects.append(object_file)
                if open_toolchain:
                    arguments=[str(compiler),*windows_flags,'-I'+str(core),'-I'+str(source),*['-D'+value for value in defines],'-DVERSION="'+version+'"','-DXS_VERSION="'+version+'"','-c',str(generated),'-o',str(object_file)]
                else:
                    arguments=[str(compiler),'--target='+target+'-pc-windows-msvc',*windows_flags,*['/I'+str(directory) for directory in include],'/I'+str(source),*['/D'+value for value in defines],'/DVERSION="'+version+'"','/DXS_VERSION="'+version+'"','/c','/Tc'+str(generated),'/Fo'+str(object_file)]
                run(arguments,source)
                retained=module_evidence/(str(len(object_receipts))+'-'+object_file.name);shutil.copyfile(object_file,retained)
                object_receipts.append({'source':filename,'source_sha256':digest(original),'generated_sha256':digest(generated),'coff':{'path':retained.relative_to(linkage).as_posix(),'sha256':digest(retained),'size_bytes':retained.stat().st_size}})
            library=runtime/'lib/perl5/auto'/Path(*name.split('::'))/(name.split('::')[-1]+'.dll');library.parent.mkdir(parents=True,exist_ok=True)
            link_map = module_evidence / 'link.map'
            if open_toolchain:
                exports = module_evidence / 'exports.def'
                exports.write_text('EXPORTS\n  boot_' + name.replace('::', '__') + '\n')
                args = [str(compiler), '-shared', '-static', '-Wl,--no-insert-timestamp', '-Wl,-Map,' + str(link_map), '-o', str(library), *map(str, objects), str(exports), str(core / 'perl544.lib')]
            else:
                args=[str(linker),'/dll','/nologo','/Brepro','/timestamp:0','/machine:'+('ARM64' if architecture=='arm64' else 'X64'),'/out:'+str(library),'/MAP:'+str(link_map),'/export:boot_'+name.replace('::','__'),*['/libpath:'+str(directory) for directory in libdirs],*[str(item) for item in objects],str(core/'perl544.lib'),'oldnames.lib','kernel32.lib','user32.lib','gdi32.lib','winspool.lib','comdlg32.lib','advapi32.lib','shell32.lib','ole32.lib','oleaut32.lib','netapi32.lib','uuid.lib','ws2_32.lib','mpr.lib','winmm.lib','version.lib','odbc32.lib','odbccp32.lib','comctl32.lib','msvcrt.lib','vcruntime.lib','ucrt.lib']
            run(args,source);pe=PE.inspect_pe(library.read_bytes(),architecture)
            open_linkage = {}
            if open_toolchain:
                dependencies = pe['imports']
                if 'perl544.dll' not in dependencies or not all(PE.system_dll(item) or item == 'perl544.dll' for item in dependencies):
                    raise ValueError('Open XS extension imports an unclassified non-system DLL: ' + name)
                text = link_map.read_text().replace(str(toolchain) + '/', 'llvm-mingw/').replace(str(work) + '/', '').replace(str(ROOT) + '/', '')
                startup = 'llvm-mingw/' + target + '-w64-mingw32/lib/dllcrt2.o:('
                if startup not in text or re.search(r'\b(?:libcmt|libcpmt|libvcruntime|libucrt|vcruntime|msvcprt)\.lib\b', text, re.I):
                    raise ValueError('Open XS extension link map misses MinGW startup or contains a Microsoft CRT library')
                link_map.write_text(text)
                open_linkage = {'profile': 'llvm-mingw-ucrt', 'system_and_perl_imports': dependencies, 'startup': startup, 'perl_import_library_sha256': digest(core / 'perl544.lib')}
            for extension in ['.lib','.exp']:
                artifact=library.with_suffix(extension)
                if artifact.exists():artifact.unlink()
            compiled.append({'release':release,'module':name,'binary':library.relative_to(runtime).as_posix(),'sha256':digest(library),'source_archive':{'sha256':receipt['sha256'],'size_bytes':archive.stat().st_size},'objects':object_receipts,'map':{'path':link_map.relative_to(linkage).as_posix(),'sha256':digest(link_map),'size_bytes':link_map.stat().st_size},**({'open_linkage':open_linkage} if open_toolchain else {})})
        interset=json.loads((ROOT/'runtime/perl-deps.lock.json').read_text())['interset'];bridge=module('ud_windows_interset','scripts/runtime/perl_build.py');destination=work/'interset';bridge._extract_interset(ROOT/'.artifacts/perl-sources'/interset['archive'],interset,destination);copy_tree(destination/'lib',runtime/'lib/perl5');copy_tree(destination,runtime/'share/sources/interset')
        for executable in runtime.rglob('*.exe'):executable.chmod(0o755)
        imports=PE.close_runtime_imports(runtime,architecture,providers)
        receipt={'schema_version':1,'state':'cross-built','platform':'win32/'+architecture,'executable':'bin/perl.exe','library_dirs':libraries,'upstream_source_sha256':'sha256:505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91','provider':selected,'provider_recipe':about.get('extra',{}),'modules_sha256':digest(ROOT/'runtime/native-perl-modules.lock.json'),'compiled_xs':compiled,'pe_imports':imports,'producer_sha256':producer_sha256,'linkage_root':str(linkage.resolve()),'toolchain':{'compiler_sha256':digest(compiler),'linker_sha256':digest(linker)},'commands':commands,'native_probe':{'status':'pending_native','reason':'Cross-built PE binaries have not been loaded by a native Windows process.'}}
        if open_toolchain:
            receipt['toolchain'].update({'profile':'llvm-mingw-ucrt','lock_sha256':digest(opensource_lock),'archive_sha256':'sha256:'+opensource['archive']['sha256']})
            receipt['linkage_root'] = linkage.name
            receipt['commands'] = [[arg.replace(str(toolchain) + '/', 'llvm-mingw/').replace(str(work) + '/', '').replace(str(ROOT) + '/', '') for arg in command] for command in commands]
        if digest(Path(__file__))!=producer_sha256:raise ValueError('Windows Perl producer changed during build')
        shutil.copytree(runtime,output)
        receipt['files']=[{'path':item.relative_to(output).as_posix(),'sha256':digest(item),'size':item.stat().st_size} for item in sorted(output.rglob('*')) if item.is_file()]
        (output.parent/(output.name+'-receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--architecture',choices=['arm64','x64'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--host-perl',type=Path,default=ROOT/'.artifacts/native-perl/darwin-arm64-source/bin/perl');parser.add_argument('--llvm',type=Path,default=Path('/opt/homebrew/opt/llvm/bin'));parser.add_argument('--sdk',type=Path,default=ROOT/'.artifacts/xwin-cache/xwin');parser.add_argument('--legacy-msvc',action='store_true');args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True);result=build(args.architecture,args.output.resolve(),args.host_perl,args.llvm,args.sdk,open_toolchain=not args.legacy_msvc);print(json.dumps({'platform':result['platform'],'xs_modules':len(result['compiled_xs']),'native_probe':result['native_probe']}))
