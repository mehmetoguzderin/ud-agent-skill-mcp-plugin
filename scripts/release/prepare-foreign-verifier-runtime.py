"""Inspect pinned ELF/PE verifier prefixes as data; never execute target code."""
import argparse
import importlib.util
import json
from pathlib import Path
import posixpath
import struct

ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
base=module('foreign_verifier_base',Path(__file__).with_name('prepare-verifier-runtime.py'))
elf=module('foreign_verifier_elf',Path(__file__).with_name('verifier-elf.py'))
pe=module('foreign_verifier_pe',ROOT/'scripts/runtime/windows_pe.py')
SYSTEM_ELF={'libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libutil.so.1','libresolv.so.2','libgcc_s.so.1','libstdc++.so.6'}


def disabled_pe_architecture(body):
    """Read all distlib launcher CPUs without admitting them as runtime roots."""
    if len(body)<64 or body[:2]!=b'MZ':raise ValueError('invalid disabled packaging PE')
    offset=struct.unpack_from('<I',body,60)[0]
    if offset<64 or offset+26>len(body)or body[offset:offset+4]!=b'PE\0\0':raise ValueError('invalid disabled packaging PE header')
    machine=struct.unpack_from('<H',body,offset+4)[0];magic=struct.unpack_from('<H',body,offset+24)[0]
    architectures={0x14c:('x86',0x10b),0x8664:('x64',0x20b),0xaa64:('arm64',0x20b)}
    if machine not in architectures or magic!=architectures[machine][1]:raise ValueError('unsupported disabled packaging PE CPU')
    return architectures[machine][0]


def origin_path(consumer,value):
    """Expand only an entire ORIGIN token within the inventoried prefix."""
    token=next((token for token in ('$ORIGIN','${ORIGIN}')if value==token or value.startswith(token+'/')),None)
    if token is None:return None
    target=posixpath.normpath(posixpath.dirname(consumer)+value[len(token):])
    if target=='..'or target.startswith('../')or target.startswith('/')or '$'in target or '\\'in target:return None
    return target


def optional_native_exclusions(platform,native,files):
    """Exclude only named optional payloads after proving no retained import.

    Release inspectors have no GUI capability. The original archive inventory
    still binds every excluded byte and notice; exclusions apply only to the
    private verification prefix, never to product Python distributions.
    """
    selected={}
    if platform.startswith('linux-'):
        machine='aarch64'if platform=='linux-arm64'else'x86_64'
        names={'lib/libtcl9.0.so','lib/libtcl9tk9.0.so','lib/itcl4.3.8/libtcl9itcl4.3.8.so','lib/thread3.0.6/libtcl9thread3.0.6.so','lib/python3.15/lib-dynload/_tkinter.cpython-315-'+machine+'-linux-gnu.so'}
        present=names&native.keys()
        if present and present!=names:raise ValueError('optional Tcl runtime inventory is incomplete')
        selected={name:'Optional Tcl/Tk GUI capability is not part of the release verifier.'for name in present}
    elif platform=='win32-arm64'and'vcruntime140_1.dll'in native and native['vcruntime140_1.dll']['architectures']==['win32-x64']:
        selected={'vcruntime140_1.dll':'Original foreign x64 DLL has no retained native import on this ARM64 prefix.'}
    excluded_basenames={posixpath.basename(name).lower()for name in selected}
    for name,metadata in native.items():
        if name in selected:continue
        for needed in metadata.get('imports',metadata.get('needed',[])):
            if posixpath.basename(needed).lower()in excluded_basenames:
                raise ValueError('optional verifier exclusion is required by retained native input: '+name)
    return [{'path':name,'sha256':files[name]['sha256'],'size':files[name]['size'],'reason':selected[name]}for name in sorted(selected)]


def derive(root,archive,asset_name,platform):
    if platform not in ('linux-arm64','linux-x64','win32-arm64','win32-x64'):raise ValueError('an explicit foreign ELF/PE platform is required')
    generator=base.digest(Path(__file__));release_file=root/'runtime/receipts/userspace-python-release.json';release=json.loads(release_file.read_bytes());assets=[row for row in release['assets']if row['name']==asset_name]
    if len(assets)!=1 or release['tag_name']!='20261026':raise ValueError('foreign verifier asset is absent from the frozen release')
    asset=assets[0];windows=platform.startswith('win32-');arch=platform.split('-')[1];files={};links={};native={};support=[];excluded=[];seen=set();total=0
    with base.verified_tar(archive,asset)as bundle:
        for row in bundle:
            name=base.paths.validate_path(row.name.rstrip('/')if row.isdir()else row.name)
            # Source inspection keeps Linux terminfo A/a distinct. These
            # original names are materialized only on their native Linux host.
            key=base.paths.path_key(name)if windows else name
            if not name.startswith('python/')or key in seen or len(seen)>=100000:raise ValueError('foreign verifier has an unsafe, duplicate, or foreign member')
            seen.add(key);name=name[7:]
            if row.isdir():continue
            if not name or not 0<=row.size<=512*1024**2:raise ValueError('foreign verifier member exceeds bounds')
            total+=row.size
            if total>2*1024**3:raise ValueError('foreign verifier prefix exceeds bounds')
            if '__pycache__'in name.split('/')or name.endswith('.pyc'):excluded.append(name);continue
            if row.issym()or row.islnk():
                target=posixpath.normpath(posixpath.join(posixpath.dirname('python/'+name),row.linkname)if row.issym()else row.linkname)
                if not target.startswith('python/'):raise ValueError('foreign verifier alias escapes its prefix')
                links[name]={'path':name,'linkname':row.linkname,'target':target[7:]};continue
            if not row.isfile():raise ValueError('foreign verifier has a special member')
            body=bundle.extractfile(row).read(row.size+1)
            if len(body)!=row.size:raise ValueError('foreign verifier member is truncated')
            files[name]={'path':name,'sha256':base.hashlib.sha256(body).hexdigest(),'size':len(body),'executable':bool(row.mode&0o111)}
            disabled='/site-packages/'in '/'+name
            if body.startswith(b'!<arch>\n'):
                support.append({'path':name,'format':'static-linker-archive','reason':'Link-time support, not dynamically loaded.'});continue
            if body[:4]==b'\x7fELF':
                if windows:
                    if not disabled:raise ValueError('foreign verifier has an unexpected ELF outside disabled packages')
                    support.append({'path':name,'format':'ELF','reason':'Disabled packaging support'});continue
                if len(body)<64 or struct.unpack_from('<H',body,18)[0]!={'arm64':183,'x64':62}[arch]:raise ValueError('foreign verifier ELF machine differs')
                if struct.unpack_from('<H',body,16)[0]==1:
                    support.append({'path':name,'format':'ELF-relocatable-object','reason':'Link-time support, not dynamically loaded.'});continue
                native[name]={'format':'ELF','architectures':[platform],**elf.inspect(body)}
            elif body[:2]==b'MZ':
                if disabled:
                    support.append({'path':name,'format':'PE','architecture':disabled_pe_architecture(body),'reason':'Disabled packaging support; site initialization is disabled.'});continue
                if not windows:raise ValueError('foreign verifier has an unexpected PE outside disabled packages')
                actual_arch=disabled_pe_architecture(body)
                if actual_arch not in pe.MACHINES:raise ValueError('runtime PE has an unsupported CPU: '+name)
                try:identity=pe.inspect_pe(body,actual_arch)
                except ValueError as error:raise ValueError('invalid verifier runtime PE '+name+': '+str(error))from error
                native[name]={'format':'PE','architectures':['win32-'+actual_arch],**identity}
            elif body[:4]in(b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xfe\xed\xfa\xcf',b'\0asm'):
                if not disabled:raise ValueError('unsupported verifier native magic outside disabled packages')
                support.append({'path':name,'reason':'Disabled foreign packaging support'})
    for name,row in links.items():
        target=row['target'];visited={name}
        while target in links:
            if target in visited or len(visited)>32:raise ValueError('foreign verifier alias cycle')
            visited.add(target);target=links[target]['target']
        if target not in files:raise ValueError('foreign verifier alias has no ordinary target')
        row['resolved_target']=target
    version=asset_name.split('+',1)[0].removeprefix('cpython-');entry='python.exe'if windows else'bin/python'+'.'.join(version.split('.')[:2])
    if entry not in native or platform not in native[entry]['architectures']:raise ValueError('foreign verifier entrypoint has no matching actual CPU')
    omitted=optional_native_exclusions(platform,native,files);omitted_paths={row['path']for row in omitted}
    if any(row['resolved_target']in omitted_paths for row in links.values()):raise ValueError('optional verifier exclusion has an undeclared alias')
    dependencies=[];unresolved=[]
    def actual(name):return links[name]['resolved_target']if name in links else name if name in files else None
    for name,metadata in native.items():
        if name in omitted_paths:continue
        if metadata['format']=='PE':
            if platform not in metadata['architectures']:
                unresolved.append({'consumer':name,'path':name,'architectures':metadata['architectures'],'classification':'unresolved-foreign-runtime-architecture'})
            for needed in metadata['imports']:
                row={'consumer':name,'path':needed}
                candidates=[posixpath.join(posixpath.dirname(name),needed),posixpath.join(posixpath.dirname(entry),needed)]
                matches=[candidate for candidate in files.keys()|links.keys()if any(candidate.lower()==wanted.lower()for wanted in candidates)]
                if pe.system_dll(needed):row['classification']='host-windows-system-library'
                elif len(matches)==1 and actual(matches[0])in native and platform in native[actual(matches[0])]['architectures']:row.update(classification='inventoried-private-runtime-library',target=actual(matches[0]))
                else:row['classification']='unresolved-native-loader-dependency';unresolved.append(row)
                dependencies.append(row)
        else:
            interpreter=metadata['interpreter'];expected='/lib/ld-linux-aarch64.so.1'if arch=='arm64'else'/lib64/ld-linux-x86-64.so.2'
            if interpreter:
                row={'consumer':name,'path':interpreter,'classification':'host-linux-system-loader'if interpreter==expected else'unresolved-native-loader-dependency'};dependencies.append(row)
                if interpreter!=expected:unresolved.append(row)
            directories=[]
            for search in metadata['search_paths']:
                for item in search.split(':'):
                    directory=origin_path(name,item)
                    if directory is not None:directories.append(directory)
                    else:unresolved.append({'consumer':name,'path':item,'classification':'unresolved-absolute-or-ambient-search-path'})
            for needed in metadata['needed']:
                row={'consumer':name,'path':needed};matches=sorted({actual(posixpath.join(directory,needed))for directory in directories if actual(posixpath.join(directory,needed))})
                if '/'in needed or '$'in needed:
                    expanded=origin_path(name,needed);target=actual(expanded)if expanded is not None else None;matches=[target]if target else[]
                if len(matches)==1:row.update(classification='inventoried-private-runtime-library',target=matches[0])
                elif needed in SYSTEM_ELF or needed==posixpath.basename(expected):row['classification']='host-linux-system-library'
                else:row['classification']='unresolved-native-loader-dependency';unresolved.append(row)
                dependencies.append(row)
    helpers=[Path(base.__file__),Path(elf.__file__),Path(pe.__file__)]
    if base.digest(Path(__file__))!=generator:raise ValueError('foreign verifier producer changed during inspection')
    return {'schema_version':1,'qualification':'publisher-archive-verifier-prefix-inventory-not-approval','platform':platform,'version':version,'entrypoint':entry,'files':[files[key]for key in sorted(files)],'links':[links[key]for key in sorted(links)],'excluded_original_pycache':sorted(excluded),'excluded_optional_payloads':omitted,'site_initialization':'disabled-with-S','pycache_policy':'private-empty-prefix-with-B','path_policy':'native-linux-case-sensitive-original-names'if not windows else'frozen-unicode16-portable','native_files':[{'path':name,'format':value['format'],'architectures':value['architectures']}for name,value in sorted(native.items())if name not in omitted_paths],'disabled_foreign_support_payloads':support,'native_dependencies':dependencies,'unresolved_dependencies':unresolved,'target_execution':False,'native_smoke':'pending-native-host','origin':{'release_receipt':{'path':release_file.relative_to(root).as_posix(),'sha256':base.digest(release_file),'size':release_file.stat().st_size},'archive':{'name':asset_name,'sha256':asset['digest'][7:],'size':asset['size'],'url':asset['browser_download_url']}},'generator':{'path':Path(__file__).resolve().relative_to(root).as_posix(),'sha256':generator},'helpers':[{'path':file.relative_to(root).as_posix(),'sha256':base.digest(file)}for file in helpers]}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','asset-name','platform','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();output=Path(args.output)
    if output.exists():raise ValueError('new foreign verifier inventory output required')
    result=derive(ROOT,Path(args.archive),args.asset_name,args.platform);output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'platform':args.platform,'files':len(result['files']),'aliases':len(result['links']),'native_files':len(result['native_files']),'unresolved_dependencies':len(result['unresolved_dependencies']),'target_execution':False}))
