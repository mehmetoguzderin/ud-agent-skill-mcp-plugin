"""Materialize a hash-bound vendor browser ZIP without executing project code."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import sys
import zipfile

if __package__:
    from .unicode_paths import path_key,validate_path
    from .elf_runtime import inspect as elf_inspect,with_interpreter
else:
    def _load(name,file):
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    _paths=_load('_ud_vendor_paths','unicode_paths.py');path_key,validate_path=_paths.path_key,_paths.validate_path
    _elf=_load('_ud_vendor_elf','elf_runtime.py');elf_inspect,with_interpreter=_elf.inspect,_elf.with_interpreter

MAX_FILE=512*1024**2
MAX_TOTAL=2*1024**3
MAX_FILES=20000
PROVIDER='google-chrome-for-testing'
PLATFORMS={'darwin/arm64':'mac-arm64','darwin/x64':'mac-x64','linux/arm64':'linux-arm64','linux/x64':'linux64','win32/x64':'win64'}


def code_architecture(bundle,item,platform):
    with bundle.open(item)as source:
        data=source.read(4096)
        if platform.startswith('linux/'):
            return len(data)>=64 and data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',data,18)[0]==(183 if platform.endswith('arm64')else 62)
        if platform.startswith('darwin/'):
            cpu=0x100000c if platform.endswith('arm64')else 0x1000007
            if data[:4]==b'\xcf\xfa\xed\xfe':return len(data)>=32 and struct.unpack_from('<I',data,4)[0]==cpu
            if data[:4]in(b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf')and len(data)>=8:
                count=struct.unpack_from('>I',data,4)[0];size=32 if data[:4]==b'\xca\xfe\xba\xbf'else 20
                return 1<=count<=64 and 8+count*size<=len(data)and any(struct.unpack_from('>I',data,8+i*size)[0]==cpu for i in range(count))
            return False
        if len(data)<64 or data[:2]!=b'MZ':return False
        offset=struct.unpack_from('<I',data,60)[0]
        if offset>1024**2:return False
        source.seek(offset);header=source.read(6)
        return len(header)==6 and header[:4]==b'PE\0\0'and struct.unpack_from('<H',header,4)[0]==0x8664


def owned_path(root,name):
    validate_path(name);current=Path(root)
    for part in name.split('/'):
        current=current/part
        try:info=current.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode)or getattr(info,'st_file_attributes',0)&0x400:raise ValueError('VENDOR_PATH_LINK_INVALID')
    return current


def verify(path,record):
    if (not isinstance(record,dict) or not isinstance(record.get('sha256'),str) or not re.fullmatch('[a-f0-9]{64}',record['sha256'])
            or type(record.get('size_bytes'))is not int or not 0<=record['size_bytes']<=MAX_FILE):raise ValueError('VENDOR_RECEIPT_INVALID')
    info=Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400 or info.st_size!=record['size_bytes']:raise ValueError('VENDOR_INTEGRITY_FAILED')
    with Path(path).open('rb')as source:
        before=os.fstat(source.fileno());digest=hashlib.file_digest(source,'sha256').hexdigest();after=os.fstat(source.fileno())
    if digest!=record['sha256'] or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('VENDOR_INTEGRITY_FAILED')


class ClosedZip:
    """Resolve only internal archive aliases; no archive path becomes a host link."""
    def __init__(self,bundle,source_root):
        self.bundle=bundle;self.root=validate_path(source_root);self.entries={};names=set();total=0
        for item in bundle.infolist():
            # ZipInfo normalizes Windows separators while reading. Validate the
            # original central-directory spelling before using that result.
            if item.orig_filename != item.filename:raise ValueError('VENDOR_ZIP_MEMBER_INVALID')
            logical=validate_path(item.filename.rstrip('/') if item.is_dir() else item.filename)
            if logical==self.root and item.is_dir():continue
            if not logical.startswith(self.root+'/'):raise ValueError('VENDOR_ZIP_ROOT_INVALID')
            name=logical[len(self.root)+1:];key=path_key(name);total+=item.file_size
            if (key in names or len(names)>=MAX_FILES or not 0<=item.file_size<=MAX_FILE or total>MAX_TOTAL
                    or item.flag_bits&1 or item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)):
                raise ValueError('VENDOR_ZIP_MEMBER_INVALID')
            names.add(key);mode=item.external_attr>>16;kind=stat.S_IFMT(mode)
            if item.is_dir():
                if item.file_size:raise ValueError('VENDOR_ZIP_MEMBER_INVALID')
                self.entries[name]=('dir',item)
            elif kind==stat.S_IFLNK:
                if item.file_size>4096:raise ValueError('VENDOR_ZIP_LINK_INVALID')
                target=bundle.read(item).decode('utf-8',errors='strict')
                if not target or target.startswith('/') or '\\'in target or '\0'in target or ':'in target:raise ValueError('VENDOR_ZIP_LINK_INVALID')
                target=posixpath.normpath(posixpath.join(posixpath.dirname(name),target))
                if target=='..'or target.startswith('../'):raise ValueError('VENDOR_ZIP_LINK_INVALID')
                self.entries[name]=('link',target)
            elif kind in (0,stat.S_IFREG):self.entries[name]=('file',item)
            else:raise ValueError('VENDOR_ZIP_MEMBER_INVALID')
        self.files={name:self.resolve(name)[1] for name,(kind,_)in self.entries.items() if kind=='file'}
        for name,(kind,_)in self.entries.items():
            if kind=='file' and self.resolve(name)[0]!=name:
                raise ValueError('VENDOR_ZIP_FILE_BELOW_ALIAS')
        aliases=[]
        for name,(kind,_)in self.entries.items():
            if kind=='link':
                target,value=self.resolve(name)
                if value is not None:self.files[name]=value
                else:aliases.append((name,target,(target,)))
        while aliases:
            alias,target,ancestors=aliases.pop()
            for name,(kind,_)in self.entries.items():
                if not name.startswith(target+'/' if target else ''):continue
                suffix=name[len(target)+1:] if target else name
                logical=alias+'/'+suffix;canonical,value=self.resolve(logical)
                if value is not None:self.files[logical]=value
                elif kind=='link':
                    if canonical in ancestors:raise ValueError('VENDOR_ZIP_LINK_CYCLE')
                    aliases.append((logical,canonical,(*ancestors,canonical)))
            if len(self.files)+len(aliases)>MAX_FILES:raise ValueError('VENDOR_ZIP_ALIAS_LIMIT_EXCEEDED')
        keys=set();total=0
        for name,item in self.files.items():
            validate_path(name);key=path_key(name);total+=item.file_size
            if key in keys or total>MAX_TOTAL:raise ValueError('VENDOR_ZIP_ALIAS_COLLISION')
            keys.add(key)
        self.inventory=[]
        digests={}
        for name,item in sorted(self.files.items()):
            if item.filename not in digests:
                with bundle.open(item)as source:digests[item.filename]=hashlib.file_digest(source,'sha256').hexdigest()
            self.inventory.append({'path':name,'sha256':digests[item.filename],'size_bytes':item.file_size})

    def resolve(self,name):
        for _ in range(64):
            if name in ('','.'):return '',None
            validate_path(name);parts=name.split('/');rewritten=False
            for index in range(1,len(parts)+1):
                prefix='/'.join(parts[:index]);kind,value=self.entries.get(prefix,('implicit',None))
                if kind=='link':
                    name=posixpath.normpath(value+('/'+'/'.join(parts[index:]) if index<len(parts) else ''));rewritten=True;break
                if index<len(parts)and kind=='file':raise ValueError('VENDOR_ZIP_NOT_DIRECTORY')
            if rewritten:continue
            kind,value=self.entries.get(name,('implicit',None))
            if kind=='file':return name,value
            if kind=='dir' or any(path.startswith(name+'/')for path in self.entries):return name,None
            raise ValueError('VENDOR_ZIP_DANGLING_LINK')
        raise ValueError('VENDOR_ZIP_LINK_CYCLE')

    def extract(self,destination):
        if destination.exists() or destination.is_symlink():raise ValueError('VENDOR_DESTINATION_EXISTS')
        destination.mkdir(mode=0o700)
        for name,item in sorted(self.files.items()):
            file=destination/name;file.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with self.bundle.open(item)as source,file.open('xb')as output:
                total=0
                while chunk:=source.read(1024**2):
                    total+=len(chunk)
                    if total>item.file_size:raise ValueError('VENDOR_ZIP_SIZE_CHANGED')
                    output.write(chunk)
                output.flush();os.fsync(output.fileno())
            if total!=item.file_size:raise ValueError('VENDOR_ZIP_SIZE_CHANGED')
            file.chmod(0o555 if item.external_attr>>16&0o111 or name.endswith('.exe')else 0o444)


def materialize_pack(pack_dir,archive,recipe_path,output_dir,manifest_path,installation_dir=None):
    root=Path(pack_dir)
    if root.is_symlink()or not root.is_dir():raise ValueError('VENDOR_PACK_ROOT_INVALID')
    for name in (recipe_path,output_dir,manifest_path):validate_path(name)
    manifest_file=owned_path(root,manifest_path);manifest=json.loads(manifest_file.read_text(encoding='utf-8'))
    if manifest.get('deferred_browser')!={'provider':PROVIDER,'recipe':recipe_path,'directory':output_dir}:raise ValueError('VENDOR_DEFERRED_MANIFEST_INVALID')
    base=manifest['files'];inventory={}
    for item in base:
        name=validate_path(item['path'])
        if name in inventory or name==manifest_path or name==output_dir or name.startswith(output_dir+'/'):raise ValueError('VENDOR_BASE_INVENTORY_INVALID')
        verify(owned_path(root,name),item);inventory[name]=item
    if recipe_path not in inventory:raise ValueError('VENDOR_RECIPE_NOT_IN_INVENTORY')
    recipe=json.loads(owned_path(root,recipe_path).read_text(encoding='utf-8'))
    if recipe.get('schema_version')!=1 or recipe.get('provider')!=PROVIDER or recipe.get('platform')not in PLATFORMS:raise ValueError('VENDOR_RECIPE_INVALID')
    slug=PLATFORMS[recipe['platform']]
    if recipe.get('source_root')!='chrome-headless-shell-'+slug or not isinstance(recipe.get('files'),list)or not 1<=len(recipe['files'])<=MAX_FILES:raise ValueError('VENDOR_RECIPE_INVALID')
    if not re.fullmatch(r'https://storage\.googleapis\.com/chrome-for-testing-public/[0-9]+(?:\.[0-9]+){3}/'+re.escape(slug)+r'/chrome-headless-shell-'+re.escape(slug)+r'\.zip',recipe['archive'].get('url','')):raise ValueError('VENDOR_RECIPE_URL_INVALID')
    executable='chrome-headless-shell.exe'if recipe['platform']=='win32/x64'else'chrome-headless-shell'
    if manifest.get('executable')!=output_dir+'/'+executable:raise ValueError('VENDOR_EXECUTABLE_INVALID')
    verify(Path(archive),recipe['archive'])
    destination=owned_path(root,output_dir)
    files=[{**item,'path':output_dir+'/'+validate_path(item['path'])}for item in recipe['files']]
    merged=[*base,*files]
    if len({path_key(item['path'])for item in merged})!=len(merged):raise ValueError('VENDOR_FINAL_PATH_COLLISION')
    linux=recipe['platform'].startswith('linux/')
    if linux:
        loader=recipe.get('linux_loader')
        if (not isinstance(loader,dict)or set(loader)!={'executable','library_dirs','materialization'}or loader['materialization']!='elf-interpreter-v1'
                or not isinstance(loader['library_dirs'],list)or not 1<=len(loader['library_dirs'])<=64 or not isinstance(installation_dir,str)
                or not Path(installation_dir).is_absolute()or'..'in Path(installation_dir).parts):raise ValueError('VENDOR_LINUX_LOADER_INVALID')
        loader_name=validate_path(loader['executable']);directories=[validate_path(name)for name in loader['library_dirs']]
        if loader_name not in inventory or len(set(directories))!=len(directories):raise ValueError('VENDOR_LINUX_LOADER_INVALID')
        for name in directories:
            directory=owned_path(root,name)
            if not directory.is_dir():raise ValueError('VENDOR_LINUX_LIBRARY_INVALID')
            children=list(directory.iterdir())
            if not children or any(not child.is_file()or child.is_symlink()or child.relative_to(root).as_posix()not in inventory for child in children):raise ValueError('VENDOR_LINUX_LIBRARY_INVALID')
    with Path(archive).open('rb')as raw:
        before=os.fstat(raw.fileno())
        if before.st_size!=recipe['archive']['size_bytes']or hashlib.file_digest(raw,'sha256').hexdigest()!=recipe['archive']['sha256']:raise ValueError('VENDOR_INTEGRITY_FAILED')
        raw.seek(0)
        with zipfile.ZipFile(raw)as bundle:
            closed=ClosedZip(bundle,recipe['source_root'])
            if closed.inventory!=recipe['files']:raise ValueError('VENDOR_ZIP_INVENTORY_MISMATCH')
            if executable not in closed.files or not code_architecture(bundle,closed.files[executable],recipe['platform']):raise ValueError('VENDOR_EXECUTABLE_ARCHITECTURE_INVALID')
            closed.extract(destination)
        after=os.fstat(raw.fileno())
        if(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('VENDOR_ZIP_CHANGED')
    if linux:
        installed=Path(installation_dir);interpreter=str(installed/loader_name)
        machine=183 if recipe['platform']=='linux/arm64'else 62;transforms=[]
        for item in files:
            file=root/item['path']
            with file.open('rb')as source:magic=source.read(4)
            if magic!=b'\x7fELF':continue
            data=file.read_bytes();info=elf_inspect(data)
            if info['machine']!=machine or info['search_paths']:raise ValueError('VENDOR_LINUX_ELF_INVALID')
            if info['interpreter']is not None:
                updated=with_interpreter(data,interpreter);file.chmod(0o600);file.write_bytes(updated);file.chmod(0o555)
                transforms.append({'path':item['path'],'source_sha256':item['sha256'],'derived_sha256':hashlib.sha256(updated).hexdigest(),'source_interpreter':info['interpreter'],'interpreter':interpreter})
                item.update(sha256=hashlib.sha256(updated).hexdigest(),size_bytes=len(updated))
        if not transforms:raise ValueError('VENDOR_LINUX_INTERPRETER_MISSING')
        manifest['loader']={'executable':loader_name,'library_dirs':directories,'mode':'direct','installed_root':str(installed)}
        manifest['materialization']={'provider':PROVIDER,'recipe_sha256':inventory[recipe_path]['sha256'],'source_archive_sha256':recipe['archive']['sha256'],'transformations':transforms}
    merged=[*base,*files]
    manifest['files']=sorted(merged,key=lambda item:item['path']);del manifest['deferred_browser']
    temporary=manifest_file.with_name(manifest_file.name+'.materialized')
    with temporary.open('x',encoding='utf-8',newline='\n')as output:output.write(json.dumps(manifest,sort_keys=True,indent=2)+'\n');output.flush();os.fsync(output.fileno())
    os.replace(temporary,manifest_file)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('pack-dir','archive','recipe','output-dir','manifest'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--installation-dir')
    args=parser.parse_args();materialize_pack(args.pack_dir,args.archive,args.recipe,args.output_dir,args.manifest,args.installation_dir)
