#!/usr/bin/env python3
"""Prepare pinned native ARM64 mutation dependencies for an offline OCI image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import shutil
import signal
import subprocess
import struct
import sys
import stat
import tarfile
import tempfile
import threading
import time
import tomllib
import zipfile
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[2]
HARNESS_NAMES=('mutmut-driver.py','python-runtime-projection.py','oci-isolation.py','oci-mutation.py','oci-exec.py','perl-test-runtime.py','python-operators.py','stryker-child.mjs','stryker-config.mjs','stryker-opacity.mjs','stryker-baseline-authority.mjs','stryker-assertions.mjs','stryker-assertion-setup.mjs','stryker-native-assertions.cjs','stryker-assertion-sdk.mjs','stryker-protected-runner.mjs','stryker-exec.py','oci-stryker.py','oci-secondary.py','secondary-child.py','collect-mutation-tests.mjs','rust-literal.py','rust-protected.py','rust-test-runtime.py','rust-compile-child.py','pytest_evidence.py')
def digest(file):
    with file.open('rb')as source:return hashlib.file_digest(source,'sha256').hexdigest()

def sdk_node_command(command, *, timeout, cwd=None):
    """Preserve a bounded diagnostic suffix when a fixed original SDK step fails."""
    try:
        return subprocess.run(command, cwd=cwd, check=True, capture_output=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        def tail(value):
            if isinstance(value, str): value=value.encode('utf-8', errors='replace')
            return (value or b'')[-8192:].decode('utf-8', errors='replace')
        status='timed out after '+str(timeout)+' seconds' if isinstance(error, subprocess.TimeoutExpired) else 'exited '+str(error.returncode)
        raise ValueError('Mutation SDK Node command '+status+': '+repr(command)+'\nstdout (final 8192 bytes):\n'+tail(error.stdout)+'\nstderr (final 8192 bytes):\n'+tail(error.stderr)) from error

def acquire(item,cache,download):
    expected=item.get('hash',item.get('sha256')).removeprefix('sha256:');size=item.get('size',item.get('size_bytes'));file=cache/expected
    if not file.exists():
        if not download:raise ValueError('locked mutation input is absent')
        temporary=None
        try:
            with tempfile.NamedTemporaryFile(mode='wb',prefix='.'+expected+'.',suffix='.partial',dir=cache,delete=False)as target:
                temporary=Path(target.name)
                with urlopen(item['url'],timeout=60)as source:
                    count=0
                    while chunk:=source.read(1024*1024):
                        count+=len(chunk)
                        if count>size:raise ValueError('mutation input exceeds its locked size')
                        target.write(chunk)
            if temporary.stat().st_size!=size or digest(temporary)!=expected:raise ValueError('mutation input integrity mismatch')
            try:os.link(temporary,file)
            except FileExistsError:pass # A concurrent publisher still has to pass the same integrity check below.
        finally:
            if temporary is not None:temporary.unlink(missing_ok=True)
    if file.is_symlink()or file.stat().st_size!=size or digest(file)!=expected:raise ValueError('mutation input integrity mismatch')
    return file

def copy_parser(source, output):
    receipt=read(source/'parser-receipt.json');lock=read(ROOT/'quality/perl-parser.lock.json')
    expected=hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if receipt.get('lock_sha256')!=expected or receipt.get('parser_release')!='PPI-1.291' or receipt.get('perl_version')!='v5.44.0' or not receipt.get('files'):
        raise ValueError('native Linux PPI parser receipt is missing or stale')
    selected=set()
    output.mkdir()
    for item in receipt['files']:
        name=item['path'];parts=name.split('/')
        if name.startswith('/')or'\\'in name or any(part in('','.','..')for part in parts)or name in selected:
            raise ValueError('native PPI inventory is unsafe or duplicated')
        selected.add(name);file=source/name
        for parent in file.parents:
            if parent==source:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('native PPI parent is not an ordinary directory')
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=item['size']or digest(file)!=item['sha256']:
            raise ValueError('native PPI parser bytes differ from their receipt')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o444)
    actual={file.relative_to(source).as_posix()for file in source.rglob('*')if file.is_file()and file.name!='parser-receipt.json'}
    if actual!=selected:raise ValueError('native PPI parser contains unlisted bytes')
    shutil.copyfile(source/'parser-receipt.json',output/'parser-receipt.json')
    return {'lock_sha256':expected,'receipt_sha256':digest(output/'parser-receipt.json'),'files':len(selected)}

def copy_uv(archive, item, version, output):
    """Admit only the exact native binaries from the frozen upstream archive."""
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != item['size'] or digest(archive) != item['sha256'].removeprefix('sha256:'):
        raise ValueError('native uv archive differs from its frozen receipt')
    if item.get('filename') != 'uv-aarch64-unknown-linux-gnu.tar.gz' or not version or '/'+version+'/' not in item.get('url',''):
        raise ValueError('native uv release or platform differs')
    expected = {'uv-aarch64-unknown-linux-gnu/uv', 'uv-aarch64-unknown-linux-gnu/uvx'}
    files = []
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        if len(members) != 3 or len({member.name for member in members}) != 3 or {member.name for member in members if member.isfile()} != expected or any(not (member.isfile() or member.name == 'uv-aarch64-unknown-linux-gnu' and member.isdir()) for member in members):
            raise ValueError('native uv archive contains an unexpected path or entry')
        for member in members:
            if not member.isfile(): continue
            if not 20 <= member.size <= 128 * 1024**2:
                raise ValueError('native uv binary exceeds its bound')
            data = source.extractfile(member).read(member.size + 1)
            if len(data) != member.size or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
                raise ValueError('native uv executable architecture differs')
            files.append((member.name.rsplit('/', 1)[1], data))
    output.mkdir()
    records = []
    for name, data in files:
        target = output / name;target.write_bytes(data);target.chmod(0o555)
        records.append({'path': 'bin/' + name, 'sha256': digest(target), 'size_bytes': len(data)})
    return {'version': version, 'archive': item, 'files': sorted(records, key=lambda row: row['path'])}

def copy_rust(source, receipt_file, output):
    receipt=read(receipt_file)
    if receipt.get('qualification')!='development-mutation-toolchain'or receipt.get('platform')!='linux/arm64'or receipt.get('toolchain',{}).get('version')!='1.99.1'or receipt.get('cargo_mutants',{}).get('crate',{}).get('version')!='27.1.0'or receipt.get('product_vendor',{}).get('cargo_lock_sha256')!=digest(ROOT/'Cargo.lock')or receipt.get('links')!=[]:
        raise ValueError('native Rust mutation input identity is missing or stale')
    verify_assertion_parser_source(receipt, ROOT)
    expected=set();output.mkdir()
    for item in receipt['files']:
        name=item['path'];parts=name.split('/')
        if name.startswith('/')or'\\'in name or any(part in('','.','..')for part in parts)or name in expected or item['mode']&0o7222:
            raise ValueError('native Rust file inventory is unsafe or writable')
        expected.add(name);file=source/name
        for parent in file.parents:
            if parent==source:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('native Rust parent must be ordinary')
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=item['size']or digest(file)!=item['sha256']:
            raise ValueError('native Rust bytes differ from their closed receipt')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(item['mode'])
    if {file.relative_to(source).as_posix()for file in source.rglob('*')if file.is_file()}!=expected or any(file.is_symlink()for file in source.rglob('*')):
        raise ValueError('native Rust input contains unlisted files or links')
    for name in ('bin/rustc','bin/cargo','bin/cargo-mutants','bin/ud-rust-assertion-parser'):
        header=(output/name).read_bytes()[:20]
        if header[:6]!=b'\x7fELF\x02\x01'or struct.unpack_from('<H',header,18)[0]!=183:raise ValueError('native Rust executable architecture differs')
    return {'path':'rust-input-receipt.json','sha256':digest(receipt_file),'size_bytes':receipt_file.stat().st_size,'files':len(expected),'version':'1.99.1','cargo_mutants_version':'27.1.0'}

def verify_assertion_parser_source(receipt, root):
    parser=receipt.get('assertion_parser')
    prefix='scripts/quality/rust-assertion-parser/'
    required={prefix+'Cargo.toml',prefix+'Cargo.lock'}
    required.update(file.relative_to(root).as_posix() for file in(root/prefix/'src').rglob('*.rs'))
    if(root/prefix/'build.rs').exists():
        raise ValueError('Rust assertion parser build-phase inputs are unsupported by this frozen SDK contract')
    if not isinstance(parser,dict)or parser.get('schema_version')!=1 or not isinstance(parser.get('source_inventory'),dict)or set(parser['source_inventory'])!=required or not any(name.endswith('.rs')for name in required):
        raise ValueError('Rust assertion parser has no complete frozen source closure')
    for name in required:
        file=root/name
        if file.is_symlink()or not file.is_file()or digest(file)!=parser['source_inventory'][name]:
            raise ValueError('Rust assertion parser source differs from its tool receipt')
    if len([item for item in receipt.get('files',[])if item.get('path')=='bin/ud-rust-assertion-parser'])!=1:
        raise ValueError('Rust assertion parser binary is missing or repeated in the tool closure')

def copy_node_npm(archive, item, version, output):
    """Retain the original npm subtree from the same hash-locked native Node archive."""
    if item.get('filename') != 'node-v' + version + '-linux-arm64.tar.xz' or archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 256 * 1024**2 or digest(archive) != item['sha256']:
        raise ValueError('native npm provider differs from the frozen Node archive')
    if output.is_symlink() or not output.is_dir() or (output / 'lib').exists() or (output / 'lib').is_symlink():
        raise ValueError('native npm destination must be the new ordinary Node extraction')
    spec=importlib.util.spec_from_file_location('ud_npm_archive_paths',ROOT/'workers/ud/src/ud_agent/unicode_paths.py');paths=importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)
    prefix='node-v'+version+'-linux-arm64/lib/node_modules/npm';data={};seen=set();total=0
    with tarfile.open(archive,'r:xz') as source:
        for member in source:
            if member.name != prefix and not member.name.startswith(prefix+'/'):continue
            name=member.name[len('node-v'+version+'-linux-arm64/'):].removesuffix('/');paths.validate_path(name);key=paths.path_key(name)
            if key in seen or len(seen)>=10000 or not(member.isfile()or member.isdir()):raise ValueError('native npm subtree has duplicate, linked or special members')
            seen.add(key)
            if member.isdir():continue
            if not 0<=member.size<=16*1024**2:raise ValueError('native npm member exceeds its bound')
            total+=member.size
            if total>128*1024**2:raise ValueError('native npm subtree exceeds its byte bound')
            body=source.extractfile(member).read(member.size+1)
            if len(body)!=member.size:raise ValueError('native npm member is truncated')
            data[name]=(body,bool(member.mode&0o111))
    base='lib/node_modules/npm/'
    file_keys={paths.path_key(name)for name in data}
    if any('/'.join(key.split('/')[:index])in file_keys for key in seen for index in range(1,len(key.split('/')))):raise ValueError('native npm member has an ordinary-file parent')
    if base+'bin/npm-cli.js' not in data or base+'package.json' not in data or base+'LICENSE' not in data:raise ValueError('native npm subtree lacks its CLI, manifest or license')
    manifest=json.loads(data[base+'package.json'][0])
    if manifest.get('name')!='npm' or not isinstance(manifest.get('version'),str) or not manifest['version']:raise ValueError('native npm manifest identity differs')
    records=[]
    for name,(body,executable) in sorted(data.items()):
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(0o555 if executable else 0o444)
        records.append({'path':name,'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body),'executable':executable})
    return {'version':manifest['version'],'provider':{'node_version':version,**item},'files':records}

def copy_git(source, receipt_file, output):
    """Admit only the closed original Git fixture pack, never an ambient tool."""
    receipt=read(receipt_file)
    provider=read(ROOT/'quality/act.lock.json')['linux_runner']['nonroot_image']
    if receipt.get('schema_version')!=1 or receipt.get('qualification')!='private-native-arm-Git-fixture-tool-not-product-runtime' or receipt.get('platform')!='linux/arm64' or receipt.get('provider')!=provider or receipt.get('generator_sha256')!=digest(ROOT/'scripts/quality/prepare-git-runtime.py') or receipt.get('elf_generator_sha256')!=digest(ROOT/'workers/ud/src/ud_agent/elf_runtime.py'):
        raise ValueError('private Git lacks its exact original native provider/producer binding')
    if len(receipt.get('probe',[]))!=6 or any(row.get('status')!=0 for row in receipt['probe']) or not receipt.get('notices') or not receipt.get('packages') or receipt.get('executable')!='bin/git':
        raise ValueError('private Git has no complete original feature/license probe')
    if source.is_symlink() or not source.is_dir() or output.exists(): raise ValueError('private Git needs a new ordinary destination')
    expected=set();total=0
    for row in receipt['files']:
        name=row['path'];parts=name.split('/')
        if name.startswith('/') or '\\'in name or any(part in ('','.','..') or ':'in part for part in parts) or name in expected or type(row['size_bytes'])is not int or not 0<=row['size_bytes']<=128*1024**2 or type(row['mode'])is not int or row['mode']&0o7222:raise ValueError('private Git file inventory is unsafe')
        expected.add(name);file=source/name;total+=row['size_bytes']
        if total>512*1024**2 or len(expected)>10000:raise ValueError('private Git closure exceeds its byte/file bound')
        for parent in file.parents:
            if parent==source:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('private Git parent must be ordinary')
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=row['size_bytes']or stat.S_IMODE(file.stat().st_mode)!=row['mode']or digest(file)!=row['sha256']:raise ValueError('private Git bytes differ from their closed receipt')
        header=file.read_bytes()[:20]
        if header[:4]==b'\x7fELF' and(header[:6]!=b'\x7fELF\x02\x01'or struct.unpack_from('<H',header,18)[0]!=183):raise ValueError('private Git contains a foreign ELF')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(row['mode'])
    if {file.relative_to(source).as_posix()for file in source.rglob('*')if file.is_file()}!=expected or any(file.is_symlink()for file in source.rglob('*')):raise ValueError('private Git closure has unlisted files or links')
    if receipt['loader']not in expected or'bin/git'not in expected or not receipt['libraries']or any('lib/'+name not in expected for name in receipt['libraries'])or any(path not in expected for path in receipt['programs'].values()):raise ValueError('private Git native loader/program closure is incomplete')
    return {'path':'git-input-receipt.json','sha256':digest(receipt_file),'size_bytes':receipt_file.stat().st_size,'version':receipt['version'],'files':len(expected),'provider':provider}

def prepare_python_projection_sdk(wheel, helper, output):
    """Append one fixed SDK binding; retain the exact locked upstream source."""
    if not wheel.name.startswith('mutmut-3.8.1-') or wheel.suffix != '.whl':
        raise ValueError('fixed projection SDK requires the pinned mutmut wheel')
    with zipfile.ZipFile(wheel) as archive:
        selected = [item for item in archive.infolist() if item.filename == 'mutmut/mutation/trampoline.py']
        if len(selected) != 1 or selected[0].is_dir() or not 1 <= selected[0].file_size <= 1024 ** 2:
            raise ValueError('original wheel has no unique bounded trampoline source')
        upstream = archive.read(selected[0])
    helper_sha = digest(helper)
    adapter = ('''\n# Fixed private mutation-SDK context/guard adapter (authored MIT).
def _ud_projection_sdk_bind():
    import hashlib as _hashlib
    import importlib.util as _util
    import os as _os
    from pathlib import Path as _Path
    import stat as _stat
    import sys as _sys
    _exit = _os._exit
    try:
        _file = _Path('/opt/mutation/harness/python-runtime-projection.py')
        _info = _file.lstat()
        if not _stat.S_ISREG(_info.st_mode) or _info.st_uid != 0 or _info.st_nlink != 1 or _info.st_mode & 0o222 or _hashlib.sha256(_file.read_bytes()).hexdigest() != '%s':
            raise RuntimeError('immutable projection SDK helper differs')
        _name = 'ud_python_runtime_projection'
        _helper = _sys.modules.get(_name) if _os.geteuid() == 0 else None
        if _helper is None:
            _spec = _util.spec_from_file_location(_name, _file)
            _helper = _util.module_from_spec(_spec)
            _sys.modules[_name] = _helper
            _spec.loader.exec_module(_helper)
        if _Path(_helper.__file__) != _file or _helper.VERSION != 'ud-python-inert-projection-1':
            raise RuntimeError('shared projection SDK identity differs')
        _helper.install_guard(_sys.modules[__name__], context_required=True)
    except BaseException:
        _exit(125)
_ud_projection_sdk_bind()
del _ud_projection_sdk_bind
''' % helper_sha).encode()
    derived = upstream + adapter
    names = [('upstream_source', 'python-trampoline-upstream.py', upstream),
             ('adapter_source', 'python-trampoline-adapter.py', adapter),
             ('derived_source', 'python-trampoline-derived.py', derived)]
    receipt = {'schema_version': 1, 'version': 'ud-python-inert-projection-1', 'helper_sha256': helper_sha,
               'distribution': 'mutmut', 'distribution_version': '3.8.1',
               'original_wheel': {'filename': wheel.name, 'sha256': digest(wheel), 'size_bytes': wheel.stat().st_size},
               'installed_path': 'python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py'}
    for field, name, data in names:
        (output / name).write_bytes(data)
        receipt[field] = {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}
    return receipt


def copy_pytest_evidence(root, harness):
    """The grader uses the exact original, never its mutable candidate copy."""
    source = root / 'tests/mutation/pytest_evidence.py'
    if source.is_symlink() or not source.is_file():
        raise ValueError('original pytest evidence source is not an ordinary file')
    shutil.copyfile(source, harness / 'pytest_evidence.py')


def copy_private_perl(source, output):
    """Keep the existing private-Perl path on a plain, pinned CI base image."""
    receipt=read(source.parent/(source.name+'-receipt.json'))
    if receipt.get('platform')!='linux/arm64' or receipt.get('probe',{}).get('status')!='passed' or receipt['probe'].get('ambient_modules')is not False or receipt['probe'].get('ambient_elf')is not False or not receipt.get('loader'):
        raise ValueError('closed native private Perl is required for the CI base')
    output.mkdir();seen=set()
    for row in receipt['files']:
        name=row['path']
        if name.startswith('/')or any(value in name for value in('\\','\0',':'))or any(part in('','.','..')for part in name.split('/'))or name in seen:raise ValueError('unsafe private Perl file')
        seen.add(name);file=source/name
        if file.is_symlink()or not file.is_file()or file.stat().st_size!=row['size']or digest(file)!=row['sha256'].removeprefix('sha256:'):raise ValueError('private Perl differs from its actual closed receipt')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o555 if file.stat().st_mode&0o111 else 0o444)
    if any(file.is_symlink()for file in source.rglob('*'))or {file.relative_to(source).as_posix()for file in source.rglob('*')if file.is_file()}!=seen:raise ValueError('private Perl has unlisted bytes or links')
    runtime={key:receipt[key]for key in('executable','library_dirs','loader')}
    def relative(value):
        if not isinstance(value,str)or value.startswith('/')or any(character in value for character in('\\','\0',':'))or any(part in('','.','..')for part in value.split('/')):raise ValueError('private Perl runtime path escapes its closed pack')
        return value
    loader=runtime['loader']
    if runtime['executable']!='bin/perl' or not isinstance(loader,dict)or set(loader)!={'executable','library_dirs'}or relative(loader['executable'])not in seen or not isinstance(runtime['library_dirs'],list)or not runtime['library_dirs']or not isinstance(loader['library_dirs'],list)or not loader['library_dirs']:raise ValueError('private Perl executable or loader binding is invalid')
    for name in [*runtime['library_dirs'],*loader['library_dirs']]:
        if not(source/relative(name)).is_dir()or(source/name).is_symlink():raise ValueError('private Perl runtime library directory is absent or aliased')
    (output/'runtime.json').write_text(json.dumps(runtime,sort_keys=True)+'\n')
    (output/'runtime.json').chmod(0o444)
    return {'receipt_sha256':digest(source.parent/(source.name+'-receipt.json')),'files':len(seen)}


CONTEXT_TREES={'private-perl':'opt/ud-agent/perl','upstream':'opt/ud-agent/upstream','uv':'opt/mutation/bin',
               'wheels':'opt/mutation/wheels','node':'opt/mutation/node','node_modules':'opt/mutation/node_modules',
               'perl-parser':'opt/mutation/perl-parser','rust':'opt/mutation/rust','harness':'opt/mutation/harness'}
CONTEXT_FILES=('python.tar.gz','requirements.txt','node-dependencies.json','target-packages.json','node-installation-receipt.json',
               'node-upstream-dependencies.json','node-assertion-sdk.json','node-assertion-sdk-upstream.js',
               'node-assertion-sdk-serializer-upstream.js','node-assertion-sdk-chai-upstream.js','rust-input-receipt.json',
               'input-receipt.json','python-trampoline-upstream.py','python-trampoline-adapter.py','python-trampoline-derived.py')


def compact_context(output, *, with_git):
    """Pack the private verified context once, retaining no expanded build input."""
    trees={**CONTEXT_TREES,**({'git':'opt/mutation/git'} if with_git else {})}
    files={name:'opt/mutation/'+name for name in (*CONTEXT_FILES,*(('git-input-receipt.json',) if with_git else ()))}
    files['native-guard']='opt/mutation/bin/ud-agent-guard'
    entries={**trees,**files};archive=output/'sdk-inputs.tar.xz'
    if output.is_symlink() or not output.is_dir() or {file.name for file in output.iterdir()}!=set(entries):
        raise ValueError('SDK compact context has missing, aliased or unlisted inputs')
    for name in entries:
        source=output/name
        if source.is_symlink() or not (source.is_dir() if name in trees else source.is_file()):
            raise ValueError('SDK compact context root must be ordinary')
    seen=set();entry_bytes={name:0 for name in entries}
    def header(member):
        name=member.name;parts=name.split('/')
        if name.startswith('/') or '\\' in name or any(part in ('','.','..') for part in parts) or name in seen or not (member.isfile() or member.isdir() or member.issym()):
            raise ValueError('SDK compact payload contains an unsafe member')
        seen.add(name)
        if member.issym():
            target=posixpath.normpath(posixpath.join(posixpath.dirname(name),member.linkname))
            enclosing=next((value for value in trees.values() if name.startswith(value+'/')),None)
            if member.linkname.startswith('/') or '\\' in member.linkname or enclosing is None or not target.startswith(enclosing+'/'):
                raise ValueError('SDK compact payload link escapes its verified closure')
        if member.isfile():entry_bytes[entry_name]+=member.size
        member.uid=member.gid=0;member.uname=member.gname=''
        return member
    try:
        # This exact payload exists both here and in BuildKit's input snapshot.
        # Compress the transport without pruning any runtime or toolchain bytes.
        with tarfile.open(archive,'x:xz',preset=6,dereference=False) as packed:
            for entry_name,destination in sorted(entries.items()):packed.add(output/entry_name,arcname=destination,filter=header)
        archive.chmod(0o444)
        payload={'path':archive.name,'sha256':digest(archive),'size_bytes':archive.stat().st_size,
                 'input_bytes':sum(entry_bytes.values()),'entry_bytes':entry_bytes}
    except BaseException:
        if archive.exists():archive.chmod(0o600);archive.unlink()
        raise
    def remove_readonly(function,name,error):
        if os.name!='nt' or not isinstance(error,PermissionError):raise error
        os.chmod(name,stat.S_IWRITE);function(name)
    for name in entries:
        if name=='input-receipt.json':continue
        source=output/name
        if source.is_dir():shutil.rmtree(source,onexc=remove_readonly)
        else:
            if os.name=='nt':source.chmod(0o600)
            source.unlink()
    return payload


def runtime_containerfile(base, projection_sdk, git, payload):
    # A read-only compressed bind input avoids an expanded BuildKit context,
    # archive COPY layer, deleted wheel layers and later metadata copy-up.
    return f'''FROM {base}
USER 0:0
RUN --mount=type=bind,source={payload['path']},target=/sdk-inputs.tar.xz,readonly python3 -c 'import hashlib,tarfile; p="/sdk-inputs.tar.xz"; assert hashlib.file_digest(open(p,"rb"),"sha256").hexdigest()=="{payload['sha256']}"; tarfile.open(p,"r:xz").extractall("/",filter=lambda m,d:tarfile.data_filter(m,d).replace(mode=m.mode & 0o777))' && python3 -c 'import tarfile;tarfile.open("/opt/mutation/python.tar.gz").extractall("/opt/mutation",filter="data")' && rm /opt/mutation/python.tar.gz && /opt/mutation/bin/uv pip install --no-cache --system --python /opt/mutation/python/bin/python3 --no-index --no-deps --require-hashes --find-links=/opt/mutation/wheels -r /opt/mutation/requirements.txt && /opt/mutation/python/bin/python3 -c 'import site,pathlib;pathlib.Path(site.getsitepackages()[0],"udtools.pth").write_text("/opt/ud-agent/upstream/udtools/src\\n")' && rm -rf /opt/mutation/wheels && /opt/mutation/python/bin/python3 -I -B -c 'import hashlib,pathlib; p=pathlib.Path("/opt/mutation/{projection_sdk['installed_path']}"); assert hashlib.sha256(p.read_bytes()).hexdigest()=="{projection_sdk['upstream_source']['sha256']}"; p.write_bytes(pathlib.Path("/opt/mutation/python-trampoline-derived.py").read_bytes())' && cp /opt/mutation/harness/perl-test-runtime.py /opt/mutation/bin/perl && {('cp /opt/mutation/git/bin/git /opt/mutation/bin/git && /opt/mutation/bin/git --version && ')if git else ''}chmod 555 /opt/mutation/bin/perl /opt/mutation/bin/ud-agent-guard && /opt/mutation/bin/uv --version && /opt/mutation/python/bin/python3 --version && /opt/mutation/node/bin/node --version && /opt/mutation/node/bin/node /opt/mutation/node/lib/node_modules/npm/bin/npm-cli.js --version && /opt/mutation/rust/bin/rustc --version && /opt/mutation/rust/bin/cargo-mutants mutants --version && /opt/mutation/node/bin/node -e 'require("/opt/mutation/node_modules/@rolldown/binding-linux-arm64-gnu");require("/opt/mutation/node_modules/lightningcss-linux-arm64-gnu")' && /opt/mutation/node/bin/node --input-type=module -e 'await import("/opt/mutation/node_modules/vitest/dist/node.js")' && find /opt/mutation \\( -type f -o -type d \\) -perm /222 -exec chmod a-w {{}} +
ENV PATH=/opt/mutation/bin:/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin PYTHONPATH=/opt/ud-agent/upstream/udtools/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["/opt/mutation/python/bin/python3", "/opt/mutation/harness/oci-mutation.py"]
'''


def prepare(output,download,rust_assets=None,git_assets=None,*,asset_root=None,base_image=None):
    output=output.resolve()
    if output.exists():raise ValueError('mutation context must be new')
    assets=Path(asset_root).resolve()if asset_root is not None else ROOT/'.artifacts'
    output.mkdir(parents=True);cache=assets/'mutation-input-cache';cache.mkdir(parents=True,exist_ok=True)
    lock=tomllib.loads((ROOT/'uv.lock').read_text());packages={item['name']:item for item in lock['package']};pending=['mutmut','pytest','regex','udapi'];selected=set()
    while pending:
        name=pending.pop()
        if name in selected:continue
        selected.add(name);pending.extend(item['name']for item in packages[name].get('dependencies',[]))
    wheels=output/'wheels';wheels.mkdir();requirements=[];receipts=[]
    for name in sorted(selected):
        item=packages[name];available=[wheel for wheel in item['wheels']if 'none-any.whl'in wheel['url']or('cp314-cp314-'in wheel['url']and'aarch64'in wheel['url']and'manylinux'in wheel['url'])]
        if not available:raise ValueError('no compatible locked ARM64 Python3.14 mutation wheel: '+name)
        # PyYAML/Coverage may publish two equivalent manylinux tag aliases;
        # choose one fixed URL order and preserve its exact upstream hash.
        wheel=sorted(available,key=lambda value:value['url'])[0];source=acquire(wheel,cache,download);filename=wheel['url'].rsplit('/',1)[-1];shutil.copyfile(source,wheels/filename);requirements.append(f'{name}=={item["version"]} --hash={wheel["hash"]}');receipts.append({'name':name,'version':item['version'],**wheel})
    (output/'requirements.txt').write_text('\n'.join(requirements)+'\n')
    userspace=read(ROOT/'runtime/userspace-inputs.lock.json')
    python=userspace['platforms']['linux/arm64']['python_download'];shutil.copyfile(acquire(python,cache,download),output/'python.tar.gz')
    uv_archive=userspace['platforms']['linux/arm64']['uv_archive']
    uv=copy_uv(acquire(uv_archive,cache,download),uv_archive,userspace['uv_version'],output/'uv')
    spec=importlib.util.spec_from_file_location('ud_mutation_node_extract',ROOT/'scripts/release/extract-node.py');extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)
    node=read(ROOT/'runtime/node-distributions.lock.json');item=node['platforms']['linux-arm64'];extract.extract(assets/'node'/item['filename'],output/'node','linux-arm64',node['version'],item['sha256'])
    npm=copy_node_npm(assets/'node'/item['filename'],item,node['version'],output/'node')
    modules=assets/'mutation-node-linux-arm64-v4'
    if digest(modules/'package-lock.json')!=digest(ROOT/'package-lock.json'):raise ValueError('Linux development Node dependencies are stale')
    installation=read(modules/'installation-receipt.json')
    if installation.get('qualification')!='locked-native-sdk-data-preparation-no-lifecycle-execution'or installation.get('target')!={'os':'linux','cpu':'arm64','libc':'glibc'}or installation.get('inputs',{}).get('package-lock.json')!=digest(ROOT/'package-lock.json'):
        raise ValueError('Linux SDK installation provenance is missing or stale')
    shutil.copytree(modules/'node_modules',output/'node_modules',symlinks=True)
    target_script='import{readFileSync,writeFileSync}from"node:fs";import{validateNodeTargetPackages}from"./scripts/quality/node-dependencies.mjs";const result=validateNodeTargetPackages(process.argv[1],JSON.parse(readFileSync("package-lock.json")),{os:"linux",cpu:"arm64",libc:"glibc"});writeFileSync(process.argv[2],JSON.stringify(result)+"\\n",{flag:"wx"});'
    sdk_node_command([shutil.which('node'),'--input-type=module','-e',target_script,str(output/'node_modules'),str(output/'target-packages.json')],cwd=ROOT,timeout=120)
    sdk_node_command([shutil.which('node'),str(ROOT/'scripts/quality/node-dependencies.mjs'),str(output/'node_modules'),str(output/'node-dependencies.json')],timeout=120)
    closure=read(output/'node-dependencies.json')
    canonical_closure=(json.dumps(closure,separators=(',',':'),ensure_ascii=False)+'\n').encode()
    if hashlib.sha256(canonical_closure).hexdigest()!=installation.get('closure',{}).get('sha256'):
        raise ValueError('Linux SDK bytes differ from their actual locked installation')
    shutil.copyfile(modules/'installation-receipt.json',output/'node-installation-receipt.json')
    # Retain the verified upstream closure separately from the exact, replayable
    # assertion instrumentation of this new private quality SDK. Shared host
    # node_modules and original npm integrity receipts remain unchanged.
    (output/'node-dependencies.json').rename(output/'node-upstream-dependencies.json')
    sdk_node_command([shutil.which('node'),str(ROOT/'scripts/quality/stryker-assertion-sdk.mjs'),str(output)],timeout=30)
    sdk_node_command([shutil.which('node'),str(ROOT/'scripts/quality/node-dependencies.mjs'),str(output/'node_modules'),str(output/'node-dependencies.json')],timeout=120)
    assertion_sdk={key:{'path':name,'sha256':digest(output/name),'size_bytes':(output/name).stat().st_size} for key,name in [('receipt','node-assertion-sdk.json'),('upstream_source','node-assertion-sdk-upstream.js'),('serializer_upstream_source','node-assertion-sdk-serializer-upstream.js'),('chai_upstream_source','node-assertion-sdk-chai-upstream.js'),('upstream_dependencies','node-upstream-dependencies.json')]}
    node_dependencies={'path':'node-dependencies.json','sha256':digest(output/'node-dependencies.json'),'size_bytes':(output/'node-dependencies.json').stat().st_size}
    parser=copy_parser(assets/'perl-mutation/parser-linux-arm64',output/'perl-parser')
    rust_assets=(Path(rust_assets)if rust_assets is not None else assets/'mutation-rust-assets').resolve(strict=True)
    rust_receipt=rust_assets/'rust-input-receipt.json'
    rust=copy_rust(rust_assets/'export',rust_receipt,output/'rust')
    shutil.copyfile(rust_receipt,output/'rust-input-receipt.json')
    git=None
    if git_assets is not None:
        git_assets=Path(git_assets).resolve(strict=True)
        git=copy_git(git_assets/'linux-arm64',git_assets/'linux-arm64-receipt.json',output/'git')
        shutil.copyfile(git_assets/'linux-arm64-receipt.json',output/'git-input-receipt.json')
    harness=output/'harness';harness.mkdir()
    for name in HARNESS_NAMES:
        if name=='pytest_evidence.py':continue
        shutil.copyfile(ROOT/'scripts/quality'/name,harness/name)
    copy_pytest_evidence(ROOT, harness)
    (harness/'rust-test-runtime.py').chmod(0o755)
    mutmut_wheels = sorted((output/'wheels').glob('mutmut-3.8.1-*.whl'))
    if len(mutmut_wheels) != 1:raise ValueError('exact original mutmut wheel required for fixed SDK adapter')
    projection_sdk = prepare_python_projection_sdk(mutmut_wheels[0], harness/'python-runtime-projection.py', output)
    cross_file=assets/'cross-build-receipt.json';cross=read(cross_file);native=cross['platforms']['linux-arm64']['ud-agent-guard'];guard=Path(native['path'])
    if not guard.is_absolute():guard=(assets if cross.get('qualification')=='native-original-guard-build-not-cross-build' else ROOT)/guard
    header=guard.read_bytes()[:64]
    if digest(guard)!=native['sha256']or header[:6]!=b'\x7fELF\x02\x01'or struct.unpack_from('<H',header,18)[0]!=183:
        raise ValueError('mutation native guard differs from its ARM64 cross-build receipt')
    shutil.copyfile(guard,output/'native-guard')
    native_guard={'path':'bin/ud-agent-guard','sha256':native['sha256'],'size_bytes':guard.stat().st_size,'architecture':'arm64','cross_receipt_sha256':digest(cross_file)}
    base=base_image or read(ROOT/'quality/mutation-runtime-bootstrap.lock.json')['provider']
    if base!=read(ROOT/'quality/mutation-runtime-bootstrap.lock.json')['provider']:raise ValueError('CI base differs from the exact locked native ARM provider')
    private_perl=copy_private_perl(assets/'native-perl/linux-arm64-source',output/'private-perl')
    shutil.copytree(assets/'upstream',output/'upstream')
    receipt={'schema_version':1,'qualification':'development-mutation-runner','platform':'linux/arm64','base':base,'python':python,'uv':uv,'node':{'version':node['version'],**item,'npm':npm},'native_guard':native_guard,'node_dependencies':node_dependencies,'node_target_packages':{'path':'target-packages.json','sha256':digest(output/'target-packages.json'),'size_bytes':(output/'target-packages.json').stat().st_size},'node_installation':{'path':'node-installation-receipt.json','sha256':digest(output/'node-installation-receipt.json'),'size_bytes':(output/'node-installation-receipt.json').stat().st_size},'python_packages':receipts,'perl_parser':parser,'rust':rust,'package_lock_sha256':digest(ROOT/'package-lock.json'),'harness':[{'path':file.name,'sha256':digest(file)}for file in sorted(harness.iterdir())]}
    receipt['node_assertion_sdk']=assertion_sdk
    receipt['python_runtime_projection']=projection_sdk
    receipt['private_perl']=private_perl
    if git is not None:receipt['git']=git
    (output/'input-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    payload=compact_context(output,with_git=git is not None)
    (output/'Containerfile').write_text(runtime_containerfile(base,projection_sdk,git,payload))
    print('SDK compact payload: '+json.dumps({'compression':'xz','preset':6,'archive_bytes':payload['size_bytes'],
          'input_bytes':payload['input_bytes'],'entry_bytes':payload['entry_bytes']},sort_keys=True),flush=True)
    return receipt

def read(path):return json.loads(path.read_text())

def watch_sdk_supervisor(parent_pid):
    """A hard-killed supervisor must not leave its SDK worker running."""
    def watch():
        while os.getppid()==parent_pid:time.sleep(0.25)
        os.kill(os.getpid(),signal.SIGTERM)
    thread=threading.Thread(target=watch,daemon=True);thread.start()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);parser.add_argument('--download',action='store_true');parser.add_argument('--rust-assets',type=Path,help='verified isolated RustSDK export/receipt root');parser.add_argument('--git-assets',type=Path,help='closed pinned native Git fixture pack/receipt root');parser.add_argument('--asset-root',type=Path);parser.add_argument('--base-image');parser.add_argument('--ci-cache-key',action='store_true');parser.add_argument('--ensure-ci',action='store_true');parser.add_argument('--load-ci-image',action='store_true');parser.add_argument('--ensure-ci-provider',action='store_true',help=argparse.SUPPRESS);parser.add_argument('--sdk-storage-worker',action='store_true',help=argparse.SUPPRESS);parser.add_argument('--transient-bytes',type=int,help='explicit CI supervisor transient allowance, at most 12000000000 bytes');args=parser.parse_args()
    if args.transient_bytes is not None:
        if not 0<args.transient_bytes<=12_000_000_000:parser.error('--transient-bytes must be positive and at most 12000000000')
        if args.ci_cache_key or args.sdk_storage_worker or sum((args.ensure_ci,args.load_ci_image,args.ensure_ci_provider))!=1:
            parser.error('--transient-bytes requires one outer CI supervisor operation')
    if args.ci_cache_key or args.ensure_ci or args.load_ci_image or args.ensure_ci_provider:
        spec=importlib.util.spec_from_file_location('ud_mutation_ci_bootstrap',ROOT/'scripts/quality/mutation-runtime-bootstrap.py');ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(ci)
        if sum((args.ci_cache_key,args.ensure_ci,args.load_ci_image,args.ensure_ci_provider))!=1:parser.error('select exactly one CI preparation operation')
        if args.ci_cache_key:print(ci.cache_key(ROOT));return
        if args.asset_root is None:parser.error('--asset-root is required')
        if args.ensure_ci and args.output is None:parser.error('--output is required')
        if not args.sdk_storage_worker:
            node=shutil.which('node')
            if not node:parser.error('Node is required to supervise CI SDK storage')
            mode='load' if args.load_ci_image else 'provider' if args.ensure_ci_provider else 'ensure'
            command=[node,str(ROOT/'scripts/quality/mutation-sdk-storage.mjs'),mode,sys.executable,str(args.asset_root.resolve()),str(args.output.resolve()) if args.output else '',str(args.download).lower(),args.base_image or '']
            if args.transient_bytes is not None:command.extend(['--transient-bytes',str(args.transient_bytes)])
            raise SystemExit(subprocess.run(command,cwd=ROOT).returncode)
        if not os.environ.get('UD_STORAGE_LEASE'):parser.error('SDK storage worker requires its supervising reservation')
        def interrupted(signum, _frame):
            raise InterruptedError('SDK storage supervisor stopped the worker (signal ' + str(signum) + ')')
        for name in ('SIGINT', 'SIGTERM'):
            if hasattr(signal,name):signal.signal(getattr(signal,name),interrupted)
        watch_sdk_supervisor(os.getppid())
        if args.load_ci_image:print(json.dumps(ci.load_image(ROOT,args.asset_root)));return
        if args.ensure_ci_provider:print(json.dumps(ci.prepare_provider(ROOT,args.asset_root,args.download,args.base_image)));return
        print(json.dumps(ci.ensure(ROOT,args.asset_root,args.output,args.download,args.base_image)));return
    if args.output is None:parser.error('--output is required')
    result=prepare(args.output,args.download,args.rust_assets,args.git_assets,asset_root=args.asset_root,base_image=args.base_image);print(json.dumps({'platform':result['platform'],'python_packages':len(result['python_packages'])}))
if __name__=='__main__':main()
