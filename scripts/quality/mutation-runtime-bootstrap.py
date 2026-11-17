"""Fixed native ARM CI bootstrap for the existing private mutation SDK.

Cold setup builds original locked tools; it never executes generated variants.
The bounded gate uses the resulting immutable image and remains a separate job.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[2]
LOCK = 'quality/mutation-runtime-bootstrap.lock.json'
SDK_LOG_LIMIT = 16 * 1024**2
RECIPES = ['scripts/quality/mutation-runtime-bootstrap.py', 'scripts/quality/prepare-mutation-runtime.py',
           'scripts/quality/prepare-mutation-node.mjs', 'scripts/quality/prepare-linux-perl-parser.py',
           'scripts/quality/prepare-perl-parser.py', 'scripts/quality/prepare-git-runtime.py',
           'scripts/runtime/prepare-native-perl.py', 'scripts/runtime/close-linux-elf.py',
           'scripts/runtime/elf_dependencies.py', 'workers/ud/src/ud_agent/elf_runtime.py',
           'scripts/runtime/perl_build.py', 'scripts/runtime/prepare-core-build.py',
           'scripts/runtime/private_perl.py', 'workers/ud/src/ud_agent/unicode_paths.py',
           'scripts/release/extract-node.py', 'scripts/quality/node-dependencies.mjs',
           'scripts/quality/stryker-assertion-sdk.mjs']
LOCKS = [LOCK, 'quality/act.lock.json', 'quality/perl-parser.lock.json', 'runtime/native-perl-source.lock.json',
         'runtime/native-perl-modules.lock.json', 'runtime/perl-deps.lock.json', 'runtime/ud-sources.lock.json',
         'runtime/userspace-inputs.lock.json', 'runtime/node-distributions.lock.json', 'package.json', 'package-lock.json',
         'uv.lock', 'Cargo.toml', 'Cargo.lock', 'packages/launcher/Cargo.toml',
         'scripts/quality/rust-assertion-parser/Cargo.toml', 'scripts/quality/rust-assertion-parser/Cargo.lock']


def sha(file):
    if file.is_symlink() or not file.is_file(): raise ValueError('ordinary SDK input required: ' + str(file))
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def read(file):
    if file.is_symlink() or not file.is_file() or file.stat().st_nlink != 1 or file.stat().st_size > 16 * 1024**2:
        raise ValueError('bounded ordinary SDK receipt required')
    return json.loads(file.read_text())


def module(name):
    spec = importlib.util.spec_from_file_location('ud_ci_' + name.replace('-', '_'), ROOT / name)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def input_rows(root, include_harness=True):
    paths = set(RECIPES + LOCKS)
    for folder in ['packages/launcher/src', 'scripts/quality/rust-assertion-parser/src']:
        paths.update(file.relative_to(root).as_posix() for file in (root / folder).rglob('*.rs'))
    if include_harness:
        producer = module('scripts/quality/prepare-mutation-runtime.py')
        paths.update(('tests/mutation/' if name == 'pytest_evidence.py' else 'scripts/quality/') + name for name in producer.HARNESS_NAMES)
    return [{'path': name, 'sha256': sha(root / name)} for name in sorted(paths)]


def cache_key(root, include_harness=True):
    return hashlib.sha256(canonical({'schema_version': 1, 'platform': 'linux/arm64', 'inputs': input_rows(root, include_harness)})).hexdigest()


def checked(command, *, cwd=None, env=None, timeout=120, log=None, stdout=None, gzip_stdout=False):
    """Collect bounded output while the original SDK tool is running.

    A completed build can emit a lot of output, and buffering it with
    ``subprocess.run`` also made repeated bootstrap logs grow without limit.
    Stop the command as soon as either bound is reached; do not truncate a
    failed build and then mistake it for evidence of a successful one.
    """
    if gzip_stdout and stdout is None: raise ValueError('compressed SDK output needs a held destination')
    limit = SDK_LOG_LIMIT
    target = None
    if log is not None:
        if log.is_symlink() or log.exists() and (not log.is_file() or log.stat().st_size > limit):
            raise ValueError('SDK bootstrap log is not an ordinary bounded file')
        target = log.open('ab')
    data = bytearray()
    process = None
    readers = []
    compressed = None
    stop_reader = threading.Event()
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE if stdout is None or gzip_stdout else stdout,
                                   stderr=subprocess.STDOUT if stdout is None else subprocess.PIPE)
        captured = process.stdout if stdout is None else process.stderr
        deadline = time.monotonic() + timeout
        chunks = queue.Queue(maxsize=2)
        if gzip_stdout: compressed = gzip.GzipFile(filename='', mode='wb', compresslevel=1, fileobj=stdout, mtime=0)
        def read_output(stream, kind):
            try:
                while not stop_reader.is_set():
                    chunk = os.read(stream.fileno(), 65536)
                    while not stop_reader.is_set():
                        try: chunks.put((kind, chunk), timeout=0.1); break
                        except queue.Full: pass
                    if not chunk: return
            except (OSError, ValueError) as error:
                while not stop_reader.is_set():
                    try: chunks.put((kind, error), timeout=0.1); break
                    except queue.Full: pass
        streams = [(captured, 'diagnostic')]
        if gzip_stdout: streams.append((process.stdout, 'archive'))
        for stream, kind in streams:
            reader = threading.Thread(target=read_output, args=(stream, kind), daemon=True); reader.start(); readers.append(reader)
        pending = len(streams)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise subprocess.TimeoutExpired(command, timeout)
            try: kind, chunk = chunks.get(timeout=remaining)
            except queue.Empty: raise subprocess.TimeoutExpired(command, timeout) from None
            if isinstance(chunk, BaseException): raise chunk
            if not chunk: pending -= 1; continue
            if kind == 'archive': compressed.write(chunk); continue
            if len(data) + len(chunk) > limit or target is not None and target.tell() + len(chunk) > limit:
                raise ValueError('SDK original command output exceeds its bounded log')
            data.extend(chunk)
            if target is not None: target.write(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise subprocess.TimeoutExpired(command, timeout)
        result = process.wait(timeout=remaining)
        if result: raise ValueError('SDK original command failed: ' + repr(command) + '\n' + bytes(data[-4000:]).decode(errors='replace'))
        if compressed is not None: compressed.close(); compressed = None
        return bytes(data)
    finally:
        stop_reader.set()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None: process.stdout.close()
            if process.stderr is not None: process.stderr.close()
        for reader in readers: reader.join(timeout=1)
        if compressed is not None: compressed.close()
        if target is not None: target.close()


def acquire(record, target, download, limit=128 * 1024**2):
    """Only an existing lock's original bytes may enter the acquisition cache."""
    expected = record.get('sha256', record.get('hash', '')).removeprefix('sha256:')
    size = record.get('size_bytes', record.get('size'))
    if not re.fullmatch('[a-f0-9]{64}', expected) or not record.get('url', '').startswith('https://') or size is not None and (type(size) is not int or not 0 <= size <= limit):
        raise ValueError('bounded exact HTTPS SDK input required')
    if not target.exists():
        if not download: raise ValueError('offline SDK input is absent: ' + str(target))
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name('.' + target.name + '.' + uuid.uuid4().hex + '.tmp')
        try:
            with urlopen(record['url'], timeout=60) as source, temporary.open('xb') as output:
                total = 0
                while chunk := source.read(1024**2):
                    total += len(chunk)
                    if total > (size if size is not None else limit): raise ValueError('locked SDK download exceeds its bound')
                    output.write(chunk)
            if size is not None and total != size or sha(temporary) != expected:
                raise ValueError('SDK acquisition differs from its locked original: ' + str(target))
            try: os.link(temporary, target)
            except FileExistsError: pass  # A concurrent verified download won.
        finally:
            temporary.unlink(missing_ok=True)
    if target.is_symlink() or target.stat().st_size > limit or size is not None and target.stat().st_size != size or sha(target) != expected:
        raise ValueError('SDK acquisition differs from its locked original: ' + str(target))
    return target


def ordinary_input_parents(base, file):
    if not file.is_relative_to(base) or file == base: raise ValueError('SDK input escapes its owned directory')
    for parent in file.parents:
        if parent.is_symlink() or not parent.is_dir(): raise ValueError('SDK input parent is aliased or absent')
        if parent == base: break


def retained_rust_ready(root, assets):
    """A completed, byte-verified closure can replace its consumed installers."""
    marker = assets / 'native-inputs.json'
    if not marker.exists() and not marker.is_symlink(): return False
    completed = read(marker); lock = read(root / LOCK)
    receipt_file = assets / 'mutation-rust-assets/rust-input-receipt.json'
    ordinary_input_parents(assets, receipt_file)
    if (completed.get('qualification') != 'original-locked-native-SDK-input-build-no-generated-variants'
            or completed.get('dependency_key') != cache_key(root, False) or completed.get('provider') != lock['provider']
            or completed.get('rust_receipt_sha256') != sha(receipt_file)):
        raise ValueError('retained native SDK completion binding differs')
    receipt = read(receipt_file); export = assets / 'mutation-rust-assets/export'
    if receipt.get('platform') != 'linux/arm64' or not receipt.get('files') or export.is_symlink() or not export.is_dir():
        raise ValueError('retained Rust closure is incomplete')
    seen = set()
    for row in receipt['files']:
        name = row.get('path', '')
        if not name or name.startswith('/') or any(value in name for value in ('\\', '\0', ':')) or any(part in ('', '.', '..') for part in name.split('/')) or name in seen:
            raise ValueError('retained Rust closure has unsafe paths')
        seen.add(name); file = export / name
        ordinary_input_parents(assets, file)
        if any(parent.is_symlink() for parent in file.parents if parent.is_relative_to(export)) or file.is_symlink() or not file.is_file() or file.stat().st_nlink != 1 or file.stat().st_size != row.get('size') or sha(file) != row.get('sha256'):
            raise ValueError('retained Rust closure differs from its receipt')
    if any(file.is_symlink() for file in export.rglob('*')) or {file.relative_to(export).as_posix() for file in export.rglob('*') if file.is_file()} != seen:
        raise ValueError('retained Rust closure has unlisted inputs')
    return True


def rust_archive_inputs(lock, assets):
    return [(item, assets / 'mutation-rust-assets/downloads' / item['url'].rsplit('/', 1)[1], limit)
            for records, limit in ((lock['rust']['toolchain_archives'], 256 * 1024**2),
                                   ([lock['rust']['cargo_mutants'], *lock['rust']['crates']], 32 * 1024**2)) for item in records]


def acquire_rust_inputs(root, assets, download, lock):
    if not retained_rust_ready(root, assets):
        for item, target, limit in rust_archive_inputs(lock, assets): acquire(item, target, download, limit)


def acquire_inputs(root, assets, download):
    lock = read(root / LOCK)
    node = lock['node']; acquire(node, assets / 'node' / node['filename'], download, 256 * 1024**2)
    acquire_rust_inputs(root, assets, download, lock)
    perl = read(root / 'runtime/native-perl-source.lock.json')
    acquire(perl, assets / 'native-perl/cache' / (perl['name'] + '.tar.gz'), download, 64 * 1024**2)
    for filename in ['runtime/native-perl-modules.lock.json', 'quality/perl-parser.lock.json']:
        for item in read(root / filename)['releases'].values():
            acquire(item, assets / 'perl-mutation/cache' / (item['sha256'] + '.tar.gz'), download, 64 * 1024**2)
    interset = read(root / 'runtime/perl-deps.lock.json')['interset']
    acquire({'url': 'https://codeload.github.com/dan-zeman/interset/tar.gz/' + interset['commit'], 'sha256': interset['archive_sha256'], 'size_bytes': interset['archive_size']}, assets / 'perl-sources' / interset['archive'], download, 64 * 1024**2)
    tools = next(row for row in read(root / 'runtime/ud-sources.lock.json')['sources'] if row['repository'] == 'UniversalDependencies/tools')
    acquire({'url': 'https://codeload.github.com/UniversalDependencies/tools/tar.gz/' + tools['commit'], 'sha256': tools['archive_sha256']}, assets / 'sources' / ('tools-' + tools['commit'] + '.tar.gz'), download, 128 * 1024**2)
    userspace = read(root / 'runtime/userspace-inputs.lock.json')['platforms']['linux/arm64']
    for item in [userspace['python_download'], userspace['uv_archive']]:
        acquire(item, assets / 'mutation-input-cache' / item['sha256'].removeprefix('sha256:'), download, 128 * 1024**2)
    packages = {item['name']: item for item in tomllib.loads((root / 'uv.lock').read_text())['package']}
    pending, selected = ['mutmut', 'pytest', 'regex', 'udapi'], set()
    while pending:
        name = pending.pop()
        if name in selected: continue
        selected.add(name); pending.extend(item['name'] for item in packages[name].get('dependencies', []))
    for name in sorted(selected):
        wheels = [item for item in packages[name]['wheels'] if 'none-any.whl' in item['url'] or 'cp314-cp314-' in item['url'] and 'aarch64' in item['url'] and 'manylinux' in item['url']]
        if not wheels: raise ValueError('missing locked native SDK wheel: ' + name)
        item = sorted(wheels, key=lambda row: row['url'])[0]
        acquire(item, assets / 'mutation-input-cache' / item['hash'].removeprefix('sha256:'), download, 128 * 1024**2)


def extract(archive, output, prefix):
    """The same bounded ordinary crate layout used by the retained recipe."""
    output.mkdir(parents=True)
    seen, total = set(), 0
    with tarfile.open(archive, 'r:*') as source:
        for item in source:
            if item.name.rstrip('/') == prefix and item.isdir(): continue
            if not item.name.startswith(prefix + '/'): raise ValueError('SDK archive has a different root')
            name = item.name[len(prefix) + 1:]
            if not name or name.startswith('/') or any(value in name for value in ('\\', '\0', ':')) or any(part in ('', '.', '..') for part in name.split('/')) or name in seen or len(seen) >= 100000:
                raise ValueError('unsafe or duplicate SDK source member')
            seen.add(name); target = output / name
            if item.isdir(): target.mkdir(parents=True, exist_ok=True); continue
            if not item.isfile() or not 0 <= item.size <= 32 * 1024**2: raise ValueError('SDK source member is linked, special or oversized')
            total += item.size
            if total > 512 * 1024**2: raise ValueError('SDK source archive is oversized')
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.extractfile(item).read(item.size + 1)
            if len(data) != item.size: raise ValueError('SDK source member is truncated')
            target.write_bytes(data); target.chmod(0o755 if item.mode & 0o111 else 0o644)


def node_profile_ready(profile):
    """Do not silently treat an interrupted Node profile as complete."""
    if not profile.exists() and not profile.is_symlink(): return False
    if profile.is_symlink() or not profile.is_dir(): raise ValueError('Node SDK profile is not an ordinary owned directory')
    if (profile / 'INCOMPLETE').exists() or not (profile / 'installation-receipt.json').is_file():
        raise ValueError('Node SDK profile is incomplete; recover its owned bootstrap before retrying')
    return True


def node_inputs(assets):
    lock = read(ROOT / LOCK); producer = module('scripts/quality/prepare-mutation-runtime.py')
    node = assets / 'node-runtime'
    archive = assets / 'node' / lock['node']['filename']
    if not node.exists():
        extractor = module('scripts/release/extract-node.py')
        extractor.extract(archive, node, 'linux-arm64', lock['node']['version'], lock['node']['sha256'])
        producer.copy_node_npm(archive, lock['node'], lock['node']['version'], node)
        (node / 'bin/npm').symlink_to('../lib/node_modules/npm/bin/npm-cli.js')
    # Re-open the exact archive before invoking the original CLI. The mutable
    # target package lifecycle is disabled by the existing Node preparer.
    if sha(archive) != lock['node']['sha256']: raise ValueError('Node provider changed')
    with tarfile.open(archive, 'r:xz') as source:
        prefix = 'node-v' + lock['node']['version'] + '-linux-arm64/'
        for member in source:
            if member.isfile() and (member.name == prefix + 'bin/node' or member.name.startswith(prefix + 'lib/node_modules/npm/')):
                relative = member.name[len(prefix):]
                data = source.extractfile(member).read()
                if (node / relative).is_symlink() or (node / relative).read_bytes() != data: raise ValueError('cached original Node CLI changed')
    if not (node / 'bin/npm').is_symlink() or os.readlink(node / 'bin/npm') != '../lib/node_modules/npm/bin/npm-cli.js': raise ValueError('original npm CLI link changed')
    profile = assets / 'mutation-node-linux-arm64-v4'
    if node_profile_ready(profile): return
    env = {'PATH': str(node / 'bin') + ':/usr/bin:/bin', 'HOME': str(assets), 'LANG': 'C.UTF-8'}
    checked([str(node / 'bin/node'), str(ROOT / 'scripts/quality/prepare-mutation-node.mjs'), '--output', str(profile)], cwd=ROOT, env=env, timeout=900, log=assets / 'node-setup.log')


def vendor_crates(lock, assets):
    # Build against the eventual SDK source tree. Copying or moving it after
    # compilation either duplicates bytes or races the supervisor's inventory.
    vendor = assets / 'mutation-rust-assets/export/vendor'; vendor.mkdir(parents=True)
    for item in lock['rust']['crates']:
        archive = assets / 'mutation-rust-assets/downloads' / item['url'].rsplit('/', 1)[1]
        if sha(archive) != item['sha256']: raise ValueError('Rust crate differs from its exact retained checksum')
        target = vendor / (item['name'] + '-' + item['version']); extract(archive, target, target.name)
        files = {file.relative_to(target).as_posix(): sha(file) for file in sorted(target.rglob('*')) if file.is_file()}
        (target / '.cargo-checksum.json').write_bytes(canonical({'files': files, 'package': item['sha256']}))
    return vendor


def native_cc(export, lock):
    """Promoted original pinned-provider compiler export; no package installation."""
    cc = export / 'native-cc'; cc.mkdir(); rows = lock['rust']['native_cc_packages']
    names = [row['package'] for row in rows]
    metadata = checked(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n', *names]).decode()
    actual = [dict(zip(['package', 'version', 'architecture'], line.split('\t'))) for line in metadata.splitlines()]
    if sorted(actual, key=lambda row: row['package']) != sorted(rows, key=lambda row: row['package']): raise ValueError('pinned native compiler packages differ from the retained provider')
    selected = {}; allowed = ('/usr/bin/', '/usr/libexec/', '/usr/lib/gcc/', '/usr/lib/aarch64-linux-gnu/', '/usr/include/', '/lib/aarch64-linux-gnu/', '/lib/ld-linux-aarch64.so.1', '/usr/share/doc/', '/usr/share/common-licenses/')
    for package in names:
        for name in checked(['dpkg-query', '-L', package]).decode().splitlines():
            if name.startswith(allowed) and Path(name).is_file(): selected[name.lstrip('/')] = Path(name).resolve(strict=True)
    for file in Path('/usr/share/common-licenses').iterdir():
        if file.is_file(): selected[str(file).lstrip('/')] = file.resolve(strict=True)
    for program in ['/usr/bin/aarch64-linux-gnu-gcc-13', '/usr/libexec/gcc/aarch64-linux-gnu/13/cc1', '/usr/libexec/gcc/aarch64-linux-gnu/13/collect2', '/usr/bin/aarch64-linux-gnu-ld.bfd', '/usr/bin/aarch64-linux-gnu-as']:
        for name in re.findall(r'(?:=>\s*)?(/[^\s()]+)', checked(['ldd', program]).decode()):
            file = Path(name).resolve(strict=True)
            if file.is_file() and file.name not in ['libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'ld-linux-aarch64.so.1']:
                selected['compiler-libs/' + file.name] = file
    origins, total = [], 0
    for name, file in sorted(selected.items()):
        data = file.read_bytes(); total += len(data)
        if len(data) > 128 * 1024**2 or total > 512 * 1024**2: raise ValueError('native compiler export exceeds retained bounds')
        target = cc / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data); target.chmod(stat.S_IMODE(file.stat().st_mode) & 0o555)
        origins.append({'path': name, 'source': str(file), 'sha256': sha(target), 'size': len(data)})
    for file in list((cc / 'usr/lib/aarch64-linux-gnu').rglob('*')):
        if file.is_file():
            target = cc / 'lib/aarch64-linux-gnu' / file.relative_to(cc / 'usr/lib/aarch64-linux-gnu'); target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != file.read_bytes(): raise ValueError('private sysroot alias conflicts')
            if not target.exists(): shutil.copyfile(file, target); target.chmod(stat.S_IMODE(file.stat().st_mode))
    loader = cc / 'usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'
    if loader.exists():
        target = cc / 'lib/ld-linux-aarch64.so.1'
        if not target.exists(): shutil.copyfile(loader, target); target.chmod(0o555)
    (cc / 'source-receipt.json').write_bytes(canonical({'schema_version': 1, 'source_image': lock['provider'], 'platform': 'linux/arm64', 'packages': actual, 'files': origins}) + b'\n')
    wrapper = '#!/bin/sh\nset -eu\nroot=/opt/mutation/rust/native-cc\nexport LD_LIBRARY_PATH="$root/compiler-libs"\nunset LD_PRELOAD LD_AUDIT GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH\nexec "$root/usr/bin/aarch64-linux-gnu-gcc-13" --sysroot="$root" -B"$root/usr/libexec/gcc/aarch64-linux-gnu/13/" -B"$root/usr/lib/gcc/aarch64-linux-gnu/13/" -B"$root/usr/bin/" "$@"\n'
    (export / 'bin/cc').write_text(wrapper); (export / 'bin/cc').chmod(0o555)
    return {'source_image': lock['provider'], 'receipt_path': 'native-cc/source-receipt.json', 'receipt_sha256': sha(cc / 'source-receipt.json'), 'packages': actual, 'wrapper_path': 'bin/cc'}


@contextmanager
def isolated_cargo_source(archive, lock_sha256):
    """Preserve upstream manifest bytes outside the product Cargo workspace."""
    with tempfile.TemporaryDirectory(prefix='ud-sdk-cargo-') as temporary:
        source = Path(temporary) / 'cargo-mutants-source'
        if source.resolve().is_relative_to(ROOT): raise ValueError('SDK third-party build source must be outside the product workspace')
        extract(archive, source, 'cargo-mutants-27.1.0')
        if sha(source / 'Cargo.lock') != lock_sha256: raise ValueError('cargo-mutants original lock changed')
        yield source


def install_rust_components(lock, assets, export, env):
    """Retire each consumed installer before extracting the next component."""
    rust_assets = assets / 'mutation-rust-assets'; stage = rust_assets / 'staging'; stage.mkdir()
    for item in lock['rust']['toolchain_archives']:
        archive = rust_assets / 'downloads' / item['url'].rsplit('/', 1)[1]
        if sha(archive) != item['sha256']: raise ValueError('Rust component differs from retained lock')
        with tarfile.open(archive, 'r:xz') as source: source.extractall(stage, filter='data')
        prefix = item['url'].rsplit('/', 1)[1].removesuffix('.tar.xz')
        checked(['/bin/bash', str(stage / prefix / 'install.sh'), '--prefix=' + str(export), '--disable-ldconfig'], env=env, timeout=180, log=assets / 'rust-setup.log')
        shutil.rmtree(stage / prefix)
    stage.rmdir()


def native_inputs(assets):
    if sys.platform != 'linux' or os.uname().machine not in ('aarch64', 'arm64'): raise ValueError('cold SDK tools require a native Linux ARM provider')
    lock = read(ROOT / LOCK); dependency_key = cache_key(ROOT, False)
    marker = assets / 'native-inputs.json'
    if marker.exists():
        if read(marker).get('dependency_key') != dependency_key: raise ValueError('cached native SDK inputs have a different recipe/lock binding')
        return
    node = assets / 'node-runtime'; env = {'PATH': str(node / 'bin') + ':/usr/bin:/bin', 'HOME': str(assets), 'LANG': 'C.UTF-8', 'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '2', 'PYTHONDONTWRITEBYTECODE': '1', 'SOURCE_DATE_EPOCH': '315532800'}
    perl = assets / 'native-perl/linux-arm64-source'
    checked([sys.executable, str(ROOT / 'scripts/runtime/prepare-native-perl.py'), '--target', 'linux/arm64', '--output', str(perl), '--build-timeout', '3600'], env=env, timeout=7200, log=assets / 'perl-setup.log')
    checked([sys.executable, str(ROOT / 'scripts/runtime/close-linux-elf.py'), '--root', str(perl), '--receipt', str(perl) + '-receipt.json', '--platform', 'linux/arm64', '--provider', lock['provider']], env=env, timeout=120, log=assets / 'perl-setup.log')
    checked([sys.executable, str(ROOT / 'scripts/quality/prepare-linux-perl-parser.py'), '--perl-pack', str(perl), '--receipt', str(perl) + '-receipt.json', '--output', str(assets / 'perl-mutation/parser-linux-arm64'), '--cache', str(assets / 'perl-mutation/cache')], env=env, timeout=120, log=assets / 'perl-setup.log')
    rust_assets = assets / 'mutation-rust-assets'; export = rust_assets / 'export'
    install_rust_components(lock, assets, export, env)
    env['PATH'] = str(export / 'bin') + ':' + env['PATH']; env['CARGO_HOME'] = str(rust_assets / 'cargo-home'); env['CARGO_TARGET_DIR'] = str(rust_assets / 'target')
    vendor = vendor_crates(lock, assets); crate = lock['rust']['cargo_mutants']
    flags = ['--locked', '--offline', '--config', 'source.crates-io.replace-with="verified-vendor"', '--config', 'source.verified-vendor.directory="' + str(vendor) + '"']
    indexed = {(row['name'], row['version']): row for row in lock['rust']['crates']}
    with isolated_cargo_source(rust_assets / 'downloads' / crate['url'].rsplit('/', 1)[1], crate['lock_sha256']) as source:
        checked([str(export / 'bin/cargo'), 'build', '--manifest-path', str(source / 'Cargo.toml'), '--release', '-j', '2', *flags], env=env, timeout=3600, log=assets / 'rust-setup.log')
        mutant_dependencies = [indexed[row['name'], row['version']] for row in tomllib.loads((source / 'Cargo.lock').read_text())['package'] if 'source' in row]
    shutil.copyfile(rust_assets / 'target/release/cargo-mutants', export / 'bin/cargo-mutants')
    (export / 'bin/cargo-mutants').chmod(0o555)
    parser = ROOT / 'scripts/quality/rust-assertion-parser'
    checked([str(export / 'bin/cargo'), 'build', '--manifest-path', str(parser / 'Cargo.toml'), '--release', '-j', '2', *flags], env=env, timeout=900, log=assets / 'rust-setup.log')
    shutil.copyfile(rust_assets / 'target/release/ud-rust-assertion-parser', export / 'bin/ud-rust-assertion-parser')
    (export / 'bin/ud-rust-assertion-parser').chmod(0o555)
    # Both selected executables have been retained; compiler intermediates are
    # not SDK inputs and must not overlap the next independent native build.
    shutil.rmtree(rust_assets / 'target')
    guard_target = assets / 'guard-target'; env['CARGO_TARGET_DIR'] = str(guard_target)
    checked([str(export / 'bin/cargo'), 'build', '--manifest-path', str(ROOT / 'Cargo.toml'), '--release', '--target', lock['rust']['target'], '--bin', 'ud-agent-guard', '-j', '2', *flags], env=env, timeout=900, log=assets / 'guard-setup.log')
    guard = assets / 'native-guard'; shutil.copyfile(guard_target / lock['rust']['target'] / 'release/ud-agent-guard', guard); guard.chmod(0o555)
    (assets / 'cross-build-receipt.json').write_bytes(canonical({'schema_version': 1, 'qualification': 'native-original-guard-build-not-cross-build', 'source_inputs': input_rows(ROOT, False), 'platforms': {'linux-arm64': {'ud-agent-guard': {'path': 'native-guard', 'sha256': sha(guard)}}}}) + b'\n')
    shutil.rmtree(guard_target)
    cc = native_cc(export, lock)
    for file in list(export.rglob('*')):
        if file.is_symlink():
            resolved = file.resolve(strict=True)
            if not resolved.is_relative_to(export) or not resolved.is_file(): raise ValueError('Rust installation has an escaping or directory link')
            data, mode = resolved.read_bytes(), stat.S_IMODE(resolved.stat().st_mode)
            file.unlink(); file.write_bytes(data); file.chmod(mode)
        if file.is_file(): file.chmod(stat.S_IMODE(file.stat().st_mode) & 0o555)
    product = {'schema_version': 1, 'cargo_lock_sha256': sha(ROOT / 'Cargo.lock'), 'packages': []}
    for item in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']:
        if 'source' in item: product['packages'].append(indexed[item['name'], item['version']])
    receipt = {'schema_version': 1, 'qualification': 'development-mutation-toolchain', 'platform': 'linux/arm64', 'toolchain': {'version': '1.99.1', 'target': lock['rust']['target'], 'archives': lock['rust']['toolchain_archives']},
               'cargo_mutants': {'crate': {key: crate[key] for key in ['name', 'version', 'sha256', 'size_bytes']}, 'lock_sha256': crate['lock_sha256'], 'dependencies': mutant_dependencies},
               'product_vendor': product, 'native_cc': cc, 'assertion_parser': {'schema_version': 1, 'source_inventory': {file.relative_to(ROOT).as_posix(): sha(file) for file in [parser / 'Cargo.toml', parser / 'Cargo.lock', *sorted((parser / 'src').rglob('*.rs'))]}},
               'files': [{'path': file.relative_to(export).as_posix(), 'sha256': sha(file), 'size': file.stat().st_size, 'mode': stat.S_IMODE(file.stat().st_mode)} for file in sorted(export.rglob('*')) if file.is_file()], 'links': []}
    (rust_assets / 'rust-input-receipt.json').write_bytes(canonical(receipt) + b'\n')
    git = assets / 'native-git'; git.mkdir()
    checked([sys.executable, str(ROOT / 'scripts/quality/prepare-git-runtime.py'), '--output', str(git / 'linux-arm64'), '--provider', lock['provider']], env=env, timeout=600, log=assets / 'git-setup.log')
    upstream = assets / 'upstream'; upstream.mkdir()
    tools = next(row for row in read(ROOT / 'runtime/ud-sources.lock.json')['sources'] if row['repository'] == 'UniversalDependencies/tools')
    core = module('scripts/runtime/prepare-core-build.py'); rules = core.extract_verified_tools(assets / 'sources' / ('tools-' + tools['commit'] + '.tar.gz'), tools, upstream)
    (upstream / 'data').mkdir()
    for name, data in rules.items(): (upstream / 'data' / name).write_bytes(data)
    marker.write_bytes(canonical({'schema_version': 1, 'qualification': 'original-locked-native-SDK-input-build-no-generated-variants', 'dependency_key': dependency_key, 'provider': lock['provider'], 'rust_receipt_sha256': sha(rust_assets / 'rust-input-receipt.json')}) + b'\n')


def cleanup_candidates(mode):
    """Only outputs created by this bootstrap stage are disposable."""
    if mode == '--node-inputs': return ['node-runtime', 'mutation-node-linux-arm64-v4']
    if mode == '--native-inputs': return [
        'native-perl/linux-arm64-source', 'native-perl/linux-arm64-source-receipt.json',
        'perl-mutation/parser-linux-arm64', 'mutation-rust-assets/staging',
        'mutation-rust-assets/export', 'mutation-rust-assets/vendor-complete',
        'mutation-rust-assets/cargo-mutants-source', 'mutation-rust-assets/cargo-home',
        'mutation-rust-assets/target', 'mutation-rust-assets/rust-input-receipt.json',
        'guard-target', 'native-guard', 'cross-build-receipt.json', 'native-git',
        'upstream', 'native-inputs.json',
    ]
    if mode == '--prepare-context': return []
    raise ValueError('unknown SDK bootstrap stage')


def process_alive(pid):
    if type(pid) is not int or pid <= 0: raise ValueError('SDK bootstrap owner PID is invalid')
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False
    except PermissionError: return True


def inspect_sdk_container(name):
    result = subprocess.run(['docker', 'inspect', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        # Docker versions differ in capitalization. Absence is evidence only for
        # this exact requested identity, never a generic failed inspection.
        diagnostic = result.stderr.decode(errors='replace').strip()
        if re.fullmatch(r'(?:error(?: response from daemon)?:\s*)?no such (?:object|container):?\s*' + re.escape(name), diagnostic, re.IGNORECASE): return None
        raise ValueError('SDK recovery cannot inspect its container: ' + result.stderr[-1000:].decode(errors='replace'))
    if len(result.stdout) > 1024**2: raise ValueError('SDK recovery container inspection is oversized')
    data = json.loads(result.stdout)
    if not isinstance(data, list) or len(data) != 1: raise ValueError('SDK recovery container inspection differs')
    return data[0]


def assert_docker_binding():
    endpoint = os.environ.get('UD_SDK_DOCKER_ENDPOINT', '')
    daemon = os.environ.get('UD_SDK_DOCKER_DAEMON', '')
    local_unix = endpoint.startswith('unix:///') and not any(char in endpoint for char in '\\\0\r\n?#%') and all(part and part not in ('.', '..') for part in endpoint[len('unix:///'):].split('/'))
    local_pipe = re.fullmatch(r'npipe:////\./pipe/[A-Za-z0-9_.-]+', endpoint)
    if (not (local_unix or local_pipe) or os.environ.get('DOCKER_HOST') != endpoint or os.environ.get('DOCKER_CONTEXT')
            or not re.fullmatch('[A-Za-z0-9._:-]{1,128}', daemon)):
        raise ValueError('SDK Docker endpoint binding is not local or pinned')
    actual = checked(['docker', 'info', '--format', '{{.ID}}'], timeout=30).decode().strip()
    if actual != daemon: raise ValueError('SDK Docker daemon identity changed')
    return {'endpoint': endpoint, 'daemon_id': daemon}


def verify_owned_context(context, root, assets, creator_pid):
    if context.is_symlink() or not context.is_dir(): raise ValueError('SDK context is not an ordinary directory')
    info = context.stat(); marker = read(context / '.sdk-context-owner.json')
    if (marker.get('root') != str(root) or marker.get('assets') != str(assets) or marker.get('context') != str(context)
            or marker.get('creator_pid') != creator_pid or marker.get('device') != info.st_dev or marker.get('inode') != info.st_ino):
        raise ValueError('SDK context ownership or inode differs')


def remove_owned_context(context, root, assets, creator_pid):
    verify_owned_context(context, root, assets, creator_pid)
    shutil.rmtree(context)


def recover_consumed_inputs(root, assets):
    """Finish only an inode-bound staging retirement; never touch live Node."""
    retired = assets / 'node-runtime.retired'
    if not retired.exists() and not retired.is_symlink(): return
    record = read(assets / 'consumed-inputs.json'); info = retired.lstat()
    if (record.get('qualification') != 'verified-SDK-consumed-input-retirement' or record.get('root') != str(root)
            or record.get('assets') != str(assets) or record.get('node') != {'device': info.st_dev, 'inode': info.st_ino}
            or retired.is_symlink() or not retired.is_dir() or hasattr(os, 'getuid') and info.st_uid != os.getuid()):
        raise ValueError('consumed SDK staging ownership differs')
    def remove_readonly(function, name, error):
        if os.name != 'nt' or not isinstance(error, PermissionError) or Path(name).is_symlink(): raise error
        os.chmod(name, stat.S_IWRITE); function(name)
    shutil.rmtree(retired, onexc=remove_readonly)


def retire_consumed_inputs(root, assets, context):
    """Drop only authenticated copies no longer used by the compact build."""
    verify_owned_context(context, root, assets, os.getpid())
    prepared = context / 'context'; lock = read(root / LOCK)
    ordinary_input_parents(context, prepared / 'input-receipt.json')
    runtime = read(prepared / 'input-receipt.json')
    payload = prepared / 'sdk-inputs.tar.xz'; recipe = prepared / 'Containerfile'
    if (prepared.is_symlink() or not prepared.is_dir() or {file.name for file in prepared.iterdir()} != {'input-receipt.json', 'sdk-inputs.tar.xz', 'Containerfile'}
            or runtime.get('qualification') != 'development-mutation-runner' or runtime.get('platform') != 'linux/arm64'
            or runtime.get('base') != lock['provider'] or runtime.get('package_lock_sha256') != sha(root / 'package-lock.json')
            or recipe.is_symlink() or not recipe.is_file() or recipe.stat().st_nlink != 1 or recipe.stat().st_size > 1024**2
            or payload.is_symlink() or not payload.is_file() or payload.stat().st_nlink != 1 or not 0 < payload.stat().st_size <= 4_000_000_000):
        raise ValueError('consumed SDK inputs require the completed compact context')
    payload_hash = sha(payload)
    if ('source=sdk-inputs.tar.xz,target=/sdk-inputs.tar.xz,readonly' not in recipe.read_text()
            or 'assert hashlib.file_digest(open(p,"rb"),"sha256").hexdigest()=="' + payload_hash + '"' not in recipe.read_text()
            or not retained_rust_ready(root, assets)):
        raise ValueError('compact SDK context or retained native inputs differ')
    recover_consumed_inputs(root, assets)
    node = assets / 'node-runtime'; archive = assets / 'node' / lock['node']['filename']
    ordinary_input_parents(assets, archive)
    if node.is_symlink() or not node.is_dir() or hasattr(os, 'getuid') and node.stat().st_uid != os.getuid() or sha(archive) != lock['node']['sha256']:
        raise ValueError('consumed Node runtime ownership or archive differs')
    expected = {}; prefix = 'node-v' + lock['node']['version'] + '-linux-arm64/'
    with tarfile.open(archive, 'r:xz') as source:
        for member in source:
            if member.isfile() and member.name.startswith(prefix):
                name = member.name[len(prefix):]
                if name in ('bin/node', 'LICENSE') or name.startswith('lib/node_modules/npm/'):
                    expected[name] = (member.size, hashlib.file_digest(source.extractfile(member), 'sha256').hexdigest())
    seen = set()
    for file in node.rglob('*'):
        name = file.relative_to(node).as_posix()
        if name == 'bin/npm' and file.is_symlink() and os.readlink(file) == '../lib/node_modules/npm/bin/npm-cli.js': continue
        if file.is_symlink() or not (file.is_dir() or file.is_file()): raise ValueError('consumed Node runtime contains aliases or special files')
        if file.is_dir():
            if not any(value.startswith(name + '/') for value in expected): raise ValueError('consumed Node runtime contains unlisted directories')
            continue
        if file.stat().st_nlink != 1 or (file.stat().st_size, sha(file)) != expected.get(name): raise ValueError('consumed Node runtime differs from its locked archive')
        seen.add(name)
    if seen != set(expected) or not {'bin/node', 'LICENSE', 'lib/node_modules/npm/bin/npm-cli.js'} <= seen or not (node / 'bin/npm').is_symlink():
        raise ValueError('consumed Node runtime is incomplete')
    # Validate every selected archive before the first destructive operation.
    originals = []
    for item, file, limit in rust_archive_inputs(lock, assets):
        if file.exists() or file.is_symlink():
            ordinary_input_parents(assets, file)
            if file.stat().st_nlink != 1: raise ValueError('consumed Rust archive ownership differs')
            acquire(item, file, False, limit); originals.append((file, file.stat()))
    info = node.stat(); record = {'schema_version': 1, 'qualification': 'verified-SDK-consumed-input-retirement', 'root': str(root), 'assets': str(assets),
        'node': {'device': info.st_dev, 'inode': info.st_ino}, 'dependency_key': cache_key(root, False), 'runtime_input_sha256': sha(prepared / 'input-receipt.json'),
        'payload_sha256': payload_hash, 'rust_archives': [file.relative_to(assets).as_posix() for file, _ in originals]}
    journal = assets / 'consumed-inputs.json'
    if journal.is_symlink() or journal.exists() and not journal.is_file(): raise ValueError('consumed SDK journal is not ordinary')
    temporary = assets / ('consumed-inputs.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as stream: stream.write(canonical(record) + b'\n')
        temporary.replace(journal)
    finally: temporary.unlink(missing_ok=True)
    node.rename(assets / 'node-runtime.retired')
    recover_consumed_inputs(root, assets)
    for file, before in originals:
        ordinary_input_parents(assets, file); after = file.lstat()
        if any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('consumed Rust archive changed before retirement')
        file.unlink()


def recover_sdk_jobs(root, assets, output=None):
    """Recover only stopped jobs and outputs named by their original journal."""
    root = root.resolve(strict=True); assets = Path(os.path.abspath(assets))
    if not assets.is_relative_to(root / '.artifacts') or assets == root / '.artifacts' or assets.is_symlink():
        raise ValueError('SDK recovery needs an owned asset directory')
    binding = assert_docker_binding()
    if assets.exists():
        for evidence in sorted(assets.glob('bootstrap-*.json')):
            record = read(evidence)
            if record.get('status') == 'passed' and record.get('cleanup') == 'removed-owned': continue
            if record.get('recovered') is True: continue
            owner, mode, candidates = record.get('owner'), record.get('mode'), record.get('cleanup_candidates')
            if (not re.fullmatch('[a-f0-9]{32}', owner or '') or evidence.name != 'bootstrap-' + owner + '.json'
                    or record.get('schema_version') != 1 or record.get('qualification') != 'original-SDK-bootstrap-not-mutant-execution'
                    or record.get('root') != str(root) or record.get('assets') != str(assets)
                    or record.get('docker') != binding
                    or not isinstance(candidates, list) or len(set(candidates)) != len(candidates)
                    or any(name not in cleanup_candidates(mode) for name in candidates)):
                raise ValueError('SDK interrupted job lacks an exact owned recovery record')
            argv = record.get('argv')
            if (not isinstance(argv, list) or argv[:3] != ['docker', 'create', '--pull=never']
                    or argv.count('--name') != 1 or argv[argv.index('--name') + 1] != 'ud-sdk-bootstrap-' + owner
                    or argv.count('--label') != 1 or argv[argv.index('--label') + 1] != 'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap=' + owner
                    or 'type=bind,src=' + str(root) + ',dst=/src,readonly' not in argv
                    or 'type=bind,src=' + str(assets) + ',dst=/src/.artifacts' not in argv or mode not in argv):
                raise ValueError('SDK interrupted command differs from its owned journal')
            if process_alive(record.get('creator_pid')): raise ValueError('SDK interrupted job owner is still active')
            name = 'ud-sdk-bootstrap-' + owner
            if assert_docker_binding() != binding: raise ValueError('SDK recovery daemon binding changed')
            actual = None if record.get('cleanup') in ('removed-owned', 'verified-absent') else inspect_sdk_container(name)
            if actual is not None:
                labels = actual.get('Config', {}).get('Labels', {})
                mounts = {row.get('Destination'): row.get('Source') for row in actual.get('Mounts', [])}
                identifier = actual.get('Id', '')
                if (actual.get('Name') != '/' + name or labels.get('io.github.mehmetoguzderin.ud-agent.sdk-bootstrap') != owner
                        or actual.get('Config', {}).get('Image') != read(root / LOCK)['provider']
                        or mounts.get('/src') != str(root) or mounts.get('/src/.artifacts') != str(assets)
                        or not re.fullmatch('[a-f0-9]{64}', identifier)):
                    raise ValueError('SDK interrupted container does not match its owned journal')
                if assert_docker_binding() != binding: raise ValueError('SDK recovery daemon binding changed')
                checked(['docker', 'rm', '--force', identifier])
                if assert_docker_binding() != binding: raise ValueError('SDK recovery daemon binding changed')
                if inspect_sdk_container(identifier) is not None: raise ValueError('SDK interrupted container remains after cleanup')
            # Absence before a job does not prove the inode currently at that
            # path belongs to it. Preserve such outputs until independently
            # identified; do not delete a replacement or a foreign file.
            pending = [relative for relative in candidates if (assets / relative).exists() or (assets / relative).is_symlink()]
            record.update(status='interrupted', cleanup='verified-absent', recovered=not pending, pending_partial_outputs=pending)
            evidence.write_bytes(canonical(record) + b'\n')
            if pending: raise ValueError('SDK interrupted outputs have ambiguous ownership and were preserved: ' + ', '.join(pending))
    if output is not None:
        output = Path(os.path.abspath(output))
        if not output.is_relative_to(root / '.artifacts') or output == root / '.artifacts' or output.is_symlink():
            raise ValueError('SDK recovery needs an owned context directory')
        if output.exists():
            for context in sorted(output.glob('context-*')):
                if context.is_symlink() or not context.is_dir() or not re.fullmatch('context-[a-f0-9]{32}', context.name):
                    raise ValueError('SDK interrupted context identity differs')
                marker = read(context / '.sdk-context-owner.json')
                if process_alive(marker.get('creator_pid')):
                    raise ValueError('SDK interrupted context owner differs or remains active')
                remove_owned_context(context, root, assets, marker.get('creator_pid'))


def container(root, assets, mode, *, output=None, network='none'):
    lock = read(root / LOCK); binding = assert_docker_binding(); owner = uuid.uuid4().hex; name = 'ud-sdk-bootstrap-' + owner
    command = ['docker', 'create', '--pull=never', '--name', name, '--label', 'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap=' + owner, '--platform', 'linux/arm64', '--user', str(os.getuid()) + ':' + str(os.getgid()), '--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '2', '--memory', '3g', '--pids-limit', '256', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=2147483648', '--mount', 'type=bind,src=' + str(root) + ',dst=/src,readonly', '--mount', 'type=bind,src=' + str(assets) + ',dst=/src/.artifacts']
    if output is not None: command += ['--mount', 'type=bind,src=' + str(output) + ',dst=/output']
    command += ['--workdir', '/src', '--entrypoint', 'python3', lock['provider'], '/src/scripts/quality/mutation-runtime-bootstrap.py', mode, '--asset-root', '/src/.artifacts']
    if output is not None: command += ['--output', '/output']
    record = {'schema_version': 1, 'qualification': 'original-SDK-bootstrap-not-mutant-execution', 'owner': owner, 'argv': command, 'network': network, 'status': 'started',
              'creator_pid': os.getpid(), 'root': str(root), 'assets': str(assets), 'mode': mode, 'docker': binding,
              'cleanup_candidates': [name for name in cleanup_candidates(mode) if not (assets / name).exists() and not (assets / name).is_symlink()]}
    evidence = assets / ('bootstrap-' + owner + '.json'); evidence.write_bytes(canonical(record) + b'\n')
    created = False
    try:
        if assert_docker_binding() != binding: raise ValueError('SDK create daemon binding changed')
        checked(command); created = True
        if assert_docker_binding() != binding: raise ValueError('SDK start daemon binding changed')
        checked(['docker', 'start', '--attach', name], timeout=10800, log=assets / ('bootstrap-' + owner + '.log'))
        if assert_docker_binding() != binding: raise ValueError('SDK inspection daemon binding changed')
        actual = json.loads(checked(['docker', 'inspect', name]))[0]
        if actual['Config']['Labels'].get('io.github.mehmetoguzderin.ud-agent.sdk-bootstrap') != owner or actual['State']['ExitCode'] != 0 or actual['State']['OOMKilled']:
            raise ValueError('owned native SDK setup did not complete cleanly')
        record.update(status='passed', actual_image=actual['Image'], actual_state=actual['State'])
    except BaseException as error:
        record.update(status='failed', error=str(error)); raise
    finally:
        if created:
            if assert_docker_binding() != binding: raise ValueError('SDK cleanup daemon binding changed')
            actual = json.loads(checked(['docker', 'inspect', name]))[0]
            identifier = actual.get('Id', '')
            mounts = {row.get('Destination'): row.get('Source') for row in actual.get('Mounts', [])}
            if (not re.fullmatch('[a-f0-9]{64}', identifier) or actual.get('Name') != '/' + name
                    or actual['Config']['Labels'].get('io.github.mehmetoguzderin.ud-agent.sdk-bootstrap') != owner
                    or actual['Config'].get('Image') != lock['provider'] or mounts.get('/src') != str(root)
                    or mounts.get('/src/.artifacts') != str(assets)):
                raise ValueError('SDK bootstrap cleanup ownership mismatch')
            record['actual_state'] = actual['State']
            if assert_docker_binding() != binding: raise ValueError('SDK cleanup daemon binding changed')
            checked(['docker', 'rm', '--force', identifier])
            if assert_docker_binding() != binding or inspect_sdk_container(identifier) is not None:
                raise ValueError('SDK bootstrap container cleanup could not be verified')
            record['cleanup'] = 'removed-owned'
        evidence.write_bytes(canonical(record) + b'\n')


def verify_image_record(root, assets):
    record = read(assets / 'ci-sdk.json')
    if record.get('schema_version') != 1 or record.get('cache_key') != cache_key(root) or record.get('qualification') != 'private-native-arm-CI-SDK-not-product-release' or not re.fullmatch('sha256:[a-f0-9]{64}', record.get('image_id', '')):
        raise ValueError('CI SDK cache does not match current executable sources and locks')
    size = record.get('archive', {}).get('size_bytes')
    if type(size) is not int or not 0 < size <= 8 * 1024**3 or record.get('archive', {}).get('path') != 'sdk-image.tar' or (assets / 'sdk-image.tar').is_symlink() or (assets / 'sdk-image.tar').stat().st_size != size or sha(assets / 'sdk-image.tar') != record['archive'].get('sha256') or sha(assets / 'input-receipt.json') != record.get('runtime_input_sha256'):
        raise ValueError('cached SDK image or runtime input receipt changed')
    compression = record['archive'].get('compression')
    if compression not in (None, 'gzip'): raise ValueError('cached SDK archive compression is unsupported')
    if compression == 'gzip':
        with (assets / 'sdk-image.tar').open('rb') as stream:
            if stream.read(2) != b'\x1f\x8b': raise ValueError('cached SDK archive compression differs from its receipt')
    runtime = read(assets / 'input-receipt.json'); producer = module('scripts/quality/prepare-mutation-runtime.py')
    expected = {name: sha(root / ('tests/mutation/' if name == 'pytest_evidence.py' else 'scripts/quality/') / name) for name in producer.HARNESS_NAMES}
    if {row['path']: row['sha256'] for row in runtime['harness']} != expected or len(runtime['harness']) != len(expected) or runtime.get('platform') != 'linux/arm64' or runtime.get('package_lock_sha256') != sha(root / 'package-lock.json'):
        raise ValueError('cached SDK executable harness or package lock binding is stale')
    return record


def load_image(root, assets):
    assets = assets.resolve(strict=True); record = verify_image_record(root, assets); binding = assert_docker_binding()
    checked(['docker', 'load', '--input', str(assets / 'sdk-image.tar')], timeout=600)
    if assert_docker_binding() != binding: raise ValueError('SDK load daemon binding changed')
    actual = json.loads(checked(['docker', 'image', 'inspect', record['image_id']]))[0]
    if actual['Id'] != record['image_id'] or actual['Architecture'] != 'arm64' or actual['Os'] != 'linux': raise ValueError('loaded SDK image has a different immutable native identity')
    return {'image_id': record['image_id'], 'runtime_input_sha256': record['runtime_input_sha256'], 'cache_key': record['cache_key']}


def retire_stale_image(assets):
    """Keep a small receipt, not an accumulating series of old SDK images."""
    archive, receipt = assets / 'sdk-image.tar', assets / 'ci-sdk.json'
    if not archive.exists() and not archive.is_symlink(): return
    if archive.is_symlink() or not archive.is_file() or not receipt.exists():
        raise ValueError('old SDK image is not a receipt-owned ordinary file')
    previous = read(receipt)
    held = previous.get('archive', {})
    if held.get('path') != archive.name or held.get('size_bytes') != archive.stat().st_size or held.get('sha256') != sha(archive):
        raise ValueError('old SDK image differs from its retained receipt')
    history = assets / 'ci-sdk.previous.json'
    if history.is_symlink(): raise ValueError('SDK history cannot be a link')
    temporary = assets / ('ci-sdk.previous.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as target: target.write(canonical(previous) + b'\n')
        temporary.replace(history)
    finally:
        temporary.unlink(missing_ok=True)
    archive.unlink()


def current_sdk_candidate(root, assets, key):
    record = assets / 'ci-sdk.json'
    if not record.exists() or read(record).get('cache_key') != key: return False
    # A retained retirement receipt can explain an interrupted replacement.
    previous = assets / 'ci-sdk.previous.json'
    return ((assets / 'sdk-image.tar').exists() or not previous.exists()
            or read(previous) != read(record))


def provider_input(root, download, base_image=None):
    """Admit only the locked native provider on the supervising local daemon."""
    lock = read(root / LOCK); provider = lock['provider']; binding = assert_docker_binding()
    if not re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}', provider): raise ValueError('SDK provider must have an immutable digest')
    if base_image is not None and base_image != provider: raise ValueError('CI base image differs from locked native provider')
    architecture = checked(['docker', 'info', '--format', '{{.Architecture}}']).decode().strip()
    if architecture not in ('aarch64', 'arm64'): raise ValueError('SDK setup requires a native ARM Docker engine')
    def inspect():
        if assert_docker_binding() != binding: raise ValueError('SDK provider daemon binding changed')
        result = subprocess.run(['docker', 'image', 'inspect', provider], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if len(result.stdout) > 4 * 1024**2 or len(result.stderr) > 1024**2: raise ValueError('SDK provider inspection is oversized')
        if result.returncode:
            diagnostic = result.stderr.decode(errors='replace').strip()
            if re.fullmatch(r'(?:error(?: response from daemon)?:\s*)?no such (?:image|object):?\s*' + re.escape(provider), diagnostic, re.IGNORECASE): return None
            raise ValueError('SDK provider inspection failed: ' + diagnostic[-1000:])
        rows = json.loads(result.stdout)
        if not isinstance(rows, list) or len(rows) != 1: raise ValueError('SDK provider inspection identity differs')
        image = rows[0]
        if (not isinstance(image, dict) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', '')) or image.get('Architecture') != 'arm64'
                or image.get('Os') != 'linux' or not isinstance(image.get('RepoDigests'), list) or provider not in image['RepoDigests']):
            raise ValueError('SDK provider differs from its immutable native identity')
        return image
    image = inspect()
    if image is None:
        if not download: raise ValueError('locked native CI provider is absent offline; acquire it in its supervised provider phase')
        if assert_docker_binding() != binding: raise ValueError('SDK pull daemon binding changed')
        checked(['docker', 'pull', '--platform', 'linux/arm64', provider], timeout=900)
        image = inspect()
        if image is None: raise ValueError('SDK provider is absent after its bounded acquisition')
    if assert_docker_binding() != binding: raise ValueError('SDK provider daemon binding changed')
    return {'schema_version': 1, 'qualification': 'verified-native-SDK-provider-input', 'provider': provider,
            'image_id': image['Id'], 'platform': 'linux/arm64', 'docker': binding, 'lock_sha256': sha(root / LOCK)}


def prepare_provider(root, assets, download, base_image=None):
    """Acquire the immutable input under a separate bounded storage lease."""
    root = root.resolve(strict=True); assets = Path(os.path.abspath(assets))
    if not assets.is_relative_to(root / '.artifacts') or assets == root / '.artifacts' or assets.is_symlink():
        raise ValueError('CI SDK preparation needs owned artifact subdirectories')
    for parent in assets.parents:
        if parent == root: break
        if parent.is_symlink(): raise ValueError('CI SDK artifact parent is aliased')
    if base_image is not None and base_image != read(root / LOCK)['provider']: raise ValueError('CI base image differs from locked native provider')
    if current_sdk_candidate(root, assets, cache_key(root)):
        record = verify_image_record(root, assets)
        return {'qualification': 'verified-cached-SDK-provider-not-required', 'image_id': record['image_id']}
    receipt = provider_input(root, download, base_image)
    assets.mkdir(parents=True, exist_ok=True)
    target = assets / 'provider-input.json'
    if target.is_symlink() or target.exists() and (not target.is_file() or target.stat().st_nlink != 1):
        raise ValueError('SDK provider receipt must be an ordinary owned file')
    temporary = assets / ('provider-input.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as stream: stream.write(canonical(receipt) + b'\n')
        temporary.replace(target)
    finally: temporary.unlink(missing_ok=True)
    return receipt


def export_image(root, assets, temporary, image_id):
    """Export to one pre-created owned inode, never Docker's hidden temp file."""
    binding = assert_docker_binding()
    owner = os.environ.get('UD_SDK_EXPORT_OWNER', '')
    if not re.fullmatch(r'[a-f0-9-]{36}', owner): raise ValueError('SDK export requires its supervising owner')
    journal = assets / 'image-export.json'
    if journal.is_symlink() or journal.exists() and (not journal.is_file() or journal.stat().st_nlink != 1):
        raise ValueError('SDK export journal must be an ordinary owned file')
    with temporary.open('xb') as output:
        temporary.chmod(0o600); info = os.fstat(output.fileno())
        record = {'schema_version': 1, 'qualification': 'owned-SDK-image-export', 'root': str(root), 'assets': str(assets),
                  'creator_pid': os.getpid(), 'owner': owner, 'path': temporary.name, 'device': info.st_dev, 'inode': info.st_ino,
                  'docker': binding, 'image_id': image_id}
        pending = assets / ('image-export.' + uuid.uuid4().hex + '.tmp')
        try:
            with pending.open('xb') as stream: stream.write(canonical(record) + b'\n')
            pending.replace(journal)
        finally: pending.unlink(missing_ok=True)
        # --output uses Docker's own atomic temporary pathname. Streaming to
        # our held descriptor keeps the monitored device/inode exact throughout.
        # Compress directly into the journaled inode: never retain a second
        # uncompressed archive. Docker load detects gzip independently of the
        # established cache pathname, which remains sdk-image.tar.
        checked(['docker', 'save', image_id], timeout=600, stdout=output, gzip_stdout=True)
        output.flush(); os.fsync(output.fileno())
        if assert_docker_binding() != binding: raise ValueError('SDK export daemon binding changed')
        observed = temporary.stat()
        if temporary.is_symlink() or observed.st_dev != info.st_dev or observed.st_ino != info.st_ino or observed.st_nlink != 1:
            raise ValueError('SDK export inode changed')


def ensure(root, assets, output, download, base_image=None):
    root = root.resolve(strict=True); assets = Path(os.path.abspath(assets)); output = Path(os.path.abspath(output)); lock = read(root / LOCK)
    for value in [assets, output]:
        if not value.is_relative_to(root / '.artifacts') or value == root / '.artifacts' or value.is_symlink(): raise ValueError('CI SDK preparation needs owned artifact subdirectories')
        for parent in value.parents:
            if parent == root: break
            if parent.is_symlink(): raise ValueError('CI SDK artifact parent is aliased')
    assets.mkdir(parents=True, exist_ok=True); output.mkdir(parents=True, exist_ok=True)
    if base_image is not None and base_image != lock['provider']: raise ValueError('CI base image differs from locked native provider')
    binding = assert_docker_binding()
    key = cache_key(root)
    if current_sdk_candidate(root, assets, key): return load_image(root, assets)
    # The provider's acquisition lease has already ended. Re-verify its exact
    # identity; the native-build lease never performs an unreserved fallback pull.
    provider_input(root, False, base_image)
    recover_consumed_inputs(root, assets)
    acquire_inputs(root, assets, download)
    if not node_profile_ready(assets / 'mutation-node-linux-arm64-v4'):
        if not download: raise ValueError('locked native Node SDK profile is absent; cold setup needs --download')
        container(root, assets, '--node-inputs', network='bridge')
    container(root, assets, '--native-inputs')
    context = output / ('context-' + uuid.uuid4().hex); context.mkdir()
    try:
        info = context.stat()
        (context / '.sdk-context-owner.json').write_bytes(canonical({'root': str(root), 'assets': str(assets), 'context': str(context), 'creator_pid': os.getpid(), 'device': info.st_dev, 'inode': info.st_ino}) + b'\n')
    except BaseException:
        context.rmdir(); raise
    temporary = assets / ('sdk-image.' + uuid.uuid4().hex + '.tar')
    archive = assets / 'sdk-image.tar'; installed = False; committed = False
    try:
        container(root, assets, '--prepare-context', output=context)
        retire_consumed_inputs(root, assets, context)
        runtime = context / 'context/input-receipt.json'; tag = 'localhost/ud-agent-mutation-runtime:ci-' + key[:24]
        if assert_docker_binding() != binding: raise ValueError('SDK build daemon binding changed')
        checked(['docker', 'buildx', 'build', '--platform', 'linux/arm64', '--pull=false', '--network=none', '--load', '--file', str(context / 'context/Containerfile'), '-t', tag, str(context / 'context')], timeout=1800, log=assets / 'image-build.log')
        if assert_docker_binding() != binding: raise ValueError('SDK inspection daemon binding changed')
        image = json.loads(checked(['docker', 'image', 'inspect', tag]))[0]
        if image['Architecture'] != 'arm64' or image['Os'] != 'linux': raise ValueError('CI SDK image is not native Linux ARM')
        # The image already contains the context; retaining the entire
        # expanded context while exporting the image needlessly duplicates
        # the largest inputs. Only its small verified receipt is still used.
        if runtime.is_symlink() or not runtime.is_file() or runtime.stat().st_size > 16 * 1024**2:
            raise ValueError('SDK build context receipt is not an ordinary bounded file')
        runtime_bytes = runtime.read_bytes()
        remove_owned_context(context, root, assets, os.getpid())
        # The old cache is stale at this point; retaining it alongside the new
        # export doubled disk use on each rebuilt SDK. Keep its receipt only.
        retire_stale_image(assets)
        if assert_docker_binding() != binding: raise ValueError('SDK export daemon binding changed')
        export_image(root, assets, temporary, image['Id'])
        temporary.rename(archive); installed = True; (assets / 'input-receipt.json').write_bytes(runtime_bytes)
        record = {'schema_version': 1, 'qualification': 'private-native-arm-CI-SDK-not-product-release', 'cache_key': key, 'dependency_key': cache_key(root, False), 'image_id': image['Id'], 'runtime_input_sha256': sha(assets / 'input-receipt.json'), 'archive': {'path': 'sdk-image.tar', 'compression': 'gzip', 'sha256': sha(archive), 'size_bytes': archive.stat().st_size}, 'source_inputs': input_rows(root), 'cold_setup_separate_from_bounded_gate': True}
        (assets / 'ci-sdk.json').write_bytes(canonical(record) + b'\n')
        verify_image_record(root, assets)
        committed = True
        return {'image_id': image['Id'], 'runtime_input_sha256': record['runtime_input_sha256'], 'cache_key': key}
    finally:
        temporary.unlink(missing_ok=True)
        if installed and not committed:
            archive.unlink(missing_ok=True)
            (assets / 'ci-sdk.json').unlink(missing_ok=True)
        if context.exists() or context.is_symlink(): remove_owned_context(context, root, assets, os.getpid())


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--asset-root', type=Path, required=True); parser.add_argument('--output', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    for name in ['--node-inputs', '--native-inputs', '--prepare-context', '--recover-jobs']: group.add_argument(name, action='store_true')
    args = parser.parse_args()
    if args.recover_jobs: recover_sdk_jobs(ROOT, args.asset_root, args.output)
    elif args.node_inputs: node_inputs(args.asset_root)
    elif args.native_inputs: native_inputs(args.asset_root)
    else:
        producer = module('scripts/quality/prepare-mutation-runtime.py')
        node_inputs(args.asset_root)
        env_path = str(args.asset_root / 'node-runtime/bin') + ':/usr/bin:/bin'; os.environ['PATH'] = env_path
        producer.prepare(args.output / 'context', False, args.asset_root / 'mutation-rust-assets', args.asset_root / 'native-git', asset_root=args.asset_root)


if __name__ == '__main__': main()
