"""Materialize a verified vendor runtime privately; never run an installer."""
from __future__ import annotations
from compression.zstd import ZstdFile
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tarfile
import zipfile

if __package__:
    from .unicode_paths import path_key, validate_path
else:
    _spec = importlib.util.spec_from_file_location('_ud_runtime_paths', Path(__file__).with_name('unicode_paths.py'))
    _paths = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_paths)
    path_key, validate_path = _paths.path_key, _paths.validate_path

MAX_FILE = 32 * 1024 ** 2
MAX_TOTAL = 512 * 1024 ** 2
SHA = re.compile('[a-f0-9]{64}\\Z')


def regular(root, name):
    validate_path(name); current = Path(root)
    for part in name.split('/'):
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('VENDOR_RUNTIME_PATH_LINK')
    if not stat.S_ISREG(info.st_mode): raise ValueError('VENDOR_RUNTIME_FILE_REQUIRED')
    return current


def verify(file, row, maximum=MAX_FILE):
    if not SHA.fullmatch(row.get('sha256', '')) or type(row.get('size_bytes')) is not int or not 0 <= row['size_bytes'] <= maximum:
        raise ValueError('VENDOR_RUNTIME_RECEIPT_INVALID')
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400 or info.st_size != row['size_bytes']:
        raise ValueError('VENDOR_RUNTIME_INTEGRITY_FAILED')
    with file.open('rb') as source:
        before = os.fstat(source.fileno()); digest = hashlib.file_digest(source, 'sha256').hexdigest(); after = os.fstat(source.fileno())
    if digest != row['sha256'] or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('VENDOR_RUNTIME_INTEGRITY_FAILED')


def verified_archive(file, row):
    """Keep the exact verified ordinary-file handle through ZIP consumption."""
    if not SHA.fullmatch(row.get('sha256', '')) or type(row.get('size_bytes')) is not int or not 0 < row['size_bytes'] <= MAX_FILE:
        raise ValueError('VENDOR_RUNTIME_RECEIPT_INVALID')
    observed = file.lstat()
    if not stat.S_ISREG(observed.st_mode) or getattr(observed, 'st_file_attributes', 0) & 0x400:
        raise ValueError('VENDOR_RUNTIME_INTEGRITY_FAILED')
    stream = os.fdopen(os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb')
    try:
        before = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (observed.st_dev, observed.st_ino, row['size_bytes']) or hashlib.file_digest(stream, 'sha256').hexdigest() != row['sha256']:
            raise ValueError('VENDOR_RUNTIME_INTEGRITY_FAILED')
        stream.seek(0); return stream, before
    except BaseException: stream.close(); raise


def pe_machine(file, expected):
    with file.open('rb') as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b'MZ': raise ValueError('VENDOR_RUNTIME_PE_INVALID')
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset > 1024 ** 2: raise ValueError('VENDOR_RUNTIME_PE_INVALID')
        source.seek(offset); header = source.read(6)
        if len(header) != 6 or header[:4] != b'PE\0\0' or struct.unpack_from('<H', header, 4)[0] != expected:
            raise ValueError('VENDOR_RUNTIME_PE_ARCHITECTURE_INVALID')


def archive_members(stream, *, bzip2=False):
    if bzip2:
        with tarfile.open(fileobj=stream, mode='r|bz2') as tar:
            for member in tar:
                yield tar, member
        return
    parts = set()
    with zipfile.ZipFile(stream) as bundle:
        if len(bundle.infolist()) != 3:
            raise ValueError('VENDOR_RUNTIME_CONDA_FRAMING_INVALID')
        for item in bundle.infolist():
            if item.filename in parts or item.flag_bits & 1 or item.is_dir() or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG) or item.file_size > 256 * 1024 ** 2:
                raise ValueError('VENDOR_RUNTIME_CONDA_FRAMING_INVALID')
            parts.add(item.filename)
            if item.filename == 'metadata.json':
                if item.file_size > 4096 or json.loads(bundle.read(item)).get('conda_pkg_format_version') != 2:
                    raise ValueError('VENDOR_RUNTIME_CONDA_FRAMING_INVALID')
                continue
            if not re.fullmatch(r'(?:pkg|info)-[A-Za-z0-9_.-]+\.tar\.zst', item.filename):
                raise ValueError('VENDOR_RUNTIME_CONDA_FRAMING_INVALID')
            with bundle.open(item) as compressed, ZstdFile(compressed) as expanded, tarfile.open(fileobj=expanded, mode='r|') as tar:
                for member in tar:
                    yield tar, member
    if sum(name.startswith('pkg-') for name in parts) != 1 or sum(name.startswith('info-') for name in parts) != 1:
        raise ValueError('VENDOR_RUNTIME_CONDA_FRAMING_INVALID')


def materialize_archive(archive, descriptor, expected, output, *, bzip2=False):
    stream, before = verified_archive(archive, descriptor)
    seen, selected, records = set(), set(), []
    total = 0
    with stream:
        for tar, member in archive_members(stream, bzip2=bzip2):
            name = validate_path(member.name); key = path_key(name)
            # Publisher archives use fractional timestamps; other PAX
            # attributes can change path, link or file semantics.
            safe_pax = all(key in ('mtime', 'atime', 'ctime') and re.fullmatch(r'-?[0-9]{1,16}(?:\.[0-9]{1,20})?', value) for key, value in member.pax_headers.items())
            if key in seen or len(seen) >= 10000 or not safe_pax or not (member.isdir() or member.isfile()) or not 0 <= member.size <= MAX_FILE:
                raise ValueError('VENDOR_RUNTIME_ARCHIVE_MEMBER_INVALID')
            seen.add(key)
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError('VENDOR_RUNTIME_ARCHIVE_SIZE_INVALID')
            if name not in expected:
                continue
            if not member.isfile():
                raise ValueError('VENDOR_RUNTIME_SELECTED_FILE_INVALID')
            row = expected[name]
            target = output / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination, 1024 ** 2)
            verify(target, row)
            selected.add(name)
            records.append({key: row[key] for key in ('path', 'sha256', 'size_bytes')})
        if selected != set(expected):
            raise ValueError('VENDOR_RUNTIME_ARCHIVE_INCOMPLETE')
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('VENDOR_RUNTIME_ARCHIVE_CHANGED')
    return records


def materialize(recipe_file, archive, source_root, output, supplier_archive=None):
    recipe_bytes = recipe_file.read_bytes(); recipe = json.loads(recipe_bytes)
    if recipe.get('schema_version') != 1 or recipe.get('provider') != 'conda-vc-runtime' or recipe.get('platform') not in ('win32/arm64', 'win32/x64') or recipe.get('executable') != 'bin/perl.exe':
        raise ValueError('VENDOR_RUNTIME_RECIPE_INVALID')
    descriptor = recipe.get('archive', {})
    target_arch = 'win-arm64' if recipe['platform'] == 'win32/arm64' else 'win-64'
    if not re.fullmatch(r'https://conda\.anaconda\.org/conda-forge/' + target_arch + r'/vc14_runtime-[A-Za-z0-9_.-]+\.conda', descriptor.get('url', '')):
        raise ValueError('VENDOR_RUNTIME_AUTHORITY_INVALID')
    supplier = recipe.get('supplier')
    if (supplier is None) != (supplier_archive is None):
        raise ValueError('VENDOR_RUNTIME_SUPPLIER_ARCHIVE_REQUIRED')
    supplier_files = {}
    if output.exists() or output.is_symlink(): raise ValueError('VENDOR_RUNTIME_NEW_OUTPUT_REQUIRED')
    expected, keys = {}, set()
    for row in recipe.get('files', []):
        source, destination = validate_path(row['source']), validate_path(row['path'])
        if source in expected or path_key(destination) in keys or not (destination.startswith('bin/vcruntime') and destination.endswith('.dll') or destination.startswith('licenses/vendor/')):
            raise ValueError('VENDOR_RUNTIME_SELECTED_INVENTORY_INVALID')
        expected[source] = row; keys.add(path_key(destination))
    if not expected or len(expected) > 32: raise ValueError('VENDOR_RUNTIME_SELECTED_INVENTORY_INVALID')
    if supplier:
        arm = target_arch == 'win-arm64'
        authority = r'anaconda/win-arm64/perl-[A-Za-z0-9_.-]+\.tar\.bz2' if arm else r'conda-forge/win-64/perl-[A-Za-z0-9_.-]+\.conda'
        if not re.fullmatch(r'https://conda\.anaconda\.org/' + authority, supplier['archive'].get('url', '')):
            raise ValueError('VENDOR_RUNTIME_SUPPLIER_AUTHORITY_INVALID')
        for row in supplier.get('files', []):
            source, destination = validate_path(row['source']), validate_path(row['path'])
            if source in supplier_files or path_key(destination) in keys or not re.fullmatch(r'(?:bin|lib)/.+\.(?:exe|dll)', destination, re.I) or source != ('Library/' if arm else '') + destination:
                raise ValueError('VENDOR_RUNTIME_SUPPLIER_INVENTORY_INVALID')
            supplier_files[source] = row
            keys.add(path_key(destination))
        if not 1 <= len(supplier_files) <= 256 or not any(row['path'] == recipe['executable'] for row in supplier_files.values()):
            raise ValueError('VENDOR_RUNTIME_SUPPLIER_INVENTORY_INVALID')
    output.mkdir(mode=0o700); records = []; completed = False
    try:
        for row in recipe.get('base_files', []):
            source, destination = validate_path(row['source']), validate_path(row['path'])
            allowed = source == destination and destination.startswith(('bin/', 'lib/')) if supplier else destination.startswith('bin/') and '/' not in destination[4:]
            if not allowed or path_key(destination) in keys or len(records) >= (5000 if supplier else 32):
                raise ValueError('VENDOR_RUNTIME_BASE_INVENTORY_INVALID')
            keys.add(path_key(destination)); file = regular(source_root, source); verify(file, row)
            target = output / destination; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(file, target); verify(target, row)
            records.append({'path': destination, 'sha256': row['sha256'], 'size_bytes': row['size_bytes']})
        records.extend(materialize_archive(archive, descriptor, expected, output))
        if supplier:
            records.extend(materialize_archive(supplier_archive, supplier['archive'], supplier_files, output, bzip2=target_arch == 'win-arm64'))
        expected_machine = 0xAA64 if target_arch == 'win-arm64' else 0x8664
        for row in records:
            if row['path'].endswith(('.exe', '.dll')): pe_machine(output / row['path'], expected_machine)
        if not any(row['path'] == recipe['executable'] for row in records): raise ValueError('VENDOR_RUNTIME_EXECUTABLE_MISSING')
        receipt = {'schema_version': 1, 'provider': recipe['provider'], 'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(), 'archive_sha256': descriptor['sha256'], 'platform': recipe['platform'], 'files': sorted(records, key=lambda row: row['path'])}
        if supplier:
            receipt['supplier_archive_sha256'] = supplier['archive']['sha256']
        (output / 'materialization.json').write_text(json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        for row in records: (output / row['path']).chmod(0o555 if row['path'].endswith('.exe') else 0o444)
        (output / 'materialization.json').chmod(0o444)
        completed = True; return receipt
    finally:
        if not completed:
            for file in output.rglob('*'):
                if file.is_file() and not file.is_symlink(): file.chmod(0o600)
            shutil.rmtree(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'archive', 'source-root', 'output-dir'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--supplier-archive', type=Path)
    args = parser.parse_args(); print(json.dumps(materialize(args.recipe, args.archive, args.source_root, args.output_dir, args.supplier_archive)))
