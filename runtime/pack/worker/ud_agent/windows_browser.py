"""Private, non-executing materialization of the pinned Windows ARM64 browser."""
from __future__ import annotations
import ctypes
from contextlib import contextmanager, nullcontext
from ctypes import wintypes
import hashlib
import importlib.util
import json
import lzma
import mmap
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

if __package__:
    from .unicode_paths import path_key, validate_path
else:
    _spec = importlib.util.spec_from_file_location('_ud_edge_paths', Path(__file__).with_name('unicode_paths.py'))
    if _spec is None or _spec.loader is None:
        raise RuntimeError('EDGE_PATH_RULES_UNAVAILABLE')
    _paths = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_paths)
    path_key, validate_path = _paths.path_key, _paths.validate_path

MAX_FILE = 1024 * 1024**2
MAX_TOTAL = 2 * 1024**3


def verify(path: Path, record: dict) -> None:
    if (not isinstance(record, dict) or not isinstance(record.get('size_bytes'), int) or isinstance(record['size_bytes'], bool)
            or not 0 <= record['size_bytes'] <= MAX_FILE or not isinstance(record.get('sha256'), str)
            or not re.fullmatch('[a-f0-9]{64}', record['sha256'])):
        raise ValueError('EDGE_RECEIPT_INVALID')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != record['size_bytes'] or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('EDGE_ARTIFACT_INTEGRITY_FAILED')
    with path.open('rb') as source:
        before = os.fstat(source.fileno()); digest = hashlib.file_digest(source, 'sha256').hexdigest(); after = os.fstat(source.fileno())
    if digest != record['sha256'] or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('EDGE_ARTIFACT_INTEGRITY_FAILED')


def _copy_range(source, output: Path, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or size > MAX_FILE:
        raise ValueError('EDGE_LAYER_BOUNDS_INVALID')
    source.seek(offset)
    with output.open('xb') as target:
        remaining = size
        while remaining:
            chunk = source.read(min(1024**2, remaining))
            if not chunk:
                raise ValueError('EDGE_LAYER_TRUNCATED')
            target.write(chunk); remaining -= len(chunk)
        target.flush(); os.fsync(target.fileno())


def pe_resource(source: Path, identifiers: list, output: Path) -> None:
    """Read a resource tree numerically; never load or execute the PE image."""
    if not isinstance(identifiers, list) or len(identifiers) != 3 or any(not isinstance(v, (str, int)) or isinstance(v, bool) for v in identifiers):
        raise ValueError('EDGE_RESOURCE_ID_INVALID')
    with source.open('rb') as raw, mmap.mmap(raw.fileno(), 0, access=mmap.ACCESS_READ) as data:
        def span(offset, size):
            if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError('EDGE_PE_BOUNDS_INVALID')
            return data[offset:offset + size]
        def word(offset): return struct.unpack('<H', span(offset, 2))[0]
        def dword(offset): return struct.unpack('<I', span(offset, 4))[0]
        if span(0, 2) != b'MZ': raise ValueError('EDGE_PE_INVALID')
        nt = dword(60)
        if span(nt, 4) != b'PE\0\0': raise ValueError('EDGE_PE_INVALID')
        count, optional_size = word(nt + 6), word(nt + 20)
        if not 1 <= count <= 96 or not 112 <= optional_size <= 4096: raise ValueError('EDGE_PE_INVALID')
        optional = nt + 24; magic = word(optional)
        directories = 96 if magic == 0x10b else 112 if magic == 0x20b else 0
        if not directories or optional_size < directories + 24 or dword(optional + directories - 4) < 3: raise ValueError('EDGE_PE_INVALID')
        resource_rva, resource_size = dword(optional + directories + 16), dword(optional + directories + 20)
        sections = []
        for index in range(count):
            item = optional + optional_size + index * 40
            span(item, 40)
            sections.append((dword(item + 12), dword(item + 20), dword(item + 16)))
        def rva(value, size):
            candidates = [start + value - virtual for virtual, start, length in sections if virtual <= value and value - virtual + size <= length]
            if len(candidates) != 1: raise ValueError('EDGE_PE_RVA_INVALID')
            span(candidates[0], size)
            return candidates[0]
        base = rva(resource_rva, resource_size)
        def resource_span(offset, size):
            if offset < 0 or offset + size > resource_size: raise ValueError('EDGE_RESOURCE_BOUNDS_INVALID')
            return base + offset
        directory = 0; seen = set()
        for depth, wanted in enumerate(identifiers):
            if directory in seen: raise ValueError('EDGE_RESOURCE_CYCLE')
            seen.add(directory); table = resource_span(directory, 16)
            entries = word(table + 12) + word(table + 14)
            if entries > 4096: raise ValueError('EDGE_RESOURCE_LIMIT_EXCEEDED')
            resource_span(directory + 16, entries * 8)
            matches = []
            for index in range(entries):
                item = table + 16 + index * 8; name = dword(item)
                if name & 0x80000000:
                    string = resource_span(name & 0x7fffffff, 2); length = word(string)
                    if length > 256: raise ValueError('EDGE_RESOURCE_ID_INVALID')
                    resource_span((name & 0x7fffffff) + 2, length * 2)
                    name = span(string + 2, length * 2).decode('utf-16le', errors='strict')
                if name == wanted: matches.append(dword(item + 4))
            if len(matches) != 1: raise ValueError('EDGE_RESOURCE_NOT_UNIQUE')
            selected = matches[0]
            if depth < 2:
                if not selected & 0x80000000: raise ValueError('EDGE_RESOURCE_TREE_INVALID')
                directory = selected & 0x7fffffff
            else:
                if selected & 0x80000000: raise ValueError('EDGE_RESOURCE_TREE_INVALID')
                item = resource_span(selected, 16); size = dword(item + 4)
                _copy_range(raw, output, rva(dword(item), size), size)


def msi_stream(msi: Path, name: str, output: Path, record: dict) -> None:
    """Query one Binary-table stream using read-only MSI APIs, with no actions."""
    if sys.platform != 'win32': raise RuntimeError('EDGE_NATIVE_WINDOWS_MSI_API_REQUIRED')
    if not re.fullmatch('[A-Za-z0-9_.-]{1,72}', name): raise ValueError('EDGE_MSI_STREAM_INVALID')
    api = ctypes.WinDLL('msi.dll', winmode=0x800, use_last_error=True)
    signatures = {
        'MsiOpenDatabaseW': ([wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT)], wintypes.UINT),
        'MsiDatabaseOpenViewW': ([wintypes.UINT, wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT)], wintypes.UINT),
        'MsiCreateRecord': ([wintypes.UINT], wintypes.UINT), 'MsiRecordSetStringW': ([wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR], wintypes.UINT),
        'MsiViewExecute': ([wintypes.UINT, wintypes.UINT], wintypes.UINT), 'MsiViewFetch': ([wintypes.UINT, ctypes.POINTER(wintypes.UINT)], wintypes.UINT),
        'MsiRecordReadStream': ([wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)], wintypes.UINT),
        'MsiCloseHandle': ([wintypes.UINT], wintypes.UINT),
    }
    for method, (arguments, result) in signatures.items():
        function = getattr(api, method); function.argtypes = arguments; function.restype = result
    handles = []
    def checked(code):
        if code != 0: raise RuntimeError('EDGE_MSI_READ_FAILED:' + str(code))
    try:
        database, view, row = wintypes.UINT(), wintypes.UINT(), wintypes.UINT()
        checked(api.MsiOpenDatabaseW(str(msi), None, ctypes.byref(database))); handles.append(database.value)
        checked(api.MsiDatabaseOpenViewW(database, 'SELECT `Data` FROM `Binary` WHERE `Name` = ?', ctypes.byref(view))); handles.append(view.value)
        parameters = api.MsiCreateRecord(1)
        if not parameters: raise RuntimeError('EDGE_MSI_READ_FAILED:record')
        handles.append(parameters); checked(api.MsiRecordSetStringW(parameters, 1, name)); checked(api.MsiViewExecute(view, parameters))
        checked(api.MsiViewFetch(view, ctypes.byref(row))); handles.append(row.value)
        total = 0; buffer = ctypes.create_string_buffer(65536)
        with output.open('xb') as target:
            while True:
                count = wintypes.DWORD(len(buffer)); checked(api.MsiRecordReadStream(row, 1, buffer, ctypes.byref(count)))
                if count.value > len(buffer) or total + count.value > record['size_bytes']: raise ValueError('EDGE_MSI_STREAM_LIMIT_EXCEEDED')
                if count.value == 0: break
                target.write(buffer.raw[:count.value]); total += count.value
            target.flush(); os.fsync(target.fileno())
        second = wintypes.UINT(); result = api.MsiViewFetch(view, ctypes.byref(second))
        if result != 259:
            if result == 0: handles.append(second.value)
            raise ValueError('EDGE_MSI_STREAM_NOT_UNIQUE')
    finally:
        errors = [api.MsiCloseHandle(handle) for handle in reversed(handles)]
        if any(code != 0 for code in errors): raise RuntimeError('EDGE_MSI_CLOSE_FAILED')
    verify(output, record)


def lzma_layer(source: Path, output: Path, record: dict) -> None:
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=MAX_FILE)
    total = 0
    with source.open('rb') as raw, output.open('xb') as target:
        while not decoder.eof:
            chunk = raw.read(1024**2) if decoder.needs_input else b''
            if not chunk and decoder.needs_input: raise ValueError('EDGE_LZMA_TRUNCATED')
            data = decoder.decompress(chunk, max_length=1024**2); total += len(data)
            if total > record['size_bytes']: raise ValueError('EDGE_LZMA_LIMIT_EXCEEDED')
            target.write(data)
        if decoder.unused_data or raw.read(1): raise ValueError('EDGE_LZMA_TRAILING_BYTES')
        target.flush(); os.fsync(target.fileno())
    verify(output, record)


def number7z(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64: raise ValueError('EDGE_7Z_INTEGER_INVALID')
    for extra in range(8):
        if value < 1 << (7 * (extra + 1)):
            return bytes([(0xff << (8 - extra) & 0xff) | (value >> (8 * extra))]) + value.to_bytes(8, 'little')[:extra]
    return b'\xff' + value.to_bytes(8, 'little')


def frame_bcj2(source: Path, output: Path) -> None:
    with source.open('rb') as raw:
        header = raw.read(20)
        if len(header) != 20: raise ValueError('EDGE_BCJ2_HEADER_INVALID')
        sizes = struct.unpack('<5I', header); packed = sum(sizes[1:])
        if not 0 < sizes[0] <= MAX_FILE or packed > MAX_FILE or source.stat().st_size != packed + 20 or sizes[0] != sum(sizes[1:4]) or sizes[2] % 4 or sizes[3] % 4: raise ValueError('EDGE_BCJ2_HEADER_INVALID')
        folder = b'\x04' + b'\x01\x00' * 3 + b'\x14\x03\x03\x01\x1b\x04\x01\x05\x00\x04\x01\x03\x02\x02\x06\x01\x00'
        pack = b'\x06\x00\x04\x09' + b''.join(number7z(sizes[i]) for i in [1, 4, 2, 3]) + b'\x00'
        unpack = b'\x07\x0b\x01\x00' + folder + b'\x0c' + b''.join(number7z(sizes[i]) for i in [3, 2, 1, 0]) + b'\x00'
        name = b'\x00' + 'layer.tar\0'.encode('utf-16le')
        metadata = b'\x01\x04' + pack + unpack + b'\x00\x05\x01\x11' + number7z(len(name)) + name + b'\x00\x00'
        next_header = struct.pack('<QQI', packed, len(metadata), zlib.crc32(metadata) & 0xffffffff)
        signature = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack('<I', zlib.crc32(next_header) & 0xffffffff) + next_header
        with output.open('xb') as target:
            target.write(signature)
            for i in [1, 4, 2, 3]:
                raw.seek(20 + sum(sizes[1:i])); remaining = sizes[i]
                while remaining:
                    chunk = raw.read(min(1024**2, remaining))
                    if not chunk: raise ValueError('EDGE_BCJ2_TRUNCATED')
                    target.write(chunk); remaining -= len(chunk)
            target.write(metadata); target.flush(); os.fsync(target.fileno())


def _decoder_run(decoder: Path, command: str, directory: Path) -> bytes:
    """Invoke the pinned Unicode/long-path decoder without installer execution."""
    environment = {'PATH': str(Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32') if sys.platform == 'win32' else '/usr/bin:/bin', 'LANG': 'C'}
    if sys.platform == 'win32': environment['SystemRoot'] = os.environ.get('SystemRoot', 'C:\\Windows')
    with tempfile.TemporaryFile(dir=directory) as output:
        flags = ['l', '-slt', '-ba', '-sccUTF-8'] if command == 'l' else ['x', '-y', '-bd', '-bb0', '-sccUTF-8'] if command == 'x' else None
        if flags is None: raise ValueError('EDGE_DECODER_COMMAND_INVALID')
        process = subprocess.Popen([str(decoder), *flags, '--', 'archive.7z'], cwd=directory, env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=120)
        except BaseException:
            process.kill(); process.wait(timeout=5); raise
        if process.returncode != 0: raise RuntimeError('EDGE_DECODER_FAILED:' + str(process.returncode))
        if output.tell() > 4 * 1024**2: raise ValueError('EDGE_DECODER_OUTPUT_LIMIT_EXCEEDED')
        output.seek(0); return output.read(4 * 1024**2 + 1)


def _listed(data: bytes) -> list[dict]:
    blocks = re.split(r'\n\s*\n', data.decode('utf-8', errors='strict').replace('\r\n', '\n').strip())
    result, names, total = [], set(), 0
    allowed = {'Path', 'Size', 'Packed Size', 'Modified', 'Created', 'Accessed', 'Attributes', 'CRC', 'Encrypted', 'Method', 'Block', 'Comment', 'Host OS', 'Version', 'Volume Index', 'Offset', 'Folder'}
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            if ' = ' not in line: raise ValueError('EDGE_ARCHIVE_LISTING_INVALID')
            key, value = line.split(' = ', 1)
            if key not in allowed or key in fields: raise ValueError('EDGE_ARCHIVE_LISTING_INVALID')
            fields[key] = value
        if (not {'Path', 'Size'} <= fields.keys() or fields.get('Encrypted', '-') != '-'
                or fields.get('Folder', '-') not in ('+', '-') or not re.fullmatch('[0-9]{1,12}', fields['Size'])): raise ValueError('EDGE_ARCHIVE_LISTING_INVALID')
        attributes = fields.get('Attributes', '')
        # Unix-mode suffixes may occur in technical listings. A link/reparse
        # record is never accepted even when its target resembles a normal file.
        if not re.fullmatch(r'[D.RHSA ]*(?: [d-][rwx-]{9})?', attributes): raise ValueError('EDGE_ARCHIVE_LISTING_INVALID')
        is_directory = attributes.startswith('D') or fields.get('Folder') == '+'
        name = fields['Path'].replace('\\', '/')
        if is_directory and name.endswith('/'): name = name[:-1]
        validate_path(name); key = path_key(name); size = int(fields['Size']); total += size
        if key in names or len(names) >= 20000 or size > MAX_FILE or total > MAX_TOTAL or is_directory and size != 0: raise ValueError('EDGE_ARCHIVE_MEMBER_INVALID')
        names.add(key); result.append({'path': name, 'size_bytes': size, 'directory': is_directory})
    if not result: raise ValueError('EDGE_ARCHIVE_LISTING_INVALID')
    kinds = {path_key(item['path']): item['directory'] for item in result}
    for item in result:
        parts = path_key(item['path']).split('/')
        if any(kinds.get('/'.join(parts[:index])) is False for index in range(1, len(parts))): raise ValueError('EDGE_ARCHIVE_MEMBER_INVALID')
    return result


def _decode7z(decoder: Path, archive: Path, destination: Path, expected: list[dict]) -> None:
    destination.mkdir(mode=0o700)
    staged = destination / 'archive.7z'
    # Both paths are newly owned; the archive is a verified intermediate layer.
    shutil.copyfile(archive, staged)
    listed = _listed(_decoder_run(decoder, 'l', destination))
    files = {item['path']: item['size_bytes'] for item in listed if not item['directory']}
    wanted = {item['path']: item['size_bytes'] for item in expected}
    if len(wanted) != len(expected) or files != wanted: raise ValueError('EDGE_ARCHIVE_INVENTORY_MISMATCH')
    _decoder_run(decoder, 'x', destination); staged.unlink()
    actual = []
    for base, directories, names in os.walk(destination, followlinks=False):
        for name in directories + names:
            file = Path(base) / name; info = file.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400: raise ValueError('EDGE_ARCHIVE_LINK_INVALID')
            if stat.S_ISREG(info.st_mode): actual.append(file.relative_to(destination).as_posix())
            elif not stat.S_ISDIR(info.st_mode): raise ValueError('EDGE_ARCHIVE_LINK_INVALID')
    if set(actual) != set(wanted): raise ValueError('EDGE_ARCHIVE_INVENTORY_MISMATCH')
    for item in expected: verify(destination / item['path'], item)


def _tar_member(archive: Path, output: Path, selected: dict) -> None:
    """Validate every member before copying just the fixed mini-installer."""
    names, found, total = set(), None, 0
    with tarfile.open(archive, mode='r:') as source:
        for member in source:
            validate_path(member.name); key = path_key(member.name); total += member.size
            if key in names or len(names) >= 20000 or not member.isfile() or not 0 <= member.size <= MAX_FILE or total > MAX_TOTAL: raise ValueError('EDGE_TAR_MEMBER_INVALID')
            names.add(key)
            if member.name == selected['member']: found = member
        if found is None or found.size != selected['size_bytes']: raise ValueError('EDGE_TAR_MEMBER_MISSING')
        stream = source.extractfile(found)
        if stream is None: raise ValueError('EDGE_TAR_MEMBER_MISSING')
        with stream, output.open('xb') as target:
            while chunk := stream.read(1024**2): target.write(chunk)
            target.flush(); os.fsync(target.fileno())
    verify(output, selected)


def _machine(path: Path) -> int:
    with path.open('rb') as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b'MZ': raise ValueError('EDGE_EXECUTABLE_PE_INVALID')
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset > 1024**2: raise ValueError('EDGE_EXECUTABLE_PE_INVALID')
        source.seek(offset); pe = source.read(6)
        if len(pe) != 6 or pe[:4] != b'PE\0\0': raise ValueError('EDGE_EXECUTABLE_PE_INVALID')
        return struct.unpack_from('<H', pe, 4)[0]


def _materialize(msi_path: Path, decoder_path: Path, recipe: dict, output_dir: Path, *, extracted_payload: Path | None = None, decoder_record: dict | None = None) -> dict:
    """Populate one private browser directory; every intermediate is hash-bound."""
    msi_path, decoder_path, output_dir = Path(msi_path), Path(decoder_path), Path(output_dir)
    if (recipe.get('schema_version') != 1 or recipe.get('provider') != 'microsoft-edge' or recipe.get('platform') != 'win32/arm64'
            or recipe.get('executable') != 'msedge.exe' or not isinstance(recipe.get('files'), list) or not 1 <= len(recipe['files']) <= 20000):
        raise ValueError('EDGE_RECIPE_INVALID')
    if extracted_payload is None and (sys.platform != 'win32' or _machine(decoder_path) != 0xaa64): raise RuntimeError('EDGE_NATIVE_ARM64_DECODER_REQUIRED')
    if output_dir.exists() or output_dir.is_symlink() or not output_dir.parent.is_dir(): raise ValueError('EDGE_DESTINATION_INVALID')
    names = set()
    for item in recipe['files']:
        name = validate_path(item['path']); key = path_key(name)
        if key in names: raise ValueError('EDGE_RECIPE_DUPLICATE_PATH')
        names.add(key)
    prefix = validate_path(recipe['source_directory'])
    verify(msi_path, recipe['archive']); verify(decoder_path, decoder_record or recipe['decoder'])
    stages = recipe['stages']
    with tempfile.TemporaryDirectory(prefix='.edge-materialize-', dir=output_dir.parent) as temporary:
        root = Path(temporary); payload = root / 'payload.exe'
        if extracted_payload is None: msi_stream(msi_path, stages['payload']['stream'], payload, stages['payload'])
        else: verify(Path(extracted_payload), stages['payload']); shutil.copyfile(extracted_payload, payload)
        compressed, block = root / 'omaha.lzma', root / 'omaha.bcj2'
        pe_resource(payload, stages['omaha_resource']['identifiers'], compressed); verify(compressed, stages['omaha_resource']); payload.unlink()
        lzma_layer(compressed, block, stages['omaha_block']); compressed.unlink()
        framed = root / 'omaha.7z'; frame_bcj2(block, framed); block.unlink()
        tar_record = {**stages['omaha_tar'], 'path': 'layer.tar'}
        _decode7z(decoder_path, framed, root / 'omaha', [tar_record]); framed.unlink()
        mini = root / 'mini.exe'; _tar_member(root / 'omaha/layer.tar', mini, stages['mini_installer']); shutil.rmtree(root / 'omaha')
        browser_resource = root / 'browser.7z'; pe_resource(mini, stages['browser_resource']['identifiers'], browser_resource); verify(browser_resource, stages['browser_resource']); mini.unlink()
        inner = {**stages['browser_archive'], 'path': stages['browser_archive']['member']}
        _decode7z(decoder_path, browser_resource, root / 'inner', [inner]); browser_resource.unlink()
        full = [{**item, 'path': prefix + '/' + item['path']} for item in recipe['files']]
        _decode7z(decoder_path, root / 'inner' / inner['path'], root / 'unpacked', full); shutil.rmtree(root / 'inner')
        final = root / 'unpacked' / prefix
        if _machine(final / 'msedge.exe') != 0xaa64: raise ValueError('EDGE_EXECUTABLE_ARCHITECTURE_INVALID')
        verify(msi_path, recipe['archive']); verify(decoder_path, decoder_record or recipe['decoder'])
        os.rename(final, output_dir)
    return {'executable': 'msedge.exe', 'files': recipe['files'], 'provider': 'microsoft-edge', 'version': recipe['version']}


@contextmanager
def _locked_installer(path: Path):
    api = ctypes.WinDLL('kernel32.dll', winmode=0x800, use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    api.GetFileInformationByHandleEx.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]; api.CloseHandle.restype = wintypes.BOOL
    handle = api.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x200000, None)
    if not handle or handle == ctypes.c_void_p(-1).value: raise OSError('EDGE_MSI_READ_LOCK_FAILED')
    try:
        attributes = (wintypes.DWORD * 2)()
        if not api.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)) or attributes[0] & 0x410:
            raise ValueError('EDGE_MSI_REPARSE_POINT_INVALID')
        yield
    finally:
        if not api.CloseHandle(handle): raise RuntimeError('EDGE_MSI_READ_LOCK_CLOSE_FAILED')


def materialize(msi_path: Path, decoder_path: Path, recipe: dict, output_dir: Path, *, extracted_payload: Path | None = None, decoder_record: dict | None = None) -> dict:
    lock = _locked_installer(Path(msi_path)) if extracted_payload is None and sys.platform == 'win32' else nullcontext()
    with lock:
        return _materialize(msi_path, decoder_path, recipe, output_dir, extracted_payload=extracted_payload, decoder_record=decoder_record)


def materialize_pack(pack_dir: Path, msi: Path, recipe_path: str, decoder_path: str, output_dir: str, manifest_path: str) -> None:
    root = Path(pack_dir)
    if root.is_symlink() or not root.is_dir(): raise ValueError('EDGE_PACK_ROOT_INVALID')
    for name in [recipe_path, decoder_path, output_dir, manifest_path]: validate_path(name)
    manifest_file = root / manifest_path; manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    expected = {'provider': 'microsoft-edge', 'recipe': recipe_path, 'decoder': decoder_path, 'directory': output_dir}
    if manifest.get('schema_version') != 1 or manifest.get('deferred_browser') != expected or manifest.get('executable') != output_dir + '/msedge.exe': raise ValueError('EDGE_DEFERRED_MANIFEST_INVALID')
    base = manifest['files']; by_name = {item['path']: item for item in base}
    if len(by_name) != len(base) or recipe_path not in by_name or decoder_path not in by_name: raise ValueError('EDGE_DEFERRED_MANIFEST_INVALID')
    for item in base:
        name = validate_path(item['path'])
        if name == manifest_path or name == output_dir or name.startswith(output_dir + '/'): raise ValueError('EDGE_DEFERRED_MANIFEST_INVALID')
        verify(root / name, item)
    recipe = json.loads((root / recipe_path).read_text(encoding='utf-8'))
    result = materialize(msi, root / decoder_path, recipe, root / output_dir)
    merged = [*base, *[{**item, 'path': output_dir + '/' + item['path']} for item in result['files']]]
    if len({path_key(item['path']) for item in merged}) != len(merged): raise ValueError('EDGE_FINAL_MANIFEST_COLLISION')
    manifest['files'] = sorted(merged, key=lambda item: item['path']); del manifest['deferred_browser']
    temporary = manifest_file.with_name(manifest_file.name + '.materialized')
    with temporary.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(manifest, sort_keys=True, indent=2) + '\n'); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, manifest_file)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['pack-dir', 'msi', 'recipe', 'decoder', 'output-dir', 'manifest']: parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    materialize_pack(Path(args.pack_dir), Path(args.msi), args.recipe, args.decoder, args.output_dir, args.manifest)
