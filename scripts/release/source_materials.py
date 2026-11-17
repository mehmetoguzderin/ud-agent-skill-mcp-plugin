"""Exact publisher package/source inventories; data inspection never runs targets."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import uuid
import zipfile
import zlib

PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]+\Z')
VERSION = re.compile(r'(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~_-]*\Z')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def control_records(raw):
    if not isinstance(raw, bytes) or len(raw) > 128 * 1024**2 or b'\0' in raw:
        raise ValueError('bounded publisher control records required')
    records, record, previous = [], {}, None
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if not line:
            if record:
                records.append(record); record = {}; previous = None
        elif line[0] in ' \t':
            if previous is None:
                raise ValueError('control continuation has no field')
            record[previous] += '\n' + line[1:]
        else:
            name, separator, value = line.partition(':')
            if not separator or not re.fullmatch('[A-Za-z0-9-]+', name) or name in record:
                raise ValueError('duplicate or malformed publisher control field')
            record[name] = value.lstrip(' \t'); previous = name
    if record:
        records.append(record)
    return records


def source_identity(value, default_version=None, dependency=False):
    expression = r'([a-z0-9][a-z0-9+.-]+)\s*\(=\s*([^()\s]+)\)' if dependency else r'([a-z0-9][a-z0-9+.-]+)(?:\s+\(([^()\s]+)\))?'
    match = re.fullmatch(expression, value)
    if not match or not VERSION.fullmatch(match[2] or default_version or ''):
        raise ValueError('exact Debian source identity required')
    return {'name': match[1], 'version': match[2] or default_version}


def installed_packages(status, manifest, architecture):
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('unsupported guest architecture')
    expected = {}
    for line in manifest.decode('utf-8', errors='strict').splitlines():
        parts = line.split('\t')
        if len(parts) != 2:
            raise ValueError('publisher package manifest has malformed rows')
        name, version = parts
        name = name.removesuffix(':' + architecture)
        if not PACKAGE.fullmatch(name) or not VERSION.fullmatch(version) or name in expected:
            raise ValueError('publisher package identity is unsafe or duplicated')
        expected[name] = version
    found = {}
    for record in control_records(status):
        if record.get('Status') != 'install ok installed':
            continue
        name, version = record.get('Package', ''), record.get('Version', '')
        if name not in expected or expected[name] != version or name in found or record.get('Architecture') not in ('all', architecture):
            raise ValueError('actual guest installation differs from its publisher manifest')
        dependencies = []
        for field in ('Built-Using', 'Static-Built-Using'):
            if record.get(field):
                dependencies.extend(source_identity(item.strip(), dependency=True) for item in record[field].split(','))
        found[name] = {'name': name, 'version': version, 'architecture': record['Architecture'],
                       'source': source_identity(record.get('Source', name), version), 'built_using': dependencies,
                       'notice_guest_path': '/usr/share/doc/' + name + '/copyright', 'notice_basename': sha(name.encode()) + '.txt'}
    if not expected or set(found) != set(expected):
        raise ValueError('guest package inventory is missing or incomplete')
    return [found[name] for name in sorted(found)]


def guest_partition(raw):
    """Validate primary GPT and select its sole bounded root filesystem."""
    raw = Path(raw); size = raw.stat().st_size
    if size < 34 * 512 or size % 512:
        raise ValueError('guest raw disk has an invalid size')
    with raw.open('rb') as source:
        source.seek(512); header = source.read(512)
        if header[:8] != b'EFI PART':
            raise ValueError('guest disk has no primary GPT')
        header_size, checksum = struct.unpack_from('<II', header, 12)
        if not 92 <= header_size <= 512:
            raise ValueError('GPT header size is invalid')
        unsigned = bytearray(header[:header_size]); unsigned[16:20] = b'\0' * 4
        current, backup, first, last = struct.unpack_from('<QQQQ', header, 24)
        entry_lba, count, width, entries_crc = struct.unpack_from('<QIII', header, 72)
        if zlib.crc32(unsigned) != checksum or struct.unpack_from('<I',header,8)[0] != 0x10000 or struct.unpack_from('<I',header,20)[0] != 0 or entry_lba < 2 or current != 1 or backup != size // 512 - 1 or not 34 <= first <= last < backup or not 1 <= count <= 4096 or not 128 <= width <= 1024 or width % 8 or count * width > 4 * 1024**2 or entry_lba * 512 + count * width > first * 512:
            raise ValueError('GPT bounds or header checksum differ')
        source.seek(entry_lba * 512); entries = source.read(count * width)
    if len(entries) != count * width or zlib.crc32(entries) != entries_crc:
        raise ValueError('GPT partition table checksum differs')
    partitions = []
    for index in range(count):
        record = entries[index * width:(index + 1) * width]
        if record[:16] == b'\0' * 16:
            continue
        start, end = struct.unpack_from('<QQ', record, 32)
        name = record[56:128].decode('utf-16-le', errors='strict').split('\0', 1)[0]
        if not first <= start <= end <= last or any(not (end < item['first_lba'] or start > item['last_lba']) for item in partitions):
            raise ValueError('GPT partitions escape or overlap')
        partitions.append({'partition': index + 1, 'type_guid': str(uuid.UUID(bytes_le=record[:16])), 'first_lba': start, 'last_lba': end, 'name': name,
                           'offset': start * 512, 'size': (end - start + 1) * 512, 'raw_size': size})
    roots = [item for item in partitions if item['name'] == 'cloudimg-rootfs']
    if len(roots) != 1:
        raise ValueError('guest root filesystem is missing or ambiguous')
    return roots[0]


def go_build_info(binary, tool, expected_tool_sha256):
    """`go version` reads executable metadata; it never executes the target."""
    binary, tool = Path(binary), Path(tool).resolve(strict=True)
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size > 512 * 1024**2 or sha(tool.read_bytes()) != expected_tool_sha256:
        raise ValueError('Go inspector or binary identity differs')
    result = subprocess.run([str(tool), 'version', '-m', '-json', str(binary.resolve(strict=True))], capture_output=True, timeout=30, check=False,
                            env={'PATH': str(tool.parent), 'GOENV': 'off', 'GOTOOLCHAIN': 'local'})
    if result.returncode or result.stderr or not result.stdout or len(result.stdout) > 8 * 1024**2:
        raise ValueError('Go executable metadata inspection failed')
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not re.fullmatch(r'go\d+\.\d+(?:\.\d+)?', data.get('GoVersion', '')) or not isinstance(data.get('Deps'), list):
        raise ValueError('Go binary has incomplete module metadata')
    dependencies = []
    for original in data['Deps']:
        item = original.get('Replace') or original
        if not isinstance(item, dict) or not isinstance(item.get('Path'), str) or not re.fullmatch(r'v[0-9][A-Za-z0-9.+-]*', item.get('Version', '')) or item.get('Sum')is not None and not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', item['Sum']):
            raise ValueError('Go binary dependency has no exact module content identity')
        dependencies.append({'path': item['Path'], 'version': item['Version'], 'h1': item.get('Sum')})
    return {'go_version': data['GoVersion'], 'main': data.get('Main'), 'path': data.get('Path'), 'dependencies': dependencies,
            'build_settings': data.get('Settings', []), 'target_execution': False, 'raw': data}


def go_zip_hash(archive, module_path, version):
    prefix = module_path + '@' + version + '/'
    digest = hashlib.sha256(); names = set(); entries = []; total = 0
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            name = member.filename
            if not name.startswith(prefix) or '\n' in name or '\r' in name or '\\' in name or '\0' in name or any(part in ('.', '..') for part in name.split('/')) or name in names or member.file_size < 0 or member.file_size > 1024**3 or len(names) >= 100_000:
                raise ValueError('Go source ZIP has an unsafe or duplicate member')
            names.add(name); total += member.file_size
            if total > 8 * 1024**3 or ((member.external_attr >> 16) & 0o170000) not in (0, 0o040000, 0o100000):
                raise ValueError('Go source ZIP exceeds its bound or contains a link')
            entries.append(member)
        for member in sorted(entries, key=lambda item:item.filename.encode('utf-8')):
            with source.open(member) as content:
                fingerprint = hashlib.file_digest(content, 'sha256').hexdigest()
            digest.update((fingerprint + '  ' + member.filename + '\n').encode())
    if not entries:
        raise ValueError('Go source ZIP is empty')
    return 'h1:' + base64.b64encode(digest.digest()).decode()


def source_index(raw):
    """Retain every checksum-listed source component, including orig/debian data."""
    result={}
    for record in control_records(raw):
        name,version,directory=record.get('Package',''),record.get('Version',''),record.get('Directory','')
        if not PACKAGE.fullmatch(name)or not VERSION.fullmatch(version)or not re.fullmatch(r'pool/(?:updates/)?(?:main|universe|restricted|multiverse)/[A-Za-z0-9+._/-]+',directory)or any(part in('','.','..')for part in directory.split('/')):
            raise ValueError('source index has an unsafe or unversioned identity')
        files=[];seen=set()
        for line in record.get('Checksums-Sha256','').splitlines():
            if not line.strip():continue
            fields=line.split()
            if len(fields)!=3 or not re.fullmatch('[0-9a-f]{64}',fields[0])or not fields[1].isdigit()or not 0<int(fields[1])<=8*1024**3 or not re.fullmatch(r'[A-Za-z0-9+_.~%-]+',fields[2])or fields[2]in seen:
                raise ValueError('source component has an invalid checksum, size or filename')
            seen.add(fields[2]);files.append({'path':directory+'/'+fields[2],'sha256':fields[0],'size_bytes':int(fields[1])})
        if not files or len([item for item in files if item['path'].endswith('.dsc')])!=1:
            raise ValueError('source package lacks a complete checksummed descriptor')
        key=name+'\0'+version
        if key in result:raise ValueError('source index duplicates an exact source version')
        result[key]={'name':name,'version':version,'files':files}
    return result


def source_requirements(packages):
    required={}
    for item in packages:
        for origin in [item['source'],*item['built_using']]:
            key=origin['name']+'\0'+origin['version']
            record=required.setdefault(key,{**origin,'consumers':[]})
            consumer={'name':item['name'],'version':item['version'],'architecture':item['architecture'],'relationship':'source'if origin is item['source']else'built-using'}
            if consumer not in record['consumers']:record['consumers'].append(consumer)
    return [required[key]for key in sorted(required)]
