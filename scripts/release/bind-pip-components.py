"""Bind exact pip/distlib distributions, launcher source and original notices."""
from __future__ import annotations
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import tarfile
import zipfile
from email.parser import BytesParser

SPEC = importlib.util.spec_from_file_location('ud_packaging_materials', Path(__file__).with_name('source-bundle.py'))
materials = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(materials)


def tar_members(base, row, prefix):
    stream, _, original = materials.opened(base, row); records = {}; bodies = {}; notices = []; total = 0; seen = set()
    try:
        with tarfile.open(fileobj=stream, mode='r:*') as archive:
            for entry in archive:
                name = materials.safe(entry.name.rstrip('/') if entry.isdir() else entry.name)
                if name in seen or len(seen) >= 50000: raise ValueError('packaging source has duplicate or oversized member inventory')
                seen.add(name)
                if name == prefix.rstrip('/') and entry.isdir(): continue
                if not name.startswith(prefix): raise ValueError('packaging source has unsafe or foreign members')
                if entry.isdir(): continue
                if not entry.isfile() or not 0 <= entry.size <= 32 * 1024**2: raise ValueError('packaging source member is special or oversized')
                total += entry.size
                if total > 256 * 1024**2: raise ValueError('packaging source expansion exceeds bound')
                with archive.extractfile(entry) as source: body = source.read(entry.size + 1)
                if len(body) != entry.size: raise ValueError('packaging source member is truncated')
                relative = name[len(prefix):]; records[relative] = {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'source_member': name}
                if re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$', relative.rsplit('/',1)[-1], re.I): notices.append({'source_archive_sha256': original['sha256'], **records[relative]})
                if relative in ('PC/launcher.c','PC/CLISimpleLauncher.vcxproj','PC/GUISimpleLauncher.vcxproj','PKG-INFO','src/pip/_vendor/vendor.txt','distlib/__init__.py'): bodies[relative] = body
    finally: stream.close()
    if not notices: raise ValueError('original packaging notices missing')
    return original, records, bodies, notices


def verify_record(entries, record):
    rows = list(csv.reader(io.StringIO(record.decode('utf-8')))); expected = {}; record_paths = [name for name in entries if name.endswith('.dist-info/RECORD')]
    if len(record_paths) != 1: raise ValueError('unique wheel RECORD required')
    for row in rows:
        if len(row) != 3 or row[0] in expected: raise ValueError('wheel RECORD is malformed or duplicated')
        name, fingerprint, size = row
        if name == record_paths[0]:
            if fingerprint or size: raise ValueError('wheel RECORD self-entry differs')
        else:
            actual = entries.get(name)
            if actual is None or fingerprint != 'sha256=' + base64.urlsafe_b64encode(bytes.fromhex(actual['sha256'])).decode().rstrip('=') or size != str(actual['size_bytes']): raise ValueError('wheel RECORD omits or changes actual member bytes')
        expected[name] = True
    if set(expected) != set(entries): raise ValueError('wheel RECORD inventory is incomplete')


def derive(root, original_sources, wheel_base):
    lock = json.loads((root / 'runtime/materials/pip-distlib-sources.lock.json').read_bytes()); sources = []; notices = []; content = {}
    if lock.get('qualification') != 'exact-pip-distlib-publisher-source-component-inputs' or [(row['name'],row['version']) for row in lock['components']] != [('pip','26.2.2'),('distlib','0.4.2')]: raise ValueError('exact original packaging source contract required')
    for component in lock['components']:
        stream, _, metadata = materials.opened(original_sources, component['metadata'])
        try:
            if metadata['size_bytes'] > 2 * 1024**2: raise ValueError('publisher packaging metadata exceeds bound')
            publisher = json.load(stream)
        finally: stream.close()
        source = component['source']; matches = [row for row in publisher['urls'] if row['packagetype']=='sdist' and row['url']==source['url'] and row['digests']['sha256']==source['sha256'] and row['size']==source['size_bytes']]
        if publisher['info']['name'].lower() != component['name'] or publisher['info']['version'] != component['version'] or len(matches) != 1: raise ValueError('packaging source identity differs from original publisher metadata')
        original, members, bodies, original_notices = tar_members(original_sources, source, component['name']+'-'+component['version']+'/'); sources.extend([original,metadata]); notices.extend(original_notices); content[component['name']] = members,bodies
    pip, pip_bodies = content['pip']; distlib, distlib_bodies = content['distlib']
    if not re.search(rb'^distlib==0\.4\.2\s*$',pip_bodies['src/pip/_vendor/vendor.txt'],re.M) or not re.search(rb"__version__\s*=\s*['\"]0\.4\.2['\"]",distlib_bodies['distlib/__init__.py']): raise ValueError('actual vendored distlib version differs')
    if not all(name in distlib for name in ('PC/launcher.c','PC/CLISimpleLauncher.vcxproj','PC/GUISimpleLauncher.vcxproj')): raise ValueError('original distlib launcher source/build recipe missing')
    wheel = lock['wheel']; stream, _, wheel_identity = materials.opened(wheel_base,wheel); entries={}; bodies={}; wheel_notices=[]; total=0
    try:
        with zipfile.ZipFile(stream) as archive:
            for entry in archive.infolist():
                name=materials.safe(entry.filename.rstrip('/')if entry.is_dir()else entry.filename)
                if entry.is_dir():continue
                if name in entries or len(entries)>=10000 or not 0<=entry.file_size<=32*1024**2 or (entry.external_attr>>16)&0o170000 not in (0,0o100000):raise ValueError('packaging wheel has duplicate/special/oversized entries')
                total+=entry.file_size
                if total>128*1024**2:raise ValueError('packaging wheel expansion exceeds bound')
                body=archive.read(entry);entries[name]={'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body),'member_path':name}
                if name.endswith(('.dist-info/RECORD','.dist-info/METADATA'))or name in ('pip/_vendor/vendor.txt','pip/_vendor/distlib/__init__.py')or name.startswith('pip/_vendor/distlib/')and name.endswith('.exe'):bodies[name]=body
                if re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$',name.rsplit('/',1)[-1],re.I):wheel_notices.append({'container_sha256':wheel_identity['sha256'],**entries[name]})
                if name.startswith('pip/'):
                    original=pip.get('src/'+name)
                    if original is None or any(entries[name][key]!=original[key]for key in ('sha256','size_bytes')):raise ValueError('installed pip member differs from exact original source distribution')
            records=[value for name,value in bodies.items()if name.endswith('.dist-info/RECORD')]; metadata=[value for name,value in bodies.items()if name.endswith('.dist-info/METADATA')]
            if len(records)!=1 or len(metadata)!=1:raise ValueError('packaging wheel metadata missing or duplicated')
            verify_record(entries,records[0]);package=BytesParser().parsebytes(metadata[0])
            if package.get_all('Name')!=['pip']or package.get_all('Version')!=['26.2.2']or not wheel_notices:raise ValueError('actual packaging wheel identity/notices differ')
    finally:stream.close()
    launchers=[]
    for name in ('t32.exe','t64.exe','t64-arm.exe','w32.exe','w64.exe','w64-arm.exe'):
        member='pip/_vendor/distlib/'+name;original=distlib.get('distlib/'+name);actual=entries.get(member)
        if original is None or actual is None or any(actual[key]!=original[key]for key in ('sha256','size_bytes')):raise ValueError('actual foreign launcher differs from original distlib distribution')
        body=bodies[member]
        if len(body)<64 or body[:2]!=b'MZ':raise ValueError('original launcher is not a PE image')
        offset=struct.unpack_from('<I',body,60)[0];machine=0xaa64 if '-arm'in name else 0x14c if '32'in name else 0x8664
        if offset<64 or offset+24>len(body)or body[offset:offset+4]!=b'PE\0\0'or struct.unpack_from('<H',body,offset+4)[0]!=machine:raise ValueError('original launcher PE CPU/signature differs')
        launchers.append({**actual,'machine':machine,'distlib_source_member':original['source_member'],'launcher_source':distlib['PC/launcher.c'],'source_relationship':'Original supplier launcher source/build files and exact distributed PE; no execution or binary reproduction.'})
    return {'schema_version':1,'qualification':'exact-pip-distlib-component-source-notices-not-reproduced-build','status':'passed','target_execution':False,'sources':sources,'notices':notices+wheel_notices,'wheel':wheel_identity,'members':list(entries.values()),'foreign_launchers':launchers,'static_runtime_condition':'Original MSVC project selects MultiThreaded; supplier toolchain redistribution entitlement is not inferred.','generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
