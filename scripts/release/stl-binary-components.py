#!/usr/bin/env python3
"""Join exact contributing STL COFF source checksums to original source bytes.

Original SDK/lib object bytes are local inspection inputs only. The output
contains object hashes, source-member hashes and external-header declarations;
it neither republishes SDK payloads nor asserts publisher entitlement.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_stl_materials', Path(__file__).with_name('source-bundle.py'))
materials = importlib.util.module_from_spec(spec); spec.loader.exec_module(materials)


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def checksums(text):
    rows = []; seen = {}
    for entry in re.finditer(r'    FileChecksum \{\n(.*?)\n    \}', text, re.S):
        block = entry.group(1); name = re.search(r'Filename: (.*?) \(0x[0-9A-Fa-f]+\)', block); kind = re.search(r'ChecksumKind: (\w+)', block); size = re.search(r'ChecksumSize: 0x([0-9A-Fa-f]+)', block); body = re.search(r'ChecksumBytes \((.*?)\n      \)', block, re.S)
        if not all((name, kind, size, body)) or kind.group(1) != 'SHA256' or int(size.group(1), 16) != 32: raise ValueError('actual STL source checksum record is incomplete or unsupported')
        chunks = []
        for line in body.group(1).splitlines():
            if not line.strip(): continue
            match = re.fullmatch(r'\s*[0-9A-Fa-f]+:\s*([0-9A-Fa-f ]+)\s+\|.*\|', line)
            if not match: raise ValueError('actual STL source checksum hex record is malformed')
            chunks.append(match.group(1).replace(' ', ''))
        fingerprint = ''.join(chunks).lower()
        if not re.fullmatch('[a-f0-9]{64}', fingerprint): raise ValueError('actual STL source checksum length differs')
        filename = name.group(1)
        if filename in seen and seen[filename] != fingerprint: raise ValueError('one STL object declares conflicting source checksums')
        if filename in seen: continue
        seen[filename] = fingerprint; rows.append({'compiler_path': filename, 'algorithm': 'SHA256', 'sha256': fingerprint})
    if not rows: raise ValueError('actual STL object has no original source checksum inventory')
    return rows


def source_members(archive, contract):
    stream, identity, source = materials.opened(archive.parent, {'path': archive.name, **contract['archive']}); result = {}; license_record = None; total = 0
    try:
        with tarfile.open(fileobj=stream, mode='r:gz') as bundle:
            for item in bundle:
                name = item.name; prefix = contract['source_root'] + '/'
                if item.isdir() and name.rstrip('/') == contract['source_root']: continue
                if not name.startswith(prefix) or '\\' in name or any(part in ('', '.', '..') for part in name.rstrip('/').split('/')): raise ValueError('original STL source has an unsafe root/member')
                if item.isdir(): continue
                if not item.isfile() or item.size > 16 * 1024 ** 2 or name[len(prefix):] in result: raise ValueError('original STL source is special, duplicate or oversized')
                total += item.size
                if len(result) > 50000 or total > 256 * 1024 ** 2: raise ValueError('original STL source expansion exceeds bound')
                with bundle.extractfile(item) as body: fingerprint = hashlib.file_digest(body, 'sha256').hexdigest()
                relative = name[len(prefix):]; record = {'member_path': name, 'sha256': fingerprint, 'size_bytes': item.size}; result[relative] = record
                if relative == 'LICENSE.txt':
                    with bundle.extractfile(item) as body: terms = body.read()
                    if b'Apache License' not in terms or b'LLVM Exceptions to the Apache 2.0 License' not in terms: raise ValueError('actual STL original license/exception text differs')
                    license_record = record
        after = __import__('os').fstat(stream.fileno())
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('original STL source changed during inspection')
    finally: stream.close()
    if license_record is None: raise ValueError('original STL source license is absent')
    return result, source, license_record


def join(rows, members):
    joined = []; external = []; unresolved = []
    for row in rows:
        normalized = row['compiler_path'].replace('\\', '/'); match = re.search(r'/github/stl/(.+)\Z', normalized, re.I)
        if match:
            relative = 'stl/' + match.group(1); member = members.get(relative)
            if not member or row['sha256'] != member['sha256']: unresolved.append({**row, 'expected_source_member': relative, 'reason': 'exact-original-STL-source-checksum-unmatched'})
            else: joined.append({**row, 'source': member})
        else:
            external.append({**row, 'classification': 'external-Microsoft-SDK-or-CRT-header-input', 'source_availability': 'separate-exact-supplier-source-duty-declaration-required', 'redistributed_source_bytes': False})
    if not any(row['source']['member_path'].endswith('.cpp') for row in joined): unresolved.append({'reason': 'actual-STL-translation-unit-source-not-joined'})
    return joined, external, unresolved


def collect(root, uv_root, archive, contract, reader):
    if contract.get('schema_version') != 1 or contract.get('repository') != 'microsoft/STL' or contract.get('license') != 'Apache-2.0 WITH LLVM-exception' or contract.get('source_root') != 'STL-' + contract.get('commit', ''): raise ValueError('exact original STL source contract required')
    members, source, license_record = source_members(archive, contract)
    # Reuse the complete original UV verifier and its actual archive reader.
    # Imported JS is fixed repository code; uv_root is only an input directory.
    code = "import{readFileSync}from'node:fs';import{verifyWindowsUv}from" + json.dumps((ROOT / 'scripts/runtime/finalize-windows-uv.mjs').as_uri()) + ";import{archiveObjectBytes}from" + json.dumps((ROOT / 'scripts/release/windows-linkage.mjs').as_uri()) + ";const receipt=verifyWindowsUv(process.argv[1]);let rows=[];for(const row of receipt.records){const lib=row.libraries.find(x=>x.library==='libcpmt');if(!lib||lib.members.length!==5)throw Error('actual STL object inventory differs');let objects=archiveObjectBytes(readFileSync(lib.archive.path),lib.members.map(x=>x.name));for(const object of objects)rows.push({platform:row.platform,binary:row.binary,library:lib.archive,original_member:object.member,declared:lib.members.find(x=>x.name===object.member),bytes:object.bytes.toString('base64')});}console.log(JSON.stringify(rows))"
    result = subprocess.run(['node', '--input-type=module', '-e', code, str(uv_root.resolve())], cwd=root, capture_output=True, timeout=300)
    if result.returncode or len(result.stdout) > 8 * 1024 ** 2: raise ValueError('original UV object/source recipe verification failed: ' + result.stderr.decode('utf-8', 'replace')[-1500:])
    reader = reader.resolve(strict=True); reader_record = {'sha256': sha(reader), 'size_bytes': reader.stat().st_size}
    if reader_record != contract.get('metadata_reader'): raise ValueError('original COFF metadata reader differs from its fixed contract')
    objects = []; seen = set(); unresolved = []
    with tempfile.TemporaryDirectory(prefix='ud-stl-data-reader-') as temporary:
        for index, item in enumerate(json.loads(result.stdout)):
            identity = item['platform'], item['original_member']
            if identity in seen: raise ValueError('actual STL contributing object is duplicate')
            seen.add(identity); body = base64.b64decode(item.pop('bytes'), validate=True); declaration = item['declared']
            if hashlib.sha256(body).hexdigest() != declaration['sha256'] or len(body) != declaration['size_bytes']: raise ValueError('actual STL object differs from exact link receipt')
            file = Path(temporary) / (str(index) + '.obj'); file.write_bytes(body)
            data = subprocess.run([str(reader), '--codeview', str(file)], capture_output=True, timeout=30)
            if data.returncode or data.stderr or len(data.stdout) > 8 * 1024 ** 2: raise ValueError('actual STL original CodeView metadata could not be read')
            text = data.stdout.decode(); joined, external, missing = join(checksums(text), members); unresolved.extend({'platform': item['platform'], 'object_sha256': declaration['sha256'], **row} for row in missing)
            objects.append({**item, 'source_files': joined, 'external_header_inputs': external, 'producers': sorted(set(re.findall(r'(?:Frontend|Backend)Version: ([0-9.]+)', text))), 'codeview_metadata_sha256': hashlib.sha256(re.sub(r'^\n?File: .*\n', '\nFile: ' + declaration['sha256'] + '\n', text, count=1).encode()).hexdigest()})
    if len(objects) != 10 or sha(reader) != reader_record['sha256']: raise ValueError('complete actual STL object inventory or reader identity differs')
    return {'schema_version': 1, 'qualification': 'exact-contributing-STL-object-codeview-source-member-joins', 'target_execution': False, 'emulation': False, 'complete_open_STL_source_unit_coverage': not unresolved, 'source': {**source, 'repository': contract['repository'], 'commit': contract['commit'], 'url': contract['archive']['url']}, 'original_license': license_record, 'license': contract['license'], 'objects': objects, 'unresolved_source_units': unresolved, 'reader': reader_record, 'linkage_receipt_sha256': sha(uv_root / 'linkage-receipt.json'), 'generator_sha256': sha(Path(__file__)), 'limits': ['This is an exact original COFF source-checksum relationship, not a reproduced binary build.', 'External Microsoft SDK/CRT headers are enumerated as separate source-unavailable input declarations; no SDK bytes are copied into corresponding-source archives.', 'Proprietary source-duty decisions and publisher redistribution authority remain separate exact gates.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--root', type=Path, default=ROOT); p.add_argument('--uv-root', type=Path, required=True); p.add_argument('--source', type=Path, required=True); p.add_argument('--lock', type=Path, default=ROOT / 'runtime/materials/msvc-stl-sources.lock.json'); p.add_argument('--reader', type=Path, default=Path('/opt/homebrew/opt/llvm/bin/llvm-readobj')); p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    if a.output.exists(): raise ValueError('new STL source component output required')
    r = collect(a.root.resolve(), a.uv_root, a.source, json.loads(a.lock.read_bytes()), a.reader); a.output.write_text(json.dumps(r, indent=2) + '\n'); print(json.dumps({'objects': len(r['objects']), 'joined_source_files': sum(len(x['source_files']) for x in r['objects']), 'unresolved': len(r['unresolved_source_units'])}))
