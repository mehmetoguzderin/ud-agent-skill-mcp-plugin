#!/usr/bin/env python3
"""Join supplier-PDB source checksums to locally cached Windows include bytes.

This identifies byte equality only. It grants no right to distribute source,
does not establish the compiler's complete input closure, and does not cover
authored XS objects, native execution, or publisher authority.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ud_perl_declarations', ROOT / 'scripts/release/declare-windows-perl-components.py')
DECL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECL)
INCLUDE_DIRS = ('.artifacts/xwin-cache/xwin/crt/include', '.artifacts/xwin-cache/xwin/sdk/include')


def expected_sources(document, load_parts):
    expected = {}
    for record in document['records']:
        for binary in record['binaries']:
            if binary['origin'] != 'supplier':
                continue
            for item in load_parts(binary['runtime_compilands']):
                if DECL.supplier_contribution(item) != 'linked-object':
                    continue
                for source in item['source_files']:
                    checksum = source['checksum']
                    if source['algorithm'] != 'sha256' or not re.fullmatch('[0-9a-f]{64}', checksum):
                        raise ValueError('Unsupported or invalid source checksum')
                    original = source['path']
                    name = original.replace('\\', '/').rsplit('/', 1)[-1].casefold()
                    if not name or name in ('.', '..'):
                        raise ValueError('Invalid PDB source name')
                    key = (name, checksum)
                    entry = expected.setdefault(key, {'original_paths': set(), 'contributors': set()})
                    entry['original_paths'].add(original)
                    entry['contributors'].add((record['platform'], binary['path'], item['id']))
    return expected


def match_sources(expected, candidates):
    matches = {key: [] for key in expected}
    for name, checksum, path in candidates:
        key = (name.casefold(), checksum)
        if key in matches:
            matches[key].append(path)
    return [{'name': name, 'sha256': checksum,
             'original_paths': sorted(value['original_paths']),
             'contributors': [{'platform': platform, 'binary_path': binary, 'module_id': module}
                              for platform, binary, module in sorted(value['contributors'])],
             'local_matches': sorted(set(matches[(name, checksum)])),
             'status': 'exact-local-byte-match' if matches[(name, checksum)] else 'no-match-in-scanned-local-includes'}
            for (name, checksum), value in sorted(expected.items())]


def generate(index, declaration):
    # The declaration verifier independently checks complete shard reconstruction.
    if json.loads(declaration.read_bytes()) != DECL.generate(index):
        raise ValueError('Windows Perl declaration is stale')
    value = json.loads(index.read_bytes())
    def load_parts(parts):
        return [row for part in parts['parts'] for row in json.loads((index.parent / part['path']).read_bytes())]
    expected = expected_sources(value['document'], load_parts)
    if not expected:
        raise ValueError('Supplier source checksum inventory is empty')
    names = {name for name, _ in expected}
    candidates = []
    for relative in INCLUDE_DIRS:
        root = ROOT / relative
        if not root.is_dir() or root.is_symlink():
            raise ValueError('Required cached include root is missing or unsafe')
        for file in root.rglob('*'):
            if file.is_symlink() or not file.is_file() or file.name.casefold() not in names:
                continue
            if not file.resolve().is_relative_to(root.resolve()):
                raise ValueError('Candidate escapes its include root')
            candidates.append((file.name, DECL.fingerprint(file)['sha256'], file.relative_to(ROOT).as_posix()))
    rows = match_sources(expected, candidates)
    return {'schema_version': 1, 'qualification': 'supplier-PDB-source-checksum-local-byte-matches-not-source-duty-review',
            'attribution_index': {'path': index.relative_to(ROOT).as_posix(), **DECL.fingerprint(index)},
            'component_declaration': {'path': declaration.relative_to(ROOT).as_posix(), **DECL.fingerprint(declaration)},
            'generator': {'path': Path(__file__).relative_to(ROOT).as_posix(), **DECL.fingerprint(Path(__file__))},
            'candidate_roots': list(INCLUDE_DIRS), 'sources': rows,
            'limits': ['Matches are evidence of equal cached bytes, not evidence of redistribution authority or license terms.',
                       'No match means only that no equal byte sequence was found under the scanned local include roots.',
                       'Supplier PDB source records do not cover authored XS objects or prove complete source closure.'],
            'publisher_redistribution_authority': 'unverified-external', 'native_execution': 'pending-native'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--declaration', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output', type=Path)
    group.add_argument('--verify', type=Path)
    args = parser.parse_args()
    result = generate(args.index.resolve(), args.declaration.resolve())
    if args.verify:
        if json.loads(args.verify.read_bytes()) != result:
            raise ValueError('Source checksum join is stale')
    else:
        if args.output.exists():
            raise ValueError('A new source checksum evidence output is required')
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'sources': len(result['sources']), 'matched': sum(row['status'] == 'exact-local-byte-match' for row in result['sources'])}))
