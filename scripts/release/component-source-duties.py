"""Apply exact independently reviewed component duties, never publisher rights."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tarfile

SPEC = importlib.util.spec_from_file_location('ud_component_duty_materials', Path(__file__).with_name('source-bundle.py'))
materials = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(materials)
PROPOSAL = 'runtime/materials/component-source-duties.proposal.json'
REVIEW = 'quality/reviews/component-source-duties-root-review.json'
QUALIFICATION = 'independent-exact-component-source-duty-review-not-publisher-authority'
DECISIONS = {
    'no-separate-source-object': {'import-metadata', 'no-recorded-image-contribution'},
    'conditional-object-code-source-treatment': {'linked-object', 'linked-compiler-runtime-component', 'incorporated-build-inputs-not-raw-header-redistribution'},
    'open-source-STL-original-license-notice-and-source-identity': {'linked-open-source-STL-component'},
}


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def descriptor(root, name):
    file = root
    for part in materials.safe(name).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('component duty input contains a link')
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024**2: raise ValueError('component duty input is special or exceeds bounds')
        body = stream.read(16 * 1024**2 + 1); after = os.fstat(fd)
        if len(body) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')): raise ValueError('component duty input changed during same-FD read')
        return json.loads(body), {'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
def binaries(group):
    result = sorted({row['binary_sha256'] for row in group['bindings']}) if 'bindings' in group else [group.get('binary_sha256', group.get('binary', {}).get('sha256'))]
    if not result or any(not isinstance(value, str) or len(value) != 64 or any(letter not in '0123456789abcdef' for letter in value) for value in result): raise ValueError('component duty group has no exact binary universe')
    return result
def terms(group): return [{key: row[key] for key in ('path', 'sha256', 'size_bytes')} for row in group['terms']]


def verify_stl_originals(root, assets_root, group):
    source = group.get('source_identity', {})
    if not isinstance(source.get('source_commit'), str) or len(source['source_commit']) != 40 or not source.get('source_archive') or len(group['terms']) < 2: raise ValueError('open-source STL has no exact original source and notice identity')
    stream, identity, original = materials.opened(assets_root, source['source_archive'])
    try:
        expected = {row['source_member']: row for row in group['terms']}; found = set()
        if len(expected) != len(group['terms']) or not {'LICENSE.txt', 'NOTICE.txt'} <= {name.rsplit('/', 1)[-1] for name in expected}: raise ValueError('open-source STL original LICENSE/NOTICE inventory differs')
        with tarfile.open(fileobj=stream, mode='r:*') as archive:
            for entry in archive:
                if entry.name not in expected: continue
                if entry.name in found or not entry.isfile() or entry.size > 8 * 1024**2: raise ValueError('original STL notice is duplicate or special')
                row = expected[entry.name]
                if entry.size != row['size_bytes']: raise ValueError('original STL notice size differs')
                with archive.extractfile(entry) as body: fingerprint = hashlib.file_digest(body, 'sha256').hexdigest()
                if fingerprint != row['sha256']: raise ValueError('original STL notice bytes differ')
                found.add(entry.name)
        if found != set(expected): raise ValueError('original STL source omits required notices')
        info = __import__('os').fstat(stream.fileno())
        if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('original STL bytes changed during same-FD inspection')
    finally: stream.close()
    return original


def derive(root, assets_root, wanted):
    """Unknown groups and missing reviews remain explicit per-binary gaps."""
    if not (root / PROPOSAL).is_file() or not (root / REVIEW).is_file(): return {}
    proposal, original = descriptor(root, PROPOSAL); review, _ = descriptor(root, REVIEW)
    if proposal.get('qualification') != 'component-level-source-duty-review-proposal-not-approval' or review.get('schema_version') != 1 or review.get('qualification') != QUALIFICATION or review.get('proposal') != {key: original[key] for key in ('path', 'sha256', 'size_bytes')}: raise ValueError('independent exact component duty review is stale')
    approvals = {}
    for row in review.get('groups', []):
        key = row['definition_sha256']
        if key in approvals: raise ValueError('independent component duty decisions duplicate')
        approvals[key] = row
    known = set(); result = {}
    for group in proposal['groups']:
        definition = group['definition_sha256']
        if definition in known or definition != hashlib.sha256(canonical({key: value for key, value in group.items() if key != 'definition_sha256'})).hexdigest(): raise ValueError('component duty proposal definition changed or duplicated')
        known.add(definition); actual = binaries(group); selected = sorted(set(actual) & set(wanted))
        if not selected: continue
        approval = approvals.get(definition); decision = approval.get('decision') if approval else 'unresolved'
        if approval and (approval.get('binary_sha256') != actual or approval.get('terms') != terms(group)): raise ValueError('component duty review changes the actual binary or original terms universe')
        if decision != 'unresolved':
            if decision not in DECISIONS or group['classification'] not in DECISIONS[decision]: raise ValueError('component duty decision does not cover this actual contribution class')
            if decision == 'conditional-object-code-source-treatment' and approval.get('source_availability') != 'unspecified': raise ValueError('conditional object-code review cannot assert source unavailability')
            for term in terms(group):
                stream, _, _ = materials.opened(root, term); stream.close()
        source = verify_stl_originals(root, assets_root, group) if decision == 'open-source-STL-original-license-notice-and-source-identity' else None
        for fingerprint in selected:
            binding = result.setdefault(fingerprint, {'complete_component_source_duties': True, 'groups': [], 'notices': [], 'required_materials': [], 'publisher_redistribution_authority': 'unverified-external'})
            binding['groups'].append({'definition_sha256': definition, 'decision': decision, 'classification': group['classification']})
            if decision == 'unresolved': binding['complete_component_source_duties'] = False
            else: binding['notices'].extend(terms(group))
            if source is not None: binding['required_materials'].append(source)
    if not approvals.keys() <= known: raise ValueError('independent component duty review contains unrelated component definitions')
    return result
