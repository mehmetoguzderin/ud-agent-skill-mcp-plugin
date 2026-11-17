"""Replay independently reviewed STL correspondence without admitting SDK duty."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file)); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
stl = module('ud_stl_correspondence_replay', 'stl-binary-components.py')
materials = module('ud_stl_correspondence_materials', 'source-bundle.py')


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def read(root, descriptor):
    stream, _, _ = materials.opened(root, {**descriptor, 'size_bytes': descriptor.get('size_bytes', descriptor.get('size'))})
    try: return json.load(stream)
    finally: stream.close()


def review_matches(proof, review, proof_sha, contract_sha):
    if review.get('schema_version') != 1 or review.get('qualification') != 'independent-source-correspondence-review-only' or review.get('proof_sha256') != proof_sha or review.get('source_lock_sha256') != contract_sha or review.get('source_archive_sha256') != proof['source']['sha256'] or review.get('license_sha256') != proof['original_license']['sha256'] or review.get('linkage_receipt_sha256') != proof['linkage_receipt_sha256'] or review.get('generator_sha256') != proof['generator_sha256'] or review.get('reader_sha256') != proof['reader']['sha256']: raise ValueError('exact independent STL correspondence review is stale')
    observed = [{'platform': row['platform'], 'object_sha256': row['declared']['sha256'], 'source_rows': len(row['source_files']), 'external_rows': len(row['external_header_inputs'])} for row in proof['objects']]
    if observed != review.get('objects') or sum(row['source_rows'] for row in observed) != review.get('counts', {}).get('joined_stl_sources') or sum(row['external_rows'] for row in observed) != review.get('counts', {}).get('external_header_inputs'): raise ValueError('independent STL review omits or changes actual contributing object/source/header rows')


def bind_declaration(proof, declaration):
    selected = [row for row in proof['objects'] if row['binary']['sha256'] == declaration['binary_sha256']]
    components = declaration.get('other_static_components', [])
    if len(components) != 1 or len(selected) != 5: raise ValueError('exact UV/STL component has no complete independently reviewed object set')
    component = components[0]
    if component.get('license') != 'Apache-2.0 WITH LLVM-exception' or component.get('classification') != 'separately-attributed-open-source-static-object-code': raise ValueError('STL source declaration classification differs')
    original = {row['name']: (row['sha256'], row['size_bytes']) for row in component['members']}; observed = {row['original_member']: (row['declared']['sha256'], row['declared']['size_bytes']) for row in selected}
    if len(original) != len(component['members']) or len(observed) != len(selected) or original != observed or any(row['library']['sha256'] != component['archive_sha256'] or row['library']['size_bytes'] != component['archive_size_bytes'] for row in selected): raise ValueError('STL exact library/object universe differs from the independently reviewed binary declaration')
    headers = [value for row in selected for value in row['external_header_inputs']]
    # A source correspondence review cannot turn proprietary headers into open
    # source or resolve their supplier/version/license obligations.
    return {'component_id': component['id'], 'binary_sha256': declaration['binary_sha256'], 'effective_open_source_correspondence': True, 'sources': [proof['source']], 'original_license': proof['original_license'], 'pending_declarations': [{'code': 'EXACT_STL_EXTERNAL_SDK_CRT_HEADER_SOURCE_DUTY_REQUIRED', 'component_id': component['id'], 'input': row} for row in headers]}


def derive(root, assets_root, descriptor, declarations, *, replay_objects=True):
    binding = read(root, descriptor)
    if set(binding) != {'schema_version', 'qualification', 'proof', 'review', 'source_contract', 'source_archive', 'uv_root'} or binding.get('schema_version') != 1 or binding.get('qualification') != 'exact-independent-STL-correspondence-binding-not-SDK-or-publisher-authority': raise ValueError('closed STL correspondence input binding required')
    proof = read(root, binding['proof']); review = read(root, binding['review']); contract = read(root, binding['source_contract']); review_matches(proof, review, binding['proof']['sha256'], binding['source_contract']['sha256'])
    archive = assets_root / materials.safe(binding['source_archive']['path']); stream, _, _ = materials.opened(assets_root, binding['source_archive']); stream.close(); uv_root = assets_root / materials.safe(binding['uv_root'])
    if replay_objects:
        replayed = stl.collect(assets_root, uv_root, archive, contract, Path('/opt/homebrew/opt/llvm/bin/llvm-readobj'))
        if canonical(replayed) != canonical(proof): raise ValueError('original STL object/source correspondence does not replay exactly')
    # Public source verification authenticates the protected exact independent
    # correspondence review and actual binary identities. The publisher's
    # private Microsoft build libraries are not redistributed replay inputs.
    joined = [bind_declaration(proof, row) for row in declarations if row.get('other_static_components')]
    if len(joined) != 2: raise ValueError('both exact owned-UV platform source declarations are required')
    return {'schema_version': 1, 'qualification': 'replayed-independent-STL-correspondence-with-separate-header-obligations', 'correspondence_verification': 'original-private-object-replay' if replay_objects else 'protected-exact-independent-review-and-original-source-archive', 'bindings': joined, 'pending_declarations': [row for value in joined for row in value['pending_declarations']], 'proof_sha256': binding['proof']['sha256'], 'review_sha256': binding['review']['sha256'], 'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
