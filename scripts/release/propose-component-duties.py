"""Prepare bounded component-level duty questions from existing byte facts.

This is a review proposal, never an affirmative coverage or publishing grant.
It does not require new symbol/source archaeology or copy vendor build inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
def receipt(root, name):
    file = root / name
    if file.is_symlink() or not file.is_file(): raise ValueError('original component review input is absent or linked')
    return {'path': name, 'sha256': sha(file), 'size_bytes': file.stat().st_size}


def perl_groups(document):
    groups = {}; seen = set()
    for row in document['components']:
        if row['id'] in seen or sha_definition(row) != row['definition_sha256']: raise ValueError('component definition is duplicated or changed')
        seen.add(row['id']); classification = row['classification']
        if classification not in ('import-metadata', 'linked-object', 'no-recorded-image-contribution'): raise ValueError('unknown actual contribution classification')
        key = row['family'], classification, row['terms_group']
        group = groups.setdefault(key, {'family': row['family'], 'classification': classification, 'terms_group': row['terms_group'], 'terms': document['terms'][row['terms_group']], 'bindings': []})
        group['bindings'].append({key: row[key] for key in ('id', 'definition_sha256', 'platform', 'binary_sha256', 'binary_size_bytes')})
    joined = [identifier for binary in document['binary_joins'] for identifier in binary['component_ids']]
    if len(joined) != len(seen) or set(joined) != seen: raise ValueError('component universe differs from actual binary joins')
    for group in groups.values():
        if group['classification'] != 'linked-object':
            group.update(proposed_duty='no-separately-contributed-implementation-source-for-this-record', applicability='actual-byte-contribution-classification-only')
        else:
            group.update(proposed_duty='conditional-object-code-terms-and-original-notices; no blanket claim that source is unavailable', applicability='pending-exact-original-installation-terms-applicability')
    return list(groups.values())


def sha_definition(row): return hashlib.sha256(canonical({key: value for key, value in row.items() if key != 'definition_sha256'})).hexdigest()


def node_groups(document, terms):
    groups = []
    for record in document['records']:
        actual = {}
        for row in record['runtime_compilands']:
            library = row['library'].replace('\\', '/'); name = library.rsplit('/', 1)[-1].lower()
            if name not in ('libcmt.lib', 'libvcruntime.lib', 'oldnames.lib', 'libucrt.lib', 'libcpmt.lib'): raise ValueError('unclassified actual Node library component')
            edition = re.search(r'/Microsoft Visual Studio/2022/([^/]+)/VC/Tools/MSVC/([^/]+)/', library)
            sdk = re.search(r'/Windows Kits/10/lib/([^/]+)/ucrt/', library)
            if (edition is None) == (sdk is None): raise ValueError('Node component has no unique recorded provider family')
            key = library
            actual.setdefault(key, []).append(row)
        for library, rows in sorted(actual.items()):
            name = library.rsplit('/', 1)[-1].lower(); stl = name == 'libcpmt.lib'; sdk = name == 'libucrt.lib'
            group = {'family': 'node-windows-' + name.removesuffix('.lib'), 'classification': 'linked-open-source-STL-component' if stl else 'linked-compiler-runtime-component', 'platform': record['platform'], 'binary': record['binary'], 'binary_archive': record['binary_archive'], 'recorded_provider_library': library, 'contributing_records': len(rows), 'attribution_sha256': hashlib.sha256(canonical(rows)).hexdigest(), 'terms': [] if stl else terms['windows-sdk' if sdk else 'msvc-2022'], 'proposed_duty': 'retain-original-STL-Apache-2.0-WITH-LLVM-exception-terms-and-notices; source-publication-not-inferred' if stl else 'conditional-object-code-terms-and-original-notices; no blanket claim that source is unavailable', 'applicability': 'pending-exact-original-installation-terms-applicability' if sdk else 'recorded-Community-2022-provider; independent-original-terms-review-required'}
            if stl: group['applicability'] = 'open-source-STL-license-and-notice-correspondence-required; proprietary-terms-cannot-substitute'
            groups.append(group)
    return groups


def uv_groups(declarations, proof, terms, notices):
    groups = []
    for declaration in declarations['components']:
        if not declaration.get('other_static_components'): continue
        rows = [row for row in proof['objects'] if row['binary']['sha256'] == declaration['binary_sha256']]
        if len(rows) != 5: raise ValueError('owned UV component does not match its exact reviewed object universe')
        base = {'subject': 'owned-uv', 'platform': declaration['platform'], 'binary_sha256': declaration['binary_sha256'], 'original_component_id': declaration['id'], 'original_definition_sha256': declaration['definition_sha256']}
        groups.append({**base, 'family': 'Microsoft-STL-14.51', 'classification': 'linked-open-source-STL-component', 'contributing_records': len(rows), 'attribution_sha256': hashlib.sha256(canonical(rows)).hexdigest(), 'terms': notices, 'proposed_duty': 'retain-original-Apache-2.0-WITH-LLVM-exception-license-and-NOTICE; existing-correspondence-review-remains-scoped', 'applicability': 'existing-independent-exact-object-source-correspondence; additional-NOTICE-preservation'})
        headers = [value for row in rows for value in row['external_header_inputs']]
        groups.append({**base, 'family': 'recorded-external-compiler-and-SDK-header-inputs', 'classification': 'incorporated-build-inputs-not-raw-header-redistribution', 'contributing_records': len(headers), 'attribution_sha256': hashlib.sha256(canonical(headers)).hexdigest(), 'terms': terms['msvc-2026'] + terms['windows-sdk'], 'proposed_duty': 'identify-applicable-component-level-object-code-terms; neither blanket-source-unavailable-nor-mandatory-source-publication-is-inferred', 'applicability': 'pending-exact-recorded-provider-family-and-original-terms-applicability'})
    return groups


def packaging_group(root, packaging):
    bindings = [{'id': 'pip-26.2.2-outer-wheel', 'binary_sha256': packaging['wheel']['sha256'], 'binary_size_bytes': packaging['wheel']['size_bytes'], 'platform': 'foreign-packaging-data'}]
    bindings.extend({'id': 'distlib-0.4.2-' + row['member_path'].rsplit('/',1)[-1], 'binary_sha256': row['sha256'], 'binary_size_bytes': row['size_bytes'], 'platform': 'foreign-packaging-data'} for row in packaging['foreign_launchers'])
    if len(bindings) != 7 or len({row['binary_sha256'] for row in bindings}) != 7: raise ValueError('exact outer wheel and all six original launcher subjects required')
    return {'subject': 'pip-distlib', 'family': 'distlib-0.4.2-original-prebuilt-launcher-static-runtime-condition', 'classification': 'linked-compiler-runtime-component', 'bindings': bindings, 'terms': [receipt(root,name) for name in ('licenses/vendor/pip-26.2.2/LICENSE.txt','licenses/vendor/distlib-0.4.2/LICENSE.txt','licenses/vendor/distlib-0.4.2/launcher.c')], 'sources': packaging['sources'], 'launcher_source': packaging['foreign_launchers'][0]['launcher_source'], 'proposed_duty': 'preserve-original-pip-vendored-notices-and-distlib-launcher-source-BSD-binary-notice; conditional-compiler-runtime-entitlement-remains-external', 'applicability': 'original-supplier-projects-select-MultiThreaded; actual-compiler-and-SDK-versions-not-established-and-not-inferred', 'source_availability': 'unspecified', 'static_runtime_condition': packaging['static_runtime_condition']}


def derive(root, node_proof):
    perl_name = 'runtime/materials/windows-perl-component-declarations.lock.json'; perl = json.loads((root / perl_name).read_bytes())
    node = json.loads((root / node_proof).read_bytes())
    if perl.get('qualification') != 'exact-Windows-Perl-Microsoft-component-declarations-no-publisher-grant' or node.get('qualification') != 'signed-PDB-linked-byte-attribution-not-reproduced-build': raise ValueError('original exact component fact records required')
    groups = [{'subject': 'private-perl', **group} for group in perl_groups(perl)] + [{'subject': 'node', **group} for group in node_groups(node, perl['terms'])]
    stl_name = 'runtime/materials/stl-component-notices.lock.json'; stl = json.loads((root / stl_name).read_bytes())
    if stl.get('qualification') != 'original-STL-license-and-NOTICE-bytes-not-binary-reproduction-or-publisher-grant': raise ValueError('original open-source STL notice inventory required')
    selected_stl = [row for row in stl['components'] if row['version_family'] == '14.44']
    if len(selected_stl) != 1: raise ValueError('recorded Node STL family notice inventory missing')
    uv_stl = [row for row in stl['components'] if row['version_family'] == '14.51']
    if len(uv_stl) != 1: raise ValueError('owned UV STL notice inventory missing')
    msvc_name = 'runtime/materials/msvc-static-components.lock.json'; stl_proof_name = 'runtime/materials/uv-stl-source-components.json'
    groups.extend(uv_groups(json.loads((root / msvc_name).read_bytes()), json.loads((root / stl_proof_name).read_bytes()), perl['terms'], uv_stl[0]['notices']))
    spec = importlib.util.spec_from_file_location('ud_packaging_duty_proposal', root / 'scripts/release/bind-pip-components.py'); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    packaging = module.derive(root, root / '.artifacts/source-materials-data/pip-distlib-original-1', root / '.artifacts/source-materials-data/python-runtime-sources')
    groups.append(packaging_group(root, packaging))
    for group in groups:
        if group['classification'] == 'linked-open-source-STL-component':
            original = selected_stl[0] if group['subject'] == 'node' else uv_stl[0]
            group['terms'] = original['notices']; group['source_identity'] = {key: original[key] for key in ('source_commit', 'source_archive')}
        group['terms'] = [{**term, 'path': term['path'].replace('.artifacts/source-materials-data/microsoft-vs2022-review/', 'licenses/vendor/Microsoft-VisualStudio-2022/')} for term in group['terms']]
        for term in group['terms']:
            if any(receipt(root, term['path'])[key] != term[key] for key in ('sha256', 'size_bytes')): raise ValueError('original versioned component terms bytes differ')
        group['publisher_redistribution_authority'] = 'unverified-external'
        group['independent_source_duty_review'] = 'pending'
        group['definition_sha256'] = hashlib.sha256(canonical(group)).hexdigest()
    return {'schema_version': 1, 'qualification': 'component-level-source-duty-review-proposal-not-approval', 'complete_component_coverage': False, 'complete_product_coverage': False, 'inputs': [receipt(root, perl_name), receipt(root, node_proof), receipt(root, stl_name), receipt(root, msvc_name), receipt(root, stl_proof_name), receipt(root,'runtime/materials/pip-distlib-sources.lock.json'), receipt(root,'scripts/release/bind-pip-components.py')], 'groups': groups, 'limits': ['Import and zero-contribution facts are separate from linked implementation objects.', 'Existing Microsoft source-duty reviews are not extended to other editions, SDK versions, open-source STL or header inputs.', 'No source-unavailable conclusion, publisher license acceptance, binary reproduction or native execution is inferred.', 'UV STL correspondence remains separately reviewed; external SDK/header terms applicability remains a separate component-level question.'], 'generator': receipt(root, 'scripts/release/propose-component-duties.py')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--node-proof', required=True); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('a new review proposal output is required')
    result = derive(args.root.resolve(), args.node_proof); args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'groups': len(result['groups']), 'sha256': sha(args.output), 'qualification': result['qualification']}))
