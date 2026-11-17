#!/usr/bin/env python3
"""Bind the published signed Node binary archives to exact signed release source."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file)); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
locked = module('ud_node_release_sources', 'collect-locked-sources.py')
materials = module('ud_node_release_materials', 'source-bundle.py')
extractor = module('ud_node_release_extractor', 'extract-node.py')
rust = module('ud_node_rust_sources', 'bind-rust-binary-sources.py')
linux_rust = module('ud_node_linux_rust_sources', 'bind-node-linux-rust-sources.py')


def vendored_rust_sources(archive):
    """Join the actual Node std-independent Cargo inputs to its signed source."""
    with tarfile.open(archive, 'r:*') as source:
        members = {}
        for row in source:
            if row.name in members: raise ValueError('Node source archive contains duplicate members')
            members[row.name] = row
        locks = [name for name in members if name.endswith('/deps/crates/Cargo.lock')]
        if len(locks) != 1 or not members[locks[0]].isfile() or members[locks[0]].size > 4 * 1024 ** 2: raise ValueError('Node actual Rust source lock is missing or ambiguous')
        root = locks[0].removesuffix('Cargo.lock'); required = tomllib.loads(source.extractfile(members[locks[0]]).read().decode())['package']; manifests = {}
        for name, member in members.items():
            if not name.startswith(root + 'vendor/') or not name.endswith('/Cargo.toml'): continue
            if not member.isfile() or member.size > 4 * 1024 ** 2: raise ValueError('Node vendored crate manifest is special or oversized')
            package = tomllib.loads(source.extractfile(member).read().decode()).get('package', {}); key = package.get('name'), package.get('version')
            if not all(isinstance(item, str) for item in key): raise ValueError('Node original crate metadata has no exact name/version')
            manifests.setdefault(key, []).append(name)
        bindings = []
        for package in required:
            if 'source' not in package: continue # The authored node_crates crate is inside the same original source.
            if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index' or 'checksum' in package and not re.fullmatch('[a-f0-9]{64}', package['checksum']): raise ValueError('Node Rust lock has an unsupported registry or malformed optional origin checksum')
            selected = manifests.get((package['name'], package['version']), [])
            if len(selected) != 1: raise ValueError('Node source omits or duplicates an actual locked Rust crate')
            prefix = selected[0].removesuffix('Cargo.toml'); notices = []
            for name, entry in members.items():
                if name.startswith(prefix) and entry.isfile() and name.rsplit('/', 1)[-1].lower().startswith(('license', 'copying', 'notice', 'copyright')):
                    if entry.size > 8 * 1024 ** 2: raise ValueError('Node vendored Rust notice exceeds bound')
                    with source.extractfile(entry) as content: fingerprint = hashlib.file_digest(content, 'sha256').hexdigest()
                    notices.append({'member_path': name, 'sha256': fingerprint, 'size_bytes': entry.size})
            if not notices: raise ValueError('Node actual Rust crate lacks original notices')
            bindings.append({'name': package['name'], 'version': package['version'], 'upstream_registry_checksum': package.get('checksum'), 'source_manifest': selected[0], 'original_notices': notices, 'relationship': 'Actual publisher Node source members authenticated by the signed whole-source archive; an optional registry checksum is origin metadata, never a claim of an unmodified crate repack.'})
    return bindings


def observed_rust(body, source_releases):
    commits = sorted({match.decode() for match in re.findall(rb'/rustc/([a-f0-9]{40})/', body)})
    if len(commits) != 1: return {'commits': commits, 'source': None, 'dependencies': [], 'pending': 'NODE_STATIC_RUST_PRODUCER_IDENTITY_UNRESOLVED'}
    runtime = source_releases.get(commits[0])
    if runtime is None: return {'commits': commits, 'source': None, 'dependencies': [], 'pending': 'NODE_OBSERVED_RUST_STANDARD_LIBRARY_SOURCE_REQUIRED'}
    return {'commits': commits, **runtime, 'pending': None}


def join_linux_runtime(platform, archive, executable, source_releases, proof):
    """Join exact observed Node bytes to the independently authenticated SRPM."""
    if proof.get('qualification') != 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction' or proof.get('target_execution') is not False or proof.get('pending_declarations') != []:
        raise ValueError('Node Linux compiler source correspondence is incomplete')
    matches = [row for row in proof['bindings'] if row['platform'] == platform]
    if len(matches) != 1: raise ValueError('Node Linux compiler source platform is missing or duplicated')
    row = matches[0]
    if row['binary'] != {key: executable[key] for key in ('sha256', 'size_bytes')} or any(row['node_archive'].get(key) != archive[key] for key in ('sha256', 'size_bytes')):
        raise ValueError('Node Linux producer proof describes different actual binary/archive bytes')
    runtime = source_releases.get(row['rust_commit'])
    if runtime is None or not row['sources'] or not row['notices'] or not row['verification_materials']:
        raise ValueError('Node Linux producer source/runtime/notices are absent')
    return {'commits': [row['rust_commit']], **runtime, 'producer_sources': row['sources'], 'producer_notices': row['notices'], 'producer_verification_materials': row['verification_materials'], 'source_correspondence_qualification': proof['qualification'], 'producer_input_lock_sha256': proof['input_lock_sha256'], 'producer_generator_sha256': proof['generator_sha256'], 'pending': None}


def original_inspection_inputs(assets_root, binaries, linux_proof=None):
    """Exact consumed containers, separate from corresponding-source claims."""
    inputs = {}
    for archive in [*[row['archive'] for row in binaries], *[row['node_archive'] for row in (linux_proof or {}).get('bindings', [])]]:
        stream, _, actual = materials.opened(assets_root, archive); stream.close()
        if actual['sha256'] in inputs and inputs[actual['sha256']]['size_bytes'] != actual['size_bytes']: raise ValueError('Node inspection archive identities conflict')
        inputs[actual['sha256']] = actual
    return [inputs[key] for key in sorted(inputs)]


def derive(root, source_file, assets_root=None, rust_sources=None, selected_platforms=None, recorder=None, source_parts=None):
    assets_root = root if assets_root is None else assets_root
    plan, locks = locked.plan(root, assets_root); selected = [row for row in plan if row['family'] == 'node']
    if len(selected) != 1: raise ValueError('one signed Node source release required')
    expected = selected[0]; inventory = json.loads(source_file.read_bytes())
    if inventory.get('schema_version') != 1 or inventory.get('qualification') != 'exact-locked-source-subinventory' or inventory.get('status') != 'passed': raise ValueError('exact Node source collection required')
    matches = [row for row in inventory['files'] if all(row.get(key) == expected[key] for key in ('family', 'name', 'version', 'url', 'sha256'))]
    if len(matches) != 1: raise ValueError('Node source archive differs from signed release identity')
    stream, _, source = materials.opened(source_file.parent, matches[0]); stream.close()
    # Reconstruct notices from the exact archive, not a supplied declaration.
    notices = locked.source_notices(source_file.parent / matches[0]['path'])
    if notices != matches[0].get('notice_files') or not notices: raise ValueError('Node source notice closure differs')
    crates = vendored_rust_sources(source_file.parent / matches[0]['path']); source_releases = {}
    node = json.loads((root / 'runtime/node-distributions.lock.json').read_bytes())
    platforms = json.loads((root / 'packages/npm-distribution/platforms.json').read_bytes())
    signed_lines = (assets_root / '.artifacts/node/SHASUMS256.txt.asc').read_text().splitlines()
    if not platforms.keys() <= node['platforms'].keys(): raise ValueError('complete published Node distribution recipes required')
    binaries = []; linux_proof = None
    for platform in platforms:
        if selected_platforms is not None and platform.replace('-', '/') not in selected_platforms: continue
        row = node['platforms'][platform]
        if signed_lines.count(row['sha256'] + '  ' + row['filename']) != 1: raise ValueError('Node binary is absent from signed publisher manifest')
        file = assets_root / '.artifacts/node' / row['filename']; stream, _, binary = materials.opened(assets_root, {'path': file.relative_to(assets_root).as_posix(), 'sha256': row['sha256']}); stream.close()
        with tempfile.TemporaryDirectory(prefix='ud-node-source-') as temporary:
            output = Path(temporary) / 'runtime'; extractor.extract(file, output, platform, node['version'], row['sha256']); members = [{'path': 'runtime/node/' + item.relative_to(output).as_posix(), 'sha256': locked.acquisition.digest(item), 'size_bytes': item.stat().st_size, 'executable': item.parent.name == 'bin'} for item in sorted(output.rglob('*')) if item.is_file()]; executable = output / 'bin' / ('node.exe' if platform.startswith('win32-') else 'node'); body = executable.read_bytes()
            observed = set(match.decode() for match in re.findall(rb'/rustc/([a-f0-9]{40})/', body))
            if platform.startswith('linux-'): observed = {'6b00bc3880198600130e1cf62b8f8a93494488cc'} # The independently replayed RPM join below must establish this identity.
            if rust_sources is not None and len(observed) == 1 and not observed <= source_releases.keys(): source_releases.update(rust.runtime_sources(rust_sources, observed, recorder))
            runtime = observed_rust(body, source_releases)
        if platform.startswith('linux-'):
            if linux_proof is None: linux_proof = linux_rust.derive(root, assets_root, source_parts, recorder)
            executable_record = next(item for item in members if item['path'] == 'runtime/node/bin/node')
            runtime = join_linux_runtime(platform.replace('-', '/'), binary, executable_record, source_releases, linux_proof)
        binaries.append({'platform': platform.replace('-', '/'), 'archive': binary, 'source_sha256': source['sha256'], 'version': node['version'], 'binary_files': members, 'rust_standard_library': runtime, 'producer_static_runtime_declaration_pending': platform.startswith('win32-')})
    # Retain the original distribution containers consumed by inspection,
    # including both archives opened by the fixed Linux producer comparison.
    # These are replay inputs, not a claim that binary tarballs are source.
    inspection = original_inspection_inputs(assets_root, binaries, linux_proof)
    pending = [{'platform': row['platform'], 'code': 'WINDOWS_NODE_STATIC_COMPILER_RUNTIME_DECLARATION_REQUIRED', 'archive_sha256': row['archive']['sha256']} for row in binaries if row['producer_static_runtime_declaration_pending']]
    pending.extend({'platform': row['platform'], 'code': row['rust_standard_library']['pending'], 'archive_sha256': row['archive']['sha256'], 'observed_commits': row['rust_standard_library']['commits']} for row in binaries if row['rust_standard_library']['pending'])
    return {'schema_version': 1, 'qualification': 'derived-node-binary-source-license-bindings', 'status': 'incomplete' if pending else 'passed', 'complete_component_coverage': not pending, 'complete_product_coverage': False, 'target_execution': False, 'emulation': False, 'binary_inputs': binaries, 'inspection_inputs': inspection, 'vendored_rust_crates': crates, 'pending_declarations': pending, 'sources': [source], 'licenses': notices, 'source_collections': [{'sha256': locked.acquisition.digest(item), 'size_bytes': item.stat().st_size} for item in ([source_file, rust_sources] if rust_sources is not None else [source_file])], 'publisher_signature': expected['signature_receipt'], 'build_recipes': [{'path': 'scripts/release/extract-node.py', 'sha256': locked.acquisition.digest(root / 'scripts/release/extract-node.py'), 'size_bytes': (root / 'scripts/release/extract-node.py').stat().st_size}], 'generator_sha256': locked.acquisition.digest(Path(__file__))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--sources', type=Path, required=True); parser.add_argument('--rust-sources', type=Path); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new Node source binding output required')
    result = derive(args.root.resolve(), args.sources, rust_sources=args.rust_sources); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'binary_archives': len(result['binary_inputs'])}))
