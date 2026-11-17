#!/usr/bin/env python3
"""Bind actual helper/uv Rust identities to signed std and exact crate sources."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
materials = module('ud_rust_bind_materials', Path(__file__).with_name('source-bundle.py'))
packages = module('ud_rust_bind_packages', Path(__file__).with_name('bind-package-sources.py'))
userspace = module('ud_rust_bind_uv', ROOT / 'scripts/runtime/prepare-userspace.py')
elf = module('ud_rust_bind_elf', ROOT / 'workers/ud/src/ud_agent/elf_runtime.py')
inspector = module('ud_rust_bind_arch', Path(__file__).with_name('inspect-package.py'))
rust_collector = module('ud_rust_bind_publisher', Path(__file__).with_name('collect-rust-runtime-sources.py'))
managed = module('ud_rust_bind_managed', Path(__file__).with_name('bind-managed-python-sources.py'))
windows_pe = module('ud_rust_bind_windows_pe', ROOT / 'scripts/runtime/windows_pe.py')
OPEN_TOOLCHAIN = 'runtime/materials/windows-open-toolchain.lock.json'
OPEN_RUNTIME = 'llvm-mingw-ucrt'
WINDOWS_TARGETS = {'win32-arm64': 'aarch64-pc-windows-gnullvm', 'win32-x64': 'x86_64-pc-windows-gnullvm'}


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def launcher_source(root):
    files = [root / 'Cargo.toml', root / 'Cargo.lock', *[file for file in (root / 'packages/launcher').rglob('*') if file.is_file()]]; fingerprint = hashlib.sha256()
    for file in sorted(files):
        if file.is_symlink(): raise ValueError('native helper source contains a link')
        fingerprint.update(file.relative_to(root).as_posix().encode()); fingerprint.update(b'\0'); fingerprint.update(file.read_bytes()); fingerprint.update(b'\0')
    return fingerprint.hexdigest()


def binary(file, platform, source_releases):
    body = file.read_bytes(); architecture = inspector.architecture(body[:65536])
    if architecture != platform.replace('/', '-'): raise ValueError('actual Rust binary architecture differs')
    commits = sorted({match.decode() for match in re.findall(rb'/rustc/([0-9a-f]{40})/', body)})
    if len(commits) != 1 or commits[0] not in source_releases: raise ValueError('actual Rust binary has no unique exact signed runtime source identity')
    linkage = elf.inspect(body) if platform.startswith('linux/') else None
    if linkage and (not linkage['interpreter'] or 'libc.so.6' not in linkage['needed']): raise ValueError('Rust binary static C runtime requires its own exact source proof')
    runtime = source_releases[commits[0]]
    return {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'platform': platform, 'rust_commit': commits[0], 'rust_source': runtime.get('source', runtime), 'rust_std_dependencies': runtime.get('dependencies', []), 'rust_verification_materials': runtime.get('verification_materials', []), 'dynamic_linkage': linkage, 'proprietary_static_runtime_declaration_required': platform.startswith('win32/')}


def runtime_sources(rust_sources, commits=None, recorder=None, *, open_windows=False):
    versions = None if commits is None else [version for version, commit in rust_collector.COMMITS.items() if commit in commits]
    if commits is not None and set(commits) != {rust_collector.COMMITS[version] for version in versions}: raise ValueError('observed Rust runtime commit has no fixed signed release identity')
    rust = rust_collector.verify_collection(rust_sources.parent, versions=versions); result = {}
    for version, commit in rust_collector.COMMITS.items():
        if commits is not None and commit not in commits: continue
        matches = [row for row in rust['files'] if row.get('family') == 'rust-runtime-source' and row['version'] == version and row['commit'] == commit]
        if len(matches) != 1: raise ValueError('signed Rust runtime source identity duplicated or absent')
        stream, _, source = materials.opened(rust_sources.parent, matches[0]); stream.close(); dependencies = []
        if open_windows and version == '1.99.1':
            scope = rust_collector.stdlib_scope
            crates = {(row['name'], row['version']): rust_sources.parent / row['path'] for row in rust['files'] if row.get('family') == 'rust-stdlib-crate'}
            proof = scope.derive(rust_sources.parent / source['path'], crates, extra_targets=scope.OPEN_WINDOWS_TARGETS)
            expected = [{key: row[key] for key in ('name', 'version', 'sha256')} for row in rust['files'] if row.get('family') == 'rust-stdlib-crate' and version in row['supported_target_consumers']]
            if proof['selected_registry_packages'] != sorted(expected, key=lambda row: (row['name'], row['version'])):
                raise ValueError('open Windows Rust std requires additional locked original crate sources')
        for row in rust['files']:
            if row.get('family') == 'rust-stdlib-crate' and version in row['supported_target_consumers']:
                stream, _, original = materials.opened(rust_sources.parent, row); stream.close(); dependencies.append(original)
                if recorder is not None:
                    for notice in row.get('notices', []): recorder.source_member(rust_sources.parent / notice['path'], row['sha256'], notice['source_path'])
        verification = []
        for row in rust['files']:
            if row['family'] == 'rust-publisher-metadata' and row['version'] in (version, 'publisher-key'):
                stream, _, original = materials.opened(rust_sources.parent, row); stream.close(); verification.append(original)
        result[commit] = {'source': source, 'dependencies': dependencies, 'verification_materials': verification}
    return result


def open_windows_map(root, cross, host, name, retained=None):
    profile = cross['windows_linkage'][host]
    native = profile['objects'][name]
    target = WINDOWS_TARGETS[host]
    if profile.get('profile') != OPEN_RUNTIME or profile.get('target') != target or profile.get('target_execution') is not False or native.get('profile') != OPEN_RUNTIME or native.get('binary_sha256') != cross['platforms'][host][name]['sha256'] or native.get('private_crt_dlls') != []:
        raise ValueError('Windows native helper receipt does not bind the original open-toolchain subject')
    link_map = native['map']
    if retained is not None:
        rows = [row for row in retained if row['platform'] == host and row['name'] == name]
        if len(rows) != 1 or rows[0]['path'] != 'maps/' + link_map['sha256'] + '.json' or any(rows[0][key] != link_map[key] for key in ('sha256', 'size')):
            raise ValueError('retained Windows link map differs from original recipe')
        link_map = rows[0]
    if not 0 < link_map['size'] <= 8 * 1024 ** 2: raise ValueError('Windows link map size exceeds bounds')
    stream, _, _ = materials.opened(root, link_map)
    try: document = json.load(stream)
    finally: stream.close()
    text = document.get('contents')
    startup = 'llvm-mingw/' + target.split('-')[0] + '-w64-mingw32/lib/crt2.o:('
    if document.get('format') != 'lld-link-map' or not isinstance(text, str) or startup not in text or re.search(r'\b(?:libcmt|libcpmt|libvcruntime|libucrt|vcruntime|msvcprt)\.lib\b', text, re.I):
        raise ValueError('Windows link map does not match the pinned open MinGW startup')
    return native


def cross_inputs(assets_root, retained=None, wanted=None):
    """Resolve original binaries without rebinding a mutable build directory."""
    if retained is None:
        file = assets_root / '.artifacts/cross-build-receipt.json'
        return json.loads(file.read_bytes()), lambda host, name, row: assets_root / row['path'], sha(file)
    stream, _, _ = materials.opened(retained.parent, {'path': retained.name, 'sha256': sha(retained), 'size_bytes': retained.stat().st_size})
    try: data = json.load(stream)
    finally: stream.close()
    fields = {'schema_version', 'qualification', 'source_sha256', 'cross_build_receipt', 'binaries'}
    if set(data) - {'link_maps'} != fields or data['schema_version'] != 1 or data['qualification'] != 'retained-original-cross-build-recipe-and-binary-inputs': raise ValueError('retained cross-build input manifest is invalid')
    stream, _, _ = materials.opened(retained.parent, data['cross_build_receipt'])
    try: cross = json.load(stream)
    finally: stream.close()
    if cross.get('source_sha256') != data['source_sha256']: raise ValueError('retained cross-build source identity differs')
    maps = data.get('link_maps', [])
    if not isinstance(maps, list) or len(maps) != (4 if cross.get('windows_toolchain') else 0): raise ValueError('retained Windows link map inventory is incomplete or foreign')
    expected = {(host, name) for host in cross['platforms'] for name in ('ud-agent', 'ud-agent-guard')}; found = {}
    for row in data['binaries']:
        key = row.get('platform'), row.get('name')
        if key not in expected or key in found: raise ValueError('retained cross-build binary inventory is incomplete or duplicate')
        original = cross['platforms'][key[0]][key[1]]
        if row.get('original_path') != original['path'] or row.get('sha256') != original['sha256'] or row.get('path') != 'files/' + original['sha256'] or row.get('executable') is not True: raise ValueError('retained cross-build binary differs from original recipe')
        # The complete original manifest remains authoritative, while replay
        # reads only binaries actually shipped by this candidate. Off-host
        # inputs are not prerequisites for a platform-scoped archive.
        if wanted is None or (row['sha256'], row['size']) in wanted:
            stream, _, _ = materials.opened(retained.parent, row); stream.close()
        found[key] = retained.parent / row['path']
    if set(found) != expected: raise ValueError('retained cross-build binary inventory is incomplete or duplicate')
    return cross, lambda host, name, row: found[(host, name)], data['cross_build_receipt']['sha256']


def derive(root, rust_sources, package_sources, provider_sources, assets_root=None, retained_native_inputs=None, wanted=None, active_platforms=None, recorder=None, *, owned_uv_declarations=None, source_parts=None):
    assets_root = root if assets_root is None else assets_root
    source_releases = {}
    def selected_binary(file, platform):
        observed = set(match.decode() for match in re.findall(rb'/rustc/([0-9a-f]{40})/', file.read_bytes()))
        if len(observed) != 1: raise ValueError('actual Rust binary has no unique exact signed runtime source identity')
        if not observed <= source_releases.keys(): source_releases.update(runtime_sources(rust_sources, observed, recorder, open_windows=bool(open_receipt)))
        return binary(file, platform, source_releases)
    provider = json.loads(provider_sources.read_bytes()); uv_sources = [row for row in provider['files'] if row['name'] == 'astral-sh/uv']
    if provider.get('status') != 'passed' or len(uv_sources) != 1 or uv_sources[0]['version'] != '316c827e058c16b71d5c507a20729c2995a7bcce': raise ValueError('uv bootstrap source differs from exact locked release commit')
    stream, _, uv_source = materials.opened(provider_sources.parent, uv_sources[0]); stream.close()
    cross, native_file, cross_sha256 = cross_inputs(assets_root, retained_native_inputs, wanted)
    if cross.get('source_sha256') != launcher_source(root) or cross.get('rust') != '1.99.1': raise ValueError('native helper cross-build source/compiler recipe is stale')
    targets = sorted(cross['platforms'])
    published = json.loads((root / 'packages/npm-distribution/platforms.json').read_bytes())
    if set(targets) - {'darwin-x64'} != set(published) - {'darwin-x64'}: raise ValueError('complete cross-built helper inventories required')
    bindings = []
    selected_hashes = None if wanted is None else {fingerprint for fingerprint, _ in wanted}
    open_materials = None
    open_receipt = cross.get('windows_toolchain')
    retained_maps = None if retained_native_inputs is None else json.loads(retained_native_inputs.read_bytes()).get('link_maps')
    map_root = assets_root if retained_native_inputs is None else retained_native_inputs.parent
    for host in targets:
        for name in ('ud-agent', 'ud-agent-guard'):
            descriptor = cross['platforms'][host][name]
            if selected_hashes is not None and descriptor['sha256'] not in selected_hashes: continue
            file = native_file(host, name, descriptor)
            if sha(file) != descriptor['sha256']: raise ValueError('cross-built helper bytes differ from source recipe')
            result = selected_binary(file, host.replace('-', '/'))
            if result['rust_commit'] != '58cf8f9c35b355199727627d07ae34a4e2846d67': raise ValueError('helper actual Rust std differs from compiler build recipe')
            if open_receipt and host in WINDOWS_TARGETS:
                if open_materials is None:
                    if open_receipt.get('path') != OPEN_TOOLCHAIN: raise ValueError('Windows cross-build toolchain receipt differs from the frozen lock')
                    stream, _, _ = materials.opened(root, open_receipt)
                    try: toolchain = json.load(stream)
                    finally: stream.close()
                    platform_notices = [toolchain['notice'], toolchain['mingw_notice']]
                    for notice in platform_notices:
                        stream, _, _ = materials.opened(root, notice); stream.close()
                    open_materials = []
                    for row in toolchain['sources']:
                        original = {**row, 'path': '.artifacts/llvm-mingw-inputs/' + row['filename']}
                        open_materials.append({**managed.checked(assets_root, original, source_parts, recorder), 'url': row['url']})
                profile = open_windows_map(map_root, cross, host, name, retained_maps)
                imports = windows_pe.inspect_pe(file.read_bytes(), host.split('-')[1])['imports']
                if imports != profile.get('system_imports') or not any(re.fullmatch(r'(?:ucrtbase|api-ms-win-crt-[a-z0-9-]+)\.dll', item) for item in imports) or not all(windows_pe.system_dll(item) or item in ('combase.dll', 'ktmw32.dll') for item in imports):
                    raise ValueError('Windows helper has a private, missing or changed UCRT import')
                result['proprietary_static_runtime_declaration_required'] = False
                result['open_windows_linkage'] = {'profile': OPEN_RUNTIME, 'target': WINDOWS_TARGETS[host], 'link_map_sha256': profile['map']['sha256'], 'toolchain_archive_sha256': toolchain['archive']['sha256'], 'system_imports': imports, 'sources': open_materials, 'notices': platform_notices}
            bindings.append({'kind': 'native-helper', 'name': name, 'binary': result, 'source_recipe_sha256': cross['source_sha256']})
    inputs = json.loads((root / 'runtime/userspace-inputs.lock.json').read_bytes())
    for host, item in inputs['platforms'].items():
        if active_platforms is not None and host not in active_platforms: continue
        override = inputs.get('derived_uv', {}).get(host)
        if override is not None:
            if selected_hashes is not None:
                stream, _, _ = materials.opened(assets_root, {'path': override['path'], 'sha256': override['sha256'].removeprefix('sha256:'), 'size_bytes': override['size']})
                try: declared = json.load(stream)
                finally: stream.close()
                if not any(row.get('platform') == host and row.get('binary', {}).get('sha256') in selected_hashes for row in declared.get('records', [])): continue
            linkage = json.loads((assets_root / override['path']).read_bytes())
            replay = None
            if owned_uv_declarations is not None:
                fingerprint = next((row.get('binary', {}).get('sha256') for row in linkage.get('records', []) if row.get('platform') == host), None)
                declaration = owned_uv_declarations.get(fingerprint)
                if declaration is None: raise ValueError('owned uv has no independently reviewed source declaration')
                replay = (root, declaration)
            file, origin = userspace.select_derived_uv(assets_root, host, override, source_replay=replay)
            for name, fingerprint in linkage['generators'].items():
                if sha(root / name) != fingerprint: raise ValueError('owned uv source recipe differs from the exact source snapshot')
            result = selected_binary(file, host)
            if result['rust_commit'] != '58cf8f9c35b355199727627d07ae34a4e2846d67': raise ValueError('owned uv actual Rust runtime differs from its compiler recipe')
            bindings.append({'kind': 'uv-bootstrap', 'name': 'uv', 'binary': result, 'binary_origin': 'owned-original-source-crossbuild', 'owned_source_recipe': origin, 'upstream_vendor_archive_origin_only': item['uv_archive'], 'uv_source': uv_source})
            continue
        if host.startswith('win32/'):
            # This archive is downloaded from Astral at install time. It has
            # no published uv binary subject to replay.
            continue
        descriptor = item['uv_archive']; archive = assets_root / '.artifacts/userspace-inputs/cache' / descriptor['sha256'][7:]
        stream, _, _ = materials.opened(assets_root, {'path': archive.relative_to(assets_root).as_posix(), 'sha256': descriptor['sha256'][7:], 'size_bytes': descriptor['size']}); stream.close()
        with tempfile.TemporaryDirectory(prefix='ud-uv-source-') as temporary:
            file = Path(temporary) / ('uv.exe' if host.startswith('win32') else 'uv'); userspace.extract_uv(archive, descriptor, file, host.startswith('win32')); result = selected_binary(file, host)
        if selected_hashes is not None and result['sha256'] not in selected_hashes: continue
        bindings.append({'kind': 'uv-bootstrap', 'name': 'uv', 'binary': result, 'archive_sha256': descriptor['sha256'][7:], 'uv_source': uv_source})
    pending = [{'code': 'EXACT_WINDOWS_STATIC_CRT_LICENSE_DECLARATION_REQUIRED', 'sha256': row['binary']['sha256'], 'platform': row['binary']['platform'], 'name': row['name']} for row in bindings if row['binary']['proprietary_static_runtime_declaration_required']]
    consumers = ([root / 'Cargo.lock'] if any(row['kind'] == 'native-helper' for row in bindings) else []) + ([provider_sources.parent / 'locks/uv.Cargo.lock'] if any(row['kind'] == 'uv-bootstrap' for row in bindings) else [])
    cargo = packages.derive(root, package_sources, [provider_sources.parent / 'locks/uv.Cargo.lock'], required_cargo_consumers=consumers)
    cargo_fingerprint = hashlib.sha256(packages.json.dumps(cargo['bindings'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    for row in bindings: row['cargo_source_bindings_sha256'] = cargo_fingerprint
    cargo_sources = {kind: [row['source'] for row in cargo['bindings'] if row['family'] == 'cargo' and packages.cargo_consumer_identity(root, consumer) in row['consumers']] for kind, consumer in [('native-helper', root / 'Cargo.lock'), ('uv-bootstrap', provider_sources.parent / 'locks/uv.Cargo.lock')]}
    return {'schema_version': 1, 'qualification': 'derived-rust-binary-source-recipe-license-bindings', 'status': 'incomplete' if pending else 'passed', 'complete_component_coverage': not pending, 'complete_product_coverage': False, 'target_execution': False, 'emulation': False, 'bindings': bindings, 'cargo_sources': cargo_sources, 'cargo_bindings': cargo['bindings'], 'cross_build_receipt_sha256': cross_sha256, 'pending_declarations': pending, 'source_collections': [{'sha256': sha(file), 'size_bytes': file.stat().st_size} for file in (rust_sources, package_sources, provider_sources)], 'generator_sha256': sha(Path(__file__))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--rust-sources', type=Path, required=True); parser.add_argument('--package-sources', type=Path, required=True); parser.add_argument('--provider-sources', type=Path, required=True); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new Rust binary source binding output required')
    result = derive(args.root.resolve(), args.rust_sources, args.package_sources, args.provider_sources); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'binaries': len(result['bindings']), 'pending_declarations': len(result['pending_declarations'])}))
