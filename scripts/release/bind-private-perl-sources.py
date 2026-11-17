#!/usr/bin/env python3
"""Join exact private Perl bytes to their locked source/module/provider recipes."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
materials = module('ud_private_perl_materials', Path(__file__).with_name('source-bundle.py'))
paths = module('ud_private_perl_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
inspector = module('ud_private_perl_binary', Path(__file__).with_name('inspect-package.py'))
managed = module('ud_private_perl_open_source_inputs', Path(__file__).with_name('bind-managed-python-sources.py'))
windows_pe = module('ud_private_perl_pe', ROOT / 'scripts/runtime/windows_pe.py')


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def receipt_platform(value):
    return 'linux/x64' if value == 'linux/amd64' else value


def original_notice_joins(archive, identity, expected):
    family, name, version, fingerprint = identity; joined = []; inline = []
    with tarfile.open(archive, 'r:*') as bundle:
        for member in bundle:
            parts = member.name.split('/')
            if not member.isfile() or len(parts) < 2: continue
            leaf = parts[-1]; target = None
            if family == 'perl' and len(parts) == 2 and leaf in ('Artistic', 'Copying', 'README'):
                target = 'share/licenses/' + ('perl-provider/' if 'windows-provider' in name else 'perl/') + leaf
            elif family == 'cpan' and len(parts) == 2 and re.fullmatch(r'(?:LICENSE(?:\.[A-Za-z0-9_-]+)?|COPYING(?:\.[A-Za-z0-9_-]+)?|Artistic|README(?:\.[A-Za-z0-9_-]+)?)', leaf, re.I):
                target = 'share/licenses/' + name + '/' + leaf
            elif family == 'ud' and name == 'dan-zeman/interset' and len(parts) == 2 and leaf == 'LICENSE.txt':
                target = next((path for path in ('share/licenses/interset/LICENSE.txt', 'share/sources/interset/LICENSE.txt') if path in expected), None)
            elif family == 'cpan' and parts[1] == 'lib' and leaf.endswith('.pm') and member.size <= 1024 ** 2:
                with bundle.extractfile(member) as stream: body = stream.read(member.size + 1)
                if b'=head1' in body and (b'LICENSE' in body or b'COPYRIGHT' in body): inline.append((member.name, body, 'lib/perl5/' + '/'.join(parts[2:])))
            if target is None or target not in expected: continue
            if not 0 < member.size <= 1024 ** 2: raise ValueError('original private Perl notice is empty or oversized')
            with bundle.extractfile(member) as stream: body = stream.read(member.size + 1)
            if hashlib.sha256(body).hexdigest() != expected[target]['sha256'] or len(body) != expected[target]['size_bytes']: raise ValueError('private Perl copied notice differs from its actual original source')
            joined.append({'source_archive_sha256': fingerprint, 'source_member': member.name, 'distributed': expected[target]})
    if not joined:
        for name, body, target in inline:
            if target in expected and expected[target]['sha256'] == hashlib.sha256(body).hexdigest() and expected[target]['size_bytes'] == len(body): joined.append({'source_archive_sha256': fingerprint, 'source_member': name, 'distributed': expected[target], 'form': 'original-inline-POD-copyright-license-preserved'})
    if not joined: raise ValueError('private Perl component original README/POD/license attribution is missing: ' + name)
    if family == 'perl' and not {'Artistic', 'Copying'} <= {row['source_member'].rsplit('/', 1)[-1] for row in joined}: raise ValueError('complete original Perl Artistic/Copying terms are missing')
    return joined


def source_requirements(root, receipt):
    core = json.loads((root / 'runtime/native-perl-source.lock.json').read_bytes()); modules = json.loads((root / 'runtime/native-perl-modules.lock.json').read_bytes()); interset = json.loads((root / 'runtime/perl-deps.lock.json').read_bytes())['interset']
    windows = receipt.get('platform', '').startswith('win32/')
    if windows:
        if receipt.get('upstream_source_sha256') != 'sha256:505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91' or receipt.get('modules_sha256') != 'sha256:' + sha(root / 'runtime/native-perl-modules.lock.json') or not receipt.get('deferred_runtime') or any(re.fullmatch(r'vcruntime[0-9_a-z]*\.dll', row['path'].rsplit('/', 1)[-1], re.I) for row in receipt['files']):
            raise ValueError('Windows Perl source recipe or vendor payload exclusion differs')
        required = [('perl', 'perl-5.44.0-windows-provider-source', '5.44.0', receipt['upstream_source_sha256'][7:])]
    else:
        if receipt.get('source_sha256') != hashlib.sha256(canonical(core)).hexdigest() or receipt.get('modules_sha256') != hashlib.sha256(canonical(modules)).hexdigest() or receipt.get('interset_commit') != interset['commit']:
            raise ValueError('private Perl source/module recipe is stale')
        required = [('perl', core['name'], core['version'], core['sha256'])]
    required += [('cpan', row['name'], row['version'], row['sha256']) for row in modules['releases'].values()]
    required.append(('ud', 'dan-zeman/interset', interset['commit'], interset['archive_sha256']))
    return required


def deferred_perl_platform(root, pack, definition, expected):
    """Bind the omitted interpreter and PE dependencies to the locked vendor archive."""
    recipe_path = definition.get('deferred_runtime', {}).get('recipe')
    if not recipe_path or recipe_path not in expected: raise ValueError('deferred Windows Perl acquisition recipe is missing')
    stream, _, _ = materials.opened(pack, expected[recipe_path])
    try: recipe = json.load(stream)
    finally: stream.close()
    platform = definition.get('platform')
    selected = json.loads((root / 'runtime/windows-perl-distributions.lock.json').read_bytes())['platforms'].get(platform.removeprefix('win32/'))
    if not selected or recipe.get('platform') != platform or recipe.get('executable') != definition['executable']:
        raise ValueError('deferred Perl platform or interpreter locator differs')
    supplier = recipe.get('supplier', {})
    archive = selected['perl']
    expected_archive = {'sha256': archive['sha256'].removeprefix('sha256:'), 'size_bytes': archive['size_bytes'], 'url': archive['url']}
    if supplier.get('archive') != expected_archive or definition.get('provider') != selected:
        raise ValueError('deferred Perl supplier archive differs from its lock')
    removed = definition.get('vendor_supplier_removed', [])
    rows = supplier.get('files', [])
    expected_rows = {(row['path'], row['sha256'], row['size_bytes']) for row in removed}
    actual = {(paths.validate_path(row['path']), row['sha256'], row['size_bytes']) for row in rows}
    if not rows or len(actual) != len(rows) or len(expected_rows) != len(removed) or actual != expected_rows or any(row[0] in expected for row in actual) or definition['executable'] not in {row[0] for row in actual}:
        raise ValueError('deferred Perl supplier byte inventory differs from omitted binaries')
    return platform.replace('/', '-')


def open_xs_bindings(root, assets_root, pack, receipt_file, definition, expected, locations, source_parts, recorder):
    """Replay original CPAN source, normalized maps and PE imports for owned XS."""
    lock_file = root / 'runtime/materials/windows-open-toolchain.lock.json'
    lock = json.loads(lock_file.read_bytes())
    toolchain = definition['toolchain']
    if toolchain.get('lock_sha256') != 'sha256:' + sha(lock_file) or toolchain.get('archive_sha256') != 'sha256:' + lock['archive']['sha256']:
        raise ValueError('open Perl XS toolchain differs from the frozen LLVM-MinGW lock')
    if definition.get('producer_sha256') != 'sha256:' + sha(root / 'scripts/runtime/prepare-windows-perl.py'):
        raise ValueError('open Perl XS producer differs from the frozen source')
    architecture = definition['platform'].split('/')[1]
    startup = 'llvm-mingw/' + ('aarch64' if architecture == 'arm64' else 'x86_64') + '-w64-mingw32/lib/dllcrt2.o:('
    linkage = receipt_file.parent / paths.validate_path(definition['linkage_root'])
    xsc = definition.get('compiled_xs', [])
    if len(xsc) != 9 or len({row['module'] for row in xsc}) != len(xsc):
        raise ValueError('open Perl XS closure does not cover all nine extensions')
    source_records = []
    for row in lock['sources']:
        original = {**row, 'path': '.artifacts/llvm-mingw-inputs/' + row['filename']}
        source_records.append({**managed.checked(assets_root, original, source_parts, recorder), 'url': row['url']})
    notices = [lock['notice'], lock['mingw_notice']]
    for notice in notices:
        stream, _, _ = materials.opened(root, notice); stream.close()
    bindings = {}
    for row in xsc:
        name = paths.validate_path(row['binary'])
        identity = next((key for key in locations if key[0] == 'cpan' and key[1] == row['release'] and key[3] == row['source_archive']['sha256']), None)
        if identity is None or locations[identity].stat().st_size != row['source_archive']['size_bytes'] or name in bindings or expected.get(name, {}).get('sha256') != row['sha256'].removeprefix('sha256:'):
            raise ValueError('open Perl XS binary or original CPAN recipe differs')
        imports = windows_pe.inspect_pe((pack / name).read_bytes(), architecture)['imports']
        proof = row['open_linkage']
        if proof.get('profile') != 'llvm-mingw-ucrt' or imports != proof.get('system_and_perl_imports') or 'perl544.dll' not in imports or not all(windows_pe.system_dll(item) or item == 'perl544.dll' for item in imports):
            raise ValueError('open Perl XS binary has changed or private runtime imports')
        map_receipt = {**row['map'], 'sha256': row['map']['sha256'].removeprefix('sha256:')}
        if not 0 < map_receipt['size_bytes'] <= 8 * 1024 ** 2: raise ValueError('open Perl XS link map size exceeds bounds')
        with managed.opened_original(linkage, map_receipt, source_parts, recorder) as (stream, _, link_map):
            text = stream.read().decode('utf-8')
        if proof.get('startup') != startup or startup not in text or re.search(r'\b(?:libcmt|libcpmt|libvcruntime|libucrt|vcruntime|msvcprt)\.lib\b', text, re.I):
            raise ValueError('open Perl XS link map does not match pinned MinGW DLL startup')
        sources = {}
        with tarfile.open(locations[identity], 'r:gz') as archive:
            for item in row['objects']:
                pathname = paths.validate_path(item['source'])
                with archive.extractfile(row['release'] + '/' + pathname) as body:
                    observed = hashlib.file_digest(body, 'sha256').hexdigest()
                if pathname in sources or 'sha256:' + observed != item['source_sha256']:
                    raise ValueError('open Perl XS source object differs from locked CPAN definitions')
                sources[pathname] = observed
        if not sources: raise ValueError('open Perl XS link is missing original source objects')
        bindings[name] = {'profile': 'llvm-mingw-ucrt', 'original_cpans': sources, 'imports': imports, 'sources': source_records, 'link_map': link_map, 'notices': notices}
    return bindings


def derive(root, pack, receipt_file, collections, elf_binding=None, *, assets_root=None, source_parts=None, recorder=None):
    generator = sha(Path(__file__))
    definition = json.loads(receipt_file.read_bytes())
    if definition.get('schema_version') != 1 or not definition.get('files') or definition.get('state') not in ('frozen-inputs', 'cross-built'):
        raise ValueError('complete private Perl build receipt required')
    expected = {}; keys = set()
    for row in definition['files']:
        name = paths.validate_path(row['path']); key = paths.path_key(name)
        if name in expected or key in keys: raise ValueError('private Perl receipt path collision')
        keys.add(key); stream, _, record = materials.opened(pack, {'path': name, 'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row['size']}); stream.close(); expected[name] = record
    actual = set()
    for file in pack.rglob('*'):
        if file.is_symlink(): raise ValueError('private Perl runtime contains an unlisted link')
        if file.is_file(): actual.add(file.relative_to(pack).as_posix())
        elif not file.is_dir(): raise ValueError('private Perl runtime contains a special file')
    if actual != set(expected): raise ValueError('private Perl runtime adds or omits declared files')
    executable = pack / definition['executable']
    if definition.get('vendor_supplier_removed'):
        platform = deferred_perl_platform(root, pack, definition, expected)
    else:
        with executable.open('rb') as source: platform = inspector.architecture(source.read(65536))
    if platform not in ('darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64') or receipt_platform(definition.get('platform', platform.replace('-', '/'))) != platform.replace('-', '/'):
        raise ValueError('private Perl executable architecture differs from build receipt')
    for name in expected:
        if name.endswith(('.so', '.bundle', '.dll', '.exe')) or name == definition['executable']:
            with (pack / name).open('rb') as source: prefix = source.read(65536)
            if prefix[:4] in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') or prefix[:2] == b'MZ':
                if inspector.architecture(prefix) != platform: raise ValueError('private Perl native module architecture differs')
    records = {}; locations = {}; collection_receipts = []; providers = []; originals = {}; required = set(source_requirements(root, definition))
    for collection in collections:
        data = json.loads(collection.read_bytes())
        if data.get('status') != 'passed' or data.get('qualification') != 'exact-locked-source-subinventory': raise ValueError('exact locked source collection required')
        collection_receipts.append({'sha256': sha(collection), 'size_bytes': collection.stat().st_size})
        for row in data['files']:
            identity = (row.get('family'), row.get('name'), row.get('version'), row['sha256'])
            if identity in originals and originals[identity][1] != row: raise ValueError('source identity conflicts')
            originals[identity] = collection, row
        providers.extend(data.get('providers', []))
    selected_providers = [row for row in providers if row.get('platform') == definition.get('platform') and row.get('archive') == definition.get('provider', {}).get('perl')] if definition.get('platform', '').startswith('win32/') else []
    recipe_hashes = {row['sha256'] for provider in selected_providers for row in provider['recipe_files']}
    for identity, (collection, row) in originals.items():
        if identity not in required and row['sha256'] not in recipe_hashes: continue
        stream, _, record = materials.opened(collection.parent, row); stream.close()
        records[identity] = {**record, 'collection_sha256': sha(collection), 'notice_files': row.get('notice_files', [])}
        locations[identity] = collection.parent / row['path']
    bindings = []
    for identity in source_requirements(root, definition):
        if identity not in records: raise ValueError('locked corresponding source missing: ' + '@'.join(identity[:3]))
        bindings.append({'family': identity[0], 'name': identity[1], 'version': identity[2], 'source_sha256': identity[3], 'source': records[identity], 'original_notice_joins': original_notice_joins(locations[identity], identity, expected)})
    if definition.get('platform', '').startswith('win32/'):
        selected = selected_providers
        if len(selected) != 1 or not selected[0]['recipe_files']: raise ValueError('exact Windows provider patches/build recipe missing')
        for row in selected[0]['recipe_files']:
            if not any(value['sha256'] == row['sha256'] and value['size_bytes'] == row['size_bytes'] for value in records.values()): raise ValueError('Windows provider recipe bytes missing')
    if definition.get('elf_origin'):
        if elf_binding is None: raise ValueError('private ELF corresponding source proof required')
        proof = json.loads(elf_binding.read_bytes())
        if proof.get('qualification') != 'derived-binary-package-source-license-bindings' or proof.get('status') != 'passed' or proof.get('private_runtime', {}).get('sha256') != sha(receipt_file): raise ValueError('private ELF source proof is stale')
        bound = {row['name']: row['sha256'] for component in proof['bindings'] for row in component['binary_files']}
        if bound != definition['elf_origin']['libraries']: raise ValueError('private ELF source proof omits a library')
    licenses = [row for row in expected.values() if row['path'].startswith('share/licenses/')]
    if not licenses: raise ValueError('private Perl original notice closure is missing')
    pending = {}
    open_xs = {}
    if platform.startswith('win32'):
        owned_xs = {row['binary'] for row in definition.get('compiled_xs', [])}
        if definition.get('toolchain', {}).get('profile') == 'llvm-mingw-ucrt':
            open_xs = open_xs_bindings(root, root if assets_root is None else assets_root, pack, receipt_file, definition, expected, locations, source_parts, recorder)
        for name, content in expected.items():
            with (pack / name).open('rb') as stream: magic = stream.read(2)
            if magic != b'MZ' or name in open_xs: continue
            row = pending.setdefault(content['sha256'], {'code': 'WINDOWS_PERL_STATIC_COMPILER_COMPONENT_DECLARATION_REQUIRED', 'sha256': content['sha256'], 'paths': [], 'producer': 'owned-crossbuilt-xs' if name in owned_xs else 'supplier-perl'})
            row['paths'].append(name)
    recipe_paths = ['scripts/runtime/prepare-native-perl.py', 'scripts/runtime/prepare-windows-perl.py', 'scripts/runtime/windows_pe.py', 'scripts/runtime/prepare-linux-perl.py', 'scripts/runtime/build-linux-perl.py', 'scripts/runtime/perl_build.py', 'scripts/runtime/close-linux-elf.py', 'scripts/runtime/prepare-perl-vendor-runtime.py', 'runtime/native-perl-source.lock.json', 'runtime/native-perl-modules.lock.json', 'runtime/windows-perl-distributions.lock.json']
    if sha(Path(__file__)) != generator: raise ValueError('source binding generator changed during verification')
    return {'schema_version': 1, 'qualification': 'derived-private-perl-source-recipe-license-bindings', 'status': 'incomplete' if pending else 'passed', 'complete_component_coverage': not pending, 'pending_declarations': list(pending.values()), 'complete_product_coverage': False, 'platform': platform.replace('-', '/'), 'target_execution': False, 'emulation': False, 'binary_receipt_sha256': sha(receipt_file), 'binary_recipe': definition, 'binary_inventory_sha256': hashlib.sha256(canonical([expected[name] for name in sorted(expected)])).hexdigest(), 'binary_files': [expected[name] for name in sorted(expected)], 'sources': bindings, 'provider_recipes': selected_providers, 'licenses': licenses, 'elf_source_binding_sha256': sha(elf_binding) if elf_binding is not None else None, 'source_collections': collection_receipts, 'build_recipes': [{'path': name, 'sha256': sha(root / name), 'size_bytes': (root / name).stat().st_size} for name in recipe_paths], 'external_dependencies': ['Operating-system kernel and system services are native host prerequisites; they are not copied into this Perl pack.'] + (['VC runtime DLLs are privately acquired from the exact vendor recipe; they are excluded from redistributed pack bytes.'] if platform.startswith('win32') else []), 'generator_sha256': generator, **({'open_xs': open_xs} if open_xs else {})}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--pack', type=Path, required=True); parser.add_argument('--receipt', type=Path, required=True); parser.add_argument('--sources', action='append', type=Path, required=True); parser.add_argument('--elf-binding', type=Path); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new native Perl source binding output required')
    result = derive(args.root.resolve(), args.pack, args.receipt, args.sources, args.elf_binding); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'files': len(result['binary_files']), 'sources': len(result['sources'])}))
