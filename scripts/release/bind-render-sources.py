"""Exact native-render metadata, original notice and locked decoder joins.

Archives and executables are inspected as data. Vendor browser binaries are not
admitted here. Only exact reviewed readable notices are source materials; unshipped supplier
programs are never selected or granted implementation coverage.
"""
from __future__ import annotations
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


bundle = module('ud_render_source_bundle', Path(__file__).with_name('source-bundle.py'))
fonts = module('ud_render_source_fonts', ROOT / 'scripts/runtime/render_manifest.py')
debian = module('ud_render_source_debian', Path(__file__).with_name('source_materials.py'))
# The protected original notice collection can predate relevance filtering.
ORIGINAL_NOTICE_COLLECTOR_SHA256 = '8e059908367c31c4f455f54a9373b0a1a38f32f56c452c9344a89c46623011a3'
METADATA = {'manifest.json', 'dependency-lock.json', 'vendor-browser-recipe.json', 'windows-browser-recipe.json', 'elf-closure.json', 'fontconfig/fonts.conf'}
BROWSERS = {'darwin/arm64': 'macos-arm64', 'darwin/x64': 'darwin-x64', 'linux/arm64': 'linux-arm64', 'linux/x64': 'linux-x64', 'win32/arm64': 'windows-arm64', 'win32/x64': 'win32-x64'}
FONTCONFIG = b'<?xml version="1.0"?>\n<fontconfig><dir prefix="relative">../fonts</dir><cachedir prefix="xdg">fontconfig</cachedir><config><rescan><int>0</int></rescan></config></fontconfig>\n'


def digest(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def record(file): return {'sha256': digest(file), 'size_bytes': file.stat().st_size}
def identity(row): return {'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row.get('size_bytes', row.get('size'))}
def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def original(base, row, assets_root):
    expected = {'path': row['path'], **identity(row)}
    stream, _, content = bundle.opened(base, expected); stream.close()
    return {**content, 'path': (base / row['path']).relative_to(assets_root).as_posix()}


def archive_inventory(file, expected):
    rows, bodies, total = {}, {}, 0
    stream, before, _ = bundle.opened(file.parent, {'path': file.name, **identity(expected)})
    with stream, tarfile.open(fileobj=stream, mode='r|gz') as archive:
        for entry in archive:
            name = bundle.safe(entry.name)
            if not entry.isfile() or name in rows or len(rows) >= 10000 or not 0 <= entry.size <= 512 * 1024**2: raise ValueError('render archive inventory is duplicate, special or oversized')
            total += entry.size
            if total > 2 * 1024**3: raise ValueError('render archive expansion exceeds bound')
            capture = name in METADATA
            if capture and entry.size > 8 * 1024**2: raise ValueError('render metadata exceeds bound')
            fingerprint = hashlib.sha256(); size = 0; body = bytearray()
            with archive.extractfile(entry) as member_stream:
                while chunk := member_stream.read(1024**2):
                    fingerprint.update(chunk); size += len(chunk)
                    if capture: body.extend(chunk)
            if size != entry.size: raise ValueError('render member is truncated')
            rows[name] = {'path': name, 'sha256': fingerprint.hexdigest(), 'size_bytes': size}
            if capture: bodies[name] = bytes(body)
        after = os.fstat(stream.fileno())
        if before != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('render archive changed during inspection')
    return rows, bodies


def validate_metadata(rows, bodies, browser, font_receipts, platform):
    """Reconstruct the producer's generated inventory and exact lock projection."""
    expected_dependency = {'browser': browser, 'fonts': font_receipts}
    if bodies.get('dependency-lock.json') != encoded(expected_dependency): raise ValueError('render dependency metadata differs from the original locked inputs')
    available = {}
    for name in rows:
        if name.startswith('fonts/'):
            leaf = name.rsplit('/', 1)[-1]
            if leaf in available: raise ValueError('render font identity is ambiguous')
            available[leaf] = name
    expected_fonts = [available[name] for name in fonts.FONT_NAMES if name in available]
    if len(expected_fonts) != len(fonts.FONT_NAMES) or 'NotoSansCJK-Regular.ttc' not in available or 'fonts/generated/NotoSansCJK-Regular.otf' not in rows: raise ValueError('render metadata omits the complete pinned font selection')
    expected_fonts.append('fonts/generated/NotoSansCJK-Regular.otf')
    edge = platform == 'win32/arm64'
    expected = {'schema_version': 1, 'executable': 'browser/msedge.exe' if edge else 'browser/chrome-headless-shell' + ('.exe' if platform.startswith('win32/') else ''), 'files': [rows[name] for name in sorted(rows, key=lambda name: Path(name).parts) if name != 'manifest.json'], 'fonts': expected_fonts,
                'deferred_browser': {'provider': 'microsoft-edge' if edge else 'google-chrome-for-testing', 'recipe': 'windows-browser-recipe.json' if edge else 'vendor-browser-recipe.json', 'directory': 'browser', **({'decoder': 'decoder/7zdec.exe'} if edge else {})}}
    if platform.startswith('linux/'):
        expected['fontconfig'] = 'fontconfig/fonts.conf'
        if bodies.get('fontconfig/fonts.conf') != FONTCONFIG: raise ValueError('render fontconfig differs from its fixed original recipe')
    if bodies.get('manifest.json') != encoded(expected): raise ValueError('render manifest differs from its complete actual archive inventory')
    if edge:
        if bodies.get('windows-browser-recipe.json') != encoded(browser): raise ValueError('render Edge recipe differs from the exact locked acquisition record')
    else:
        recipe = json.loads(bodies.get('vendor-browser-recipe.json', b'null'))
        required = {'schema_version', 'provider', 'platform', 'version', 'archive', 'source_root', 'files'} | ({'linux_loader'} if platform.startswith('linux/') else set())
        if not isinstance(recipe, dict) or set(recipe) != required or recipe['schema_version'] != 1 or recipe['provider'] != 'google-chrome-for-testing' or recipe['platform'] != platform or recipe['version'] != browser['version'] or recipe['archive'] != {key: browser[key] for key in ('url', 'sha256', 'size_bytes')} or not isinstance(recipe['files'], list) or not recipe['files']: raise ValueError('render vendor recipe differs from its original locked archive')
        seen = set()
        for row in recipe['files']:
            if set(row) != {'path', 'sha256', 'size_bytes'} or bundle.safe(row['path']) in seen or not re.fullmatch('[a-f0-9]{64}', row['sha256']) or type(row['size_bytes']) is not int or row['size_bytes'] < 0: raise ValueError('render vendor recipe inventory is invalid')
            seen.add(row['path'])
        if bodies['vendor-browser-recipe.json'] != encoded(recipe): raise ValueError('render vendor recipe serialization differs from the source producer')
        if platform.startswith('linux/'):
            loader = recipe['linux_loader']
            if set(loader) != {'executable', 'library_dirs', 'materialization'} or loader['materialization'] != 'elf-interpreter-v1' or loader['library_dirs'] != ['elf/lib'] or bundle.safe(loader['executable']) not in rows: raise ValueError('render loader metadata is not bound to an actual pack member')
    if 'elf-closure.json' in bodies:
        closure = json.loads(bodies['elf-closure.json'])
        if set(closure) != {'schema_version', 'source', 'libraries', 'transformations'} or closure['schema_version'] != 1 or not isinstance(closure['libraries'], dict) or not closure['libraries'] or not isinstance(closure['transformations'], list): raise ValueError('render ELF closure metadata is invalid')
        for name, origin in closure['libraries'].items():
            if bundle.safe(name) not in rows or not name.startswith('elf/') or origin.get('sha256') != rows[name]['sha256'] or 'image_path' not in origin or 'browser_path' in origin: raise ValueError('render ELF closure metadata identifies foreign bytes')
        if bodies['elf-closure.json'] != encoded(closure): raise ValueError('render ELF closure serialization differs')
    return sorted(METADATA & bodies.keys())


def deb_member(archive, section, member_path, expected):
    """Read one ordinary copyright source form from an exact Debian container."""
    stream, before, _ = bundle.opened(archive.parent, {'path': archive.name, **identity(expected)})
    with stream:
        raw = stream.read(256 * 1024**2 + 1); after = os.fstat(stream.fileno())
        if before != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('render original package changed during notice inspection')
    if len(raw) > 256 * 1024**2 or raw[:8] != b'!<arch>\n': raise ValueError('render notice supplier archive is not a bounded Debian container')
    offset, data = 8, None
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b'`\n': raise ValueError('render notice Debian member header is invalid')
        try: name, size = header[:16].decode('ascii').strip().removesuffix('/'), int(header[48:58])
        except (UnicodeError, ValueError): raise ValueError('render notice Debian member framing is invalid') from None
        start = offset + 60
        if size < 0 or start + size > len(raw): raise ValueError('render notice Debian container is truncated')
        if re.fullmatch(section + r'\.tar(?:\.(?:xz|gz|bz2|zst))?', name):
            if data is not None: raise ValueError('render notice Debian data member is duplicated')
            data = raw[start:start + size]
        offset = start + size + (size & 1)
    if offset != len(raw) or data is None: raise ValueError('render notice Debian data member is missing')
    found = None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tar:
        for entry in tar:
            if entry.name.removeprefix('./') != member_path: continue
            if found is not None or not entry.isfile() or not 0 < entry.size <= 8 * 1024**2: raise ValueError('render original notice member is duplicate, special or oversized')
            with tar.extractfile(entry) as stream: found = stream.read(entry.size + 1)
            if len(found) != entry.size: raise ValueError('render original notice member is truncated')
    if found is None: raise ValueError('render original notice is absent from its locked supplier package')
    return found


def deb_notice(archive, member_path, expected):
    found = deb_member(archive, 'data', member_path, expected)
    return {'sha256': hashlib.sha256(found).hexdigest(), 'size_bytes': len(found)}


def package_source_requirements(archive, package, expected):
    records = debian.control_records(deb_member(archive, 'control', 'control', expected))
    if len(records) != 1 or any(records[0].get(field) != package[key] for field, key in [('Package', 'name'), ('Version', 'version'), ('Architecture', 'architecture')]): raise ValueError('render inspection container control identity differs from its locked package')
    record = records[0]
    required = [debian.source_identity(record.get('Source', package['name']), package['version'])]
    for field in ('Built-Using', 'Static-Built-Using'):
        required.extend(debian.source_identity(item.strip(), dependency=True) for item in record.get(field, '').split(',') if item.strip())
    return required


def capture_notice_sources(source_root, assets_root, render_subjects, output, wanted=()):
    """One-time extraction proof. Only original plaintext is retained, never
    the supplier's unshipped executable container or an implementation claim."""
    if output.exists(): raise ValueError('render original notice collection must be new')
    lock_file = source_root / 'runtime/perl-deps.lock.json'
    packages = json.loads(lock_file.read_bytes())['debian']['architectures']['arm64']['packages']
    indexed = {row['name']: row for row in packages}
    if len(indexed) != len(packages): raise ValueError('render original notice package lock is duplicated')
    output.mkdir(parents=True); (output / 'blobs').mkdir()
    files, extractions, seen, checked = {}, [], set(), {}
    for subject in render_subjects:
        if subject['id'] != 'render-assets-linux-arm64': continue
        for member in subject['members']:
            match = re.fullmatch(r'licenses/oci/(usr/share/doc/([^/]+)/copyright)', member['path'])
            content = identity(member); key = content['sha256'], content['size_bytes']
            if not match or key in seen or wanted and key not in wanted or match[2] not in indexed: continue
            package = indexed[match[2]]; name = '.artifacts/perl-debs/arm64/debs/' + bundle.safe(package['file'])
            if name not in checked:
                checked[name] = original(assets_root, {'path': name, 'sha256': package['sha256'], 'size_bytes': package['size']}, assets_root)
            container = checked[name]
            body = deb_member(assets_root / name, 'data', match[1], container)
            if {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)} != content: raise ValueError('copied render notice differs from its exact locked supplier member')
            body.decode('utf-8', errors='strict')
            if b'\0' in body: raise ValueError('original copyright notice is not plain readable source')
            notice = {'path': 'blobs/' + content['sha256'], **content, 'family': 'original-readable-copyright-source', 'role': 'preferred-source-form-original-notice-not-unshipped-implementation'}
            (output / notice['path']).write_bytes(body); files[notice['sha256']] = notice; seen.add(key)
            extractions.append({'supplier': package, 'original_member': match[1], 'source_identity': package_source_requirements(assets_root / name, package, container), 'notice': notice})
    extractions.sort(key=lambda row: row['original_member'])
    decoder = json.loads((source_root / 'runtime/native-decoder.lock.json').read_bytes())['source']
    stream, before, _ = bundle.opened(source_root, decoder)
    with stream, (output / 'blobs' / decoder['sha256']).open('xb') as target:
        while chunk := stream.read(1024**2): target.write(chunk)
        after = os.fstat(stream.fileno())
        if before != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('original decoder source changed during collection')
    if record(output / 'blobs' / decoder['sha256']) != identity(decoder): raise ValueError('original decoder source copy differs')
    files[decoder['sha256']] = {'path': 'blobs/' + decoder['sha256'], **identity(decoder), 'family': 'native-decoder-source', 'role': 'original-preferred-corresponding-source-archive'}
    value = {'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [files[key] for key in sorted(files)], 'notices': [], 'original_extractions': extractions, 'supplier_lock_sha256': digest(lock_file), 'collector_sha256': digest(Path(__file__)), 'scope': 'Original readable copyright notice source forms only; no unshipped supplier implementation bytes, implementation coverage, reproduced binary, or publisher authority. The additional 7-Zip source archive is the locked decoder source.'}
    (output / 'receipt.json').write_bytes(encoded(value))
    return value


def locked_notice_bindings(source_root, assets_root, render_subjects, wanted=()):
    selected = []
    for subject in render_subjects:
        if subject['id'] != 'render-assets-linux-arm64': continue
        for member in subject['members']:
            match = re.fullmatch(r'licenses/oci/(usr/share/doc/([^/]+)/copyright)', member['path'])
            content = identity(member)
            if match and (not wanted or (content['sha256'], content['size_bytes']) in wanted):
                selected.append((match[1], match[2], content))
    if not selected:
        return []
    packages = {row['name']: row for row in json.loads((source_root / 'runtime/perl-deps.lock.json').read_bytes())['debian']['architectures']['arm64']['packages']}
    selected = [(member, content) for member, package, content in selected if package in packages]
    if not selected:
        return []
    name = 'runtime/materials/native-render-notice-sources.lock.json'
    lock_file = source_root / name; lock = json.loads(lock_file.read_bytes())
    review = json.loads((source_root / 'quality/reviews/native-render-notice-sources-root-review.json').read_bytes())
    if lock.get('schema_version') != 1 or lock.get('qualification') != 'frozen-original-render-notice-source-extractions' or review.get('schema_version') != 1 or review.get('qualification') != 'independent-exact-render-notice-source-extraction-review-not-publisher-authority' or review.get('decision') != 'original-readable-notice-source-only' or review.get('reviewed_by') != 'root' or review.get('author') != 'native_transactions' or review.get('implementation_coverage') is not False or review.get('publisher_authority') is not False or review.get('lock') != {'path': name, **record(lock_file)}: raise ValueError('render original notice extraction lacks its exact independent source-bound review')
    stream, _, _ = bundle.opened(assets_root, lock['collection'])
    with stream: raw = stream.read(8 * 1024**2 + 1)
    if len(raw) > 8 * 1024**2: raise ValueError('render original notice collection exceeds bound')
    collection = json.loads(raw); table = collection.get('original_extractions')
    table_hash = hashlib.sha256(json.dumps(table, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if collection.get('schema_version') != 1 or collection.get('qualification') != 'pinned-source-and-notices' or collection.get('status') != 'passed' or not isinstance(table, list) or not table or len(table) > 1000 or table_hash != lock.get('extractions_sha256') or table_hash != review.get('extractions_sha256') or collection.get('supplier_lock_sha256') != digest(source_root / 'runtime/perl-deps.lock.json') or collection.get('collector_sha256') not in (ORIGINAL_NOTICE_COLLECTOR_SHA256, digest(Path(__file__))): raise ValueError('render original notice extraction identity changed')
    base = (assets_root / lock['collection']['path']).parent
    original_by_path = {}; declared = {row['path']: row for row in collection['files']}
    for row in table:
        package = row['supplier']; notice = row['notice']; member = 'usr/share/doc/' + package['name'] + '/copyright'
        if packages.get(package['name']) != package or row['original_member'] != member or member in original_by_path or declared.get(notice['path']) != notice or notice.get('family') != 'original-readable-copyright-source' or notice.get('role') != 'preferred-source-form-original-notice-not-unshipped-implementation': raise ValueError('render original notice source differs from its reviewed supplier/member universe')
        original_by_path[member] = row
    bindings, seen = [], set()
    for member, content in selected:
        source = original_by_path.get(member)
        key = content['sha256'], content['size_bytes']
        if source is None or key in seen: continue
        if identity(source['notice']) != content: raise ValueError('render copied notice differs from its independently reviewed original plaintext')
        material = original(base, source['notice'], assets_root); seen.add(key)
        origin = {'form': 'original-readable-copyright-notice-provided-as-preferred-source', 'original_member': source['original_member'], 'supplier_sha256': source['supplier']['sha256'], 'source': material}
        bindings.append({'content': content, 'sources': [origin], 'notices': [material], 'required_materials': [material]})
    return bindings


def decoder_binding(source_root, assets_root):
    lock = json.loads((source_root / 'runtime/native-decoder.lock.json').read_bytes())
    receipt_file = assets_root / '.artifacts/native-decoder/windows-arm64/7zdec.exe.receipt.json'
    receipt = json.loads(receipt_file.read_bytes())
    if receipt.get('schema_version') != 1 or receipt.get('target') != lock['compiler']['target'] or receipt.get('source') != lock['source'] or receipt.get('compiler', {}).get('version') != lock['compiler']['version'] or receipt.get('build_profile') != 'Alone7z/ST_MODE/Unicode/long-path/no-RAR' or identity(receipt) != identity(lock['program']): raise ValueError('render decoder differs from its exact source/build receipt')
    binary_name = '.artifacts/native-decoder/windows-arm64/7zdec.exe'
    stream, before, _ = bundle.opened(assets_root, {'path': binary_name, **identity(receipt)})
    with stream:
        binary = stream.read(64 * 1024**2 + 1); after = os.fstat(stream.fileno())
        if before != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('render decoder changed during source verification')
    position = struct.unpack_from('<I', binary, 60)[0] if len(binary) >= 64 else len(binary)
    if len(binary) > 64 * 1024**2 or binary[:2] != b'MZ' or position + 6 > len(binary) or binary[position:position + 4] != b'PE\0\0' or struct.unpack_from('<H', binary, position + 4)[0] != 0xaa64: raise ValueError('render decoder is not the exact ARM64 PE subject')
    source = original(source_root, lock['source'], source_root)
    sources = [source]
    runtime = json.loads((source_root / 'runtime/materials/lima-runtime-sources.lock.json').read_bytes())
    zig = next(row for row in runtime['runtime_sources'] if row['role'] == 'zig-source')
    if zig['url'] != 'https://ziglang.org/download/' + lock['compiler']['version'] + '/zig-' + lock['compiler']['version'] + '.tar.xz': raise ValueError('render decoder compiler source version differs')
    base = assets_root / '.artifacts/source-materials-data/native-decoder-zig'
    filename = base / 'receipt.json'
    if filename.exists():
        collection = json.loads(filename.read_bytes())
        if collection.get('schema_version') != 1 or collection.get('status') != 'passed' or collection.get('qualification') != 'pinned-source-and-notices':
            raise ValueError('render decoder original compiler source receipt is invalid')
        rows = collection['files']
    else:
        # Older source collections recorded this same exact archive for Lima.
        base = assets_root / '.artifacts/source-materials-data/derived-lima-go'
        rows = json.loads((base / 'receipt.json').read_bytes())['derived_runtime_sources']
    actual = [row for row in rows if row['role'] == 'zig-source']
    if len(actual) != 1 or identity(actual[0]) != identity(zig) or actual[0]['url'] != zig['url']: raise ValueError('render decoder original compiler source is missing')
    sources.append(original(base, actual[0], assets_root))
    notices = []; found = set()
    for archive, source_row in [(source_root / lock['source']['path'], sources[0]), (base / actual[0]['path'], sources[1])]:
        with tarfile.open(archive, 'r:*') as tar:
            for member in tar:
                if not member.isfile() or member.size > 1024**2 or not re.search(r'license|copying', member.name, re.I): continue
                with tar.extractfile(member) as stream: fingerprint = hashlib.file_digest(stream, 'sha256').hexdigest()
                for name, expected in lock['license_receipts'].items():
                    if fingerprint != expected: continue
                    notice = original(source_root, {'path': name, 'sha256': expected, 'size_bytes': member.size}, source_root)
                    notices.append({**notice, 'source_archive_sha256': source_row['sha256'], 'source_member': member.name}); found.add(name)
    if found != set(lock['license_receipts']): raise ValueError('render decoder original source/license closure is incomplete')
    recipes = [{'path': name, **record(source_root / name)} for name in ('scripts/runtime/build-native-decoder.py', 'runtime/native-decoder.lock.json')]
    return {'content': identity(lock['program']), 'sources': [*sources, *recipes], 'notices': notices, 'required_materials': sources}, {'content': identity(lock['source']), 'sources': sources[:1], 'notices': notices[:], 'required_materials': sources[:1]}


def derive(source_root, assets_root, runtime_root, discovery, wanted=(), recorder=None):
    source_root, assets_root, runtime_root = map(Path, (source_root, assets_root, runtime_root))
    generator = digest(Path(__file__)); result = []; considered = set(); owned = set()
    auxiliary = json.loads((runtime_root / 'runtime/auxiliary-artifacts.json').read_bytes())
    locked_fonts = [row for row in json.loads((source_root / 'runtime/render-deps.lock.json').read_bytes())['debian']['architectures']['arm64']['packages'] if row['name'].startswith('fonts-noto-')]
    notices = [{'path': name, **record(source_root / name)} for name in ('LICENSE', 'NOTICE')]
    for subject in discovery['subjects']:
        if not subject['id'].startswith('render-assets-'): continue
        host = subject['id'].removeprefix('render-assets-').replace('-', '/')
        if host not in BROWSERS: raise ValueError('render subject has an unsupported native platform')
        matches = [row for row in auxiliary['assets'] if row['id'] == subject['id'] and identity(row) == identity(subject)]
        if len(matches) != 1: raise ValueError('render archive differs from its actual frozen auxiliary descriptor')
        original(runtime_root, matches[0], runtime_root)
        rows, bodies = archive_inventory(runtime_root / matches[0]['path'], matches[0])
        if sorted(rows.values(), key=lambda row: row['path']) != sorted(({key: member[key] for key in ('path', 'sha256', 'size_bytes')} for member in subject['members']), key=lambda row: row['path']): raise ValueError('render discovery differs from actual archive bytes')
        lock_name = 'runtime/native-browser-' + BROWSERS[host] + '.lock.json'
        browser = json.loads((source_root / lock_name).read_bytes())
        owned.update((row['sha256'], row['size_bytes']) for name, row in rows.items() if name in METADATA or name in ('decoder/7zdec.exe', 'decoder/7z2606-src.tar.xz'))
        for name in validate_metadata(rows, bodies, browser, locked_fonts, host):
            content = identity(rows[name]); key = content['sha256'], content['size_bytes']; considered.add(key)
            if wanted and key not in wanted: continue
            sources = [{'form': 'preferred-source-form-shipped-as-readable-data', 'artifact': subject['id'], 'artifact_sha256': subject['sha256'], 'member_path': name, **content}, *[{'path': filename, **record(source_root / filename)} for filename in ('scripts/runtime/prepare-native-render.py', 'scripts/runtime/render_manifest.py', 'scripts/runtime/close-native-render.py', lock_name, 'runtime/render-deps.lock.json')]]
            result.append({'content': content, 'sources': sources, 'notices': notices, 'required_materials': []})
        if host == 'win32/arm64':
            for binding in decoder_binding(source_root, assets_root):
                content = binding['content']; key = content['sha256'], content['size_bytes']; considered.add(key)
                if rows.get('decoder/7zdec.exe') and identity(rows['decoder/7zdec.exe']) != identity(json.loads((source_root / 'runtime/native-decoder.lock.json').read_bytes())['program']): raise ValueError('actual render decoder member differs')
                if wanted and key not in wanted: continue
                result.append(binding)
    copied = locked_notice_bindings(source_root, assets_root, discovery['subjects'], wanted)
    result.extend(copied); considered.update((row['content']['sha256'], row['content']['size_bytes']) for row in copied)
    if digest(Path(__file__)) != generator: raise ValueError('render source binding code changed during verification')
    unresolved = [{'sha256': fingerprint, 'size_bytes': size} for fingerprint, size in sorted((owned & set(wanted) if wanted else owned) - considered)]
    return {'schema_version': 1, 'qualification': 'exact-native-render-configuration-notice-decoder-source-joins', 'status': 'incomplete' if unresolved else 'passed', 'target_execution': False, 'emulation': False, 'bindings': result, 'generator_sha256': generator, 'unresolved': unresolved}
