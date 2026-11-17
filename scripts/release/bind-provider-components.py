"""Join shipped provider members to exact retained source and original notices.

Only frozen provider inventories select subjects. Target executables are read as
data; no provider, guest, installer or target program is executed here.
"""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import zipfile
import concurrent.futures
import argparse
import ast
from contextlib import contextmanager, nullcontext


def load_module(root, name, relative):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def fingerprint(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def content(row):
    return {'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row.get('size_bytes', row.get('size'))}


def verified(base, row):
    name = row['path']
    if not isinstance(name, str) or not name or name.startswith('/') or re.search(r'[\\\x00:]', name) or any(part in ('', '.', '..') for part in name.split('/')): raise ValueError('unsafe provider replay input path')
    file = base
    for part in name.split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('provider replay input contains a link')
    before = file.stat(); expected = content(row)
    if not file.is_file() or before.st_size > 8 * 1024**3 or expected['size_bytes'] is not None and before.st_size != expected['size_bytes'] or fingerprint(file) != expected['sha256']: raise ValueError('provider replay input bytes differ: ' + name)
    after = file.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('provider replay input changed')
    return file


@contextmanager
def original_source(base, row, assets_root, source_parts=None, recorder=None):
    """Read a declared original in place, or from the verified source bundle.

    Staged files remain subject to their normal verification; streaming is
    only used when the declared original was deliberately not materialized.
    """
    name = row['path']
    if not isinstance(name, str) or not name or name.startswith('/') or re.search(r'[\\\x00:]', name) or any(part in ('', '.', '..') for part in name.split('/')): raise ValueError('unsafe provider replay input path')
    file = base / name
    # Inspect all existing parents even when the leaf was deliberately omitted.
    for parent in (file, *file.parents):
        if parent == base.parent: break
        if parent.is_symlink(): raise ValueError('provider replay input contains a link')
    if file.exists() or file.is_symlink() or source_parts is None:
        yield verified(base, row)
        return
    expected = content(row)
    if type(expected['size_bytes']) is not int or expected['size_bytes'] < 0: raise ValueError('streamed provider source has no exact size')
    file.relative_to(assets_root)  # A collection cannot name a foreign input.
    with source_parts.open_blob(expected['sha256'], expected['size_bytes']) as stream:
        if recorder is not None: recorder.source_blob(file, expected['sha256'], expected['size_bytes'])
        yield stream


def material(base, row, assets_root, source_parts=None, recorder=None):
    with original_source(base, row, assets_root, source_parts, recorder) as source:
        size = source.stat().st_size if isinstance(source, Path) else content(row)['size_bytes']
        return {'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': size, 'path': (base / row['path']).relative_to(assets_root).as_posix()}


def notice_members(file, declarations, archive_hash=None):
    """Check retained notices against their original source archive members."""
    wanted = {row.get('source_path', row.get('path')): content(row) for row in declarations}
    if not wanted: raise ValueError('provider source lacks original notices')
    found = {}; archive_hash = fingerprint(file) if archive_hash is None else archive_hash
    opener = {'name': file} if isinstance(file, (str, Path)) else {'fileobj': file}
    with tarfile.open(mode='r:*', **opener) as archive:
        for entry in archive:
            if entry.name not in wanted: continue
            if entry.name in found or not entry.isfile() or not 0 <= entry.size <= 8 * 1024**2: raise ValueError('provider source notice is duplicate or special')
            with archive.extractfile(entry) as stream: actual = {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'size_bytes': entry.size}
            if actual != wanted[entry.name]: raise ValueError('provider source notice differs from original archive')
            found[entry.name] = {'source_archive_sha256': archive_hash, 'member_path': entry.name, **actual}
    if set(found) != set(wanted): raise ValueError('provider original source notice missing')
    return list(found.values())


def archive_notices(file, archive_hash=None):
    result = []; archive_hash = fingerprint(file) if archive_hash is None else archive_hash
    opener = {'name': file} if isinstance(file, (str, Path)) else {'fileobj': file}
    with tarfile.open(mode='r:*', **opener) as archive:
        for entry in archive:
            if not entry.isfile() or not re.fullmatch(r'(?:LICENSE|COPYING|NOTICE|COPYRIGHT|PATENTS)(?:[._-].*)?', entry.name.rsplit('/', 1)[-1], re.I): continue
            if not 0 <= entry.size <= 8 * 1024**2: raise ValueError('provider original notice exceeds bound')
            with archive.extractfile(entry) as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            result.append({'source_archive_sha256': archive_hash, 'member_path': entry.name, 'sha256': digest, 'size_bytes': entry.size})
    if not result: raise ValueError('provider source original notices missing')
    return result


HOST_GO = re.compile(r'(?:/bin/limactl|/libexec/lima/(?:limactl-mcp|limactl-menu|privileged/lima-privileged-block-device)|/share/lima/lima-guestagent\.[^/]+\.gz)$')


def protected_runtime_sources(source_root, data):
    lock = json.loads((source_root / 'runtime/materials/lima-runtime-sources.lock.json').read_bytes())
    if lock.get('schema_version') != 1 or lock.get('qualification') != 'frozen-lima-runtime-original-source-identities': raise ValueError('provider C runtime source authority missing')
    expected = {row['role']: row for row in lock['runtime_sources']}
    actual = {row['role']: row for row in data.get('derived_runtime_sources', [])}
    if set(expected) != {'go-source', 'zig-source', 'libseccomp-source'} or len(actual) != len(data.get('derived_runtime_sources', [])) or set(actual) != set(expected) or any(content(actual[key]) != content(value) or actual[key]['url'] != value['url'] for key, value in expected.items()): raise ValueError('provider source-closed C runtime inputs missing or changed')
    return [actual[key] for key in sorted(expected)]


def go_subject(file, row, temporary):
    if row['path'].endswith('.gz'):
        target = temporary / hashlib.sha256(row['path'].encode()).hexdigest(); size = 0
        with gzip.open(file, 'rb') as source, target.open('xb') as output:
            while data := source.read(1024**2):
                size += len(data)
                if size > 256 * 1024**2: raise ValueError('provider Go subject expansion exceeds bound')
                output.write(data)
        return target
    return file


def collect_host_go(source_root, assets_root, output, download=False):
    """Acquire only exact module/stdlib identities embedded in shipped Lima."""
    source_root, assets_root, output = map(Path, (source_root, assets_root, output))
    if output.exists(): raise ValueError('provider Go collection requires a new directory')
    helper = load_module(source_root, 'ud_host_go_sources', Path('scripts/release/collect-go-sources.py'))
    provider = assets_root / '.artifacts/provider-assets/lazy-v6-derived'
    lock = json.loads((provider / 'provider-receipts.json').read_bytes())
    reuse = assets_root / '.artifacts/source-materials-data/derived-lima-go'
    previous = json.loads((reuse / 'receipt.json').read_bytes()); inspector = previous['go_inspector']
    go = Path(inspector['path']); binaries = []; modules = {}; standards = set()
    with tempfile.TemporaryDirectory(prefix='ud-provider-go-metadata-') as temporary:
        for row in lock['files']:
            if not HOST_GO.search(row['path']): continue
            original = verified(provider, row); subject = go_subject(original, row, Path(temporary))
            info = helper.materials.go_build_info(subject, go, inspector['sha256'])
            if info['main']['Path'] != 'github.com/lima-vm/lima/v2' or dict((item['Key'], item.get('Value', '')) for item in info['build_settings']).get('vcs.modified') != 'false': raise ValueError('Lima Go binary has an unbound main source')
            binaries.append({'path': row['path'], **content(row), 'build_info': info})
            standards.add(info['go_version'])
            for item in info['dependencies']:
                if item['h1'] is None: raise ValueError('Lima dependency lacks embedded source content hash')
                key = (item['path'], item['version'])
                if key in modules and modules[key]['h1'] != item['h1']: raise ValueError('Lima binaries disagree on a source module')
                modules.setdefault(key, {**item, 'consumers': []})['consumers'].append(row['path'])
    output.mkdir(parents=True); (output / 'modules').mkdir(); (output / 'standard-libraries').mkdir(); (output / 'main-sources').mkdir(); (output / 'metadata').mkdir()
    (output / 'INCOMPLETE').write_text('Provider Go source collection has not completed.\n')
    reusable = {(item['path'], item['version']): item for item in previous['modules']}
    def obtain(item):
        relative = 'modules/' + hashlib.sha256((item['path'] + '@' + item['version']).encode()).hexdigest(); target = output / relative
        cached = reusable.get((item['path'], item['version']))
        if cached and cached['h1'] == item['h1']: shutil.copyfile(verified(reuse, cached['archive']), target)
        url = 'https://proxy.golang.org/' + helper.escaped(item['path']) + '/@v/' + helper.escaped(item['version']) + '.zip'
        if not target.exists() and download: helper.acquisition.acquire(url, target, maximum=512 * 1024**2)
        if not target.is_file(): raise ValueError('Missing exact Lima source module: ' + item['path'] + '@' + item['version'])
        if helper.materials.go_zip_hash(target, item['path'], item['version']) != item['h1']: raise ValueError('Lima source module content differs from embedded hash')
        notices = []
        with zipfile.ZipFile(target) as archive:
            for entry in archive.infolist():
                if re.fullmatch(r'(?:LICENSE|COPYING|NOTICE|COPYRIGHT|PATENTS)(?:[._-].*)?', entry.filename.rsplit('/', 1)[-1], re.I):
                    if entry.file_size > 8 * 1024**2: raise ValueError('Lima module notice exceeds bound')
                    raw = archive.read(entry); notices.append({'path': entry.filename, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)})
        if not notices: raise ValueError('Lima source module omits original notices: ' + item['path'])
        return {**item, 'url': url, 'archive': {'path': relative, 'sha256': fingerprint(target), 'size_bytes': target.stat().st_size}, 'acquired': True, 'license_files': notices}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: selected = list(pool.map(obtain, [modules[key] for key in sorted(modules)]))
    catalog = reuse / 'metadata/go-releases.json'; shutil.copyfile(catalog, output / 'metadata/go-releases.json'); releases = json.loads(catalog.read_bytes()); standard_rows = []
    for version in sorted(standards):
        matches = [item for release in releases if release['version'] == version for item in release['files'] if item['kind'] == 'source']
        if len(matches) != 1: raise ValueError('Exact Lima standard-library source absent from original publisher catalog')
        row = matches[0]; relative = 'standard-libraries/' + row['filename']; target = output / relative
        old = reuse / relative
        if old.is_file(): shutil.copyfile(verified(reuse, {'path': relative, 'sha256': row['sha256'], 'size_bytes': row['size']}), target)
        url = 'https://go.dev/dl/' + row['filename']
        if not target.exists() and download: helper.acquisition.acquire(url, target, row['size'], row['sha256'])
        verified(output, {'path': relative, 'sha256': row['sha256'], 'size_bytes': row['size']})
        standard_rows.append({'version': version, 'url': url, 'path': relative, 'sha256': row['sha256'], 'size_bytes': row['size'], 'acquired': True, 'publisher_catalog': {'path': 'metadata/go-releases.json', 'sha256': fingerprint(catalog), 'size_bytes': catalog.stat().st_size}})
    source_base = assets_root / '.artifacts/source-materials-data/provider-sources-binary-v2'; source_data = json.loads((source_base / 'receipt.json').read_bytes()); sources = []
    for row in source_data['files']:
        if row['name'] != 'lima-vm/lima': continue
        commits = {dict((item['Key'], item.get('Value', '')) for item in binary['build_info']['build_settings']).get('vcs.revision') for binary in binaries}
        if commits != {row['version']}: raise ValueError('Lima binary main commit differs from exact supplier source')
        relative = 'main-sources/' + row['sha256']; shutil.copyfile(verified(source_base, row), output / relative)
        sources.append({'repository': row['name'], 'commit': row['version'], 'path': relative, **content(row), 'acquired': True, 'license_files': [{'path': notice['source_path'], **content(notice)} for notice in row['notices']]})
    if len(sources) != 1 or not binaries: raise ValueError('Lima Go source main or subjects missing')
    report = {'schema_version': 1, 'qualification': 'binary-bound-go-module-source-inventory', 'status': 'passed', 'target_execution': False, 'emulation': False, 'go_inspector': inspector, 'binaries': binaries, 'modules': selected, 'main_sources': sources, 'standard_libraries': standard_rows, 'module_hashes_pending': [], 'standard_libraries_pending': [], 'static_c_dependencies_pending': [], 'cgo_relationship': 'Darwin system frameworks are prerequisites, not redistributed libraries.'}
    (output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n'); (output / 'INCOMPLETE').unlink(); return report


def provider_sources(source_root, assets_root, wanted=None, source_parts=None, recorder=None):
    base = assets_root / '.artifacts/source-materials-data/provider-sources-binary-v2'
    data = json.loads((base / 'receipt.json').read_bytes())
    lock = json.loads((source_root / 'runtime/materials/provider-source-mappings.lock.json').read_bytes())
    if data.get('status') != 'passed' or data.get('qualification') != 'pinned-source-and-notices': raise ValueError('provider source collection is incomplete')
    # Whole runtime/bootstrap locks can change acquisition metadata without
    # changing these source archives. Reconstruct the source universe from its
    # own exact authorities, then select current binary commits below.
    for name, digest in data['locks'].items():
        if name in ('runtime/materials/provider-source-mappings.lock.json', 'runtime/materials/provider-binary-sources.lock.json') and fingerprint(source_root / name) != digest: raise ValueError('provider source authority changed: ' + name)
    expected = {(row['name'], row['version']): row for row in lock['sources']}
    actual = {(row['name'], row['version']): row for row in data['files']}
    if len(actual) != len(data['files']) or set(expected) != set(actual): raise ValueError('provider source universe differs from frozen mappings')
    result = {}
    for key, row in actual.items():
        if content(row) != content(expected[key]): raise ValueError('provider source identity differs from frozen mapping')
        if wanted is not None and key not in wanted: continue
        archive = material(base, row, assets_root, source_parts, recorder)
        with original_source(base, row, assets_root, source_parts, recorder) as source:
            notices = notice_members(source, row['notices'], archive['sha256'])
        originals = [archive, *[material(base, notice, assets_root) for notice in row['notices']]]
        result[key] = {'source': {'repository': key[0], 'commit': key[1], 'archive': archive}, 'notices': notices, 'required_materials': originals}
    return result


def observe_archive(file, descriptor, profile):
    if file.is_symlink() or not file.is_file() or content(descriptor) != {'sha256': fingerprint(file), 'size_bytes': file.stat().st_size}: raise ValueError('actual provider archive differs from candidate')
    lazy = profile['lazy_assets']
    if content(lazy) != content(descriptor): raise ValueError('provider candidate archive differs from frozen runtime')
    expected = {row['path']: content(row) for row in lazy['files']}
    if len(expected) != len(lazy['files']) or not expected: raise ValueError('provider frozen member inventory is empty or duplicated')
    found = {}; total = 0
    with tarfile.open(file, 'r:gz') as archive:
        for entry in archive:
            if entry.isdir(): continue
            if entry.name not in expected or entry.name in found or not entry.isfile() or not 0 <= entry.size <= 2 * 1024**3: raise ValueError('provider archive adds, duplicates or changes a member')
            total += entry.size
            if total > 4 * 1024**3: raise ValueError('provider archive expansion exceeds bound')
            with archive.extractfile(entry) as stream: actual = {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'size_bytes': entry.size}
            if actual != expected[entry.name]: raise ValueError('provider archive member bytes differ from frozen inventory')
            found[entry.name] = actual
    if set(found) != set(expected): raise ValueError('provider archive omits frozen members')
    return found


@contextmanager
def provider_archive_member(artifact, name, expected):
    """Read one actual provider member into disposable private storage.

    Archive identity and the requested member are reverified before use; the
    archive's member path is never used as a host extraction path.
    """
    file = Path(artifact['file'])
    if file.is_symlink() or not file.is_file(): raise ValueError('provider archive is absent or linked')
    before = file.stat(); identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    if content(artifact) != {'sha256': fingerprint(file), 'size_bytes': before.st_size}: raise ValueError('actual provider archive differs from candidate')
    if not isinstance(name, str) or not name or name.startswith('/') or re.search(r'[\\\x00:]', name) or any(part in ('', '.', '..') for part in name.split('/')): raise ValueError('provider archive member path is unsafe')
    if type(expected.get('size_bytes')) is not int or not 0 <= expected['size_bytes'] <= 512 * 1024**2: raise ValueError('selected provider member exceeds the private workspace bound')
    with tempfile.TemporaryDirectory(prefix='ud-provider-member-') as temporary:
        output = Path(temporary) / 'member'; found = False
        with tarfile.open(file, 'r:gz') as archive:
            for entry in archive:
                if entry.name != name: continue
                if found or not entry.isfile() or entry.size != expected['size_bytes']: raise ValueError('selected provider archive member is duplicate, special or changed')
                found = True; digest = hashlib.sha256(); size = 0
                with archive.extractfile(entry) as source, output.open('xb') as target:
                    while chunk := source.read(1024**2):
                        size += len(chunk)
                        if size > expected['size_bytes']: raise ValueError('selected provider member exceeds its receipt')
                        digest.update(chunk); target.write(chunk)
                if size != expected['size_bytes'] or digest.hexdigest() != expected['sha256']: raise ValueError('selected provider member differs from frozen bytes')
        after = file.stat()
        if not found or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('selected provider member is missing or its archive changed')
        yield output


def go_materials(source_root, assets_root, base, selected_binaries, subject_files=None, member_source=None, source_parts=None, recorder=None):
    """Rehash all original Go inputs and reconstruct each module content hash."""
    helper = load_module(source_root, 'ud_provider_go_materials', Path('scripts/release/source_materials.py'))
    data = json.loads((base / 'receipt.json').read_bytes())
    if data.get('status') != 'passed' or data.get('qualification') != 'binary-bound-go-module-source-inventory' or any(data.get(key) for key in ('module_hashes_pending', 'standard_libraries_pending', 'static_c_dependencies_pending')): raise ValueError('provider Go source closure is incomplete')
    subjects = {row['sha256']: row for row in data['binaries']}; result = {}
    if len(subjects) != len(data['binaries']):
        # Equal bytes across architectures/entry points can share one identity.
        for row in data['binaries']:
            if content(row) != content(subjects[row['sha256']]): raise ValueError('Go subject digest has conflicting sizes')
    selected = {name: body for name, body in selected_binaries.items() if body['sha256'] in subjects}
    if not selected: return result
    observed_infos = {}
    with tempfile.TemporaryDirectory(prefix='ud-provider-go-replay-') as temporary:
        for name, body in selected.items():
            declared = subjects[body['sha256']]
            if subject_files is None:
                cached = assets_root / '.artifacts/provider-assets/lazy-v6-derived' / name
                if cached.exists() or cached.is_symlink() or member_source is None:
                    original = verified(assets_root / '.artifacts/provider-assets/lazy-v6-derived', {'path': name, **body})
                    selected_source = nullcontext(original)
                else: selected_source = member_source(name, body)
            else: selected_source = nullcontext(subject_files[name])
            with selected_source as original, tempfile.TemporaryDirectory(prefix='input-', dir=temporary) as input_temporary:
                subject = go_subject(original, {'path': name}, Path(input_temporary)) if subject_files is None else original
                observed = helper.go_build_info(subject, Path(data['go_inspector']['path']), data['go_inspector']['sha256'])
            if observed != declared['build_info']: raise ValueError('actual provider Go metadata differs from its source declaration')
            observed_infos[name] = observed
    main_sources = {}; expected_modules = {}; expected_versions = set(); needs_c_runtime = False
    protected = json.loads((source_root / 'runtime/materials/lima-runtime-sources.lock.json').read_bytes())
    for name, info in observed_infos.items():
        match = re.match(r'^github\.com/([^/]+/[^/]+)(?:/|$)', info['main']['Path'])
        if match is None: raise ValueError('provider Go main has no declared exact repository')
        repository = match[1]; settings = {row['Key']: row.get('Value', '') for row in info['build_settings']}; commit = settings.get('vcs.revision')
        if commit is None:
            kind = {'containerd/containerd': 'containerd', 'opencontainers/runc': 'runc'}.get(repository)
            proof = data.get('derivation', {}).get(str(kind) + '_derivation', {})
            if kind is None or proof.get('builder_sha256') != fingerprint(source_root / ('scripts/runtime/build-lima-' + kind + '.py')): raise ValueError('provider Go derived main lacks its exact source-bound build recipe')
            builder = ast.parse((source_root / ('scripts/runtime/build-lima-' + kind + '.py')).read_bytes())
            constants = [ast.literal_eval(row.value) for row in builder.body if isinstance(row, ast.Assign) and any(isinstance(target, ast.Name) and target.id == ('RUNC_COMMIT' if kind == 'runc' else 'COMMIT') for target in row.targets)]
            if constants != [proof.get('commit')]: raise ValueError('provider derived Go main commit differs from protected builder')
            def has_subject(value):
                if isinstance(value, dict): return 'sha256' in value and content(value) == selected[name] or any(has_subject(item) for item in value.values())
                if isinstance(value, list): return any(has_subject(item) for item in value)
                return False
            if not has_subject(proof.get('binaries')): raise ValueError('provider derived Go main recipe has a foreign binary')
            commit = proof['commit']
        matches = [row for row in data['main_sources'] if row['repository'] == repository and row['commit'] == commit]
        if len(matches) != 1: raise ValueError('provider Go main source differs from observed repository/commit')
        source = matches[0]; main_sources[(repository, commit)] = source
        pinned = [row for row in protected['main_sources'] if row['repository'] == repository]
        if pinned and (len(pinned) != 1 or pinned[0]['commit'] != commit or content(pinned[0]) != content(source)): raise ValueError('provider Go main archive differs from protected original source')
        if repository == 'lima-vm/lima':
            mapping = json.loads((source_root / 'runtime/materials/provider-source-mappings.lock.json').read_bytes())
            pinned = [row for row in mapping['sources'] if row['name'] == repository and row['version'] == commit]
            if len(pinned) != 1 or content(pinned[0]) != content(source): raise ValueError('Lima main archive differs from frozen source mapping')
        needs_c_runtime |= repository == 'opencontainers/runc' and settings.get('CGO_ENABLED') == '1'
        if settings.get('vcs.revision') is None and content(data['derivation'][kind + '_derivation']['main_source']) != content(source): raise ValueError('derived Go main source differs from actual build inputs')
        sums = {}
        if any(row['h1'] is None for row in info['dependencies']):
            with original_source(base, source, assets_root, source_parts, recorder) as original:
                opener = {'name': original} if isinstance(original, Path) else {'fileobj': original}
                with tarfile.open(mode='r:*', **opener) as archive:
                    entries = [row for row in archive if row.name.count('/') == 1 and row.name.endswith('/go.sum')]
                    if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 32 * 1024**2: raise ValueError('provider main source go.sum missing or ambiguous')
                    raw = archive.extractfile(entries[0]).read().decode('utf-8')
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) != 3 or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', parts[2]): raise ValueError('provider Go source go.sum is malformed')
                if not parts[1].endswith('/go.mod'): sums[(parts[0], parts[1])] = parts[2]
        for dependency in info['dependencies']:
            key = dependency['path'], dependency['version']; expected = dependency['h1'] or sums.get(key)
            if expected is None or key in expected_modules and expected_modules[key] != expected: raise ValueError('provider Go actual dependency has no unique source hash')
            expected_modules[key] = expected
        expected_versions.add(info['go_version'])
    module_rows = {(row['path'], row['version']): row for row in data['modules']}
    if len(module_rows) != len(data['modules']) or not set(expected_modules) <= set(module_rows) or any(module_rows[key]['h1'] != value for key, value in expected_modules.items()): raise ValueError('provider Go module source set omits or changes actual dependencies')
    standard_rows = {row['version']: row for row in data['standard_libraries']}
    if len(standard_rows) != len(data['standard_libraries']) or not expected_versions <= set(standard_rows): raise ValueError('provider Go standard-library source set omits an actual compiler version')
    sources = []; notices = []; originals = []
    for source in main_sources.values():
        archive = material(base, source, assets_root, source_parts, recorder)
        builds = [{'module': info['main'], 'vcs_modified': next((row.get('Value', '') for row in info['build_settings'] if row['Key'] == 'vcs.modified'), None)} for info in observed_infos.values() if info['main']['Path'].startswith('github.com/' + source['repository'])]
        sources.append({'repository': source['repository'], 'commit': source['commit'], 'archive': archive, 'observed_build_metadata': builds, 'relationship': 'Exact original source identity; no binary reproduction or clean upstream worktree is inferred.'}); originals.append(archive)
        with original_source(base, source, assets_root, source_parts, recorder) as original:
            notices.extend(notice_members(original, source['license_files'], archive['sha256']))
    for key in sorted(expected_modules):
        dependency = module_rows[key]
        archive = material(base, dependency['archive'], assets_root, source_parts, recorder)
        with original_source(base, dependency['archive'], assets_root, source_parts, recorder) as original:
            if helper.go_zip_hash(original, dependency['path'], dependency['version']) != dependency['h1']: raise ValueError('provider Go module content hash differs')
        sources.append({'module': dependency['path'], 'version': dependency['version'], 'h1': dependency['h1'], 'archive': archive}); originals.append(archive)
        with original_source(base, dependency['archive'], assets_root, source_parts, recorder) as original, zipfile.ZipFile(original) as package:
            actual_notices = {row.filename for row in package.infolist() if re.fullmatch(r'(?:LICENSE|COPYING|NOTICE|COPYRIGHT|PATENTS)(?:[._-].*)?', row.filename.rsplit('/', 1)[-1], re.I)}
            declared = {row['path']: row for row in dependency['license_files']}
            if not actual_notices or len(declared) != len(dependency['license_files']) or not set(declared) <= actual_notices: raise ValueError('provider Go original notice member set changed')
            for name in sorted(actual_notices):
                entry = package.getinfo(name)
                if entry.file_size > 8 * 1024**2: raise ValueError('provider Go original module notice exceeds bound')
                raw = package.read(entry); actual = {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
                if name in declared and actual != content(declared[name]): raise ValueError('provider Go original module notice differs')
                notices.append({'source_archive_sha256': archive['sha256'], 'member_path': name, **actual})
    for source in [*[standard_rows[key] for key in sorted(expected_versions)], *(protected_runtime_sources(source_root, data) if needs_c_runtime else [])]:
        if 'publisher_catalog' in source:
            catalog = material(base, source['publisher_catalog'], assets_root)
            releases = json.loads((base / source['publisher_catalog']['path']).read_bytes())
            expected = [row for release in releases if release['version'] == source['version'] for row in release['files'] if row['kind'] == 'source']
            if len(expected) != 1 or expected[0]['sha256'] != source['sha256'] or expected[0]['size'] != source['size_bytes'] or expected[0]['filename'] != Path(source['path']).name: raise ValueError('provider Go standard library differs from original publisher catalog')
            sources.append(catalog); originals.append(catalog)
        archive = material(base, source, assets_root, source_parts, recorder); sources.append(archive); originals.append(archive)
        with original_source(base, source, assets_root, source_parts, recorder) as original:
            notices.extend(archive_notices(original, archive['sha256']))
    if not notices: raise ValueError('provider Go source notices absent')
    for name, body in selected.items():
        if content(subjects[body['sha256']]) != body: raise ValueError('provider Go binary size differs')
        result[name] = {'sources': sources, 'notices': notices, 'required_materials': originals}
    return result


def guest_materials(source_root, assets_root, architecture, image, recorder=None, source_parts=None):
    lock = json.loads((source_root / 'runtime/materials/lima-ubuntu/extracted-images.lock.json').read_bytes())
    if lock.get('schema_version') != 1 or lock.get('qualification') != 'source-bound-previously-verified-guest-package-extraction-identities': raise ValueError('source-bound guest extraction authority missing')
    for key in ('image_lock', 'producer', 'tool_recipe'): verified(source_root, lock[key])
    anchor = lock['images'][architecture]
    if content(anchor['image']) != image: raise ValueError('provider guest image differs from protected extraction authority')
    inventory_file = verified(assets_root, anchor['extraction_receipt'])
    status_file = verified(assets_root, anchor['status'])
    manifest_file = verified(source_root, {'path': 'runtime/materials/lima-ubuntu/' + architecture + '.manifest', **content(anchor['publisher_manifest'])})
    helper = load_module(source_root, 'ud_provider_guest_sources', Path('scripts/release/bind-binary-sources.py'))
    helper.ROOT = source_root
    base = assets_root / '.artifacts/source-materials-data'
    inventory = json.loads(inventory_file.read_bytes()); source_file = base / 'ubuntu-sources-historical/receipt.json'; sources = json.loads(source_file.read_bytes())
    if inventory.get('status') != 'passed' or inventory.get('qualification') != 'image-bound-publisher-package-and-notice-inventory' or content(inventory['image']) != image or inventory.get('guest_architecture') != architecture: raise ValueError('provider guest inventory does not bind actual image')
    if sources.get('status') != 'passed' or sources.get('missing') or not any(row['sha256'] == fingerprint(inventory_file) for row in sources['subjects']): raise ValueError('provider guest source closure is incomplete or unbound')
    keyring = assets_root / '.artifacts/lima-product/ubuntu/ubuntu-archive-keyring.gpg'
    gpgv = Path(shutil.which('gpgv') or '').resolve(strict=True)
    helper.authenticated_sources(source_file, sources, keyring, gpgv)
    # Signature/index metadata remains on disk for gpgv and index tools; the
    # much larger checksum-bound originals can be read from source parts.
    originals = [material(source_file.parent, row, assets_root, source_parts, recorder) for row in sources['files']]
    originals.extend(material(source_file.parent, row, assets_root) for row in sources['metadata'])
    if content(inventory['status_file']) != content(anchor['status']): raise ValueError('provider guest database is not the protected extraction output')
    status = status_file.read_bytes()
    publisher_rows = [line.split('\t') for line in manifest_file.read_text().replace('\\n', '\n').replace('\\t', '\t').splitlines()]
    if any(len(row) != 2 for row in publisher_rows): raise ValueError('provider guest publisher manifest malformed')
    manifest = ''.join(name + '\t' + version + '\n' for name, version in publisher_rows).encode()
    observed = helper.materials.installed_packages(status, manifest, architecture)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    if len(observed) != anchor['packages'] or hashlib.sha256(canonical(sorted((row['name'], row['version']) for row in observed))).hexdigest() != anchor['package_universe_sha256']: raise ValueError('provider guest package universe differs from protected publisher inventory')
    project = lambda rows: sorted((row['name'], row['version'], row['architecture'], json.dumps(row['source'], sort_keys=True), json.dumps(row['built_using'], sort_keys=True)) for row in rows)
    if project(observed) != project(inventory['packages']): raise ValueError('provider guest package inventory omits actual database entries')
    available = {(row['name'], row['version']): row for row in sources['sources']}; selected = []
    for required in helper.materials.source_requirements(observed):
        source = available.get((required['name'], required['version']))
        if source is None: raise ValueError('provider guest corresponding source missing')
        selected.append(source)
    notices = [material(inventory_file.parent, row['notice'], assets_root) for row in inventory['packages']]
    notice_inventory = sorted([{'package': row['name'], 'version': row['version'], 'architecture': row['architecture'], **material(inventory_file.parent, row['notice'], assets_root)} for row in inventory['packages']], key=lambda row: (row['package'], row['version'], row['architecture']))
    if hashlib.sha256(canonical(notice_inventory)).hexdigest() != anchor['notices_inventory_sha256']: raise ValueError('provider guest notice attribution differs from protected extraction')
    originals.extend([material(inventory_file.parent, inventory['status_file'], assets_root), *notices])
    # The verification keyring is an exact member of an already required
    # Ubuntu source archive. Preserve that origin instead of relying on a
    # developer cache pathname in relocated replay.
    key_sources = [row for row in sources['sources'] if row['name'] == 'ubuntu-keyring']
    key_members = []
    for package in key_sources:
        for row in package['files']:
            if '.tar.' not in row['path']: continue
            original = next(item for item in sources['files'] if item['sha256'] == row['sha256'])
            with original_source(source_file.parent, original, assets_root, source_parts, recorder) as selected_source:
                opener = {'name': selected_source} if isinstance(selected_source, Path) else {'fileobj': selected_source}
                with tarfile.open(mode='r:*', **opener) as archive:
                    for entry in archive:
                        if entry.name.endswith('/keyrings/ubuntu-archive-keyring.gpg'):
                            if not entry.isfile() or entry.size > 1024**2: raise ValueError('publisher original keyring member is invalid')
                            with archive.extractfile(entry) as stream: value = hashlib.file_digest(stream, 'sha256').hexdigest()
                            if value == fingerprint(keyring): key_members.append((row['sha256'], entry.name))
    if len(key_members) != 1: raise ValueError('publisher verification keys lack exact original source bytes')
    if recorder is not None: recorder.source_member(keyring, *key_members[0])
    return {'sources': [{'image_sha256': image['sha256'], 'packages': [{'name': row['name'], 'version': row['version']} for row in selected]}], 'notices': notices, 'required_materials': originals}


def derive(source_root, assets_root, runtime_root, provider_artifacts, recorder=None, source_parts=None):
    source_root, assets_root, runtime_root = map(Path, (source_root, assets_root, runtime_root))
    profiles = json.loads((runtime_root / 'runtime/runtime.lock.json').read_bytes()).get('provider_receipts', {})
    artifacts = {row['id']: row for row in provider_artifacts}
    if len(artifacts) != len(provider_artifacts): raise ValueError('provider artifact identity duplicated')
    selected = {}
    for profile, contract in profiles.items():
        identifier = 'provider-assets-' + profile.replace('/', '-')
        if identifier in artifacts: selected[profile] = observe_archive(Path(artifacts[identifier]['file']), artifacts[identifier], contract)
    if len(selected) != len(artifacts): raise ValueError('provider artifact lacks a frozen supported profile')
    if not selected: return {'schema_version': 1, 'qualification': 'actual-provider-members-original-source-and-notices', 'status': 'passed', 'bindings': [], 'unresolved': [], 'generator_sha256': fingerprint(Path(__file__))}
    provider_lock = json.loads((source_root / 'runtime/provider-assets.lock.json').read_bytes())
    mapping = json.loads((source_root / 'runtime/materials/provider-source-mappings.lock.json').read_bytes())
    wanted_sources = set()
    if any(profile.startswith('apple-container/') for profile in selected):
        wanted_sources.update((row['name'], row['version']) for row in mapping['sources'] if row['name'] not in ('microsoft/WSL', 'astral-sh/uv', 'lima-vm/lima'))
    if any(profile.startswith('wslc/') for profile in selected): wanted_sources.add(('microsoft/WSL', provider_lock['wslc']['source_commit']))
    if any(profile.startswith('lima-nerdctl/') for profile in selected): wanted_sources.add(('lima-vm/lima', json.loads((source_root / 'runtime/lima-inputs.lock.json').read_bytes())['sources']['lima']['commit']))
    sources = provider_sources(source_root, assets_root, wanted_sources, source_parts, recorder); bindings = []; unresolved = []
    lima = {name: row for profile, members in selected.items() if profile.startswith('lima-nerdctl/') for name, row in members.items()}
    origins = {}
    for profile, members in selected.items():
        identifier = 'provider-assets-' + profile.replace('/', '-')
        for name, row in members.items():
            if name in origins and origins[name][1] != row: raise ValueError('provider archives disagree on a member identity')
            origins.setdefault(name, (artifacts[identifier], row))
    def member_source(name, body):
        origin = origins.get(name)
        if origin is None or origin[1] != body: raise ValueError('provider member is not bound to an actual candidate archive')
        return provider_archive_member(origin[0], name, body)
    go = go_materials(source_root, assets_root, assets_root / '.artifacts/source-materials-data/lima-host-go', lima, member_source=member_source, source_parts=source_parts, recorder=recorder) if lima else {}
    for profile, members in selected.items():
        engine, _, arch = profile.split('/')
        repository = {'apple-container': 'apple/container', 'wslc': 'microsoft/WSL', 'lima-nerdctl': 'lima-vm/lima'}[engine]
        main = [row for key, row in sources.items() if key[0] == repository]
        provider_lock = json.loads((source_root / 'runtime/provider-assets.lock.json').read_bytes())
        commit = json.loads((source_root / 'runtime/lima-inputs.lock.json').read_bytes())['sources']['lima']['commit'] if engine == 'lima-nerdctl' else provider_lock['apple_container' if engine == 'apple-container' else 'wslc']['source_commit']
        main = [row for row in main if row['source']['commit'] == commit]
        if len(main) != 1: raise ValueError('provider exact main source is missing or ambiguous')
        closure = [row for key, row in sources.items() if engine == 'apple-container' and key[0] not in ('microsoft/WSL', 'astral-sh/uv', 'lima-vm/lima')] if engine == 'apple-container' else main
        ordinary = {'sources': [row['source'] for row in closure], 'notices': [notice for row in closure for notice in row['notices']], 'required_materials': [material for row in closure for material in row['required_materials']]}
        for name, actual in members.items():
            details = go.get(name, ordinary)
            if name.endswith('/guest/ubuntu.img'):
                details = guest_materials(source_root, assets_root, 'amd64' if arch == 'x64' else arch, actual, recorder, source_parts)
            elif name.endswith('/guest/containerd.tar.gz'):
                cached = assets_root / '.artifacts/provider-assets/lazy-v6-derived' / name
                if cached.exists() or cached.is_symlink():
                    selected_source = nullcontext(verified(assets_root / '.artifacts/provider-assets/lazy-v6-derived', {'path': name, **actual}))
                else: selected_source = member_source(name, actual)
                children = {}; files = {}; expanded = 0
                with selected_source as file:
                    with tempfile.TemporaryDirectory(prefix='ud-provider-guest-sources-') as temporary:
                        with tarfile.open(file, 'r:gz') as archive:
                            for child in archive:
                                if not child.isfile():
                                    if child.isdir(): continue
                                    raise ValueError('provider guest runtime contains special members')
                                expanded += child.size
                                if child.name in children or len(children) >= 10000 or not 0 <= child.size <= 256 * 1024**2 or expanded > 1_000_000_000: raise ValueError('provider guest runtime inventory is duplicate or oversized')
                                target = Path(temporary) / str(len(files)); files[child.name] = target
                                with archive.extractfile(child) as stream, target.open('xb') as output: shutil.copyfileobj(stream, output, 1024**2)
                                if target.stat().st_size != child.size: raise ValueError('provider guest runtime member is truncated')
                                children[child.name] = {'sha256': fingerprint(target), 'size_bytes': child.size}
                        runtime_sources = go_materials(source_root, assets_root, assets_root / '.artifacts/source-materials-data/derived-lima-go', children, files, source_parts=source_parts, recorder=recorder)
                if not {'bin/nerdctl', 'bin/containerd', 'bin/containerd-shim-runc-v2', 'bin/ctr', 'bin/runc', 'bin/rootlesskit', 'bin/rootlessctl'} <= set(runtime_sources): raise ValueError('provider guest runtime lacks complete binary source joins')
                first = next(iter(runtime_sources.values()))
                details = {'sources': [*ordinary['sources'], *first['sources']], 'notices': [*ordinary['notices'], *first['notices']], 'required_materials': [*ordinary['required_materials'], *first['required_materials']]}
            elif name.endswith('/kernel/vmlinux'):
                base = assets_root / '.artifacts/source-materials-data/apple-kernel'; kernel = json.loads((base / 'receipt.json').read_bytes())
                if kernel.get('status') != 'passed' or kernel.get('kernel_sha256', '').removeprefix('sha256:') != actual['sha256']: raise ValueError('provider kernel source is not bound to actual kernel')
                required = [material(base, kernel[key], assets_root) for key in ('kernel_source', 'kernel_config', 'kata_source')]
                required.extend(material(base, row, assets_root) for row in [kernel['kernel_source']['developer_signature'], *kernel['kernel_source']['key_certificates']])
                details = {'sources': required, 'notices': archive_notices(base / kernel['kernel_source']['path']), 'required_materials': required}
            elif HOST_GO.search(name) and name not in go:
                raise ValueError('shipped Lima Go program has no exact source closure: ' + name)
            bindings.append({'profile': profile, 'member_path': name, 'content': actual, **details})
    return {'schema_version': 1, 'qualification': 'actual-provider-members-original-source-and-notices', 'status': 'passed' if not unresolved else 'incomplete', 'target_execution': False, 'bindings': bindings, 'unresolved': unresolved, 'generator_sha256': fingerprint(Path(__file__))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect-host-go', action='store_true', required=True)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--assets-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    result = collect_host_go(args.source_root, args.assets_root, args.output, args.download)
    print(json.dumps({'status': result['status'], 'binaries': len(result['binaries']), 'modules': len(result['modules']), 'standard_libraries': len(result['standard_libraries'])}))
