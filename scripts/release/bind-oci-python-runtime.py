"""Bind the pinned official CPython build layer to original source and notices."""
from __future__ import annotations
import ast
import base64
import csv
import gzip
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import posixpath
import re
import tarfile
import tempfile
import textwrap
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[2]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
oci = module('ud_python_provider_oci', ROOT / 'scripts/runtime/oci_filesystem.py')
materials = module('ud_python_provider_materials', Path(__file__).with_name('source-bundle.py'))
managed = module('ud_python_provider_original_sources', Path(__file__).with_name('bind-managed-python-sources.py'))


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def build_identity(config, lock):
    variables = {}
    for value in config.get('config', {}).get('Env', []):
        key, separator, content = value.partition('=')
        if not separator or key in variables: raise ValueError('official Python image environment is ambiguous')
        variables[key] = content
    version = variables.get('PYTHON_VERSION'); fingerprint = variables.get('PYTHON_SHA256')
    if version != lock.get('python_version') or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version or '') or not re.fullmatch('[a-f0-9]{64}', fingerprint or ''): raise ValueError('official CPython provider version/source identity differs')
    index = -1; matches = []
    for row in config.get('history', []):
        if row.get('empty_layer') is not True: index += 1
        command = row.get('created_by', '')
        if 'https://www.python.org/ftp/python/' in command and 'make install' in command:
            if row.get('empty_layer') is True or not all(fragment in command for fragment in ('PYTHON_SHA256', 'sha256sum -c', './configure', '--enable-shared', '--with-ensurepip')): raise ValueError('official CPython build instructions are incomplete')
            matches.append({'layer_index': index, 'instructions': command, 'instructions_sha256': hashlib.sha256(command.encode()).hexdigest()})
    if len(matches) != 1 or index + 1 != len(config.get('rootfs', {}).get('diff_ids', [])): raise ValueError('official CPython build layer is absent or ambiguous')
    return {'name': 'CPython', 'version': version, 'source_sha256': fingerprint, 'source_url': f'https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz', **matches[0]}


def owned_path(name, version):
    """Only this build's installed CPython namespace, never arbitrary /usr/local."""
    series = '.'.join(version.split('.')[:2])
    if '/site-packages/' in name or name.lower().endswith(('.whl', '.zip', '.exe', '.dll')): return False
    return name.startswith(('usr/local/lib/python' + series + '/', 'usr/local/include/python' + series + '/')) or name in ('usr/local/bin/python' + series, 'usr/local/bin/python' + series + '-config', 'usr/local/bin/pydoc' + series, 'usr/local/bin/idle' + series, 'usr/local/lib/libpython' + series + '.so.1.0', 'usr/local/lib/libpython3.so', 'usr/local/lib/pkgconfig/python-' + series + '.pc', 'usr/local/lib/pkgconfig/python-' + series + '-embed.pc', 'usr/local/share/man/man1/python' + series + '.1')


FLATTENED_LAYOUT = 'flattened-no-installers-v1'
LAYOUT_LABEL = 'org.ud-agent.cpython-provider-layout'


def installer_member(name, version):
    series = '.'.join(version.split('.')[:2])
    python = 'usr/local/lib/python' + series
    if name.startswith(python + '/'):
        relative = name.removeprefix(python + '/')
        return relative == 'ensurepip' or relative.startswith(('ensurepip/', 'site-packages/pip/', 'site-packages/pip-')) or relative == 'site-packages/pip'
    return bool(re.fullmatch(r'usr/local/bin/pip(?:[0-9]+(?:\.[0-9]+)?)?', name))


def python_namespace(name, version):
    if installer_member(name, version):
        return False
    series = '.'.join(version.split('.')[:2])
    aliases = ('usr/local/bin/python', 'usr/local/bin/python-config', 'usr/local/bin/python3', 'usr/local/bin/python3-config', 'usr/local/bin/pydoc', 'usr/local/bin/pydoc3', 'usr/local/bin/idle', 'usr/local/bin/idle3', 'usr/local/lib/libpython' + series + '.so', 'usr/local/lib/pkgconfig/python3.pc', 'usr/local/lib/pkgconfig/python3-embed.pc', 'usr/local/share/man/man1/python3.1')
    libraries = ('usr/local/lib/python' + series, 'usr/local/include/python' + series)
    site = 'usr/local/lib/python' + series + '/site-packages'
    return owned_path(name, version) or name in aliases or any(name == prefix or name.startswith(prefix + '/') and not name.startswith(site + '/') for prefix in libraries)


def compare_flattened_python(donor, filesystem, version):
    source = {name for name in donor.inventory if python_namespace(name, version)}
    actual = {name for name in filesystem.inventory if python_namespace(name, version)}
    missing, extra = sorted(source - actual), sorted(actual - source)
    if missing or extra:
        raise ValueError('flattened CPython namespace differs: missing ' + repr(missing[:5]) + ', extra ' + repr(extra[:5]))
    for name in sorted(source):
        original_kind, original = donor.inventory[name]
        kind, file = filesystem.inventory[name]
        if kind != original_kind or filesystem.metadata[name] != donor.metadata[name]:
            raise ValueError('flattened CPython member mode, ownership or type differs: ' + name)
        if kind == 'file':
            if file.stat().st_size != original.stat().st_size or sha(file) != sha(original):
                raise ValueError('flattened CPython member bytes differ: ' + name)
        elif kind == 'link':
            if file != original:
                raise ValueError('flattened CPython alias differs: ' + name)
        elif kind != 'dir':
            raise ValueError('flattened CPython contains an unsupported member: ' + name)
    return len(source)


def donor_filesystem(provenance_file, manifest, config, directory, observe, recorder):
    layers = manifest.get('layers', [])
    diff_ids = config.get('rootfs', {}).get('diff_ids', [])
    metadata = json.loads(provenance_file.read_bytes())
    declared = {row['path']: row for row in metadata.get('private_donor_layers', [])}
    if len(declared) != len(metadata.get('private_donor_layers', [])) or not layers or len(layers) != len(diff_ids):
        raise ValueError('original locked CPython donor layer inventory is incomplete')
    filesystem = oci.Filesystem(directory)
    for index, (layer, diff_id) in enumerate(zip(layers, diff_ids, strict=True)):
        digest = layer['digest']
        if layer['mediaType'] not in ('application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip') or not re.fullmatch('sha256:[a-f0-9]{64}', digest):
            raise ValueError('locked CPython donor layer has an invalid distribution descriptor')
        name = 'layers/' + digest[7:]
        row = {'path': name, 'sha256': digest[7:], 'size_bytes': layer['size']}
        if declared.get(name) != row:
            raise ValueError('locked CPython donor layer is unavailable: ' + name)
        origin = provenance_file.parent / name
        stream, identity, _ = materials.opened(provenance_file.parent, row)
        try:
            with gzip.GzipFile(fileobj=stream) as expanded:
                if 'sha256:' + hashlib.file_digest(expanded, 'sha256').hexdigest() != diff_id:
                    raise ValueError('locked CPython donor uncompressed layer differs')
            stream.seek(0)
            filesystem.file_observer = lambda name, file, serial: observe(name, file, serial, layer, index)
            with tarfile.open(fileobj=stream, mode='r:gz') as archive:
                filesystem.add_layer(archive)
            materials.verify_held_path(stream, origin, identity)
        finally:
            stream.close()
        if recorder is not None:
            recorder.private_vendor_input(origin, 'cpython-donor-layer', row)
    return filesystem


PROVIDER_SOURCE_FORMS = frozenset((
    'etc/apt/apt.conf.d/docker-autoremove-suggests', 'etc/apt/apt.conf.d/docker-clean',
    'etc/apt/apt.conf.d/docker-gzip-indexes', 'etc/apt/apt.conf.d/docker-no-languages',
    'etc/apt/sources.list.d/debian.sources', 'etc/dpkg/dpkg.cfg.d/docker',
    'etc/dpkg/dpkg.cfg.d/docker-apt-speedup', 'etc/fstab', 'etc/hostname',
    'etc/resolv.conf', 'etc/networks', 'usr/sbin/policy-rc.d',
))


class InstallationConfinementError(ValueError):
    """A resolved installation path exists outside its declared scope."""


def provider_source_form(name, body, index):
    """The readable form itself is shipped; this makes no package authorship claim."""
    expected_layer = 1 if name == 'etc/networks' else 0
    if index != expected_layer or name not in PROVIDER_SOURCE_FORMS or len(body) > 65536 or b'\0' in body or body.startswith((b'\x7fELF', b'MZ')): return False
    try: body.decode('utf-8')
    except UnicodeDecodeError: return False
    return True


def pip_script_template(base, source, source_parts=None, recorder=None):
    """Read the literal template from original pip; never import vendor code."""
    with managed.opened_original(base, source, source_parts, recorder) as (stream, _, original):
        with zipfile.ZipFile(stream) as wheel:
            info = wheel.getinfo('pip/_internal/operations/install/wheel.py')
            if info.file_size > 1024**2: raise ValueError('original pip script generator exceeds bound')
            body = wheel.read(info); tree = ast.parse(body)
            removed_tests = []
            for entry in wheel.infolist():
                name = entry.filename
                if entry.is_dir() or not name.startswith('pip/') or not set(name.split('/')[:-1]) & {'test', 'tests', 'idle_test'}: continue
                if entry.file_size > 32 * 1024**2: raise ValueError('original pip test member exceeds bound')
                content = wheel.read(entry)
                removed_tests.append({'member_path': name, 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)})
    templates = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != 'PipScriptMaker': continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name) or statement.targets[0].id != 'script_template': continue
            value = statement.value
            if not isinstance(value, ast.Call) or ast.unparse(value.func) != 'textwrap.dedent' or len(value.args) != 1 or value.keywords: raise ValueError('original pip script template is not literal')
            templates.append(textwrap.dedent(ast.literal_eval(value.args[0])))
    if len(templates) != 1 or not isinstance(templates[0], str): raise ValueError('original pip script template is absent or ambiguous')
    return templates[0], {'source_archive_sha256': original['sha256'], 'member_path': info.filename, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'provider_removed_original_test_members': removed_tests}


def installed_metadata(filesystem, packages, python_version, template, *, removed_pip_bytecode=False, removed_pip_tests=()):
    """Verify finite installed receipts and source-form entry point wrappers.

    RECORD does not authorize any recorded implementation byte: every such
    byte still needs its independent wheel/source fact in component closure.
    """
    series = '.'.join(python_version.split('.')[:2]); site = 'usr/local/lib/python' + series + '/site-packages'; result = []
    original_tests = {row['member_path']: row for row in removed_pip_tests}
    def installed_file(path):
        resolved, file = filesystem.resolve(path)
        if not (resolved.startswith(site + '/') or resolved.startswith('usr/local/bin/')): raise InstallationConfinementError('installed Python metadata resolves outside its installation')
        return file
    for name, version in sorted(packages.items()):
        stem = name.replace('-', '_') + '-' + version + '.dist-info'; record_name = site + '/' + stem + '/RECORD'
        try: file = installed_file(record_name)
        except InstallationConfinementError: raise
        except ValueError: continue
        if file.stat().st_size > 2 * 1024**2: raise ValueError('installed Python RECORD exceeds bound')
        rows = list(csv.reader(io.StringIO(file.read_text(encoding='utf-8')))); seen = set(); absent_bytecode = []; absent_tests = []
        if not rows or len(rows) > 50000: raise ValueError('installed Python RECORD is empty or oversized')
        for row in rows:
            if len(row) != 3 or not row[0] or row[0] in seen or row[0].startswith('/') or '\\' in row[0] or '\0' in row[0]: raise ValueError('installed Python RECORD is malformed or duplicate')
            seen.add(row[0]); path = posixpath.normpath(site + '/' + row[0])
            if not path.startswith('usr/local/') or not (path.startswith(site + '/') or path.startswith('usr/local/bin/')): raise ValueError('installed Python RECORD escapes its installation')
            try: target = installed_file(path)
            except InstallationConfinementError: raise
            except ValueError:
                original = original_tests.get(row[0]) if name == 'pip' else None
                if original is not None:
                    expected_hash = 'sha256=' + base64.urlsafe_b64encode(bytes.fromhex(original['sha256'])).decode().rstrip('=')
                    if row[1] != expected_hash or row[2] != str(original['size_bytes']): raise ValueError('provider-removed pip test differs from its exact original wheel member')
                    absent_tests.append({'path': path, 'original_wheel_member': original}); continue
                match = re.fullmatch(r'pip/(.*?/)?__pycache__/([^/]+)\.cpython-' + series.replace('.', '') + r'\.pyc', row[0])
                recorded_identity = row[1:] == ['', ''] or re.fullmatch(r'sha256=[A-Za-z0-9_-]{43}', row[1]) and row[2].isdigit()
                if name != 'pip' or not removed_pip_bytecode or not match or not recorded_identity: raise
                # The authenticated provider recipe removes bytecode after
                # ensurepip. Its stale RECORD references are not shipped bytes
                # and are explicitly kept separate from verified live files.
                source_path = 'pip/' + (match[1] or '') + match[2] + '.py'
                if source_path not in original_tests: installed_file(site + '/' + source_path)
                absent_bytecode.append({'path': path, 'recorded_hash': row[1] or None, 'recorded_size_bytes': int(row[2]) if row[2] else None}); continue
            if path == record_name:
                if row[1:] != ['', '']: raise ValueError('installed Python RECORD self-entry differs')
            elif row[1] != 'sha256=' + base64.urlsafe_b64encode(bytes.fromhex(sha(target))).decode().rstrip('=') or row[2] != str(target.stat().st_size): raise ValueError('installed Python RECORD changes referenced bytes')
        if stem + '/RECORD' not in seen: raise ValueError('installed Python RECORD omits itself')
        result.append({'image_path': record_name, 'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'package': {'name': name, 'version': version}, 'form': 'verified-installed-record-readable-source-form', 'absent_provider_removed_bytecode': absent_bytecode, 'absent_provider_removed_test_files': absent_tests})
        installer = site + '/' + stem + '/INSTALLER'
        try: file = installed_file(installer)
        except InstallationConfinementError: raise
        except ValueError: continue
        if file.read_bytes() != b'pip\n': raise ValueError('installed Python installer identity differs')
        result.append({'image_path': installer, 'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'package': {'name': name, 'version': version}, 'form': 'verified-pip-installer-readable-source-form'})
    for name, package, module, function in (('pip3', 'pip', 'pip._internal.cli.main', 'main'), ('pip' + series, 'pip', 'pip._internal.cli.main', 'main'), ('udapy', 'udapi', 'udapi.cli', 'main')):
        if package not in packages: continue
        path = 'usr/local/bin/' + name
        try: file = installed_file(path)
        except InstallationConfinementError: raise
        except ValueError: continue
        body = file.read_bytes(); expected = (template % {'module': module, 'import_name': function, 'func': function}).encode()
        if body not in [shebang + expected for shebang in (b'#!/usr/local/bin/python\n', ('#!/usr/local/bin/python' + series + '\n').encode())]: raise ValueError('installed Python entry point differs from original pip template')
        result.append({'image_path': path, 'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'package': {'name': package, 'version': packages[package]}, 'form': 'original-pip-template-readable-entry-point-source-form'})
    return result


def source_notices(base, source, version, source_parts=None, recorder=None):
    notices = []; prefix = 'Python-' + version + '/'; seen = set(); total = 0
    with managed.opened_original(base, source, source_parts, recorder) as (stream, _, original):
        with tarfile.open(fileobj=stream, mode='r:*') as archive:
            for row in archive:
                if row.name == prefix[:-1] and row.isdir(): continue
                if not row.name.startswith(prefix) or row.name in seen or len(seen) >= 200000: raise ValueError('CPython source members have a foreign prefix or duplicate')
                seen.add(row.name); total += row.size
                if not 0 <= row.size <= 512 * 1024**2 or total > 2 * 1024**3: raise ValueError('CPython source archive exceeds bounds')
                if not row.isfile() or not re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$', row.name.rsplit('/', 1)[-1], re.I): continue
                if row.size > 8 * 1024**2: raise ValueError('CPython original notice exceeds bound')
                with archive.extractfile(row) as body: fingerprint = hashlib.file_digest(body, 'sha256').hexdigest()
                notices.append({'source_archive_sha256': original['sha256'], 'member_path': row.name, 'sha256': fingerprint, 'size_bytes': row.size})
        if prefix + 'LICENSE' not in {row['member_path'] for row in notices}: raise ValueError('original CPython license is missing')
    return original, notices


def bind_provider(base_manifest, base_config, manifest, config, lock, platform):
    if base_config.get('os') != 'linux' or base_config.get('architecture') != platform.split('/')[1]: raise ValueError('original CPython provider CPU differs')
    layers = base_manifest.get('layers', []); diff_ids = base_config.get('rootfs', {}).get('diff_ids', [])
    if not layers or len(layers) != len(diff_ids) or manifest.get('layers', [])[:len(layers)] != layers or config.get('rootfs', {}).get('diff_ids', [])[:len(diff_ids)] != diff_ids or config.get('history', [])[:len(base_config.get('history', []))] != base_config.get('history', []): raise ValueError('worker does not preserve the exact locked CPython provider layers and build history')
    original = build_identity(base_config, lock); current = build_identity(config, lock)
    if original != current or original['layer_index'] >= len(layers): raise ValueError('worker CPython source/build identity differs from its actual provider')
    return original


def provider_metadata(file, lock, platform):
    data = json.loads(file.read_bytes())
    if data.get('qualification') != 'immutable-publisher-oci-source-build-metadata-not-reproduced-build' or data.get('index_digest') != lock['index_digest']: raise ValueError('exact original CPython provider metadata required')
    records = {row['sha256']: row for row in data['files']}; used = []
    if len(records) != len(data['files']): raise ValueError('provider metadata input is duplicated')
    def load(fingerprint, size=None):
        row = records.get(fingerprint.removeprefix('sha256:'))
        if not row or size is not None and row['size_bytes'] != size: raise ValueError('original provider metadata is absent')
        stream, _, actual = materials.opened(file.parent, row)
        try:
            if actual['size_bytes'] > 8 * 1024**2: raise ValueError('provider metadata exceeds bounds')
            value = json.load(stream)
        finally: stream.close()
        used.append(actual); return value
    index = load(lock['index_digest']); rows = [row for row in index['manifests'] if row.get('platform', {}).get('os') == 'linux' and row.get('platform', {}).get('architecture') == platform.split('/')[1]]
    if len(rows) != 1 or rows[0]['digest'] != lock['platforms'][platform]: raise ValueError('original provider platform differs from its locked index')
    manifest = load(rows[0]['digest'], rows[0]['size']); config = load(manifest['config']['digest'], manifest['config']['size'])
    return manifest, config, used


def derive(root, runtime_root, pack, platform, source_file, provenance_file, *, source_parts=None, recorder=None):
    lock = json.loads((root / 'runtime/core-image.lock.json').read_bytes())
    if lock.get('platforms', {}).get(platform) is None or 'docker.io/library/python:' + str(lock.get('python_version')) + '-slim@' + lock.get('index_digest', '') not in (root / 'runtime/Containerfile.core').read_text(): raise ValueError('actual worker recipe does not select the source-locked CPython provider')
    image = pack['images'][platform]; archive = pack['index_transport']; stream, _, _ = materials.opened(runtime_root, {'path': archive['path'], 'sha256': archive['sha256'][7:], 'size_bytes': archive['size_bytes']})
    try:
        with tarfile.open(fileobj=stream, mode='r:') as outer:
            members = {}
            for row in outer:
                if row.name in members: raise ValueError('actual OCI metadata member duplicates')
                members[row.name] = row
            def read(fingerprint):
                row = members.get('blobs/sha256/' + fingerprint[7:])
                if row is None or not row.isfile() or row.size > 8 * 1024**2: raise ValueError('actual OCI Python metadata is absent or oversized')
                raw = outer.extractfile(row).read()
                if 'sha256:' + hashlib.sha256(raw).hexdigest() != fingerprint: raise ValueError('actual OCI Python metadata identity differs')
                return json.loads(raw)
            config = read(image['config_digest']); manifest = read(image['digest'])
    finally: stream.close()
    original_manifest, original_config, metadata = provider_metadata(provenance_file, lock, platform)
    layout = (config.get('config', {}).get('Labels') or {}).get(LAYOUT_LABEL)
    flattened = layout == FLATTENED_LAYOUT
    if layout is not None and not flattened:
        raise ValueError('unrecognized CPython provider layout')
    if flattened:
        recipe = (root / 'runtime/Containerfile.core').read_text()
        if 'FROM scratch\nCOPY --from=build / /' not in recipe or f'{LAYOUT_LABEL}="{FLATTENED_LAYOUT}"' not in recipe or original_config.get('os') != 'linux' or config.get('os') != 'linux' or original_config.get('architecture') != platform.split('/')[1] or config.get('architecture') != platform.split('/')[1]:
            raise ValueError('flattened CPython provider recipe or platform differs')
        identity = build_identity(original_config, lock)
        variables = config.get('config', {}).get('Env', [])
        for key, value in (('PYTHON_VERSION', identity['version']), ('PYTHON_SHA256', identity['source_sha256'])):
            if [item for item in variables if item.startswith(key + '=')] != [key + '=' + value]:
                raise ValueError('flattened CPython provider metadata differs from the original')
    else:
        identity = bind_provider(original_manifest, original_config, manifest, config, lock, platform)
    inventory = json.loads(source_file.read_bytes()); sources = [row for row in inventory['files'] if row.get('version') == identity['version'] and row.get('sha256') == identity['source_sha256'] and row.get('url') == identity['source_url']]
    if len(sources) != 1: raise ValueError('actual CPython provider original source is absent or duplicated')
    source, notices = source_notices(source_file.parent, sources[0], identity['version'], source_parts, recorder); bindings = []; source_forms = []
    pip_lock = json.loads((root / 'runtime/materials/pip-distlib-sources.lock.json').read_bytes())['wheel']
    pip_sources = [row for row in inventory['files'] if row.get('name') == 'pip' and all(row.get(key) == pip_lock.get(key) for key in ('sha256', 'size_bytes', 'url'))]
    if len(pip_sources) != 1: raise ValueError('original installed pip generator identity is absent or duplicated')
    if flattened and recorder is not None:
        recorder.private_vendor_input(source_file.parent / pip_sources[0]['path'], 'cpython-pip-generator', pip_lock)
    template, generator_source = pip_script_template(source_file.parent, pip_sources[0], None if flattened else source_parts, None if flattened else recorder)
    uv = tomllib.loads((root / 'uv.lock').read_text()); packages = {} if flattened else {'pip': '26.2.2'}
    for package in uv['package']:
        if package['name'] in ('colorama', 'regex', 'termcolor', 'udapi'):
            if package['name'] in packages: raise ValueError('locked installed Python component is ambiguous')
            packages[package['name']] = package['version']
    if len(packages) != (4 if flattened else 5): raise ValueError('locked worker Python component set is incomplete')
    def observe(name, file, serial, layer, index):
        if flattened and installer_member(name, identity['version']):
            return
        if name in PROVIDER_SOURCE_FORMS and file.stat().st_size <= 65536 and provider_source_form(name, file.read_bytes(), index):
            source_forms.append({'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'image_path': name, 'layer_digest': layer['digest'], 'layer_index': index, 'form': 'locked-provider-readable-configuration-source-form'})
        elif name == 'root/.wget-hsts' and index == identity['layer_index'] and file.stat().st_size <= 65536:
            body = file.read_bytes()
            if body.startswith(b'# HSTS 1.0 Known Hosts database for GNU Wget.\n') and b'\0' not in body:
                body.decode('utf-8')
                source_forms.append({'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'image_path': name, 'layer_digest': layer['digest'], 'layer_index': index, 'form': 'locked-provider-readable-download-state-source-form'})
        if index != identity['layer_index'] or not owned_path(name, identity['version']): return
        with file.open('rb') as body: prefix = body.read(2)
        if prefix == b'MZ': raise ValueError('CPython provider namespace contains an unrelated PE binary')
        bindings.append({'content': {'sha256': sha(file), 'size_bytes': file.stat().st_size}, 'image_path': name, 'layer_digest': layer['digest'], 'layer_index': index})
    def without_installer(name, *_):
        if installer_member(name, identity['version']) or name.lower().endswith(('.exe', '.dll', '.whl')):
            raise ValueError('installer or foreign runtime in a flattened OCI layer: ' + name)
    with tempfile.TemporaryDirectory(prefix='ud-python-provider-') as temporary:
        filesystem = oci.verified_filesystem(runtime_root, pack, platform, Path(temporary) / 'opaque', True, file_observer=without_installer if flattened else observe)
        if flattened:
            donor = donor_filesystem(provenance_file, original_manifest, original_config, Path(temporary) / 'donor', observe, recorder)
            compared = compare_flattened_python(donor, filesystem, identity['version'])
            def retained(row):
                name = row['image_path']
                kind, file = filesystem.inventory.get(name, (None, None))
                return kind == 'file' and row['content'] == {'sha256': sha(file), 'size_bytes': file.stat().st_size}
            bindings = [row for row in bindings if retained(row)]
            source_forms = [row for row in source_forms if retained(row)]
        removes_bytecode = all(fragment in identity['instructions'] for fragment in ('find /usr/local -depth', "-name '*.pyc'", "-exec rm -rf '{}' +"))
        removes_tests = all(fragment in identity['instructions'] for fragment in ('find /usr/local -depth', '-type d', '-name test -o -name tests -o -name idle_test', "-exec rm -rf '{}' +"))
        installed = installed_metadata(filesystem, packages, identity['version'], template, removed_pip_bytecode=removes_bytecode, removed_pip_tests=generator_source['provider_removed_original_test_members'] if removes_tests else ())
    if not any(row['image_path'] == 'usr/local/bin/python' + '.'.join(identity['version'].split('.')[:2]) for row in bindings): raise ValueError('actual CPython provider build layer lacks its interpreter')
    return {'schema_version': 1, 'qualification': 'exact-OCI-provider-CPython-component-source-recipe-not-reproduced-build', 'status': 'passed', 'target_execution': False, 'platform': platform, 'provider': {'image': lock['image'], 'index_digest': lock['index_digest'], 'platform_manifest': lock['platforms'][platform]}, 'config_digest': image['config_digest'], 'component': identity, 'source': source, 'notices': notices, 'metadata_materials': metadata, 'bindings': bindings, 'provider_source_forms': source_forms, 'installed_source_forms': installed, 'installed_script_generator': generator_source, **({'flattened_provider': {'layout': layout, 'compared_members': compared, 'original_layer_digests': [layer['digest'] for layer in original_manifest['layers']]}} if flattened else {}), 'generator_sha256': sha(Path(__file__))}
