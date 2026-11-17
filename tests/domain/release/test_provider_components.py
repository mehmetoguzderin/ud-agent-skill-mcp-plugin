import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('ud_test_provider_components', ROOT / 'scripts/release/bind-provider-components.py')
provider = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(provider)
PARTS_SPEC = importlib.util.spec_from_file_location('ud_test_provider_source_parts', ROOT / 'scripts/release/materialize-replay-inputs.py')
parts_module = importlib.util.module_from_spec(PARTS_SPEC); PARTS_SPEC.loader.exec_module(parts_module)


class SourceParts:
    """Small in-memory stand-in with the same exact-byte admission contract."""
    def __init__(self, rows): self.rows = rows

    @contextmanager
    def open_blob(self, fingerprint, size):
        body = self.rows.get(fingerprint)
        if body is None or len(body) != size or hashlib.sha256(body).hexdigest() != fingerprint:
            raise ValueError('inspection source blob is missing or differs')
        with io.BytesIO(body) as stream, parts_module.BlobView(stream, 0, len(body)) as view: yield view


class StreamRecorder:
    def __init__(self): self.rows = []
    def source_blob(self, file, fingerprint, size): self.rows.append((file, fingerprint, size))
    def source_member(self, file, fingerprint, name): self.rows.append((file, fingerprint, name))


def receipt(file, name=None):
    return {'path': name or file.name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size_bytes': file.stat().st_size}


def archive(file, rows):
    with tarfile.open(file, 'w:gz') as target:
        for name, data in rows:
            entry = tarfile.TarInfo(name); entry.size = len(data); target.addfile(entry, io.BytesIO(data))


class ProviderComponents(unittest.TestCase):
    def test_selected_provider_member_is_read_from_the_exact_archive_and_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root / 'provider.tar.gz'; body = b'original provider executable'
            name = 'runtime/providers/lima-nerdctl/darwin-arm64/bin/limactl'; archive(file, [(name, body)])
            descriptor = {**receipt(file), 'file': str(file)}; expected = {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            with provider.provider_archive_member(descriptor, name, expected) as selected:
                self.assertEqual(selected.read_bytes(), body); self.assertNotEqual(selected.name, 'limactl')
            self.assertFalse(selected.exists())
            with self.assertRaisesRegex(ValueError, 'member differs'):
                with provider.provider_archive_member(descriptor, name, {**expected, 'sha256': '0' * 64}): pass
            with self.assertRaisesRegex(ValueError, 'missing'):
                with provider.provider_archive_member(descriptor, 'missing', expected): pass
            archive(file, [(name, b'changed provider executable')])
            with self.assertRaisesRegex(ValueError, 'archive differs'):
                with provider.provider_archive_member(descriptor, name, expected): pass

    def test_go_binding_reads_missing_provider_cache_from_the_candidate_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            assets, base, subject, _, _, data, raw = self.go_fixture(directory)
            name = 'runtime/providers/lima-nerdctl/darwin-arm64/bin/limactl'; expected = provider.content(receipt(subject))
            outer = assets / 'candidate.tar.gz'; archive(outer, [(name, subject.read_bytes())]); descriptor = {**receipt(outer), 'file': str(outer)}
            (base / 'receipt.json').write_text(json.dumps(data)); paths = []
            def selected_source(member, body):
                self.assertEqual((member, body), (name, expected))
                return provider.provider_archive_member(descriptor, member, body)
            def inspect(args, **_):
                paths.append(Path(args[-1])); self.assertEqual(paths[-1].read_bytes(), subject.read_bytes())
                return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(raw).encode())
            with patch('subprocess.run', side_effect=inspect):
                result = provider.go_materials(ROOT, assets, base, {name: expected}, member_source=selected_source)
            self.assertIn(name, result); self.assertEqual(len(paths), 1); self.assertFalse(paths[0].exists())
            cached = assets / '.artifacts/provider-assets/lazy-v6-derived' / name; cached.parent.mkdir(parents=True); cached.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                provider.go_materials(ROOT, assets, base, {name: expected}, member_source=selected_source)

    def test_provider_replay_uses_the_candidate_when_expanded_lima_binary_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, assets, runtime, _, _, _, _, _ = self.fixture(root)
            other = root / 'other'; other.mkdir(); _, go_base, subject, _, _, go_data, raw = self.go_fixture(other)
            destination = assets / '.artifacts/source-materials-data/lima-host-go'; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(go_base, destination)
            (source / 'scripts/release').mkdir(parents=True)
            shutil.copyfile(ROOT / 'scripts/release/source_materials.py', source / 'scripts/release/source_materials.py')
            go_data['go_inspector']['path'] = str(destination / 'native-go-inspector')
            (destination / 'receipt.json').write_text(json.dumps(go_data))
            shutil.copyfile(ROOT / 'runtime/materials/lima-runtime-sources.lock.json', source / 'runtime/materials/lima-runtime-sources.lock.json')
            (source / 'runtime/lima-inputs.lock.json').write_text(json.dumps({'sources': {'lima': {'commit': '1' * 40}}}))
            mapping = source / 'runtime/materials/provider-source-mappings.lock.json'
            rows = json.loads(mapping.read_bytes()); rows['sources'][0]['name'] = 'lima-vm/lima'; mapping.write_text(json.dumps(rows))
            source_receipt = assets / '.artifacts/source-materials-data/provider-sources-binary-v2/receipt.json'
            receipt_data = json.loads(source_receipt.read_bytes()); receipt_data['files'][0]['name'] = 'lima-vm/lima'
            receipt_data['locks']['runtime/materials/provider-source-mappings.lock.json'] = receipt(mapping)['sha256']; source_receipt.write_text(json.dumps(receipt_data))
            name = 'runtime/providers/lima-nerdctl/darwin-arm64/bin/limactl'; body = subject.read_bytes()
            file = root / 'lima-provider.tar.gz'; archive(file, [(name, body)])
            contract = {**receipt(file), 'files': [{'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}]}
            (runtime / 'runtime/runtime.lock.json').write_text(json.dumps({'provider_receipts': {'lima-nerdctl/darwin/arm64': {'lazy_assets': contract}}}))
            artifact = {'id': 'provider-assets-lima-nerdctl-darwin-arm64', **receipt(file), 'file': str(file)}
            cached = assets / '.artifacts/provider-assets/lazy-v6-derived' / name
            self.assertFalse(cached.exists())
            with patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(raw).encode())):
                result = provider.derive(source, assets, runtime, [artifact])
            self.assertEqual(result['status'], 'passed'); self.assertEqual(result['bindings'][0]['member_path'], name)
            self.assertEqual(result['bindings'][0]['content'], {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)})
            self.assertFalse(cached.exists())

    def test_compressed_go_provider_member_is_inspected_and_its_temporary_bytes_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            assets, base, subject, _, _, data, raw = self.go_fixture(directory)
            name = 'runtime/providers/lima-nerdctl/darwin-arm64/share/lima/lima-guestagent.arm64.gz'
            compressed = gzip.compress(subject.read_bytes()); expected = {'sha256': hashlib.sha256(compressed).hexdigest(), 'size_bytes': len(compressed)}
            data['binaries'][0].update(expected); (base / 'receipt.json').write_text(json.dumps(data))
            outer = assets / 'candidate.tar.gz'; archive(outer, [(name, compressed)]); descriptor = {**receipt(outer), 'file': str(outer)}; paths = []
            def inspect(args, **_):
                paths.append(Path(args[-1])); self.assertEqual(paths[-1].read_bytes(), subject.read_bytes())
                return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(raw).encode())
            with patch('subprocess.run', side_effect=inspect):
                result = provider.go_materials(ROOT, assets, base, {name: expected}, member_source=lambda name, value: provider.provider_archive_member(descriptor, name, value))
            self.assertIn(name, result); self.assertEqual(len(paths), 1); self.assertFalse(paths[0].exists())

    def go_fixture(self, directory):
        assets = Path(directory); base = assets / 'go'; base.mkdir()
        original = base / 'main.tar.gz'; archive(original, [('main/LICENSE', b'Main original MIT\n')])
        standard = base / 'go1.27.3.src.tar.gz'; archive(standard, [('go/LICENSE', b'Go original BSD\n')])
        package = base / 'module.zip'
        with zipfile.ZipFile(package, 'w') as target:
            target.writestr('example.org/module@v1.0.0/LICENSE', b'Module BSD original notice\n')
            target.writestr('example.org/module@v1.0.0/module.go', b'package module\n')
        catalog = base / 'catalog.json'; catalog.write_text(json.dumps([{'version': 'go1.27.3', 'files': [{'kind': 'source', 'filename': standard.name, 'sha256': receipt(standard)['sha256'], 'size': standard.stat().st_size}]}]))
        tool = base / 'native-go-inspector'; tool.write_bytes(b'Hash-selected inspector fixture, never executed')
        subject = base / 'program'; subject.write_bytes(b'Exact immutable target subject')
        raw = {'GoVersion': 'go1.27.3', 'Main': {'Path': 'github.com/example/main', 'Version': 'v1.0.0'}, 'Path': 'github.com/example/main/cmd', 'Deps': [{'Path': 'example.org/module', 'Version': 'v1.0.0', 'Sum': 'h1:48lwWjkwnYtaLkmBVs62EQx1Om2YKpHu8oNSEhRmXB8='}], 'Settings': [{'Key': 'CGO_ENABLED', 'Value': '0'}, {'Key': 'vcs.revision', 'Value': '1' * 40}]}
        info = {'go_version': 'go1.27.3', 'main': raw['Main'], 'path': raw['Path'], 'dependencies': [{'path': 'example.org/module', 'version': 'v1.0.0', 'h1': raw['Deps'][0]['Sum']}], 'build_settings': raw['Settings'], 'target_execution': False, 'raw': raw}
        notice = lambda name, data: {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}
        data = {'qualification': 'binary-bound-go-module-source-inventory', 'status': 'passed', 'go_inspector': {'path': str(tool), 'sha256': receipt(tool)['sha256']}, 'binaries': [{**receipt(subject), 'build_info': info}], 'main_sources': [{'repository': 'example/main', 'commit': '1' * 40, **receipt(original), 'license_files': [notice('main/LICENSE', b'Main original MIT\n')]}], 'modules': [{'path': 'example.org/module', 'version': 'v1.0.0', 'h1': raw['Deps'][0]['Sum'], 'archive': receipt(package), 'license_files': [notice('example.org/module@v1.0.0/LICENSE', b'Module BSD original notice\n')]}], 'standard_libraries': [{'version': 'go1.27.3', **receipt(standard), 'publisher_catalog': receipt(catalog)}]}
        return assets, base, subject, package, catalog, data, raw

    def test_go_subject_module_hash_publisher_catalog_and_original_notices_are_independent(self):
        for change in (None, 'module', 'catalog', 'metadata', 'missing-module', 'wrong-stdlib', 'wrong-main', 'missing-notice', 'wrong-derived-commit'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                assets, base, subject, package, catalog, data, raw = self.go_fixture(directory)
                if change == 'module':
                    with zipfile.ZipFile(package, 'w') as target:
                        target.writestr('example.org/module@v1.0.0/LICENSE', b'Module BSD original notice\n')
                        target.writestr('example.org/module@v1.0.0/module.go', b'package different\n')
                    data['modules'][0]['archive'] = receipt(package)
                if change == 'catalog':
                    entries = json.loads(catalog.read_bytes()); entries[0]['files'][0]['sha256'] = '0' * 64
                    catalog.write_text(json.dumps(entries)); data['standard_libraries'][0]['publisher_catalog'] = receipt(catalog)
                if change == 'metadata': raw = {**raw, 'GoVersion': 'go1.27.4'}
                if change == 'missing-module': data['modules'] = []
                if change == 'wrong-stdlib': data['standard_libraries'][0]['version'] = 'go1.27.2'
                if change == 'wrong-main': data['main_sources'][0]['commit'] = '2' * 40
                if change == 'missing-notice': data['modules'][0]['license_files'] = []
                if change == 'wrong-derived-commit':
                    raw['Main'] = {'Path': 'github.com/opencontainers/runc', 'Version': '(devel)'}; raw['Settings'] = [{'Key': 'CGO_ENABLED', 'Value': '1'}]
                    data['binaries'][0]['build_info'].update(main=raw['Main'], build_settings=raw['Settings'], raw=raw)
                    data['main_sources'][0].update(repository='opencontainers/runc', commit='2' * 40)
                    data['derivation'] = {'runc_derivation': {'builder_sha256': receipt(ROOT / 'scripts/runtime/build-lima-runc.py')['sha256'], 'commit': '2' * 40, 'main_source': data['main_sources'][0], 'binaries': {'arm64': receipt(subject)}}}
                (base / 'receipt.json').write_text(json.dumps(data))
                run = lambda: provider.go_materials(ROOT, assets, base, {'program': provider.content(receipt(subject))}, {'program': subject})
                with patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(raw).encode())):
                    if change not in (None, 'missing-notice'):
                        with self.assertRaisesRegex(ValueError, 'module content|publisher catalog|Go metadata|module source set|standard-library source set|main source|notice member set|protected builder'): run()
                    else:
                        binding = run()['program']
                        self.assertEqual({row['member_path'] for row in binding['notices']}, {'main/LICENSE', 'example.org/module@v1.0.0/LICENSE', 'go/LICENSE'})
                        self.assertEqual({row['sha256'] for row in binding['required_materials']}, {receipt(base / name)['sha256'] for name in ('main.tar.gz', 'module.zip', 'catalog.json', 'go1.27.3.src.tar.gz')})

    def test_go_sources_stream_from_verified_parts_without_staging_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            assets, base, subject, _, _, data, raw = self.go_fixture(directory)
            files = [base / 'main.tar.gz', base / 'module.zip', base / 'go1.27.3.src.tar.gz']
            bodies = {receipt(file)['sha256']: file.read_bytes() for file in files}
            expected = set(bodies); recorder = StreamRecorder()
            for file in files: file.unlink()
            (base / 'receipt.json').write_text(json.dumps(data))
            run = lambda parts: provider.go_materials(ROOT, assets, base, {'program': provider.content(receipt(subject))}, {'program': subject}, source_parts=parts, recorder=recorder)
            with patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(raw).encode())):
                result = run(SourceParts(bodies))
                self.assertTrue(expected <= {row['sha256'] for row in result['program']['required_materials']})
                self.assertEqual(expected, {row[1] for row in recorder.rows})
                self.assertTrue(all(not file.exists() for file in files))
                fingerprint = next(iter(bodies)); altered = dict(bodies); altered[fingerprint] = b'altered'
                with self.assertRaisesRegex(ValueError, 'missing or differs'): run(SourceParts(altered))

    def test_source_closed_c_runtime_requires_all_exact_frozen_original_inputs(self):
        original = json.loads((ROOT / 'runtime/materials/lima-runtime-sources.lock.json').read_bytes())['runtime_sources']
        result = provider.protected_runtime_sources(ROOT, {'derived_runtime_sources': original})
        self.assertEqual({row['role'] for row in result}, {'go-source', 'zig-source', 'libseccomp-source'})
        for changed in ([], original[:-1], [*original, original[0]], [{**row, 'sha256': '0' * 64} for row in original]):
            with self.assertRaisesRegex(ValueError, 'C runtime inputs missing or changed'):
                provider.protected_runtime_sources(ROOT, {'derived_runtime_sources': changed})

    def fixture(self, directory):
        root = Path(directory); source = root / 'source'; assets = root / 'assets'; runtime = root / 'runtime'
        (source / 'runtime/materials').mkdir(parents=True); (runtime / 'runtime').mkdir(parents=True)
        base = assets / '.artifacts/source-materials-data/provider-sources-binary-v2'; base.mkdir(parents=True)
        license_bytes = b'MIT\nCopyright original supplier\n'; original = base / 'source.tar.gz'
        archive(original, [('source/LICENSE', license_bytes), ('source/main.c', b'int main(void) { return 0; }\n')])
        notice = base / 'license'; notice.write_bytes(license_bytes)
        row = {'name': 'microsoft/WSL', 'version': '1' * 40, **receipt(original), 'notices': [{**receipt(notice), 'source_path': 'source/LICENSE'}]}
        (source / 'runtime/provider-assets.lock.json').write_text(json.dumps({'version': 'fixture', 'wslc': {'source_commit': '1' * 40}}))
        locks = {'runtime/provider-assets.lock.json': receipt(source / 'runtime/provider-assets.lock.json')['sha256']}
        (source / 'runtime/materials/provider-source-mappings.lock.json').write_text(json.dumps({'sources': [row]}))
        locks['runtime/materials/provider-source-mappings.lock.json'] = receipt(source / 'runtime/materials/provider-source-mappings.lock.json')['sha256']
        (base / 'receipt.json').write_text(json.dumps({'status': 'passed', 'qualification': 'pinned-source-and-notices', 'locks': locks, 'files': [row]}))
        member = 'runtime/providers/wslc/win32-arm64/bin/wslc.exe'; data = b'MZexact supplier executable fixture'
        file = root / 'provider.tar.gz'; archive(file, [(member, data)])
        contract = {**receipt(file), 'files': [{'path': member, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}]}
        (runtime / 'runtime/runtime.lock.json').write_text(json.dumps({'provider_receipts': {'wslc/win32/arm64': {'lazy_assets': contract}}}))
        artifact = {'id': 'provider-assets-wslc-win32-arm64', **receipt(file), 'file': str(file)}
        return source, assets, runtime, artifact, member, data, original, notice

    def test_actual_shipped_member_joins_exact_original_source_and_notice(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, member, data, original, notice = self.fixture(directory)
            result = provider.derive(source, assets, runtime, [artifact])
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(len(result['bindings']), 1)
            binding = result['bindings'][0]
            self.assertEqual(binding['member_path'], member)
            self.assertEqual(binding['content'], {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)})
            self.assertEqual(binding['sources'][0]['repository'], 'microsoft/WSL')
            self.assertEqual(binding['sources'][0]['archive']['sha256'], receipt(original)['sha256'])
            self.assertEqual(binding['notices'][0]['sha256'], receipt(notice)['sha256'])
            self.assertEqual({row['sha256'] for row in binding['required_materials']}, {receipt(original)['sha256'], receipt(notice)['sha256']})

    def test_provider_source_replay_uses_verified_part_without_expanded_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, member, _, original, notice = self.fixture(directory)
            body = original.read_bytes(); fingerprint = hashlib.sha256(body).hexdigest(); original.unlink()
            recorder = StreamRecorder()
            result = provider.derive(source, assets, runtime, [artifact], recorder, SourceParts({fingerprint: body}))
            self.assertEqual(result['bindings'][0]['member_path'], member)
            self.assertEqual(result['bindings'][0]['sources'][0]['archive']['sha256'], fingerprint)
            self.assertEqual(result['bindings'][0]['notices'][0]['sha256'], receipt(notice)['sha256'])
            self.assertFalse(original.exists()); self.assertTrue(any(row[1] == fingerprint for row in recorder.rows))
            with self.assertRaisesRegex(ValueError, 'missing or differs'):
                provider.derive(source, assets, runtime, [artifact], StreamRecorder(), SourceParts({fingerprint: b'wrong'}))

    def test_changed_original_source_or_notice_cannot_be_admitted(self):
        for selected in ('source', 'notice'):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                source, assets, runtime, artifact, _, _, original, notice = self.fixture(directory)
                (original if selected == 'source' else notice).write_bytes(b'altered original')
                with self.assertRaisesRegex(ValueError, 'bytes differ'):
                    provider.derive(source, assets, runtime, [artifact])

    def test_source_binding_rejects_changed_authority_even_when_cached_sources_match(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, *_ = self.fixture(directory)
            (source / 'runtime/materials/provider-source-mappings.lock.json').write_text('{"sources":[]}\n')
            with self.assertRaisesRegex(ValueError, 'authority changed'):
                provider.derive(source, assets, runtime, [artifact])

    def test_ancillary_acquisition_metadata_does_not_invalidate_unchanged_source_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, *_ = self.fixture(directory)
            (source / 'runtime/provider-assets.lock.json').write_text(json.dumps({'version': 'same-source-new-acquisition-metadata', 'wslc': {'source_commit': '1' * 40}}))
            self.assertEqual(provider.derive(source, assets, runtime, [artifact])['status'], 'passed')

    def test_current_binary_source_commit_must_match_available_exact_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, *_ = self.fixture(directory)
            (source / 'runtime/provider-assets.lock.json').write_text(json.dumps({'wslc': {'source_commit': '2' * 40}}))
            with self.assertRaisesRegex(ValueError, 'main source'):
                provider.derive(source, assets, runtime, [artifact])

    def test_exact_outer_archive_hash_does_not_excuse_missing_duplicate_or_foreign_members(self):
        for mode in ('missing', 'duplicate', 'foreign', 'changed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                source, assets, runtime, artifact, member, data, *_ = self.fixture(directory)
                file = Path(artifact['file'])
                rows = [] if mode == 'missing' else [(member, data)]
                if mode == 'duplicate': rows.append((member, data))
                if mode == 'foreign': rows.append(('../escape', data))
                if mode == 'changed': rows = [(member, b'changed content')]
                archive(file, rows)
                actual = receipt(file); artifact.update(actual)
                lock = json.loads((runtime / 'runtime/runtime.lock.json').read_bytes())
                lock['provider_receipts']['wslc/win32/arm64']['lazy_assets'].update(actual)
                (runtime / 'runtime/runtime.lock.json').write_text(json.dumps(lock))
                with self.assertRaisesRegex(ValueError, 'omits|adds|duplicates|bytes differ'):
                    provider.derive(source, assets, runtime, [artifact])

    def test_duplicate_artifact_and_absent_frozen_profile_reject_before_source_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets, runtime, artifact, *_ = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, 'duplicated'):
                provider.derive(source, assets, runtime, [artifact, artifact])
            with self.assertRaisesRegex(ValueError, 'profile'):
                provider.derive(source, assets, runtime, [{**artifact, 'id': 'provider-assets-unrelated'}])

    def test_shortened_guest_cache_cannot_reauthorize_its_own_image_or_source_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory); base = assets / '.artifacts/source-materials-data/ubuntu-arm64-v2'; base.mkdir(parents=True)
            (base / 'status').write_bytes(b'Package: forged\nVersion: 1\nStatus: install ok installed\n\n')
            inventory = {'status': 'passed', 'packages': [{'name': 'forged', 'version': '1'}], 'status_file': receipt(base / 'status')}
            (base / 'receipt.json').write_text(json.dumps(inventory))
            sources = assets / '.artifacts/source-materials-data/ubuntu-sources-historical'; sources.mkdir()
            (sources / 'receipt.json').write_text(json.dumps({'status': 'passed', 'missing': [], 'subjects': [receipt(base / 'receipt.json')]}))
            image = {'sha256': '8eb876c2ccc4b6ff89e4a65d511815923b285e04503ba465809bf587f763da24', 'size_bytes': 940373504}
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                provider.guest_materials(ROOT, assets, 'arm64', image)

    def test_guest_source_replay_streams_exact_original_and_checks_keyring_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'source'; assets = root/'assets'
            authority = source/'runtime/materials/lima-ubuntu'; authority.mkdir(parents=True)
            base = assets/'.artifacts/source-materials-data/ubuntu-arm64-v2'; base.mkdir(parents=True)
            sources_base = assets/'.artifacts/source-materials-data/ubuntu-sources-historical'; sources_base.mkdir(parents=True)
            keys = assets/'.artifacts/lima-product/ubuntu'; keys.mkdir(parents=True)
            keyring = keys/'ubuntu-archive-keyring.gpg'; keyring.write_bytes(b'exact keyring')
            original = sources_base/'source.tar.gz'; archive(original, [('ubuntu/keyrings/ubuntu-archive-keyring.gpg', keyring.read_bytes())])
            original_row = receipt(original); body = original.read_bytes(); original.unlink()
            status = base/'status'; status.write_bytes(b'actual signed database fixture')
            notice = base/'notice'; notice.write_bytes(b'original package notice')
            manifest = authority/'arm64.manifest'; manifest.write_text('ubuntu-keyring\t1\n')
            package = {'name':'ubuntu-keyring', 'version':'1', 'architecture':'arm64', 'source':{}, 'built_using':[], 'notice':receipt(notice)}
            image = {'sha256':'1'*64, 'size_bytes':100}
            inventory = {'status':'passed', 'qualification':'image-bound-publisher-package-and-notice-inventory', 'image':image, 'guest_architecture':'arm64', 'status_file':receipt(status), 'packages':[package]}
            inventory_file = base/'receipt.json'; inventory_file.write_text(json.dumps(inventory))
            collections = {'status':'passed', 'missing':[], 'subjects':[receipt(inventory_file)], 'files':[original_row], 'metadata':[], 'sources':[{'name':'ubuntu-keyring', 'version':'1', 'files':[original_row]}]}
            (sources_base/'receipt.json').write_text(json.dumps(collections))
            identity = lambda file, path: {**receipt(file), 'path':path}
            protected = []
            for name in ('image-lock', 'producer', 'tool-recipe'):
                file = source/name; file.write_text(name); protected.append(identity(file, name))
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
            notice_record = {'package':'ubuntu-keyring', 'version':'1', 'architecture':'arm64', **provider.material(base, receipt(notice), assets)}
            anchor = {'image':image, 'extraction_receipt':identity(inventory_file, inventory_file.relative_to(assets).as_posix()), 'status':identity(status, status.relative_to(assets).as_posix()), 'publisher_manifest':receipt(manifest), 'packages':1, 'package_universe_sha256':hashlib.sha256(canonical([('ubuntu-keyring','1')])).hexdigest(), 'notices_inventory_sha256':hashlib.sha256(canonical([notice_record])).hexdigest()}
            lock = {'schema_version':1, 'qualification':'source-bound-previously-verified-guest-package-extraction-identities', 'image_lock':protected[0], 'producer':protected[1], 'tool_recipe':protected[2], 'images':{'arm64':anchor}}
            (authority/'extracted-images.lock.json').write_text(json.dumps(lock))
            helper = SimpleNamespace(authenticated_sources=lambda *args: None, materials=SimpleNamespace(installed_packages=lambda *args: [package], source_requirements=lambda rows:[{'name':'ubuntu-keyring', 'version':'1'}]))
            parts = SourceParts({original_row['sha256']:body}); recorder = StreamRecorder()
            verifier = root / 'inert-signature-tool'; verifier.write_bytes(b'not executed by the mocked signature verifier')
            with patch.object(provider, 'load_module', return_value=helper), patch.object(provider.shutil, 'which', return_value=str(verifier)):
                result = provider.guest_materials(source, assets, 'arm64', image, recorder, parts)
            self.assertIn(original_row['sha256'], {row['sha256'] for row in result['required_materials']})
            self.assertIn((keyring, original_row['sha256'], 'ubuntu/keyrings/ubuntu-archive-keyring.gpg'), recorder.rows)
            self.assertFalse(original.exists())


if __name__ == '__main__': unittest.main()
