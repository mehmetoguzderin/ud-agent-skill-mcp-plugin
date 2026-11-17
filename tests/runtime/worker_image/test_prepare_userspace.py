import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("userspace_builder_tests", ROOT / "scripts/runtime/prepare-userspace.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class UserspaceBuildTests(unittest.TestCase):
    def uv_replay_fixture(self, root):
        assets = root / 'relocated-assets'; source = root / 'candidate-source'
        assets.mkdir(); source.mkdir()
        body = bytearray(2048); body[:2] = b'MZ'; struct.pack_into('<I', body, 60, 128); body[128:132] = b'PE\0\0'
        struct.pack_into('<HH', body, 132, 0xAA64, 1); struct.pack_into('<H', body, 148, 240)
        struct.pack_into('<H', body, 152, 0x20B); struct.pack_into('<Q', body, 176, 0x180000000)
        struct.pack_into('<I', body, 212, 1024); struct.pack_into('<I', body, 260, 16)
        struct.pack_into('<IIII', body, 400, 1024, 4096, 1024, 1024)
        struct.pack_into('<II', body, 272, 4096, 40); struct.pack_into('<I', body, 1036, 0x1300)
        body[1792:1805] = b'kernel32.dll\0'
        binary = assets / 'uv.exe'; binary.write_bytes(body)
        names = ['libcmt', 'libcpmt', 'libucrt', 'libvcruntime']
        link_map = source / 'retained.map'
        link_map.write_text(''.join(f' 0001:0 symbol 1400000000 {name}:D:\\original\\{name}.obj\n' for name in names))
        libraries = [{'library': name, 'archive': {'path': f'private/{name}.lib', 'sha256': 'a' * 64, 'size_bytes': 99}, 'members': [{'name': f'D:\\original\\{name}.obj', 'sha256': 'b' * 64, 'size_bytes': 11}]} for name in names]
        record = {'platform': 'win32/arm64', 'binary': {'path': binary.name, 'sha256': builder.digest(binary)[7:], 'size_bytes': len(body)}, 'map': {'path': 'original.map', 'sha256': builder.digest(link_map)[7:], 'size_bytes': link_map.stat().st_size}, 'imports': ['kernel32.dll'], 'profile': 'static-msvc-crt', 'private_crt_dlls': [], 'target_execution': False, 'libraries': libraries}
        original = {'schema_version': 1, 'qualification': 'original-source-crossbuild-linkage-not-native-acceptance', 'source_commit': '316c827e058c16b71d5c507a20729c2995a7bcce', 'version': '0.13.7', 'publisher_redistribution_authority': 'unverified-external', 'source_receipt_sha256': 'c' * 64, 'build_receipt_sha256': 'd' * 64, 'records': [record]}
        receipt = assets / 'linkage.json'; receipt.write_text(json.dumps(original))
        descriptor = {'path': receipt.name, 'sha256': builder.digest(receipt), 'size': receipt.stat().st_size}
        def declaration_row(row): return {'library': row['library'], 'archive_sha256': row['archive']['sha256'], 'archive_size_bytes': row['archive']['size_bytes'], 'members': row['members']}
        declaration = {'platform': 'win32/arm64', 'binary_name': 'uv', 'binary_sha256': record['binary']['sha256'], 'system_imports': ['kernel32.dll'], 'license': 'LicenseRef-Microsoft-VisualStudio-2026-CRT', 'classification': 'proprietary-static-object-code', 'publisher_redistribution_authority': 'unverified-external', 'static_libraries': [declaration_row(row) for row in libraries if row['library'] != 'libcpmt'], 'other_static_components': [declaration_row(row) for row in libraries if row['library'] == 'libcpmt'], 'link_map': {'path': link_map.name, 'sha256': record['map']['sha256'], 'size': record['map']['size_bytes']}, 'original_source_build': {'source_commit': original['source_commit'], 'version': original['version'], 'source_receipt_sha256': original['source_receipt_sha256'], 'build_receipt_sha256': original['build_receipt_sha256'], 'linkage_receipt_sha256': descriptor['sha256'][7:], 'target_execution': False}}
        declaration['definition_sha256'] = hashlib.sha256(json.dumps(declaration, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return assets, source, descriptor, declaration, binary

    def test_owned_uv_portable_replay_checks_actual_binary_and_retained_map_without_private_sdk(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets, source, descriptor, declaration, binary = self.uv_replay_fixture(Path(temporary))
            selected, origin = builder.select_derived_uv(assets, 'win32/arm64', descriptor, source_replay=(source, declaration))
            self.assertEqual(selected, binary)
            self.assertEqual(origin['verification'], 'retained-reviewed-source-build-and-link-map')
            self.assertFalse(origin['target_execution'])
            self.assertEqual(sorted(file.name for file in assets.iterdir()), ['linkage.json', 'uv.exe'])
            self.assertEqual(sorted(file.name for file in source.iterdir()), ['retained.map'])
            binary.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'executable bytes differ'):
                builder.select_derived_uv(assets, 'win32/arm64', descriptor, source_replay=(source, declaration))

    def test_owned_uv_portable_replay_rejects_stale_declaration_map_and_source_identities(self):
        for change in ('definition', 'linkage', 'source', 'binary', 'object', 'map', 'map-path', 'imports', 'map-objects', 'pe-imports'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                assets, source, descriptor, declaration, _ = self.uv_replay_fixture(Path(temporary))
                if change == 'definition': declaration['definition_sha256'] = '0' * 64
                elif change == 'linkage': declaration['original_source_build']['linkage_receipt_sha256'] = '0' * 64
                elif change == 'source': declaration['original_source_build']['source_commit'] = '0' * 40
                elif change == 'binary': declaration['binary_sha256'] = '0' * 64
                elif change == 'object': declaration['static_libraries'][0]['members'][0]['sha256'] = '0' * 64
                elif change == 'map': (source / 'retained.map').write_text('changed')
                elif change == 'map-path': declaration['link_map']['path'] = '../outside'
                elif change == 'imports': declaration['system_imports'] = ['private.dll']
                elif change in ('map-objects', 'pe-imports'):
                    receipt = assets / descriptor['path']; original = json.loads(receipt.read_bytes())
                    if change == 'map-objects':
                        link_map = source / 'retained.map'; link_map.write_text(link_map.read_text() + ' 0001:0 extra 1400000000 libcmt:D:\\original\\extra.obj\n')
                        original['records'][0]['map'].update(sha256=builder.digest(link_map)[7:], size_bytes=link_map.stat().st_size)
                        declaration['link_map'].update(sha256=builder.digest(link_map)[7:], size=link_map.stat().st_size)
                    else:
                        original['records'][0]['imports'] = ['advapi32.dll']; declaration['system_imports'] = ['advapi32.dll']
                    receipt.write_text(json.dumps(original)); descriptor.update(sha256=builder.digest(receipt), size=receipt.stat().st_size)
                    declaration['original_source_build']['linkage_receipt_sha256'] = descriptor['sha256'][7:]
                if change != 'definition':
                    definition = {key: value for key, value in declaration.items() if key != 'definition_sha256'}
                    declaration['definition_sha256'] = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                with self.assertRaises(ValueError):
                    builder.select_derived_uv(assets, 'win32/arm64', descriptor, source_replay=(source, declaration))

    def test_locked_core_wheels_cover_both_python_abis_on_all_six_hosts(self):
        sources = json.loads((ROOT / "runtime/ud-sources.lock.json").read_text())
        commit = next(item["commit"] for item in sources["sources"] if item["repository"] == "UniversalDependencies/tools")
        packages = builder.core_packages(tomllib.loads((ROOT / "uv.lock").read_text()), commit)
        self.assertTrue(packages)
        for host in builder.HOSTS:
            for package in packages:
                wheels = builder.select_wheels(package, host)
                self.assertTrue(wheels)
                names = [item["filename"] for item in wheels]
                if not any("-none-any.whl" in name for name in names):
                    self.assertTrue(any("-cp314-cp314-" in name for name in names))
                    self.assertTrue(any("-cp315-cp315-" in name for name in names))

    def test_verified_offline_cache_never_accepts_corrupt_or_missing_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            content = b"verified bytes"
            expected = "sha256:" + hashlib.sha256(content).hexdigest()
            record = {"url": "https://github.com/astral-sh/uv/releases/download/0.13.7/asset", "sha256": expected, "size": len(content)}
            with self.assertRaisesRegex(ValueError, "offline cache"):
                builder.acquire(record, cache, False)
            target = cache / expected[7:]
            target.write_bytes(content)
            self.assertEqual(builder.acquire(record, cache, False), target)
            target.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "integrity"):
                builder.acquire(record, cache, False)

    def test_native_dependency_copy_is_confined_and_hash_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "inputs"
            (source / "bin").mkdir(parents=True)
            perl = source / "bin/perl"
            perl.write_bytes(b"owned executable")
            perl.chmod(0o755)
            descriptor = {"root": "inputs", "executable": "bin/perl", "library_dirs": ["lib"], "files": [{"path": "bin/perl", "sha256": builder.digest(perl), "size": perl.stat().st_size}]}
            result = builder.copy_dependency(root, descriptor, root / "output")
            self.assertEqual((root / "output/bin/perl").read_bytes(), perl.read_bytes())
            self.assertEqual(result["executable"], "bin/perl")
            descriptor["files"][0]["sha256"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(ValueError, "receipt"):
                builder.copy_dependency(root, descriptor, root / "rejected")
            for value in ("../escape", "/absolute", "C:drive", "a\\b"):
                with self.assertRaises(ValueError):
                    builder.relative(value)

    def test_current_windows_inputs_select_exact_publisher_archives(self):
        locked = json.loads((ROOT / 'runtime/userspace-inputs.lock.json').read_bytes())
        self.assertNotIn('derived_uv', locked)
        for host, triple in [('win32/arm64', 'aarch64-pc-windows-msvc'), ('win32/x64', 'x86_64-pc-windows-msvc')]:
            descriptor = locked['platforms'][host]['uv_archive']
            self.assertEqual(descriptor['url'], f'https://github.com/astral-sh/uv/releases/download/{locked["uv_version"]}/uv-{triple}.zip')
            self.assertRegex(descriptor['sha256'], r'^sha256:[a-f0-9]{64}$')
            self.assertGreater(descriptor['size'], 0)

    def test_owned_uv_override_cannot_relabel_vendor_inputs_or_select_unverified_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'receipt.json'; file.write_text('{}')
            original = {'path': file.name, 'sha256': builder.digest(file), 'size': file.stat().st_size}
            for host, changed in [('linux/arm64', original), ('win32/arm64', {**original, 'path': '../outside'}), ('win32/x64', {**original, 'sha256': 'sha256:' + '0' * 64}), ('win32/arm64', {**original, 'size': 0}), ('win32/x64', {**original, 'native_execution': True})]:
                with self.subTest(host=host, descriptor=changed), self.assertRaises(ValueError): builder.select_derived_uv(root, host, changed)


if __name__ == "__main__":
    unittest.main()
