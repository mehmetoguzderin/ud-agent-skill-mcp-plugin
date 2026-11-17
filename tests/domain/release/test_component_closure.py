import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_closure', ROOT / 'scripts/release/component-closure.py')
closure = importlib.util.module_from_spec(spec); spec.loader.exec_module(closure)


class ComponentClosureTests(unittest.TestCase):
    def test_oci_package_source_proof_identity_survives_checkout_relocation(self):
        def report(root, fingerprint='a' * 64):
            proof = {'inventory': {'path': root + '/inventory.json', 'sha256': fingerprint, 'size_bytes': 41},
                     'corresponding_sources': {'path': root + '/sources.json', 'sha256': 'b' * 64, 'size_bytes': 92}}
            return {'package_source_binding': proof,
                    'source_binding_sha256': hashlib.sha256(closure.canonical(proof)).hexdigest()}

        assembled = report('/assembler')
        verified = report('/verifier')
        self.assertNotEqual(assembled['source_binding_sha256'], verified['source_binding_sha256'])
        self.assertEqual(closure.content_identity(assembled), closure.content_identity(verified))
        self.assertNotEqual(closure.content_identity(assembled), closure.content_identity(report('/verifier', 'c' * 64)))

    def test_source_archive_binary_members_do_not_escape_component_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'LICENSE').write_text('Fixture original license\n'); (root / 'runtime').mkdir()
            body = b'MZ' + bytes(128); (root / 'runtime/foreign.exe').write_bytes(body)
            source = closure.source_inventory(root); manifest = json.dumps(source).encode(); archive = root / 'source.tar.gz'
            with tarfile.open(archive, 'w:gz') as target:
                for row in source['files']:
                    data = (root / row['path']).read_bytes(); member = tarfile.TarInfo(row['path']); member.size = len(data); member.mode = 0o755 if row['executable'] else 0o644; target.addfile(member, io.BytesIO(data))
                member = tarfile.TarInfo('SOURCE-MANIFEST.json'); member.size = len(manifest); target.addfile(member, io.BytesIO(manifest))
            candidate = {'schema_version': 1, 'source_tree_sha256': source['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'source-archive', 'path': archive.name, 'sha256': closure.digest(archive), 'size': archive.stat().st_size}]}
            result = closure.derive(root, candidate, {'schema_version': 1, 'families': []})
            self.assertFalse(result['complete_available_shipped_component_coverage'])
            self.assertEqual([row['path'] for row in result['unresolved_shipped_members']], ['runtime/foreign.exe'])
            self.assertEqual(result['subjects'][0]['members'], 3)

    def test_original_universal_source_wheel_cannot_admit_compiled_launchers_or_nested_wheels(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive = root / 'original.whl'
            bodies = {'vendor/module.py': b'def actual_source():\n    return 7\n', 'vendor/launcher.exe': b'MZ' + bytes(64), 'vendor/nested.whl': b'PK\x03\x04' + bytes(64)}
            with zipfile.ZipFile(archive, 'w') as bundle:
                for name, body in bodies.items(): bundle.writestr(name, body)
            wanted = {(hashlib.sha256(body).hexdigest(), len(body)) for body in bodies.values()}; facts = closure.Facts()
            source = {'path': archive.name, **closure.record(archive)}
            closure.zip_source_member_facts(archive, source, [{'member_path': 'LICENSE', 'sha256': 'a' * 64}], facts, wanted, 'b' * 64)
            self.assertEqual(len(facts.rows), 1)
            value = next(iter(facts.rows.values())); self.assertEqual(value['sha256'], hashlib.sha256(bodies['vendor/module.py']).hexdigest())

    def test_actual_available_bytes_and_missing_distribution_subjects_are_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'LICENSE').write_text('Original authored fixture terms\n'); (root / 'skills/demo').mkdir(parents=True)
            content = b'A real standalone support resource\n'; (root / 'skills/demo/reference.md').write_bytes(content)
            archive = root / 'resource.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                member = tarfile.TarInfo('skills/demo/reference.md'); member.size = len(content); output.addfile(member, io.BytesIO(content))
            source = closure.source_inventory(root)
            candidate = {'schema_version': 1, 'source_tree_sha256': source['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'userspace-core-linux-arm64', 'path': archive.name, 'sha256': closure.digest(archive), 'size': archive.stat().st_size}]}
            result = closure.derive(root, candidate, {'schema_version': 1, 'families': []}, diagnostic=True)
            self.assertTrue(result['complete_available_shipped_component_coverage'])
            self.assertFalse(result['complete_product_coverage'])
            self.assertEqual(len(result['missing_distribution_subjects']), 16)
            self.assertEqual(result['unresolved_shipped_members'], [])
            candidate['source_tree_sha256'] = 'a' * 64
            with self.assertRaisesRegex(ValueError, 'retained exact candidate'): closure.derive(root, candidate, {'schema_version': 1, 'families': []})

    def test_a_binary_copied_into_source_or_a_passed_claim_cannot_issue_source_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'LICENSE').write_text('Fixture license\n'); (root / 'runtime').mkdir()
            body = bytearray(64); body[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', body, 18, 183); (root / 'runtime/unknown').write_bytes(body)
            file = root / 'runtime.tar.gz'
            with tarfile.open(file, 'w:gz') as output:
                member = tarfile.TarInfo('bin/unknown'); member.size = len(body); output.addfile(member, io.BytesIO(body))
            candidate = {'schema_version': 1, 'source_tree_sha256': closure.source_inventory(root)['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'userspace-core-linux-arm64', 'path': file.name, 'sha256': closure.digest(file), 'size': file.stat().st_size, 'complete_product_coverage': True}]}
            result = closure.derive(root, candidate, {'schema_version': 1, 'families': []}, diagnostic=True)
            self.assertFalse(result['complete_available_shipped_component_coverage']); self.assertEqual(result['unresolved_shipped_members'][0]['architecture'], 'linux-arm64')
            for recipe in [{'schema_version': 1, 'families': [], 'complete': True}, {'schema_version': 1, 'families': [{'kind': 'passed-proof', 'status': 'passed', 'bindings': []}]}]:
                with self.subTest(recipe=recipe), self.assertRaises(ValueError): closure.derive(root, candidate, recipe, diagnostic=True)

    def test_exact_proprietary_declarations_require_independent_terms_and_definition_binding(self):
        # Actual pinned six-binary/terms fixture, without any Microsoft SDK
        # library payload copied into the test or distributable source.
        values = closure.proprietary_declarations(ROOT); self.assertEqual(len(values), 6)
        self.assertTrue(all(row['publisher_redistribution_authority'] == 'unverified-external' for row in values.values()))

    def test_a_prebuilt_software_archive_in_the_source_tree_is_not_its_own_corresponding_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'runtime').mkdir(); (root / 'LICENSE').write_text('Authored fixture terms\n'); wheel = root / 'runtime/foreign.whl'
            with zipfile.ZipFile(wheel, 'w') as bundle: bundle.writestr('foreign/module.dll', b'MZ' + bytes(128))
            payload = wheel.read_bytes(); archive = root / 'package.tar.gz'
            with tarfile.open(archive, 'w:gz') as target:
                item = tarfile.TarInfo('runtime/foreign.whl'); item.size = len(payload); target.addfile(item, io.BytesIO(payload))
            candidate = {'schema_version': 1, 'source_tree_sha256': closure.source_inventory(root)['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'userspace-core-linux-arm64', 'path': archive.name, 'sha256': closure.digest(archive), 'size': archive.stat().st_size}]}
            result = closure.derive(root, candidate, {'schema_version': 1, 'families': []}, diagnostic=True)
            self.assertFalse(result['complete_available_shipped_component_coverage']); self.assertEqual(result['unresolved_shipped_members'][0]['path'], 'runtime/foreign.whl')


if __name__ == '__main__': unittest.main()
