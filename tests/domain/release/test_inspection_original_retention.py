import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('inspection_original_retention', ROOT / 'scripts/release/retain-component-inspection-inputs.py')
retention = importlib.util.module_from_spec(spec); spec.loader.exec_module(retention)


def write(root, path, body):
    file = root / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body)
    return {'path': path, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}


def document(root, path, value):
    write(root, path, json.dumps(value).encode())


def fixture(root):
    document(root, 'runtime/userspace-inputs.lock.json', {'platforms': {}})


class InspectionOriginalRetentionTests(unittest.TestCase):
    def successful(self, action, *args):
        try: return action(*args)
        except ValueError as error: self.fail('Known exact original was rejected: ' + str(error))

    def test_no_observed_bootstrap_input_requires_no_runtime_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.successful(retention.retain_inspected_originals, root, root, {'families': []}, set())
            self.assertEqual(result['required_materials'], [])
            self.assertEqual(result['joins'], [])
            with self.assertRaises(FileNotFoundError): retention.retain_inspected_originals(root, root, {'families': []}, {'.artifacts/userspace-inputs/cache/' + 'a' * 64})

    def test_only_observed_selected_originals_are_retained_and_unknown_reads_stay_unresolved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            source = write(root, 'known/blobs/original', b'Original readable source\n')
            write(root, 'unknown.bin', b'Unreviewed input'); write(root, 'known/blobs/unread', b'Unused source')
            document(root, 'known/receipt.json', {'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [{**source, 'path': 'blobs/original'}], 'notices': []})
            recipe = {'families': [{'kind': 'locked-source-members', 'sources': 'known/receipt.json'}]}; observed = {'known/blobs/original', 'unknown.bin'}
            recorder = retention.inspection.Recorder(root, root); recorder.paths.update(observed)
            result = self.successful(retention.retain_inspected_originals, root, root, recipe, observed, recorder)
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(result['required_materials'], [source])
            self.assertNotIn('source_facts', result)
            catalog = recorder.finish({'files': [], 'sha256': 'a' * 64}, {'subjects': []}, result['required_materials'])
            self.assertEqual(catalog['unretained_inputs'], ['unknown.bin'])
            write(root, source['path'], b'x' * source['size_bytes'])
            with self.assertRaisesRegex(ValueError, 'hash or identity'): retention.retain_inspected_originals(root, root, recipe, observed)

    def test_cleaned_family_retains_only_receipt_matched_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            source = write(root, 'known/blobs/original', b'Original readable source\n')
            document(root, 'known/receipt.json', {'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [{**source, 'path': 'blobs/original'}], 'notices': []})
            recipe = {'families': [{'kind': 'locked-source-members', 'sources': 'known/receipt.json'}]}
            recorder = retention.inspection.Recorder(root, root)
            for name in ('known/blobs/original', 'known/receipt.json'):
                recorder.note(root / name); recorder.checkpoint(root / name); (root / name).unlink()
            result = retention.retain_inspected_originals(root, root, recipe, frozenset(recorder.paths), recorder)
            self.assertEqual(result['required_materials'], [source])
            recorder.observations.rows['known/blobs/original']['row']['sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'differs from its family receipt'):
                retention.retain_inspected_originals(root, root, recipe, frozenset(recorder.paths), recorder)

    def test_locked_bootstrap_container_is_exact_inspection_data_and_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); body = b'Original archive data only\n'; fingerprint = hashlib.sha256(body).hexdigest()
            path = '.artifacts/userspace-inputs/cache/' + fingerprint
            archive = write(root, path, body)
            document(root, 'runtime/userspace-inputs.lock.json', {'platforms': {'darwin/arm64': {'uv_archive': {'sha256': 'sha256:' + fingerprint, 'size': len(body)}}}})
            result = self.successful(retention.retain_inspected_originals, root, root, {'families': []}, {path})
            self.assertEqual(result['required_materials'], [archive])
            self.assertEqual(result['joins'][0]['form'], 'exact-locked-bootstrap-original-inspection-archive')
            write(root, path, b'x' * len(body))
            with self.assertRaisesRegex(ValueError, 'hash or identity'): retention.retain_inspected_originals(root, root, {'families': []}, {path})

    def test_observed_ubuntu_keyring_retains_only_locked_public_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = '.artifacts/lima-product/ubuntu/ubuntu-archive-keyring.gpg'
            keyring = write(root, path, b'Original Ubuntu public keyring')
            document(root, 'runtime/lima-guest.lock.json', {'package_authentication': {'keyring_sha256': 'sha256:' + keyring['sha256']}})
            result = retention.retain_inspected_originals(root, root, {'families': []}, {path})
            self.assertEqual(result['required_materials'], [keyring])
            self.assertEqual(result['joins'][0]['form'], 'exact-locked-ubuntu-archive-keyring')
            write(root, path, b'x' * keyring['size_bytes'])
            with self.assertRaisesRegex(ValueError, 'hash or identity'):
                retention.retain_inspected_originals(root, root, {'families': []}, {path})

    def windows_fixture(self, root, *, changed_member=False, missing=False):
        fixture(root); raw = 'raw-perl'; member = 'lib/CORE/perl544.lib'; body = b'Original supplier inspection member\n'
        observed = write(root, raw + '/' + member, body)
        document(root, 'raw-receipt.json', {'platform': 'win32/arm64', 'files': [{'path': member, 'sha256': 'sha256:' + observed['sha256'], 'size': observed['size_bytes']}]})
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:bz2') as archive:
            if not missing:
                value = b'changed original member\n' if changed_member else body
                row = tarfile.TarInfo('Library/' + member); row.size = len(value); archive.addfile(row, io.BytesIO(value))
        supplier = write(root, '.artifacts/native-perl/cache/windows/original.tar.bz2', data.getvalue())
        document(root, 'runtime/windows-perl-distributions.lock.json', {'platforms': {'arm64': {'perl': {'filename': 'original.tar.bz2', 'sha256': 'sha256:' + supplier['sha256'], 'size_bytes': supplier['size_bytes']}}}})
        recipe = {'families': [{'kind': 'private-perl', 'platform': 'win32/arm64', 'sources': [], 'runtime_only': {'input_pack': raw, 'input_receipt': 'raw-receipt.json'}}]}
        return recipe, observed, supplier

    def test_removed_windows_member_retains_exact_supplier_origin_instead_of_a_runtime_waiver(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe, observed, supplier = self.windows_fixture(root)
            recorder = retention.inspection.Recorder(root, root); recorder.paths.add(observed['path'])
            result = self.successful(retention.retain_inspected_originals, root, root, recipe, {observed['path']}, recorder)
            self.assertEqual(result['required_materials'], [supplier])
            catalog = recorder.finish({'files': [], 'sha256': 'a' * 64}, {'subjects': []}, result['required_materials'])
            self.assertEqual(catalog['unretained_inputs'], [])
            row = next(row for row in catalog['inputs'] if row['path'] == observed['path'])
            self.assertEqual(row['retention'], {'kind': 'corresponding-source-member', 'blob_sha256': supplier['sha256'], 'member': 'Library/lib/CORE/perl544.lib'})
            self.assertEqual(row['sha256'], observed['sha256'])

    def test_missing_or_changed_supplier_member_cannot_borrow_the_archive_receipt(self):
        for options in ({'changed_member': True}, {'missing': True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); recipe, observed, _ = self.windows_fixture(root, **options)
                with self.assertRaisesRegex(ValueError, 'exact original supplier bytes|omits an observed'): retention.retain_inspected_originals(root, root, recipe, {observed['path']})


if __name__ == '__main__': unittest.main()
