import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('inspection_inputs', ROOT / 'scripts/release/replay-inspection-inputs.py')
inputs = importlib.util.module_from_spec(spec); spec.loader.exec_module(inputs)


class InspectionInputTests(unittest.TestCase):
    def test_private_cpython_donor_input_requires_exact_bytes_and_stays_outside_source_parts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = b'independently authenticated immutable provider layer'
            fingerprint = hashlib.sha256(body).hexdigest()
            name = '.artifacts/source-materials-data/core-image-provenance-v1/layers/' + fingerprint
            file = root / name
            file.parent.mkdir(parents=True)
            file.write_bytes(body)
            source = {'sha256': 'a' * 64, 'files': []}
            with inputs.Recorder(root, root) as recorder:
                recorder.private_vendor_input(file, 'cpython-donor-layer', {'sha256': fingerprint, 'size_bytes': len(body)})
                catalog = recorder.finish(source, {'subjects': []}, [])
            self.assertEqual(catalog['unretained_inputs'], [])
            row, = catalog['inputs']
            self.assertEqual(row['retention'], {'kind': 'private-locked-cpython-input', 'role': 'cpython-donor-layer'})
            self.assertTrue(inputs.verify(catalog, root, source['sha256'], [], observations=recorder.observations)['verified'])
            with self.assertRaisesRegex(ValueError, 'outside its locked role'):
                inputs.private_vendor_reference({**row, 'path': 'unrelated.bin'}, 'cpython-donor-layer')
            file.write_bytes(b'altered content')
            with self.assertRaisesRegex(ValueError, 'retained identity'):
                inputs.verify(catalog, root, source['sha256'], [])

    def test_windows_perl_supplier_and_build_inputs_remain_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = {'sha256': 'a' * 64, 'files': []}
            roles = {
                '.artifacts/native-perl/cache/windows/perl-5.44.conda': 'windows-perl-supplier-archive',
                '.artifacts/native-perl/perl-open-x64/bin/perl.exe': 'windows-perl-build-input-member',
            }
            with inputs.Recorder(root, root) as recorder:
                for name, role in roles.items():
                    path = root / name
                    path.parent.mkdir(parents=True)
                    body = name.encode()
                    path.write_bytes(body)
                    if role == 'windows-perl-build-input-member':
                        path.chmod(0o755)
                    expected = {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
                    with self.assertRaisesRegex(ValueError, 'retained identity'):
                        recorder.private_vendor_input(path, role, {**expected, 'sha256': '0' * 64})
                    recorder.private_vendor_input(path, role, expected)
                catalog = recorder.finish(source, {'subjects': []}, [])
            self.assertEqual(catalog['unretained_inputs'], [])
            self.assertEqual(
                {row['path']: row['retention'] for row in catalog['inputs']},
                {name: {'kind': 'private-locked-windows-perl-input', 'role': role} for name, role in roles.items()},
            )
            self.assertTrue(inputs.verify(catalog, root, source['sha256'], [], observations=recorder.observations)['verified'])
            row = catalog['inputs'][0]
            with self.assertRaisesRegex(ValueError, 'outside its locked role'):
                inputs.private_vendor_reference(row, 'windows-perl-vc-archive')
            (root / row['path']).unlink()
            with self.assertRaises(FileNotFoundError):
                inputs.verify(catalog, root, source['sha256'], [])

    def test_windows_keeps_verified_archive_mode_without_claiming_native_posix_bits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'foreign-executable'; body = b'exact foreign executable'; file.write_bytes(body); file.chmod(0o444)
            expected = {'path': file.name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'executable': True}
            modeled_os = SimpleNamespace(**vars(os)); modeled_os.name = 'nt'
            with mock.patch.object(inputs, 'os', modeled_os):
                stream, actual = inputs.opened(root, expected)
                with stream: self.assertEqual(stream.read(), body)
                self.assertEqual(actual, expected)
                with self.assertRaisesRegex(ValueError, 'retained identity'):
                    inputs.opened(root, {**expected, 'sha256': '0' * 64})
                with self.assertRaisesRegex(ValueError, 'byte identity'):
                    inputs.opened(root, {'path': file.name, 'executable': True})
            self.assertFalse(file.stat().st_mode & 0o111)

    def test_windows_audit_events_keep_read_inputs_and_exact_tool_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); tool = root / 'tool with spaces.exe'; tool.write_bytes(b'actual tool')
            recorder = inputs.Recorder(root, root); recorder.active = True
            with mock.patch.object(recorder, 'note') as note:
                for flags in (os.O_RDONLY, os.O_RDWR, os.O_WRONLY, os.O_WRONLY | os.O_CREAT):
                    recorder.audit('open', (str(root / 'input'), None, flags))
                self.assertEqual(note.call_count, 2)
            for executable, arguments in [(str(tool), ['ignored']), (None, [str(tool), 'argument']), (None, '"' + str(tool) + '" "argument with spaces"')]:
                with mock.patch.object(inputs.shutil, 'which', return_value=str(tool)) as lookup:
                    recorder.audit('subprocess.Popen', (executable, arguments, None, None))
                    lookup.assert_called_once_with(str(tool))
            self.assertEqual(recorder.tools, {tool.resolve().as_posix(): tool.name})
            for arguments in ('"unterminated', '', None):
                with self.assertRaisesRegex(ValueError, 'unambiguous executable'):
                    recorder.audit('subprocess.Popen', (None, arguments, None, None))
            with mock.patch.object(inputs.shutil, 'which', return_value=None), self.assertRaisesRegex(ValueError, 'unresolved or ambiguous'):
                recorder.audit('subprocess.Popen', (None, r'C:\Program Files\tool.exe argument', None, None))

    def test_separately_inventoried_candidate_roots_do_not_leak_staging_prefixes_into_cache_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate = root / 'new-candidate'; candidate.mkdir()
            (candidate / 'original-archive').write_bytes(b'actual separately inventoried subject')
            (root / 'original.json').write_text('{"original":true}')
            with inputs.Recorder(candidate, root) as recorder:
                recorder.separately_verified(candidate / 'original-archive', hashlib.sha256((candidate / 'original-archive').read_bytes()).hexdigest(), (candidate / 'original-archive').stat().st_size)
                (candidate / 'original-archive').read_bytes(); (root / 'original.json').read_bytes()
                result = recorder.finish({'sha256': 'a' * 64, 'files': []}, {'subjects': []}, [])
            self.assertEqual([row['path'] for row in result['inputs']], ['original.json'])
            self.assertEqual(result['unretained_inputs'], [])

    def test_actual_reads_retain_metadata_and_reference_actual_source_and_archive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'source.tar').write_bytes(b'original-source')
            (root / 'subject.zip').write_bytes(b'actual distribution archive')
            (root / 'private-perl').write_bytes(b'actual executable member')
            (root / 'receipt.json').write_text('{"schema_version":1,"files":[]}\n')
            receipt = lambda name: {'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest(), 'size_bytes': (root / name).stat().st_size}
            source = {'sha256': 'a' * 64, 'files': []}
            discovery = {'subjects': [{'id': 'native', **receipt('subject.zip'), 'members': [{'path': 'bin/perl', **receipt('private-perl')}]}]}
            required = [receipt('source.tar')]
            with inputs.Recorder(root, root) as recorder:
                for name in ('source.tar', 'subject.zip', 'private-perl', 'receipt.json'):
                    (root / name).read_bytes()
                catalog = recorder.finish(source, discovery, required)
            self.assertEqual(catalog['unretained_inputs'], [])
            kinds = {row['path']: row['retention']['kind'] for row in catalog['inputs']}
            self.assertEqual(kinds, {'source.tar': 'corresponding-source-blob', 'subject.zip': 'released-artifact', 'private-perl': 'released-artifact-member', 'receipt.json': 'retained-json-metadata'})
            checked = inputs.verify(catalog, root, source['sha256'], catalog['subjects'], required_materials=required, discovered_subjects=discovery['subjects'])
            self.assertEqual(checked, {'verified': True, 'inputs': 4, 'unretained': 0})
            (root / 'private-perl').write_bytes(b'foreign executable bytes')
            with self.assertRaisesRegex(ValueError, 'retained identity'):
                inputs.verify(catalog, root, source['sha256'], catalog['subjects'], required_materials=required, discovered_subjects=discovery['subjects'])

    def test_private_sdk_bytes_are_not_retained_or_admitted_by_a_completeness_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'private.lib').write_bytes(b'!<arch>\nprivate vendor object')
            source = {'sha256': 'a' * 64, 'files': []}; discovery = {'subjects': []}
            with inputs.Recorder(root, root) as recorder:
                (root / 'private.lib').read_bytes(); catalog = recorder.finish(source, discovery, [])
            self.assertEqual(catalog['unretained_inputs'], ['private.lib'])
            self.assertNotIn('base64', catalog['inputs'][0]['retention'])
            with self.assertRaisesRegex(ValueError, 'Unretained'):
                inputs.verify(catalog, root, source['sha256'], [])
            forged = copy.deepcopy(catalog); forged['unretained_inputs'] = []
            with self.assertRaisesRegex(ValueError, 'unresolved list differs'):
                inputs.verify(forged, root, source['sha256'], [])
            forged = copy.deepcopy(catalog)
            forged['inputs'][0]['retention'] = {'kind': 'corresponding-source-blob', 'member': 'blobs/' + forged['inputs'][0]['sha256']}
            forged['inventory_sha256'] = hashlib.sha256(inputs.canonical(forged['inputs'])).hexdigest()
            with self.assertRaisesRegex(ValueError, 'selected original source blob'):
                inputs.verify(forged, root, source['sha256'], [])

    def test_inspection_verification_requires_every_observed_family_input_to_remain_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'family-a.json').write_text('{"family":"a"}')
            (root/'family-b.json').write_text('{"family":"b"}')
            source = {'sha256': 'a' * 64, 'files': []}; discovery = {'subjects': []}
            with inputs.Recorder(root, root) as recorder:
                (root/'family-a.json').read_bytes(); (root/'family-b.json').read_bytes()
                catalog = recorder.finish(source, discovery, [])
            self.assertEqual([row['path'] for row in catalog['inputs']], ['family-a.json', 'family-b.json'])
            self.assertTrue(inputs.verify(catalog, root, source['sha256'], [])['verified'])
            (root/'family-a.json').unlink()
            # A retained metadata receipt is not evidence that the consumed
            # original input is still present for the final exact verification.
            with self.assertRaises(FileNotFoundError): inputs.verify(catalog, root, source['sha256'], [])

    def test_verified_family_inputs_reconcile_after_cleanup_without_waiving_original_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source_file = root / 'original.tar'; metadata = root / 'family.json'
            source_file.write_bytes(b'original source archive'); metadata.write_bytes(b'{"family":"perl"}')
            required = [{'sha256': hashlib.sha256(source_file.read_bytes()).hexdigest(), 'size_bytes': source_file.stat().st_size}]
            source = {'sha256': 'a' * 64, 'files': []}; discovery = {'subjects': []}
            with inputs.Recorder(root, root) as recorder:
                source_file.read_bytes(); metadata.read_bytes()
                recorder.checkpoint(source_file, required[0]); recorder.checkpoint(metadata)
                source_file.unlink(); metadata.unlink()
                self.assertEqual(recorder.observed_bytes(metadata), b'{"family":"perl"}')
                catalog = recorder.finish(source, discovery, required)
            self.assertEqual(catalog['unretained_inputs'], [])
            self.assertEqual([row['retention']['kind'] for row in catalog['inputs']], ['retained-json-metadata', 'corresponding-source-blob'])
            result = inputs.verify(catalog, root, source['sha256'], [], required_materials=required, observations=recorder.observations)
            self.assertEqual(result, {'verified': True, 'inputs': 2, 'unretained': 0})
            with self.assertRaises(FileNotFoundError): inputs.verify(catalog, root, source['sha256'], [], required_materials=required)
            with self.assertRaisesRegex(ValueError, 'selected original source blob'):
                inputs.verify(catalog, root, source['sha256'], [], required_materials=[], observations=recorder.observations)
            source_file.write_bytes(b'changed source archive!')
            with self.assertRaisesRegex(ValueError, 'retained identity'):
                inputs.verify(catalog, root, source['sha256'], [], required_materials=required, observations=recorder.observations)

    def test_family_checkpoint_refuses_missing_unobserved_changed_and_foreign_inputs(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as foreign:
            root = Path(temporary); file = root / 'input.bin'; file.write_bytes(b'actual')
            recorder = inputs.Recorder(root, root)
            with self.assertRaisesRegex(ValueError, 'not observed'): recorder.checkpoint(file)
            recorder.note(file)
            with self.assertRaisesRegex(ValueError, 'retained identity'):
                recorder.checkpoint(file, {'sha256': 'a' * 64, 'size_bytes': len(b'actual')})
            recorder.checkpoint(file)
            file.write_bytes(b'altered')
            with self.assertRaisesRegex(ValueError, 'changed between family checkpoints'): recorder.checkpoint(file)
            with self.assertRaisesRegex(ValueError, 'outside its input root'): recorder.checkpoint(Path(foreign) / 'outside')
            file.unlink(); missing = root / 'missing'; recorder.note(missing)
            with self.assertRaises(FileNotFoundError): recorder.checkpoint(missing)
            with self.assertRaisesRegex(ValueError, 'foreign input root'):
                inputs.verify({'schema_version': 1, 'qualification': inputs.QUALIFICATION, 'source_inventory_sha256': 'a' * 64, 'subjects': [], 'inputs': [], 'tools': [], 'unretained_inputs': [], 'inventory_sha256': hashlib.sha256(inputs.canonical([])).hexdigest()}, Path(foreign), 'a' * 64, [], observations=recorder.observations)

    def test_deleted_source_member_requires_its_real_archive_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'LICENSE'; file.write_bytes(b'notice')
            recorder = inputs.Recorder(root, root); recorder.source_member(file, 'b' * 64, 'pkg/LICENSE')
            recorder.checkpoint(file); file.unlink()
            source = {'sha256': 'a' * 64, 'files': []}; required = [{'sha256': 'b' * 64, 'size_bytes': 100}]
            catalog = recorder.finish(source, {'subjects': []}, required)
            self.assertTrue(inputs.verify(catalog, root, source['sha256'], [], required_materials=required, observations=recorder.observations)['verified'])
            recorder.references.clear()
            with self.assertRaisesRegex(ValueError, 'not verified against its original archive'):
                inputs.verify(catalog, root, source['sha256'], [], required_materials=required, observations=recorder.observations)

    def test_source_member_join_after_cleanup_requires_checkpointed_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'LICENSE'; file.write_bytes(b'notice')
            recorder = inputs.Recorder(root, root); recorder.note(file); recorder.checkpoint(file)
            file.unlink(); recorder.source_member(file, 'b' * 64, 'pkg/LICENSE')
            source = {'sha256': 'a' * 64, 'files': []}; required = [{'sha256': 'b' * 64, 'size_bytes': 100}]
            compact = recorder.finish_compact(source, {'subjects': []}, required)
            self.assertTrue(inputs.verify_compact(compact, root, source, {'subjects': []}, recorder=recorder, required_materials=required)['verified'])
            with self.assertRaisesRegex(ValueError, 'not captured before cleanup'):
                inputs.Recorder(root, root).source_member(root / 'other', 'b' * 64, 'pkg/other')

    def test_compact_family_report_reconciles_after_cleanup_without_per_read_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); data = root / 'source.tar'; meta = root / 'family.json'
            data.write_bytes(b'original source'); meta.write_bytes(b'{"family":"perl"}')
            source = {'sha256': 'a' * 64, 'files': []}; discovery = {'subjects': []}
            required = [{'sha256': hashlib.sha256(data.read_bytes()).hexdigest(), 'size_bytes': data.stat().st_size}]
            with inputs.Recorder(root, root) as recorder:
                data.read_bytes(); meta.read_bytes()
                recorder.checkpoint(data, required[0]); recorder.checkpoint(meta)
                data.unlink(); meta.unlink()
                compact = recorder.finish_compact(source, discovery, required)
            self.assertEqual(compact['schema_version'], 2)
            self.assertEqual(compact['input_count'], 2)
            self.assertNotIn('inputs', compact)
            self.assertEqual([row['path'] for row in compact['metadata']], ['family.json'])
            self.assertEqual(inputs.verify_compact(compact, root, source, discovery, recorder=recorder, required_materials=required), {'verified': True, 'inputs': 2, 'unretained': 0})
            altered = copy.deepcopy(compact); altered['inventory_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'differs from verified family observations'):
                inputs.verify_compact(altered, root, source, discovery, recorder=recorder, required_materials=required)
            with self.assertRaisesRegex(ValueError, 'differs from verified family observations'):
                inputs.verify_compact(compact, root, source, discovery, recorder=recorder, required_materials=[])

    def test_compact_report_rejects_a_read_file_removed_without_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'family.json'; file.write_text('{}')
            source = {'sha256': 'a' * 64, 'files': []}; discovery = {'subjects': []}
            with inputs.Recorder(root, root) as recorder:
                file.read_bytes(); file.unlink()
                with self.assertRaisesRegex(ValueError, 'disappeared without a checkpoint'):
                    recorder.finish_compact(source, discovery, [])

    def test_undeclared_subprocess_inputs_and_path_links_do_not_gain_archive_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'actual').write_bytes(b'member'); (root / 'link').symlink_to('actual')
            with inputs.Recorder(root, root) as recorder:
                recorder.note(root / 'link')
                with self.assertRaisesRegex(ValueError, 'link'):
                    recorder.finish({'sha256': 'a' * 64, 'files': []}, {'subjects': []}, [])
            for value in ('../foreign', '/absolute', 'drive:path', 'path\\escape'):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'unsafe'): inputs.safe(value)

    def test_identical_notice_cache_bytes_may_have_several_verified_original_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); notice = root / 'notice'; notice.write_bytes(b'Original shared license\n')
            recorder = inputs.Recorder(root, root)
            recorder.source_member(notice, 'a' * 64, 'one/LICENSE')
            recorder.source_member(notice, 'b' * 64, 'two/LICENSE')
            catalog = recorder.finish({'sha256': 'c' * 64, 'files': []}, {'subjects': []}, [{'sha256': 'b' * 64, 'size_bytes': 123}])
            self.assertEqual(catalog['inputs'][0]['retention'], {'kind': 'corresponding-source-member', 'blob_sha256': 'b' * 64, 'member': 'two/LICENSE'})
            notice.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed between'): recorder.source_member(notice, 'd' * 64, 'three/LICENSE')


if __name__ == '__main__': unittest.main()
