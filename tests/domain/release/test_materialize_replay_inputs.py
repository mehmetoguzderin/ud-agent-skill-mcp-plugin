import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('materializer', ROOT / 'scripts/release/materialize-replay-inputs.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def receipt(root, name):
    body = (root / name).read_bytes()
    return {'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'executable': False}


class MaterializeReplayInputsTests(unittest.TestCase):
    def test_private_cleanup_preserves_external_alias_target_and_retained_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); owned = root / 'owned'; owned.mkdir(mode=0o700)
            outside = root / 'outside'; outside.write_bytes(b'outside'); outside.chmod(0o444)
            (owned / 'alias').symlink_to(outside)
            local = owned / 'sealed'; local.write_bytes(b'private'); local.chmod(0o444)
            module.remove_private_tree(owned)
            self.assertFalse(owned.exists()); self.assertEqual(outside.read_bytes(), b'outside')
            self.assertFalse(outside.stat().st_mode & 0o222)
            if os.name == 'nt':
                owned.mkdir(mode=0o700); os.link(outside, owned / 'foreign-hardlink')
                with self.assertRaises(PermissionError): module.remove_private_tree(owned)
                self.assertEqual(outside.read_bytes(), b'outside'); self.assertFalse(outside.stat().st_mode & 0o222)
                # The fixture created this link and restores its own cleanup authority.
                outside.chmod(0o600); (owned / 'foreign-hardlink').unlink(); owned.rmdir()

    def test_storage_owner_liveness_is_a_read_only_native_query(self):
        for invalid in (0, -1, True, 0x100000000):
            with self.subTest(pid=invalid), self.assertRaisesRegex(ValueError, 'PID is invalid'):
                module.require_live_process(invalid)
        if os.name == 'nt':
            with mock.patch.object(os, 'kill', side_effect=AssertionError('liveness must not send a signal')):
                module.require_live_process(os.getpid())
        else: module.require_live_process(os.getpid())
        child = subprocess.Popen([sys.executable, '-c', 'pass'])
        self.assertEqual(child.wait(timeout=10), 0)
        with self.assertRaises((OSError, ValueError)): module.require_live_process(child.pid)

    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {'UD_STORAGE_LEASE': ''})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def fixture(self, root):
        original = root / 'original'; original.mkdir(); source = original / 'source.tar.gz'
        program = b'def original_program():\n    return 17\n'
        with tarfile.open(source, 'w:gz') as target:
            row = tarfile.TarInfo('original/module.py'); row.size = len(program); target.addfile(row, io.BytesIO(program))
        source_record = receipt(original, source.name)
        inventory = {'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [source_record]}
        collection = original / 'receipt.json'; collection.write_text(json.dumps(inventory))
        plan = root / 'plan'; index = module.materials.bundle([('original', collection)], plan, 4096, [{'sha256': source_record['sha256'], 'size_bytes': source_record['size_bytes']}])
        (root / 'runtime').mkdir(); release = root / 'release'; release.mkdir()
        index_name = 'ud-agent-corresponding-source-index.json'; names = [index_name, *[row['path'] for row in index['parts']]]
        records = []
        for number, name in enumerate(names):
            shutil.copyfile(plan / name, release / name)
            row = receipt(root, 'release/' + name)
            records.append({'id': 'corresponding-source-index' if number == 0 else index['parts'][number-1]['id'], 'path': row['path'], 'sha256': row['sha256'], 'size': row['size_bytes']})
        # The historical cache paths deliberately do not exist. Only actual
        # release sidecars may provide the original stream.
        lock_rows = [{**row, 'path': '.artifacts/old-cache/' + Path(row['path']).name} for row in records]
        lock = root / 'runtime/source-materials.lock.json'; lock.write_text(json.dumps({'schema_version': 1, 'index': lock_rows[0], 'parts': lock_rows[1:]}))
        native = release / 'native.tar.gz'; executable = b'MZ' + bytes(64)
        with tarfile.open(native, 'w:gz') as target:
            row = tarfile.TarInfo('bin/real-tool'); row.size = len(executable); target.addfile(row, io.BytesIO(executable))
        artifact = receipt(root, 'release/native.tar.gz'); records.insert(0, {'id': 'native-macos-arm64', 'path': artifact['path'], 'sha256': artifact['sha256'], 'size': artifact['size_bytes']})
        (root / 'LICENSE').write_text('Original fixture terms\n')
        source_files = []
        for name in ('LICENSE', 'runtime/source-materials.lock.json'):
            row = receipt(root, name); source_files.append({'path': name, 'sha256': row['sha256'], 'size': row['size_bytes'], 'executable': False})
        source_receipt = {'sha256': 'a'*64, 'files': source_files}
        content = lambda body: {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
        rows = [
            {'path': '.artifacts/input/receipt.json', **content(b'{"original":true}'), 'executable': False, 'retention': {'kind': 'retained-json-metadata', 'base64': 'eyJvcmlnaW5hbCI6dHJ1ZX0='}},
            {'path': '.artifacts/input/source.tar.gz', **{key: source_record[key] for key in ('sha256', 'size_bytes')}, 'executable': False, 'retention': {'kind': 'corresponding-source-blob', 'member': 'blobs/'+source_record['sha256']}},
            {'path': '.artifacts/private/bin/tool', **content(executable), 'executable': True, 'retention': {'kind': 'released-artifact-member', 'artifact': records[0]['id'], 'member': 'bin/real-tool'}},
            {'path': 'node_modules/original/module.py', **content(program), 'executable': False, 'retention': {'kind': 'corresponding-source-member', 'blob_sha256': source_record['sha256'], 'member': 'original/module.py'}},
        ]
        rows.sort(key=lambda row: row['path'])
        catalog = {'schema_version': 1, 'qualification': module.inputs.QUALIFICATION, 'source_inventory_sha256': source_receipt['sha256'], 'subjects': [{'id': row['id'], 'sha256': row['sha256']}for row in records], 'inputs': rows, 'tools': [], 'unretained_inputs': [], 'inventory_sha256': hashlib.sha256(module.inputs.canonical(rows)).hexdigest()}
        report = {'source_inventory_sha256': source_receipt['sha256'], 'inspection_inputs': catalog, 'required_materials': [{key: source_record[key]for key in ('sha256', 'size_bytes')}]}
        shutil.rmtree(original); shutil.rmtree(plan)
        return {'artifacts': records}, source_receipt, report, program, executable

    def test_replay_cache_is_reconstructed_without_original_paths_and_from_actual_member_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, program, executable = self.fixture(root); target = root / 'new-private-cache'
            result = module.materialize(root, candidate, source, report, target)
            self.assertEqual(result['inputs'], 4); self.assertEqual(result['source_blobs'], 1)
            self.assertEqual((target/'node_modules/original/module.py').read_bytes(), program)
            self.assertEqual((target/'.artifacts/private/bin/tool').read_bytes(), executable)
            self.assertFalse((target/'node_modules/original/module.py').stat().st_mode & 0o222)
            self.assertEqual(bool((target/'.artifacts/private/bin/tool').stat().st_mode & 0o111), os.name != 'nt')
            self.assertFalse((root/'.artifacts/old-cache').exists())

    def test_candidate_archive_root_is_distinct_from_protected_source_and_cache_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, program, executable = self.fixture(root)
            artifact_root = root / 'candidate'; artifact_root.mkdir()
            shutil.move(root / 'release', artifact_root / 'release')
            self.assertFalse((root / candidate['artifacts'][0]['path']).exists())
            target = root / 'private'
            result = module.materialize(root, candidate, source, report, target, candidate_root=artifact_root)
            self.assertEqual(result['inputs'], 4)
            self.assertEqual((target / 'node_modules/original/module.py').read_bytes(), program)
            self.assertEqual((target / '.artifacts/private/bin/tool').read_bytes(), executable)
            self.assertEqual((target / 'LICENSE').read_bytes(), (root / 'LICENSE').read_bytes())

    def test_compact_replay_reads_subjects_and_sources_in_place_and_retains_only_requested_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, program, executable = self.fixture(root)
            artifact_root = root / 'candidate'; artifact_root.mkdir(); shutil.move(root / 'release', artifact_root / 'release')
            target = root / 'compact'
            result = module.materialize(root, candidate, source, report, target, candidate_root=artifact_root, compact=True)
            self.assertEqual(result['inputs'], 4); self.assertEqual(result['source_blobs'], 1)
            self.assertEqual((target/'node_modules/original/module.py').read_bytes(), program)
            self.assertEqual((target/'.artifacts/private/bin/tool').read_bytes(), executable)
            self.assertFalse((target/'LICENSE').exists())
            self.assertFalse((target/'release').exists())
            self.assertFalse(any(root.glob('ud-inspection-source-blobs-*')))

    def test_compact_replay_reads_source_members_without_writing_original_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, program, _ = self.fixture(root)
            original = next(row for row in report['inspection_inputs']['inputs'] if row['retention']['kind'] == 'corresponding-source-blob')
            rows = [row for row in report['inspection_inputs']['inputs'] if row is not original]
            report['inspection_inputs']['inputs'] = rows
            report['inspection_inputs']['inventory_sha256'] = hashlib.sha256(module.inputs.canonical(rows)).hexdigest()
            target = root/'compact-members-only'
            with mock.patch.object(module, 'original_blobs', side_effect=AssertionError('whole blob must not be staged')):
                result = module.materialize(root, candidate, source, report, target, compact=True)
            self.assertEqual(result['source_blobs'], 1)
            self.assertEqual((target/'node_modules/original/module.py').read_bytes(), program)
            self.assertFalse((target/original['path']).exists())
            self.assertFalse(any(root.glob('ud-inspection-source-blobs-*')))

    def test_streamed_source_blob_rejects_missing_or_changed_parts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, _, report, _, _ = self.fixture(root)
            source = report['required_materials'][0]; seen = []
            def consume(identity, stream):
                seen.append(identity); self.assertEqual(stream.read(2), b'\x1f\x8b'); stream.seek(0)
            self.assertEqual(module.stream_original_blobs(root, candidate, {source['sha256']: source['size_bytes']}, consume), {source['sha256']})
            self.assertEqual(seen, [source['sha256']])
            with self.assertRaisesRegex(ValueError, 'missing'):
                module.stream_original_blobs(root, candidate, {'0'*64: 1}, consume)
            part = next(row for row in candidate['artifacts'] if row['id'] == 'corresponding-source-0000')
            part_path = root/part['path']; original = bytearray(part_path.read_bytes()); original[0] ^= 1; part_path.write_bytes(original)
            with self.assertRaises(ValueError):
                module.stream_original_blobs(root, candidate, {source['sha256']: source['size_bytes']}, consume)

    def test_source_manifest_streams_and_seeks_across_shard_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root/'original'; original.mkdir()
            body = bytes(range(256)) * 33
            (original/'source').write_bytes(body); record = receipt(original, 'source')
            collection = original/'receipt.json'
            collection.write_text(json.dumps({'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [record]}))
            bundle = root/'release'; index = module.materials.bundle([('source', collection)], bundle, 1024, [{'sha256': record['sha256'], 'size_bytes': len(body)}])
            records = []
            for number, name in enumerate(['ud-agent-corresponding-source-index.json', *[row['path'] for row in index['parts']]]):
                row = receipt(root, 'release/'+name)
                records.append({'id': 'corresponding-source-index' if number == 0 else index['parts'][number-1]['id'], 'path': row['path'], 'sha256': row['sha256'], 'size': row['size_bytes']})
            (root/'runtime').mkdir()
            (root/'runtime/source-materials.lock.json').write_text(json.dumps({'schema_version': 1, 'index': records[0], 'parts': records[1:]}))
            self.assertGreater(len(index['parts']), 2)
            with module.SourceParts(root, {'artifacts': records}) as source:
                self.assertEqual(source.manifest['files'][0]['sha256'], record['sha256'])
                with source.open_blob(record['sha256'], len(body)) as stream:
                    stream.seek(997); self.assertEqual(stream.read(2300), body[997:3297])
                    stream.seek(-40, io.SEEK_END); self.assertEqual(stream.read(), body[-40:])
                with self.assertRaisesRegex(ValueError, 'missing or differs'):
                    with source.open_blob(record['sha256'], len(body)+1): pass

    def test_source_member_extraction_accepts_seekable_zip_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive_path = root/'source.zip'; body = b'original source bytes'
            with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive: archive.writestr('src/file.txt', body)
            destination = root/'out'; destination.mkdir()
            row = {'path': 'selected/file.txt', 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'executable': False}
            original = receipt(root, 'source.zip')
            with module.SeekableParts(root, [{'path': original['path'], 'sha256': original['sha256'], 'size': original['size_bytes']}], original['sha256'], original['size_bytes']) as parts:
                with module.BlobView(parts, 0, original['size_bytes']) as blob:
                    module.copy_members(None, original, {'src/file.txt': [row]}, destination, source_archive=True, stream=blob)
            self.assertEqual((destination/'selected/file.txt').read_bytes(), body)

    def test_compact_replay_detects_source_changed_during_member_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, _, _ = self.fixture(root); target = root/'compact'
            original = module.copy_members; changed = False
            def mutate(*args, **kwargs):
                nonlocal changed
                if not changed:
                    (root/'LICENSE').write_text('Changed fixture terms\n'); changed = True
                return original(*args, **kwargs)
            with mock.patch.object(module, 'copy_members', side_effect=mutate), self.assertRaisesRegex(ValueError, 'changed during inspection'):
                module.materialize(root, candidate, source, report, target, compact=True)
            self.assertFalse(target.exists())
            self.assertFalse(any(root.glob('ud-inspection-source-blobs-*')))

    def test_compact_replay_rejects_catalog_over_budget_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, _, _ = self.fixture(root); target = root/'compact'
            rows = report['inspection_inputs']['inputs']; rows[0]['size_bytes'] = module.MAX_REPLAY_BYTES
            report['inspection_inputs']['inventory_sha256'] = hashlib.sha256(module.inputs.canonical(rows)).hexdigest()
            with self.assertRaisesRegex(ValueError, '4 GB'): module.materialize(root, candidate, source, report, target, compact=True)
            self.assertFalse(target.exists())

    def test_compact_source_bundle_consumes_one_blob_at_a_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root/'original'; original.mkdir()
            expected = {}
            for name, body in [('one', b'first source'), ('two', b'second source')]:
                (original/name).write_bytes(body); row = receipt(original, name); expected[row['sha256']] = body
            collection = original/'receipt.json'
            collection.write_text(json.dumps({'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [receipt(original, name) for name in ('one', 'two')]}))
            required = [{'sha256': digest, 'size_bytes': len(body)} for digest, body in expected.items()]
            plan = root/'bundle'; index = module.materials.bundle([('original', collection)], plan, 4096, required)
            (root/'runtime').mkdir(); (root/'release').mkdir()
            names = ['ud-agent-corresponding-source-index.json', *[row['path'] for row in index['parts']]]; records = []
            for number, name in enumerate(names):
                shutil.copyfile(plan/name, root/'release'/name); row = receipt(root, 'release/'+name)
                records.append({'id': 'corresponding-source-index' if number == 0 else index['parts'][number-1]['id'], 'path': row['path'], 'sha256': row['sha256'], 'size': row['size_bytes']})
            (root/'runtime/source-materials.lock.json').write_text(json.dumps({'schema_version': 1, 'index': records[0], 'parts': records[1:]}))
            scratch = root/'scratch'; scratch.mkdir(); seen = []
            def consume(digest, blob):
                self.assertEqual(list(scratch.iterdir()), [blob]); self.assertEqual(blob.read_bytes(), expected[digest]); seen.append(digest)
            result = module.original_blobs(root, {'artifacts': records}, {key: len(value) for key, value in expected.items()}, scratch, consume=consume)
            self.assertEqual(set(result), set(expected)); self.assertEqual(set(seen), set(expected)); self.assertEqual(list(scratch.iterdir()), [])
            replaced = {}
            def substitute(digest, blob):
                body = blob.read_bytes(); blob.chmod(0o600)
                retained = root / 'retained-original'; blob.rename(retained)
                blob.write_bytes(body); replaced.update(file=blob, retained=retained, body=body)
            with self.assertRaisesRegex(ValueError, 'identity changed during consumption'):
                module.original_blobs(root, {'artifacts': records}, {key: len(value) for key, value in expected.items()}, scratch, consume=substitute)
            self.assertEqual(replaced['file'].read_bytes(), replaced['body'])
            self.assertEqual(replaced['retained'].read_bytes(), replaced['body'])
            self.assertNotEqual(replaced['file'].stat().st_ino, replaced['retained'].stat().st_ino)

    def test_repeated_original_blob_reuses_verified_source_and_rejects_altered_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, _, _ = self.fixture(root)
            rows = report['inspection_inputs']['inputs']; original = next(row for row in rows if row['retention']['kind'] == 'corresponding-source-blob')
            rows.append({**original, 'path': '.artifacts/input/another.tar.gz'}); rows.sort(key=lambda row: row['path'])
            report['inspection_inputs']['inventory_sha256'] = hashlib.sha256(module.inputs.canonical(rows)).hexdigest()
            target = root/'private'; module.materialize(root, candidate, source, report, target)
            first, second = target/original['path'], target/'.artifacts/input/another.tar.gz'
            self.assertEqual(first.read_bytes(), second.read_bytes())
            if os.name == 'nt':
                self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)
                self.assertEqual((first.stat().st_nlink, second.stat().st_nlink), (1, 1))
                self.assertFalse((first.stat().st_mode | second.stat().st_mode) & 0o222)
            else: self.assertEqual(first.stat().st_ino, second.stat().st_ino)
            blob = root/'wrong-original'; blob.write_bytes(b'wrong'); blob.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'differs'):
                module.put_private_blob(target, {**original, 'path': '.artifacts/input/rejected.tar.gz'}, blob)
            self.assertFalse((target/'.artifacts/input/rejected.tar.gz').exists())

    def test_omitted_or_forged_member_reference_fails_and_removes_owned_partial_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, _, _ = self.fixture(root)
            row = next(row for row in report['inspection_inputs']['inputs'] if row['retention']['kind']=='released-artifact-member'); row['retention']['member']='bin/foreign-tool'
            report['inspection_inputs']['inventory_sha256']=hashlib.sha256(module.inputs.canonical(report['inspection_inputs']['inputs'])).hexdigest()
            target = root/'rejected-cache'
            with self.assertRaisesRegex(ValueError, 'omitted a referenced member'): module.materialize(root,candidate,source,report,target)
            self.assertFalse(target.exists()); self.assertFalse((root/'rejected-cache-original-blobs').exists())

    def test_same_path_archive_and_source_inputs_verify_and_reuse_prepopulated_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);candidate,source,report,program,_=self.fixture(root)
            artifact=candidate['artifacts'][0]
            rows=report['inspection_inputs']['inputs']
            rows.append({'path':artifact['path'],'sha256':artifact['sha256'],'size_bytes':artifact['size'],'executable':False,'retention':{'kind':'released-artifact','artifact':artifact['id']}})
            name='skills/demo/original.py';(root/name).parent.mkdir(parents=True);(root/name).write_bytes(program)
            row=receipt(root,name);source['files'].append({'path':name,'sha256':row['sha256'],'size':row['size_bytes'],'executable':False})
            original=next(row for row in rows if row['retention']['kind']=='corresponding-source-member')
            rows.append({**original,'path':name});rows.sort(key=lambda row:row['path'])
            report['inspection_inputs']['inventory_sha256']=hashlib.sha256(module.inputs.canonical(rows)).hexdigest()
            target=root/'overlap-cache';result=module.materialize(root,candidate,source,report,target)
            self.assertEqual(result['inputs'],6)
            self.assertEqual((target/artifact['path']).read_bytes(),(root/artifact['path']).read_bytes())
            self.assertEqual((target/name).read_bytes(),program)
            # Existing exact output does not excuse a wrong source reference.
            with self.assertRaisesRegex(ValueError,'referenced bytes'):
                module.put(target,{'path':name,**{key:row[key]for key in ('sha256','size_bytes')},'executable':False},io.BytesIO(b'wrong original'))

    def test_corrupt_public_source_sidecar_and_escape_paths_cannot_be_materialized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);candidate,source,report,_,_=self.fixture(root)
            escaped=copy.deepcopy(report);escaped['inspection_inputs']['inputs'][0]['path']='../outside'
            escaped['inspection_inputs']['inventory_sha256']=hashlib.sha256(module.inputs.canonical(escaped['inspection_inputs']['inputs'])).hexdigest()
            with self.assertRaisesRegex(ValueError,'unsafe'):module.materialize(root,candidate,source,escaped,root/'escape-cache')
            part=next(row for row in candidate['artifacts'] if row['id']=='corresponding-source-0000');(root/part['path']).write_bytes(b'corrupted stream')
            with self.assertRaises(ValueError):module.materialize(root,candidate,source,report,root/'corrupt-cache')
            self.assertFalse((root/'outside').exists());self.assertFalse((root/'corrupt-cache').exists())

    def test_storage_plan_counts_output_union_original_once_and_largest_sequential_oci_workspace(self):
        source = {'files': [{'path': 'same', 'size': 3}]}
        subjects = [{'path': 'same', 'size': 3, 'id': 'native'}, {'path': 'image', 'size': 7, 'id': 'core-oci-index'}, {'path': 'render', 'size': 8, 'id': 'render-oci-index'}]
        report = {'inspection_inputs': {'inputs': [{'path': 'same', 'size_bytes': 3, 'sha256': 'a', 'retention': {'kind': 'corresponding-source-blob'}}, {'path': 'member', 'size_bytes': 2, 'retention': {'kind': 'corresponding-source-member', 'blob_sha256': 'a'}}]}, 'required_materials': [{'sha256': 'a', 'size_bytes': 11}], 'subjects': [{'id': 'core-oci-index', 'bindings': [{'size_bytes': 13}]}, {'id': 'render-oci-index', 'bindings': [{'size_bytes': 17}, {'size_bytes': 19}]}]}
        self.assertEqual(module.replay_storage_bytes(source, subjects, report), 128 * 1024 ** 2 + 3 + 7 + 8 + 2 + 11 + 36)
        for mutate in [lambda value: value['subjects'].clear(), lambda value: value['required_materials'].clear(), lambda value: value['inspection_inputs']['inputs'][0].update(size_bytes=True), lambda value: value['inspection_inputs']['inputs'][1].update(size_bytes=32 * 1024 ** 3)]:
            bad = copy.deepcopy(report); mutate(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError): module.replay_storage_bytes(source, subjects, bad)

    def test_compact_plan_counts_transport_normalization_without_copying_all_original_blobs(self):
        source = {'files': [{'path': 'large-source', 'size': 900}]}
        subjects = [{'path': 'image', 'size': 13, 'id': 'core-linux-arm64-docker-archive-0'}, {'path': 'index', 'size': 7, 'id': 'core-oci-index'}]
        rows = [{'path': 'input-a', 'size_bytes': 3, 'sha256': 'a', 'retention': {'kind': 'corresponding-source-blob'}}, {'path': 'input-b', 'size_bytes': 2, 'sha256': 'b', 'retention': {'kind': 'corresponding-source-blob'}}]
        report = {'inspection_inputs': {'inputs': rows}, 'required_materials': [{'sha256': 'a', 'size_bytes': 11}, {'sha256': 'b', 'size_bytes': 17}], 'subjects': [{'id': subjects[0]['id'], 'bindings': [{'size_bytes': 50}]}, {'id': subjects[1]['id'], 'bindings': [{'size_bytes': 13}]}]}
        expected = 128 * 1024 ** 2 + 3 + 2 + 50 + 2 * 13 + 64 * 1024 ** 2
        self.assertEqual(module.replay_storage_bytes(source, subjects, report, compact=True), expected)

    def test_os_family_defers_only_source_blobs_bound_to_its_authenticated_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe = root/'runtime/materials/component-source-replay.json'; recipe.parent.mkdir(parents=True)
            family = {'kind': 'oci-os-packages', 'pack': 'core', 'sources': 'os/receipt.json'}
            recipe.write_text(json.dumps({'schema_version': 1, 'families': [family]}))
            original = {'path': 'blobs/a', 'sha256': 'a'*64, 'size_bytes': 123}
            metadata = {'path': 'release/InRelease', 'sha256': 'b'*64, 'size_bytes': 4}
            collection = {'status': 'passed', 'qualification': 'publisher-authenticated-exact-corresponding-source-closure', 'files': [original, metadata], 'metadata': [metadata]}
            body = json.dumps(collection).encode()
            catalog = {'inputs': [
                {'path': 'os/receipt.json', 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'retention': {'kind': 'retained-json-metadata', 'base64': module.base64.b64encode(body).decode()}},
                {'path': 'os/blobs/a', 'sha256': original['sha256'], 'size_bytes': 123, 'executable': False, 'retention': {'kind': 'corresponding-source-blob'}},
                {'path': 'os/release/InRelease', 'sha256': metadata['sha256'], 'size_bytes': 4, 'executable': False, 'retention': {'kind': 'corresponding-source-blob'}},
            ]}
            subjects = [{'id': 'core-oci-index'}]
            self.assertEqual(module.streamed_os_source_paths(root, subjects, catalog), {'os/blobs/a'})
            recipe.write_text(json.dumps({'schema_version': 1, 'families': [family, {'kind': 'other-family', 'sources': family['sources']}]}))
            self.assertEqual(module.streamed_os_source_paths(root, subjects, catalog), set())
            recipe.write_text(json.dumps({'schema_version': 1, 'families': [family]}))
            catalog['inputs'][0]['sha256'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'receipt differs'): module.streamed_os_source_paths(root, subjects, catalog)

    def test_provider_deferral_uses_only_receipt_bound_sources_and_keeps_other_consumers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe = root/'runtime/materials/component-source-replay.json'; recipe.parent.mkdir(parents=True)
            recipe.write_text(json.dumps({'schema_version': 1, 'families': [{'kind': 'provider-runtime'}]}))
            prefix = '.artifacts/source-materials-data/'
            def source(path, byte): return {'path': path, 'sha256': byte * 64, 'size_bytes': 7}
            ordinary = source('blobs/guest', 'a'); metadata = source('metadata/index', 'b')
            uv = {**source('blobs/uv', 'c'), 'name': 'astral-sh/uv'}
            provider = {**source('blobs/provider', 'd'), 'name': 'lima-vm/lima'}
            go = source('modules/original', 'e'); catalog = source('metadata/go-releases.json', 'f')
            collections = [
                ('ubuntu-sources-historical', {'status':'passed', 'qualification':'publisher-authenticated-exact-corresponding-source-closure', 'files':[ordinary, metadata], 'metadata':[metadata]}),
                ('provider-sources-binary-v2', {'status':'passed', 'qualification':'pinned-source-and-notices', 'files':[uv, provider]}),
                ('lima-host-go', {'status':'passed', 'qualification':'binary-bound-go-module-source-inventory', 'main_sources':[], 'modules':[{'archive':go}], 'standard_libraries':[dict(source('stdlib', '1'), publisher_catalog=catalog)]}),
            ]
            rows = []
            for folder, body in collections:
                encoded = json.dumps(body).encode(); name = prefix + folder + '/receipt.json'
                rows.append({'path':name, 'sha256':hashlib.sha256(encoded).hexdigest(), 'size_bytes':len(encoded), 'retention':{'kind':'retained-json-metadata','base64':module.base64.b64encode(encoded).decode()}})
                for original in ([ordinary, metadata] if folder.startswith('ubuntu-') else [uv, provider] if folder.startswith('provider-') else [go, catalog, body['standard_libraries'][0]]):
                    rows.append({'path':prefix+folder+'/'+original['path'], 'sha256':original['sha256'], 'size_bytes':original['size_bytes'], 'executable':False, 'retention':{'kind':'corresponding-source-blob'}})
            inputs = {'inputs':rows}; subjects = [{'id':'provider-assets-lima-nerdctl-darwin-arm64'}]
            actual = module.streamed_provider_source_paths(root, subjects, inputs)
            self.assertEqual(actual, {prefix+'ubuntu-sources-historical/blobs/guest', prefix+'provider-sources-binary-v2/blobs/provider', prefix+'lima-host-go/modules/original', prefix+'lima-host-go/stdlib'})
            self.assertEqual(module.streamed_provider_source_paths(root, [{'id':'npm'}], inputs), set())
            rows[-1]['sha256'] = '0'*64
            self.assertNotIn(prefix+'lima-host-go/stdlib', module.streamed_provider_source_paths(root, subjects, inputs))

    def test_node_deferral_is_limited_to_exact_locked_inputs_and_counts_family_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); metadata = root/'runtime/materials'; metadata.mkdir(parents=True)
            (metadata/'component-source-replay.json').write_text(json.dumps({'schema_version':1, 'families':[{'kind':'node'}]}))
            prefix = '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/'
            source = {'path':prefix+'source.rpm', 'sha256':'a'*64, 'size_bytes':123}
            key = {'path':prefix+'key', 'sha256':'b'*64, 'size_bytes':8}
            signature = {'path':prefix+'sig', 'sha256':'c'*64, 'size_bytes':9}
            member = {'name':'source.tar', 'sha256':'d'*64, 'size_bytes':99}
            lock = {'schema_version':1, 'qualification':'exact-red-hat-node-linux-rust-source-provenance-input-lock', 'source_rpm':source, 'redhat_key':key, 'upstream_signature':signature, 'source_rpm_members':[member]}
            (metadata/'node-linux-rust.lock.json').write_text(json.dumps(lock))
            originals = [source, key, signature, {**member, 'path':prefix+'extracted/'+member['name']}]
            rows = [{**row, 'executable':False, 'retention':{'kind':'corresponding-source-blob'}} for row in originals]
            catalog = {'inputs':rows}
            self.assertEqual(module.streamed_node_source_paths(root, [{'id':'npm'}], catalog), {row['path'] for row in originals})
            self.assertEqual(module.streamed_node_source_paths(root, [{'id':'native-macos-arm64'}], catalog), set())
            rows[0]['sha256'] = '0'*64
            self.assertNotIn(source['path'], module.streamed_node_source_paths(root, [{'id':'npm'}], catalog))
            report = {'inspection_inputs':catalog, 'required_materials':[], 'subjects':[]}
            for row in rows: row['retention'] = {'kind':'retained-json-metadata'}
            omitted = {row['path'] for row in rows}
            self.assertEqual(module.replay_storage_bytes({'files':[]}, [], report, compact=True, streamed_paths=omitted), 128*1024**2 + sum(row['size_bytes'] for row in rows))

    def test_perl_family_cleanup_preserves_verified_inputs_for_final_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, _, report, program, _ = self.fixture(root)
            assets = root/'family-inputs'; assets.mkdir()
            artifact = candidate['artifacts'][0]; source = next(row for row in report['required_materials'])
            payload = b'MZ' + bytes(64); pack = '.artifacts/native-perl/darwin-arm64'
            rows = [
                {'path':pack+'/bin/perl', 'sha256':hashlib.sha256(payload).hexdigest(), 'size_bytes':len(payload), 'executable':True, 'retention':{'kind':'released-artifact-member', 'artifact':artifact['id'], 'member':'bin/real-tool'}},
                {'path':pack+'/lib/original.tar.gz', 'sha256':source['sha256'], 'size_bytes':source['size_bytes'], 'executable':False, 'retention':{'kind':'corresponding-source-blob', 'member':'blobs/'+source['sha256']}},
            ]
            discovery = {'subjects':[{'id':artifact['id'], 'sha256':artifact['sha256'], 'size_bytes':artifact['size'], 'members':[{'path':'bin/real-tool', 'sha256':rows[0]['sha256'], 'size_bytes':len(payload)}]}]}
            source_receipt = {'sha256':'a'*64, 'files':[]}
            with module.SourceParts(root, candidate) as parts, module.inputs.Recorder(root, assets) as recorder:
                with module.staged_perl_family(root, candidate, root, assets, pack, rows, parts, [source], recorder):
                    self.assertEqual((assets/rows[0]['path']).read_bytes(), payload)
                    self.assertTrue((assets/rows[1]['path']).read_bytes())
                self.assertFalse((assets/pack).exists())
                catalog = recorder.finish(source_receipt, discovery, [source])
                self.assertEqual({row['path'] for row in catalog['inputs']}, {row['path'] for row in rows})
                self.assertTrue(module.inputs.verify(catalog, assets, source_receipt['sha256'], catalog['subjects'], required_materials=[source], discovered_subjects=discovery['subjects'], observations=recorder.observations)['verified'])
                with self.assertRaises(FileNotFoundError):
                    module.inputs.verify(catalog, assets, source_receipt['sha256'], catalog['subjects'], required_materials=[source], discovered_subjects=discovery['subjects'])
            self.assertFalse((assets/pack).exists())
            # A changed artifact never leaves a partial family behind.
            (root/artifact['path']).write_bytes(b'altered')
            with module.SourceParts(root, candidate) as parts, module.inputs.Recorder(root, assets) as recorder:
                with self.assertRaises(ValueError):
                    with module.staged_perl_family(root, candidate, root, assets, pack, rows, parts, [source], recorder): pass
            self.assertFalse((assets/pack).exists())

    def test_perl_family_deferral_requires_a_complete_nonshared_supported_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); metadata = root/'runtime/materials'; metadata.mkdir(parents=True)
            pack = '.artifacts/native-perl/darwin-arm64'; recipe = metadata/'component-source-replay.json'
            family = {'kind':'private-perl', 'platform':'darwin/arm64', 'pack':pack}
            recipe.write_text(json.dumps({'schema_version':1, 'families':[family]}))
            row = {'path':pack+'/bin/perl', 'size_bytes':4, 'retention':{'kind':'released-artifact-member', 'artifact':'native-macos-arm64', 'member':'bin/perl'}}
            catalog = {'inputs':[row]}; subjects = [{'id':'native-macos-arm64'}]
            self.assertEqual(module.deferred_perl_families(root, subjects, catalog), {pack:[row]})
            self.assertEqual(module.deferred_perl_families(root, [], catalog), {})
            catalog['inputs'].append({'path':pack+'/other', 'size_bytes':3, 'retention':{'kind':'unretained-local-input'}})
            self.assertEqual(module.deferred_perl_families(root, subjects, catalog), {})
            catalog['inputs'].pop()
            recipe.write_text(json.dumps({'schema_version':1, 'families':[family, {'kind':'private-perl', 'platform':'linux/arm64', 'pack':pack}]}))
            self.assertEqual(module.deferred_perl_families(root, subjects, catalog), {})
            recipe.write_text(json.dumps({'schema_version':1, 'families':[dict(family, runtime_only={'input_pack':'other', 'input_receipt':'other.json'})]}))
            self.assertEqual(module.deferred_perl_families(root, subjects, catalog), {})

    def test_windows_perl_runtime_only_pack_reconciles_supplier_members_after_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, _, report, program, _ = self.fixture(root)
            assets = root/'family-inputs'; assets.mkdir(); artifact = candidate['artifacts'][0]; source = report['required_materials'][0]
            output_pack = '.artifacts/native-perl/win32-runtime'; input_pack = '.artifacts/native-perl/win32-supplier'
            payload = b'MZ' + bytes(64); body_hash = hashlib.sha256(payload).hexdigest()
            artifact_ref = {'kind':'released-artifact-member', 'artifact':artifact['id'], 'member':'bin/real-tool'}
            rows = [
                {'path':output_pack+'/bin/perl.exe', 'sha256':body_hash, 'size_bytes':len(payload), 'executable':True, 'retention':artifact_ref},
                {'path':input_pack+'/bin/perl.exe', 'sha256':body_hash, 'size_bytes':len(payload), 'executable':True, 'retention':artifact_ref},
                {'path':input_pack+'/lib/supplier.py', 'sha256':hashlib.sha256(program).hexdigest(), 'size_bytes':len(program), 'executable':False, 'retention':{'kind':'corresponding-source-member', 'blob_sha256':source['sha256'], 'member':'original/module.py'}},
            ]
            discovery = {'subjects':[{'id':artifact['id'], 'sha256':artifact['sha256'], 'size_bytes':artifact['size'], 'members':[{'path':'bin/real-tool', 'sha256':body_hash, 'size_bytes':len(payload)}]}]}
            source_receipt = {'sha256':'a'*64, 'files':[]}
            with module.SourceParts(root, candidate) as parts, module.inputs.Recorder(root, assets) as recorder:
                with module.staged_perl_family(root, candidate, root, assets, output_pack, rows, parts, [source], recorder, input_pack=input_pack):
                    for row in rows: self.assertEqual(hashlib.sha256((assets/row['path']).read_bytes()).hexdigest(), row['sha256'])
                self.assertFalse((assets/output_pack).exists()); self.assertFalse((assets/input_pack).exists())
                # The supplier archive was independently checked before this join.
                recorder.source_member(assets/rows[2]['path'], source['sha256'], 'original/module.py')
                catalog = recorder.finish(source_receipt, discovery, [source])
                self.assertEqual(next(row for row in catalog['inputs'] if row['path'] == rows[2]['path'])['retention'], rows[2]['retention'])
                self.assertTrue(module.inputs.verify(catalog, assets, source_receipt['sha256'], catalog['subjects'], required_materials=[source], discovered_subjects=discovery['subjects'], observations=recorder.observations)['verified'])
            bad = [dict(row) for row in rows]; bad[2] = {**bad[2], 'sha256':'0'*64}
            with module.SourceParts(root, candidate) as parts, module.inputs.Recorder(root, assets) as recorder:
                with self.assertRaises(ValueError):
                    with module.staged_perl_family(root, candidate, root, assets, output_pack, bad, parts, [source], recorder, input_pack=input_pack): pass
            self.assertFalse((assets/output_pack).exists()); self.assertFalse((assets/input_pack).exists())

    def test_compact_perl_reconstructs_recipe_pack_from_receipt_and_candidate_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, _, report, _, _ = self.fixture(root)
            artifact = candidate['artifacts'][0]; archive_path = root/artifact['path']; body = b'actual selected Perl executable'
            archive_name = 'runtime/pack/native/darwin-arm64/perl/bin/perl'
            with tarfile.open(archive_path, 'w:gz') as output:
                entry = tarfile.TarInfo(archive_name); entry.size = len(body); entry.mode = 0o755; output.addfile(entry, io.BytesIO(body))
            content = archive_path.read_bytes(); artifact.update(sha256=hashlib.sha256(content).hexdigest(), size=len(content))
            metadata_dir = root/'runtime/materials'; metadata_dir.mkdir()
            pack = '.artifacts/native-perl/darwin-arm64'; receipt_path = pack+'-receipt.json'
            family = {'kind':'private-perl', 'platform':'darwin/arm64', 'pack':pack, 'receipt':receipt_path}
            (metadata_dir/'component-source-replay.json').write_text(json.dumps({'schema_version':1, 'families':[family]}))
            packed = json.dumps({'files':[{'path':'bin/perl', 'sha256':'sha256:'+hashlib.sha256(body).hexdigest(), 'size':len(body)}]}).encode()
            metadata = {'path':receipt_path, 'sha256':hashlib.sha256(packed).hexdigest(), 'size_bytes':len(packed), 'retention':{'kind':'retained-json-metadata', 'base64':module.base64.b64encode(packed).decode()}}
            compact = {'metadata':[metadata]}; families = module.compact_perl_families(root, candidate['artifacts'], compact, report['required_materials'])
            self.assertEqual(families[pack][0]['retention'], {'kind':'released-artifact-member', 'artifact':artifact['id'], 'member':archive_name})
            assets = root/'private-family'; assets.mkdir()
            with module.SourceParts(root, candidate) as parts, module.inputs.Recorder(root, assets) as recorder:
                with module.staged_perl_family(root, candidate, root, assets, pack, families[pack], parts, report['required_materials'], recorder):
                    executable = assets/pack/'bin/perl'; self.assertEqual(executable.read_bytes(), body); self.assertEqual(bool(executable.stat().st_mode & 0o111), os.name != 'nt')
                self.assertFalse((assets/pack).exists())
                self.assertTrue(families[pack][0]['executable'])
                self.assertTrue(recorder.observed_receipt(executable)['executable'])
            altered = copy.deepcopy(compact); altered['metadata'][0]['sha256'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'metadata differs'): module.compact_perl_families(root, candidate['artifacts'], altered, report['required_materials'])

    def test_compact_windows_perl_uses_supplier_only_for_filtered_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); metadata_dir = root/'runtime/materials'; metadata_dir.mkdir(parents=True)
            pack = '.artifacts/native-perl/win-runtime'; original = '.artifacts/native-perl/win-original'
            family = {'kind':'private-perl', 'platform':'win32/arm64', 'pack':pack, 'receipt':'out.json', 'runtime_only':{'input_pack':original, 'input_receipt':'in.json'}}
            (metadata_dir/'component-source-replay.json').write_text(json.dumps({'schema_version':1, 'families':[family]}))
            supplier = 'a'*64; (root/'runtime/windows-perl-distributions.lock.json').write_text(json.dumps({'platforms':{'arm64':{'perl':{'sha256':'sha256:'+supplier, 'size_bytes':20}}}}))
            kept = {'path':'bin/perl.exe', 'sha256':'sha256:'+'b'*64, 'size':4}; removed = {'path':'lib/perl.pdb', 'sha256':'sha256:'+'c'*64, 'size':3}
            def metadata(name, files):
                body = json.dumps({'files':files}).encode()
                return {'path':name, 'sha256':hashlib.sha256(body).hexdigest(), 'size_bytes':len(body), 'retention':{'kind':'retained-json-metadata', 'base64':module.base64.b64encode(body).decode()}}
            compact = {'metadata':[metadata('out.json', [kept]), metadata('in.json', [kept, removed])]}
            families = module.compact_perl_families(root, [{'id':'native-windows-arm64'}], compact, [{'sha256':supplier, 'size_bytes':20}])
            rows = {row['path']:row for row in families[pack]}
            self.assertEqual(rows[original+'/lib/perl.pdb']['retention'], {'kind':'corresponding-source-member', 'blob_sha256':supplier, 'member':'Library/lib/perl.pdb'})
            self.assertEqual(rows[original+'/bin/perl.exe']['retention']['artifact'], 'native-windows-arm64')
            with self.assertRaisesRegex(ValueError, 'supplier source is missing'):
                module.compact_perl_families(root, [{'id':'native-windows-arm64'}], compact, [])

    def test_missing_plan_or_insufficient_space_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate, source, report, _, _ = self.fixture(root); target = root/'never-created'
            planned = module.replay_storage_bytes(source, candidate['artifacts'], report)
            for free in [module.FREE_RESERVE_BYTES + planned - 1, module.FREE_RESERVE_BYTES - 1]:
                with mock.patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)), self.assertRaisesRegex(ValueError, 'free reserve'):
                    module.materialize(root, candidate, source, report, target)
                self.assertFalse(target.exists())
            with mock.patch.object(module, 'owned_storage_bytes', return_value=module.MAX_OWNED_BYTES), self.assertRaisesRegex(ValueError, '40 GB'):
                module.materialize(root, candidate, source, report, target)
            self.assertFalse(target.exists())

    def test_each_put_checks_expected_size_and_both_filesystems_before_creating_parents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); destination = root/'new'; row = {'path': 'nested/out', 'sha256': hashlib.sha256(b'abc').hexdigest(), 'size_bytes': 3}
            for spaces in [(module.FREE_RESERVE_BYTES + 2, module.FREE_RESERVE_BYTES + 100), (module.FREE_RESERVE_BYTES + 100, module.FREE_RESERVE_BYTES + 2)]:
                with mock.patch.object(module.shutil, 'disk_usage', side_effect=[SimpleNamespace(free=n) for n in spaces]), self.assertRaisesRegex(ValueError, 'free reserve'):
                    module.put(destination, row, io.BytesIO(b'abc'))
                self.assertFalse(destination.exists())
            with self.assertRaisesRegex(ValueError, 'size is invalid'): module.put(destination, {**row, 'size_bytes': True}, io.BytesIO(b'abc'))
            self.assertFalse(destination.exists())

    def test_forged_lease_does_not_fall_back_and_nested_stage_uses_outer_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); stage = root/'.artifacts/first/.artifacts/second'; stage.mkdir(parents=True)
            self.assertEqual(module.storage_owner(stage), root)
            with mock.patch.dict(os.environ, {'UD_STORAGE_LEASE': 'forged'}), mock.patch.object(module, 'owned_storage_bytes') as measure:
                with self.assertRaisesRegex(ValueError, 'inherited storage lease'): module.admit_storage(stage, root/'output', 1024)
                measure.assert_not_called()

    def test_inherited_lease_accepts_both_exact_owned_scratch_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); lock = root / '.artifacts/.storage-reservation'; lock.mkdir(parents=True)
            identifier = '08a52077-0bc2-4b2d-9ad6-bac853320d78'
            compact = module.base64.urlsafe_b64encode(bytes.fromhex(identifier.replace('-', ''))).rstrip(b'=').decode()
            for name in ('ud-storage-' + identifier, 'ud-' + compact):
                with self.subTest(name=name):
                    directory = root / name; directory.mkdir()
                    record = {'schema_version': 1, 'id': identifier, 'root': str(root), 'lock': str(lock), 'parent': str(root), 'directory': str(directory), 'pid': os.getpid(), 'plannedBytes': 4096}
                    bodies = [(lock / 'reservation.json', record), (directory / '.ud-storage-owner.json', {'id': identifier, 'lock': str(lock)})]
                    for file, value in bodies:
                        if os.name == 'nt':
                            file.unlink(missing_ok=True)
                            authority = module.module('ud_test_replay_windows_storage', '../quality/windows-storage-acl.py').WindowsStorage()
                            authority.create(str(file), 'file', json.dumps(value).encode())
                        else:
                            file.write_text(json.dumps(value)); file.chmod(0o600)
                    token = module.base64.urlsafe_b64encode(json.dumps(record).encode()).rstrip(b'=').decode()
                    with mock.patch.dict(os.environ, {'UD_STORAGE_LEASE': token}): self.assertEqual(module.admit_storage(root, root / 'output', 1024), root)
                    shutil.rmtree(directory)

    def test_standalone_command_uses_shared_reservation_and_keeps_existing_output_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); candidate, source, report, program, _ = self.fixture(root); target = root/'standalone-output'
            command = [sys.executable, '-B', str(ROOT/'scripts/release/materialize-replay-inputs.py'), '--root', str(root), '--output', str(target)]
            for name, value in [('candidate', candidate), ('source', source), ('report', report)]:
                file = root/(name+'.json'); file.write_text(json.dumps(value)); command.extend(['--'+name, str(file)])
            self.assertIsNotNone(shutil.which('node'), 'Node is part of the coordinator test prerequisites')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=dict(os.environ))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['verified']); self.assertEqual((target/'node_modules/original/module.py').read_bytes(), program)
            self.assertFalse((root/'.artifacts/.storage-reservation').exists())


if __name__=='__main__':unittest.main()
