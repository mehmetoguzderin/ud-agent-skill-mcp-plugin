import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from contextlib import contextmanager


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('node_linux_rust_sources', ROOT / 'scripts/release/bind-node-linux-rust-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


def entry(name, data, mode=stat.S_IFREG | 0o644):
    name = name.encode() + b'\0'
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b'070701' + b''.join(f'{value:08x}'.encode() for value in fields)
    return header + name + bytes((-(len(header) + len(name))) % 4) + data + bytes((-len(data)) % 4)


class SignedNodeRustSourceTests(unittest.TestCase):
    def test_closed_cpio_members_preserve_exact_bytes_and_reject_tampering(self):
        source = b'original upstream\x00source\n'; patch_bytes = b'original distributor patch\n'
        records = [{'name': 'rust-src.tar.xz', 'size_bytes': len(source), 'sha256': hashlib.sha256(source).hexdigest()}, {'name': 'fix.patch', 'size_bytes': len(patch_bytes), 'sha256': hashlib.sha256(patch_bytes).hexdigest()}]
        trailer = entry('TRAILER!!!', b'')
        good = entry('./rust-src.tar.xz', source) + entry('./fix.patch', patch_bytes) + trailer
        self.assertEqual(binding.verify_cpio(io.BytesIO(good), records), {'rust-src.tar.xz', 'fix.patch'})
        for invalid in [
            good[:-25],
            entry('./rust-src.tar.xz', source[:-1] + b'x') + entry('./fix.patch', patch_bytes) + trailer,
            entry('./rust-src.tar.xz', source) + trailer,
            entry('./rust-src.tar.xz', source) + entry('./fix.patch', patch_bytes) + entry('./extra', b'') + trailer,
            entry('./rust-src.tar.xz', source) + entry('./fix.patch', patch_bytes) + entry('./fix.patch', patch_bytes) + trailer,
            entry('./rust-src.tar.xz', source, stat.S_IFLNK | 0o777) + entry('./fix.patch', patch_bytes) + trailer,
            entry('./../rust-src.tar.xz', source) + entry('./fix.patch', patch_bytes) + trailer,
        ]:
            with self.subTest(prefix=invalid[:20], size=len(invalid)), self.assertRaises(ValueError):
                binding.verify_cpio(io.BytesIO(invalid), records)

    def test_multi_call_tool_preserves_selected_symlink_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'rpm2archive'; target.write_text('not executed')
            selected = Path(temporary) / 'rpm2cpio'; selected.symlink_to(target)
            with patch.object(binding.shutil, 'which', return_value=str(selected)):
                self.assertEqual(binding.required_tool('rpm2cpio'), selected)
                self.assertEqual(binding.required_tool('rpm2cpio').name, 'rpm2cpio')

    def test_original_collection_retains_deduplicated_exact_bytes_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifacts = root / '.artifacts'; artifacts.mkdir()
            rows = []
            for name, contents in [('source', b'original source'), ('notice', b'original notice'), ('signature', b'signed data')]:
                path = artifacts / name; path.write_bytes(contents)
                rows.append({'path': '.artifacts/' + name, 'sha256': hashlib.sha256(contents).hexdigest(), 'size_bytes': len(contents)})
            def subject(platform):
                return {'platform': platform, 'sources': [rows[0]], 'notices': [rows[1]], 'verification_materials': [rows[2]]}
            result = {'qualification': 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction', 'target_execution': False, 'pending_declarations': [], 'bindings': [subject('linux/arm64'), subject('linux/x64')], 'generator_sha256': 'a' * 64, 'input_lock_sha256': 'b' * 64, 'limitations': ['not binary reproduction']}
            output = artifacts / 'collection'
            receipt = binding.write_collection(root, result, output)
            self.assertEqual(receipt['qualification'], 'pinned-source-and-notices')
            self.assertEqual(len(receipt['files']), 3)
            self.assertEqual(len(receipt['original_inputs']), 6)
            self.assertEqual(json.loads((output / 'receipt.json').read_text()), receipt)
            for record in receipt['files']:
                data = (output / record['path']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), record['sha256'])
                self.assertEqual(len(data), record['size_bytes'])
            (artifacts / 'signature').write_bytes(b'corrupted')
            with self.assertRaises(ValueError):
                binding.write_collection(root, result, artifacts / 'bad-collection')
            self.assertFalse((artifacts / 'bad-collection').exists())
            with self.assertRaises(ValueError):
                binding.write_collection(root, result, output)
            self.assertEqual(json.loads((output / 'receipt.json').read_text()), receipt)

    def test_collection_rejects_missing_families_and_unsafe_source_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / '.artifacts').mkdir()
            outside = root / 'outside'; outside.write_bytes(b'outside')
            (root / '.artifacts/link').symlink_to(outside)
            row = {'path': '.artifacts/link', 'sha256': hashlib.sha256(b'outside').hexdigest(), 'size_bytes': 7}
            subject = {'platform': 'linux/arm64', 'sources': [row], 'notices': [row], 'verification_materials': [row]}
            other = {**subject, 'platform': 'linux/x64'}
            result = {'qualification': 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction', 'target_execution': False, 'pending_declarations': [], 'bindings': [subject, other], 'generator_sha256': 'a' * 64, 'input_lock_sha256': 'b' * 64, 'limitations': []}
            with self.assertRaises((ValueError, OSError)):
                binding.write_collection(root, result, root / '.artifacts/bad')
            self.assertFalse((root / '.artifacts/bad').exists())
            subject['sources'] = []
            with self.assertRaises(ValueError):
                binding.write_collection(root, result, root / '.artifacts/missing')
            self.assertFalse((root / '.artifacts/missing').exists())

    def test_private_stage_keeps_verified_bytes_when_original_is_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; private = root / 'private'
            original.mkdir(); private.mkdir(); (original / 'source').write_bytes(b'verified')
            record = {'path': 'source', 'sha256': hashlib.sha256(b'verified').hexdigest(), 'size_bytes': 8}
            staged = binding.VerifiedStage(original, private); staged.add(record)
            (original / 'source').write_bytes(b'replaced')
            self.assertEqual((private / 'source').read_bytes(), b'verified')
            mode = (private / 'source').stat().st_mode
            if os.name == 'nt':
                self.assertTrue(mode & stat.S_IRUSR); self.assertFalse(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            else: self.assertEqual(mode & 0o777, 0o400)
            staged.add(record)
            with self.assertRaises(ValueError):
                staged.add({**record, 'sha256': 'a' * 64})
            with self.assertRaises(ValueError):
                binding.VerifiedStage(original, root / 'other').add(record)

    def test_private_stage_enforces_aggregate_size_and_does_not_count_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; private = root / 'private'
            original.mkdir(); private.mkdir()
            records = []
            for name, value in [('first', b'1234'), ('second', b'5678')]:
                (original / name).write_bytes(value)
                records.append({'path': name, 'sha256': hashlib.sha256(value).hexdigest(), 'size_bytes': len(value)})
            staged = binding.VerifiedStage(original, private, maximum_bytes=7)
            staged.add(records[0]); staged.add(records[0])
            with self.assertRaisesRegex(ValueError, 'total size bound'):
                staged.add(records[1])
            self.assertEqual(staged.total_bytes, 4)
            self.assertFalse((private / 'second').exists())

    def test_private_stage_streams_exact_parts_and_preserves_the_observation(self):
        body = b'original signed source'; fingerprint = hashlib.sha256(body).hexdigest()
        class Parts:
            def __init__(self, value): self.value = value
            @contextmanager
            def open_blob(self, sha, size):
                if sha != fingerprint or size != len(body) or hashlib.sha256(self.value).hexdigest() != sha: raise ValueError('missing or altered source part')
                with io.BytesIO(self.value) as stream: yield stream
        class Recorder:
            def __init__(self): self.rows = []
            def source_blob(self, *row): self.rows.append(row)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; private = root / 'private'; original.mkdir(); private.mkdir()
            record = {'path':'source/archive', 'sha256':fingerprint, 'size_bytes':len(body)}; recorder = Recorder()
            staged = binding.VerifiedStage(original, private, source_parts=Parts(body), recorder=recorder); staged.add(record)
            self.assertEqual((private / record['path']).read_bytes(), body)
            self.assertFalse((original / record['path']).exists())
            self.assertEqual(recorder.rows, [(original / record['path'], fingerprint, len(body))])
            with self.assertRaisesRegex(ValueError, 'missing or altered'):
                binding.VerifiedStage(original, root / 'bad', source_parts=Parts(b'wrong')).add(record)
            (original / 'source').mkdir(); (original / record['path']).write_bytes(b'wrong')
            with self.assertRaises(ValueError): binding.VerifiedStage(original, root / 'other', source_parts=Parts(body)).add(record)

    def test_node_staging_needs_only_its_exact_rust_version_and_reachable_crates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); private = root / 'private'; private.mkdir()
            (root / 'runtime/materials').mkdir(parents=True)
            def material(name, data=b'original'):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
                return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}
            source = material('inputs/source')
            lock = {name: source for name in ('source_rpm', 'redhat_key', 'rust_key', 'upstream_signature')}
            lock.update(rust_version='1.88.0', source_rpm_members=[])
            (root / 'runtime/materials/node-linux-rust.lock.json').write_text(json.dumps(lock))
            manifest = material('.artifacts/node/SHASUMS256.txt.asc')
            key = material('.artifacts/node/nodejs-release-keys.kbx')
            node = {'signed_manifest_sha256': manifest['sha256'], 'release_keyring_sha256': key['sha256'], 'platforms': {}}
            for arch in ('arm64', 'x64'):
                archive = material('.artifacts/node/' + arch + '.tar.xz')
                node['platforms']['linux-' + arch] = {'filename': arch + '.tar.xz', 'sha256': archive['sha256']}
            (root / 'runtime/node-distributions.lock.json').write_text(json.dumps(node))
            prefix = '.artifacts/source-materials-data/rust-runtime-sources-node-v4/'
            selected = material(prefix + 'selected')
            crate = material(prefix + 'crate')
            rows = [
                {**selected, 'path': 'selected', 'family': 'rust-runtime-source', 'version': '1.88.0'},
                {**crate, 'path': 'crate', 'family': 'rust-stdlib-crate', 'version': '0.1', 'supported_target_consumers': ['1.88.0']},
                {'path': 'absent-other-version', 'family': 'rust-runtime-source', 'version': '1.99.1'},
                {'path': 'absent-dev-crate', 'family': 'rust-stdlib-crate', 'supported_target_consumers': ['1.99.1']},
            ]
            (root / prefix / 'receipt.json').write_text(json.dumps({'files': rows}))
            staged = binding.stage_inputs(root, root, private)
            self.assertEqual((private / prefix / 'selected').read_bytes(), b'original')
            self.assertEqual((private / prefix / 'crate').read_bytes(), b'original')
            self.assertNotIn(prefix + 'absent-other-version', staged.records)
            (root / prefix / 'crate').unlink()
            with self.assertRaises((ValueError, OSError)):
                binding.stage_inputs(root, root, root / 'missing-selected')


if __name__ == '__main__': unittest.main()
