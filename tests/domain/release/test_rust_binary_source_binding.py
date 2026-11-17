import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('rust_binary_binding', ROOT / 'scripts/release/bind-rust-binary-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class RustBinarySourceTests(unittest.TestCase):
    def test_retained_cross_inputs_bind_the_closed_original_subjects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'files').mkdir(); body = b'original binary'; fingerprint = hashlib.sha256(body).hexdigest(); (root / 'files' / fingerprint).write_bytes(body)
            cross = {'source_sha256': 'a' * 64, 'platforms': {'darwin-arm64': {name: {'path': 'old-target/' + name, 'sha256': fingerprint} for name in ('ud-agent', 'ud-agent-guard')}}}
            recipe = root / 'cross.json'; recipe.write_text(json.dumps(cross)); data = {'schema_version': 1, 'qualification': 'retained-original-cross-build-recipe-and-binary-inputs', 'source_sha256': 'a' * 64, 'cross_build_receipt': {'path': recipe.name, 'sha256': binding.sha(recipe), 'size_bytes': recipe.stat().st_size}, 'binaries': [{'platform': 'darwin-arm64', 'name': name, 'original_path': 'old-target/' + name, 'path': 'files/' + fingerprint, 'sha256': fingerprint, 'size_bytes': len(body), 'executable': True} for name in ('ud-agent', 'ud-agent-guard')]}
            manifest = root / 'INPUTS.json'; manifest.write_text(json.dumps(data)); actual, locate, source_hash = binding.cross_inputs(root, manifest)
            self.assertEqual(actual, cross); self.assertEqual(locate('darwin-arm64', 'ud-agent', {}), root / 'files' / fingerprint); self.assertEqual(source_hash, binding.sha(recipe))
            for mutate in (lambda value: value['binaries'].pop(), lambda value: value['binaries'].append(value['binaries'][0]), lambda value: value['binaries'][0].update(original_path='new-target/ud-agent')):
                changed = json.loads(json.dumps(data)); mutate(changed); manifest.write_text(json.dumps(changed))
                with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'inventory|original recipe'): binding.cross_inputs(root, manifest)
            manifest.write_text(json.dumps(data)); (root / 'files' / fingerprint).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'size or kind|hash or identity'): binding.cross_inputs(root, manifest)

    def test_binary_source_commit_is_observed_from_actual_bytes(self):
        commit = 'b940084d7eb6a299eb4bfeb8e34901bc051e7ac4'; other = '58cf8f9c35b355199727627d07ae34a4e2846d67'
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'binary'; header = b'\xcf\xfa\xed\xfe' + struct.pack('<I', 0x100000C) + bytes(24); body = header + ('/rustc/' + commit + '/library/std/src/panicking.rs').encode(); file.write_bytes(body)
            result = binding.binary(file, 'darwin/arm64', {commit: {'sha256': 'a' * 64}})
            self.assertEqual(result['rust_commit'], commit); self.assertEqual(result['sha256'], binding.sha(file)); self.assertFalse(result['proprietary_static_runtime_declaration_required'])
            for value in [header, body + ('/rustc/' + other + '/library/core/src/lib.rs').encode()]:
                file.write_bytes(value)
                with self.assertRaisesRegex(ValueError, 'unique exact signed'): binding.binary(file, 'darwin/arm64', {commit: {}})
            file.write_bytes(body)
            with self.assertRaisesRegex(ValueError, 'architecture'): binding.binary(file, 'darwin/x64', {commit: {}})

    def test_windows_binary_never_infers_crt_grant_from_absent_imports(self):
        commit = 'b940084d7eb6a299eb4bfeb8e34901bc051e7ac4'
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'binary'; body = bytearray(128); body[:2] = b'MZ'; struct.pack_into('<I', body, 60, 64); body[64:68] = b'PE\0\0'; struct.pack_into('<H', body, 68, 0xAA64); body.extend(('/rustc/' + commit + '/library/std/src/lib.rs').encode()); file.write_bytes(body)
            self.assertTrue(binding.binary(file, 'win32/arm64', {commit: {}})['proprietary_static_runtime_declaration_required'])

    def test_passed_boolean_or_truncated_metadata_cannot_authorize_rust_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for rows in ([], [{'name': 'rust-src', 'version': '1.99.1'}] * 2):
                (root / 'receipt.json').write_text(json.dumps({'schema_version': 1, 'qualification': 'exact-locked-source-subinventory', 'status': 'passed', 'authenticated': True, 'files': rows}))
                with self.assertRaisesRegex(ValueError, 'duplicated or incomplete'): binding.rust_collector.verify_collection(root)


if __name__ == '__main__': unittest.main()
