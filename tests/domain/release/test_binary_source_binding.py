import base64
import copy
import hashlib
import importlib.util
import json
import io
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('binary_source_binding', ROOT / 'scripts/release/bind-binary-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)
spec = importlib.util.spec_from_file_location('private_elf_source', ROOT / 'scripts/release/collect-private-perl-libs.py')
private = importlib.util.module_from_spec(spec); spec.loader.exec_module(private)


class BinarySourceBindingTests(unittest.TestCase):
    def test_real_pinned_glibc_package_identity_uses_exact_source_and_file_list(self):
        # This is the actual pinned provider's package/source identity, with
        # independently small file bytes for parser and corruption boundaries.
        status = b'Package: libc6\nStatus: install ok installed\nArchitecture: arm64\nVersion: 2.39-0ubuntu8.8\nSource: glibc\nDescription: Fixture for the actual selected package identity\n\n'
        digest = hashlib.sha256(b'ELF fixture').hexdigest()
        original = [{'library': 'libc.so.6', 'sha256': digest, 'resolved_image_path': '/usr/lib/aarch64-linux-gnu/libc.so.6', 'aliases': ['/usr/lib/aarch64-linux-gnu/libc.so.6', '/lib/aarch64-linux-gnu/libc.so.6'], 'package': 'libc6', 'package_list_path': '/var/lib/dpkg/info/libc6:arm64.list', 'package_list_base64': base64.b64encode(b'/lib/aarch64-linux-gnu/libc.so.6\n').decode()}]
        notice = {'libc6': {'resolved_path': '/usr/share/doc/libc6/copyright', 'bytes_base64': base64.b64encode(b'Original publisher notice\n').decode()}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); packages = private.derive(status, copy.deepcopy(original), notice, {'libc.so.6': digest}, root)
            self.assertEqual(packages[0]['source'], {'name': 'glibc', 'version': '2.39-0ubuntu8.8'})
            for mode in ('wrong-file-list', 'wrong-hash', 'missing-library', 'escaping-alias'):
                rows = copy.deepcopy(original)
                if mode == 'wrong-file-list': rows[0]['package_list_base64'] = base64.b64encode(b'/not-the-library\n').decode()
                elif mode == 'wrong-hash': rows[0]['sha256'] = '0' * 64
                elif mode == 'missing-library': rows = []
                else: rows[0]['aliases'].append('/tmp/ambient/libc.so.6')
                with self.subTest(mode=mode), self.assertRaises(ValueError): private.derive(status, rows, notice, {'libc.so.6': digest}, root)

    def test_derived_binding_refuses_omission_stale_subject_and_changed_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); notice = b'Original libc notice\n'; source = b'Exact source archive fixture\n'
            status = b'Package: libc6\nStatus: install ok installed\nArchitecture: arm64\nVersion: 2.39-0ubuntu8.8\nSource: glibc\n\n'
            (root / 'notice').write_bytes(notice); (root / 'source').write_bytes(source); (root / 'status').write_bytes(status)
            def record(name, body): return {'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            inventory = {'schema_version': 1, 'status': 'passed', 'qualification': 'image-bound-publisher-package-and-notice-inventory', 'image': {'sha256': 'sha256:' + 'a' * 64}, 'status_file': record('status', status), 'packages': [{'name': 'libc6', 'version': '2.39-0ubuntu8.8', 'architecture': 'arm64', 'source': {'name': 'glibc', 'version': '2.39-0ubuntu8.8'}, 'built_using': [], 'notice': record('notice', notice)}]}
            file = root / 'inventory.json'; file.write_text(json.dumps(inventory)); required = binding.materials.source_requirements(inventory['packages'])
            sources = {'schema_version': 1, 'status': 'passed', 'qualification': 'publisher-authenticated-exact-corresponding-source-closure', 'subjects': [{'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}], 'required_sources': 1, 'missing': [], 'metadata': [], 'files': [record('source', source)], 'sources': [{**required[0], 'files': [record('source', source)]}]}
            other = root / 'sources.json'
            with patch.object(binding, 'authenticated_sources') as authentication:
                other.write_text(json.dumps(sources)); result = binding.derive(file, other); self.assertEqual(result['bindings'][0]['sources'][0]['version'], '2.39-0ubuntu8.8'); self.assertFalse(result['complete_product_coverage']); authentication.assert_called_once()
                for mode in ('omit', 'stale', 'wrong-version', 'corrupt'):
                    changed = copy.deepcopy(sources)
                    if mode == 'omit': changed['sources'] = []
                    elif mode == 'stale': changed['subjects'][0]['sha256'] = '0' * 64
                    elif mode == 'wrong-version': changed['sources'][0]['version'] = '2.39-0ubuntu8.7'
                    else: (root / 'source').write_bytes(b'corrupt')
                    other.write_text(json.dumps(changed))
                    with self.subTest(mode=mode), self.assertRaises(ValueError): binding.derive(file, other)
                # The OS family can verify the original through the existing
                # source-parts reader after its staging file has been removed.
                other.write_text(json.dumps(sources)); (root/'source').unlink()
                class SourceParts:
                    @contextmanager
                    def open_blob(self, fingerprint, size):
                        if (fingerprint, size) != (hashlib.sha256(source).hexdigest(), len(source)): raise ValueError('unexpected original source')
                        yield io.BytesIO(source)
                recorder = Mock()
                result = binding.derive(file, other, source_parts=SourceParts(), recorder=recorder)
                self.assertEqual(result['bindings'][0]['sources'][0]['version'], '2.39-0ubuntu8.8')
                recorder.source_blob.assert_called_once_with(root/'source', hashlib.sha256(source).hexdigest(), len(source))

    def test_authentication_cannot_be_replaced_by_a_passed_boolean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'sources.json'; file.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'authentication tools'): binding.authenticated_sources(file, {'status': 'passed', 'authenticated': True}, None, None)


if __name__ == '__main__': unittest.main()
