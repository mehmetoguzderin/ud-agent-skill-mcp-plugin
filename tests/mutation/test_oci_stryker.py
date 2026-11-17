"""Portable policy cases; actual execution belongs to native ARM OCI evidence."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ud_oci_stryker_policy', ROOT / 'scripts/quality/oci-stryker.py')
BACKEND = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKEND)


class OciStrykerTests(unittest.TestCase):
    def test_foreign_backend_diagnostic_flag_rejects_before_native_or_filesystem_actions(self):
        entry_spec = importlib.util.spec_from_file_location('ud_oci_stryker_entry_policy', ROOT / 'scripts/quality/oci-mutation.py')
        entry = importlib.util.module_from_spec(entry_spec)
        entry_spec.loader.exec_module(entry)
        for backend in ['python', 'perl', 'rust', 'python-static', 'faults']:
            with self.subTest(backend=backend), patch.object(entry.sys, 'argv', ['oci-mutation.py', '--backend', backend, '--diagnostic-stryker-range', 'packages/example.ts:1:1-2:1']), patch.object(entry.os, 'geteuid', side_effect=AssertionError('native actions must not begin'), create=True):
                with self.assertRaisesRegex(ValueError, 'exclusive'):
                    entry.main()

    def test_diagnostic_override_changes_only_generated_config_and_binds_actual_source_range(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = 'packages/example/src/example.ts'
            file = root / name
            file.parent.mkdir(parents=True)
            data = 'const x="😀";\r\nexport const y=true;\n'.encode()
            file.write_bytes(data)
            original = b"export default {coverageAnalysis:'off',mutate:['packages/**'],thresholds:{high:100,low:100,break:100}};\n"
            (root / 'stryker.config.mjs').write_bytes(original)
            receipt = {'source_tree_sha256': 'a' * 64, 'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}]}
            config, scope = BACKEND.diagnostic_configuration(root, receipt, name + ':1:1-2:21')
            self.assertEqual(scope, {'schema_version': 1, 'kind': 'selected-stryker-diagnostic', 'scope_complete': False, 'source_tree_sha256': 'a' * 64, 'range': name + ':1:1-2:21', 'file': name, 'source_sha256': hashlib.sha256(data).hexdigest(), 'source_size_bytes': len(data), 'start': {'line': 1, 'column': 1}, 'end': {'line': 2, 'column': 21}})
            self.assertIn('mutate: ["' + name + ':1:1-2:21"]', config)
            self.assertIn("coverageAnalysis: 'perTest'", config)
            self.assertIn("...original", config)
            self.assertNotIn('testFilter', config)
            self.assertNotIn('testFiles', config)
            self.assertEqual((root / 'stryker.config.mjs').read_bytes(), original)
            default, absent = BACKEND.diagnostic_configuration(root, receipt)
            self.assertIsNone(absent)
            self.assertNotIn('mutate:', default)
            self.assertNotIn('coverageAnalysis:', default)
            for value in ['../' + name + ':1:1-2:21', name + ':01:1-2:21', name + ':1:0-2:21', name + ':1:1-4:1', name + ':1:1-2:22', name + ':2:2-1:1', name + ':2:2-2:2']:
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'range'):
                    BACKEND.diagnostic_configuration(root, receipt, value)
            with self.assertRaisesRegex(ValueError, 'absent'):
                BACKEND.diagnostic_configuration(root, {**receipt, 'files': []}, name + ':1:1-2:21')
            file.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'differs'):
                BACKEND.diagnostic_configuration(root, receipt, name + ':1:1-2:21')

    def test_verifies_exact_source_bytes_and_native_helper_machine_from_the_image_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); work = root / 'work'; work.mkdir(); image = root / 'image'; (image / 'bin').mkdir(parents=True)
            data = b'export const answer = 40;\n'; (work / 'source.mjs').write_bytes(data)
            native = bytearray(64); native[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', native, 18, 183)
            (image / 'bin/ud-agent-guard').write_bytes(native)
            receipt = {'files': [{'path': 'source.mjs', 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'executable': False}]}
            runtime = {'platform': 'linux/arm64', 'native_guard': {'path': 'bin/ud-agent-guard', 'architecture': 'arm64', 'size_bytes': len(native), 'sha256': hashlib.sha256(native).hexdigest()}}
            with patch.object(BACKEND, 'Path', lambda name: image if name == '/opt/mutation' else Path(name)):
                self.assertEqual(BACKEND.verify_inputs(work, receipt, runtime), image / 'bin/ud-agent-guard')
                (work / 'source.mjs').write_bytes(b'changed source')
                with self.assertRaisesRegex(ValueError, 'source differs'):
                    BACKEND.verify_inputs(work, receipt, runtime)
                (work / 'source.mjs').write_bytes(data)
                native[18:20] = struct.pack('<H', 62); (image / 'bin/ud-agent-guard').write_bytes(native)
                runtime['native_guard']['sha256'] = hashlib.sha256(native).hexdigest()
                with self.assertRaisesRegex(ValueError, 'architecture'):
                    BACKEND.verify_inputs(work, receipt, runtime)

    def test_rejects_unsafe_duplicate_and_empty_source_inventories_before_any_execution(self):
        runtime = {'platform': 'linux/arm64'}
        for files in [[], [{'path': '../outside'}], [{'path': '/outside'}], [{'path': 'a//b'}], [{'path': 'C:stream'}], [{'path': 'a\\b'}]]:
            with self.subTest(files=files), self.assertRaises(ValueError):
                BACKEND.verify_inputs(Path('unused'), {'files': files}, runtime)
        with self.assertRaisesRegex(ValueError, 'ARM64'):
            BACKEND.verify_inputs(Path('unused'), {'files': []}, {'platform': 'linux/amd64'})

    def test_host_execution_is_rejected_without_starting_a_subprocess(self):
        with patch.object(BACKEND.sys, 'platform', 'win32'), patch.object(BACKEND.subprocess, 'Popen', side_effect=AssertionError('must not start')):
            with self.assertRaisesRegex(ValueError, 'host Stryker execution is refused'):
                BACKEND.run(Path('unused'), Path('unused'), {})


if __name__ == '__main__':
    unittest.main()
