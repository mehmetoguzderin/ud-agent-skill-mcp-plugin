"""Original fixture-byte tests; generated programs never execute on the host."""
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('secondary_native_fixture', ROOT / 'scripts/quality/oci-secondary.py')
backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)
model_spec = importlib.util.spec_from_file_location('native_fixture_posix_model', Path(__file__).with_name('posix_file_model.py'))
model = importlib.util.module_from_spec(model_spec); model_spec.loader.exec_module(model)


class NativeFixtureTests(unittest.TestCase):
    def test_foreign_posix_model_preserves_real_bytes_inodes_links_and_mode_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with model.posix_files(backend, root, enabled=True):
                file = root / 'original'; file.write_bytes(b'actual original bytes'); file.chmod(0o555)
                descriptor = backend.os.open(file, backend.os.O_RDONLY | backend.os.O_NOFOLLOW)
                try:
                    actual = os.fstat(descriptor); modeled = backend.os.fstat(descriptor)
                    self.assertEqual((modeled.st_dev, modeled.st_ino, modeled.st_size), (actual.st_dev, actual.st_ino, actual.st_size))
                    self.assertEqual(modeled.st_mode & 0o777, 0o555)
                    self.assertEqual(os.read(descriptor, 100), b'actual original bytes')
                    os.link(file, root / 'hardlink')
                    self.assertEqual(backend.os.fstat(descriptor).st_nlink, 2)
                finally: os.close(descriptor)
                alias = root / 'alias'; alias.symlink_to(file)
                with self.assertRaises(OSError):
                    backend.os.open(alias, backend.os.O_RDONLY | backend.os.O_NOFOLLOW)
                with self.assertRaisesRegex(AssertionError, 'escaped'):
                    backend.os.open(root.parent / 'foreign', backend.os.O_RDONLY)

    def fixture(self, root):
        self.enterContext(model.posix_files(backend, root))
        work, sdk, state = root / 'source', root / 'sdk', root / 'state'
        work.mkdir(); (sdk / 'bin').mkdir(parents=True); state.mkdir()
        native = sdk / 'bin/ud-agent-guard'; native.write_bytes(b'original fixture bytes, never executed'); native.chmod(0o555)
        runtime = {'native_guard': {'path': 'bin/ud-agent-guard', 'architecture': 'arm64', 'size_bytes': native.stat().st_size, 'sha256': hashlib.sha256(native.read_bytes()).hexdigest()},
                   'node_dependencies': {'path': 'node-dependencies.json', 'size_bytes': 1, 'sha256': 'a' * 64}}
        return work, sdk, state, native, runtime

    def test_normal_helper_is_exact_readonly_independent_input_reusable_across_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            work, sdk, _, native, runtime = self.fixture(Path(directory))
            expected = {'path': 'target/debug/ud-agent-guard', 'sha256': hashlib.sha256(b'original fixture bytes, never executed').hexdigest(), 'size': 38, 'mode': 0o555}
            self.assertEqual(backend.stage_native_fixture(work, runtime, sdk), expected)
            target = work / expected['path']; original = target.stat()
            self.assertEqual(target.read_bytes(), b'original fixture bytes, never executed')
            self.assertNotEqual((original.st_dev, original.st_ino), (native.stat().st_dev, native.stat().st_ino))
            self.assertEqual(original.st_mode & 0o777, 0o555)
            self.assertEqual(backend.stage_native_fixture(work, runtime, sdk), expected)
            self.assertEqual(target.stat().st_ino, original.st_ino)

    def test_altered_sdk_bytes_writable_sdk_or_substituted_destination_are_rejected(self):
        for scenario in ('hash', 'writable-sdk', 'sdk-symlink', 'directory-symlink', 'destination-bytes', 'destination-hardlink', 'destination-fifo'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); work, sdk, _, native, runtime = self.fixture(root)
                if scenario == 'hash': runtime['native_guard']['sha256'] = '0' * 64
                elif scenario == 'writable-sdk': native.chmod(0o755)
                elif scenario == 'sdk-symlink':
                    original = sdk / 'original'; native.rename(original); native.symlink_to(original)
                elif scenario == 'directory-symlink': (work / 'target').symlink_to(sdk, target_is_directory=True)
                else:
                    backend.stage_native_fixture(work, runtime, sdk)
                    target = work / 'target/debug/ud-agent-guard'
                    if scenario == 'destination-bytes':
                        target.chmod(0o755); target.write_bytes(b'forged'); target.chmod(0o555)
                    elif scenario == 'destination-hardlink':
                        os.link(target, root / 'alias')
                    else:
                        target.chmod(0o755); target.unlink()
                        if hasattr(os, 'mkfifo'):
                            os.mkfifo(target, 0o555)
                        else:
                            target.write_bytes(b'modeled FIFO')
                            target_info = target.stat()
                            real = backend.os.fstat
                            def fifo(descriptor):
                                value = real(descriptor)
                                if (value.st_dev, value.st_ino) == (target_info.st_dev, target_info.st_ino):
                                    value.st_mode = stat.S_IFIFO | 0o555
                                return value
                            self.enterContext(patch.object(backend.os, 'fstat', fifo))
                with self.assertRaises((ValueError, OSError)):
                    backend.stage_native_fixture(work, runtime, sdk)

    def test_vitest_handoff_includes_fixture_without_granting_writable_source(self):
        with tempfile.TemporaryDirectory() as directory:
            work, sdk, state, _, runtime = self.fixture(Path(directory))
            source = work / 'source.mjs'; source.write_bytes(b'export default true;\r\n')
            receipt = {'files': [{'path': source.name, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]}
            calls = []
            def execute(argv, **options):
                calls.append(options)
                inventory = options['workspace']
                self.assertIs(inventory['readonly_tree'], True)
                self.assertEqual([row['path'] for row in inventory['files']], ['source.mjs', 'target/debug/ud-agent-guard'])
                self.assertEqual(inventory['files'][1]['mode'], 0o555)
                digest = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                return {'status': 0, 'handoff': {'cwd': '.', 'files': 2, 'inventory_sha256': digest, 'source_inventory_sha256': digest, 'readonly_tree': True}}
            stage = backend.stage_native_fixture
            with patch.object(backend, 'stage_native_fixture', side_effect=lambda work, runtime: stage(work, runtime, sdk)):
                jobs = backend.Jobs(work, state, receipt, execute, runtime)
                for runner in ('vitest', 'pytest', 'vitest'):
                    jobs.run(runner, 'tests/fixture.test.mjs' if runner == 'vitest' else 'tests/test_fixture.py')
            self.assertEqual(len(calls), 3)
            self.assertEqual([json.loads(call['request']['bytes'])['runner'] for call in calls], ['vitest', 'pytest', 'vitest'])
            self.assertEqual(source.read_bytes(), b'export default true;\r\n')


if __name__ == '__main__':
    unittest.main()
