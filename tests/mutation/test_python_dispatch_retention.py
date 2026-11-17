"""Retain actual dispatch observations without making them inventory authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('python_dispatch_proof_fixture', ROOT / 'tests/mutation/test_python_generation_projection_proof.py')
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


class PythonDispatchRetentionTests(unittest.TestCase):
    def test_file_binding_uses_held_change_time_and_refuses_aliases_without_nofollow(self):
        proof = fixture_module.proof
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'evidence'; file.write_bytes(b'exact bytes')
            ordinary_lstat, ordinary_open = os.lstat, os.open
            def path_metadata(path):
                value = ordinary_lstat(path)
                fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                fields['st_ctime_ns'] = 0  # Windows path birthtime differs from held ChangeTime.
                return SimpleNamespace(**fields)
            proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
            proxy.O_NOFOLLOW = 0; proxy.lstat = path_metadata
            with patch.object(proof, 'os', proxy):
                self.assertEqual(proof.data(file), b'exact bytes')
                target = Path(temporary) / 'target'; target.write_bytes(b'exact bytes')
                file.unlink(); file.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'ordinary'):
                    proof.data(file)
                file.unlink(); file.write_bytes(b'exact bytes')
                def replace_before_open(path, flags):
                    file.rename(Path(temporary) / 'retained-original')
                    file.symlink_to(target)
                    return ordinary_open(path, flags)
                proxy.open = replace_before_open
                with self.assertRaisesRegex(ValueError, 'changed before read'):
                    proof.data(file)

    def test_optional_dispatch_is_retained_byte_exact_without_changing_definitions_or_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = fixture_module.Fixture(Path(temporary))
            discovery = fixture.prove()
            self.assertNotIn('full-suite-dispatch.json', {row['path'] for row in discovery['raw_artifacts']})
            report = {'schema_version': 1, 'strategy': 'full-discovered-original-suite-not-coverage-selection',
                      'source_tree_sha256': fixture.receipt['sha256'], 'tests': ['tests/test_original.py::test_café'],
                      'function_names': ['scripts.sample.x_accepted'], 'observed_associations': {},
                      'observed_durations': {'tests/test_original.py::test_café': 0.125}}
            content = (json.dumps(report, ensure_ascii=False, indent=3) + '\n').encode()
            path = fixture.state / 'full-suite-dispatch.json'
            path.write_bytes(content)
            captured = fixture.prove()
            self.assertEqual(captured['inventory'], discovery['inventory'])
            self.assertEqual(captured['inventory_sha256'], discovery['inventory_sha256'])
            self.assertEqual(captured['source_materializations'], discovery['source_materializations'])
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(next(row for row in captured['raw_artifacts'] if row['path'] == path.name),
                             {'path': path.name, 'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)})
            path.unlink()
            outside = Path(temporary) / 'outside-dispatch.json'; outside.write_bytes(content)
            path.symlink_to(outside)
            with self.assertRaises((ValueError, OSError)):
                fixture.prove()


if __name__ == '__main__':
    unittest.main()
