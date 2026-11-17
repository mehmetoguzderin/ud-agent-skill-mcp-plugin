import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('inspection_alias_reads', ROOT / 'scripts/release/replay-inspection-inputs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InspectionAliasReadTests(unittest.TestCase):
    def test_outside_private_overlay_reads_observe_exact_canonical_input_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / 'assets'
            assets.mkdir()
            (assets / 'metadata.json').write_bytes(b'{"exact":"original"}\n')
            alias = root / 'private-overlay'
            alias.symlink_to(assets, target_is_directory=True)
            source = {'sha256': 'a' * 64, 'files': []}
            with m.Recorder(root / 'source', assets) as recorder:
                self.assertEqual((alias / 'metadata.json').read_bytes(), b'{"exact":"original"}\n')
                catalog = recorder.finish(source, {'subjects': []}, [], [])
            self.assertEqual([row['path'] for row in catalog['inputs']], ['metadata.json'])
            self.assertEqual(catalog['inputs'][0]['retention']['kind'], 'retained-json-metadata')
            self.assertTrue(m.verify(catalog, assets, source['sha256'], [], require_retained=True)['verified'])

    def test_input_root_links_still_cannot_gain_ordinary_input_or_member_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / 'assets'
            assets.mkdir()
            original = root / 'outside.json'
            original.write_bytes(b'{"outside":true}\n')
            link = assets / 'linked.json'
            link.symlink_to(original)
            with m.Recorder(root / 'source', assets) as recorder:
                self.assertEqual(link.read_bytes(), original.read_bytes())
                with self.assertRaises(ValueError):
                    recorder.finish({'sha256': 'a' * 64, 'files': []}, {'subjects': []}, [], [])


if __name__ == '__main__':
    unittest.main()
