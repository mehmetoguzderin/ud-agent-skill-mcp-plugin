import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('merge_providers', ROOT / 'scripts/runtime/merge-provider-assets.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(root, engine, arch, name='payload'):
    root.mkdir()
    relative = f'runtime/providers/{engine}/darwin-{arch}/{name}'
    file = root / relative
    file.parent.mkdir(parents=True)
    file.write_bytes((engine + arch).encode())
    value = {'schema_version': 1, 'provider_receipts': {f'{engine}/darwin/{arch}': {'schema_version': 1}}, 'files': [{'path': relative, 'size_bytes': file.stat().st_size, 'sha256': module.digest(file)}]}
    (root / 'provider-receipts.json').write_text(json.dumps(value))
    return file


class ProviderMergeTests(unittest.TestCase):
    def test_merges_closed_disjoint_bytes_and_binds_each_original_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first', root / 'second'
            a = fixture(first, 'apple-container', 'arm64')
            b = fixture(second, 'lima-nerdctl', 'x64')
            result = module.merge([first, second], root / 'output')
            self.assertEqual(sorted(result['provider_receipts']), ['apple-container/darwin/arm64', 'lima-nerdctl/darwin/x64'])
            self.assertEqual((root / 'output' / a.relative_to(first)).read_bytes(), a.read_bytes())
            self.assertEqual((root / 'output' / b.relative_to(second)).read_bytes(), b.read_bytes())
            self.assertEqual(result['origins'][0]['receipt_sha256'], module.digest(first / 'provider-receipts.json'))
            self.assertFalse((root / 'output/INCOMPLETE').exists())
            self.assertEqual(len(result['files']), 2)

    def test_rejects_duplicates_corruption_and_output_inside_source_without_writing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first', root / 'second'
            fixture(first, 'lima-nerdctl', 'arm64')
            changed = fixture(second, 'lima-nerdctl', 'x64')
            with self.assertRaisesRegex(ValueError, 'disjoint sources'):
                module.merge([first, first], root / 'output')
            with self.assertRaisesRegex(ValueError, 'separate output'):
                module.merge([first, second], first / 'output')
            changed.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                module.merge([first, second], root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_rejects_provider_identity_collisions_and_linked_parent_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first', root / 'second'
            fixture(first, 'lima-nerdctl', 'arm64')
            fixture(second, 'lima-nerdctl', 'arm64')
            with self.assertRaisesRegex(ValueError, 'duplicate or unsupported'):
                module.merge([first, second], root / 'output')
            manifest = json.loads((second / 'provider-receipts.json').read_text())
            manifest['provider_receipts'] = {'lima-nerdctl/darwin/x64': {'schema_version': 1}}
            # The same bytes under a Unicode-portable collision remain invalid.
            (second / 'provider-receipts.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'file collision'):
                module.merge([first, second], root / 'output')


if __name__ == '__main__':
    unittest.main()
