import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_unicode_path_generator', ROOT / 'scripts/generate/unicode-paths.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class UnicodeGeneratorTests(unittest.TestCase):
    def test_official_sources_reproduce_the_complete_frozen_inventory(self):
        actual = generator.generate(ROOT)
        self.assertEqual(actual, (ROOT / 'workers/ud/src/ud_agent/unicode_casefold.json').read_text())
        value = json.loads(actual)
        self.assertEqual(value['mapping']['ß'], 'ss')
        self.assertEqual(value['normalization_assigned_ranges'][0], [0, 887])
        self.assertEqual(len(value['mapping']), 1557)
        self.assertEqual(len(value['normalization_assigned_ranges']), 731)
        self.assertEqual({item['path'] for item in value['provenance']['sources']}, {'runtime/unicode-16/UnicodeData.txt', 'runtime/unicode-16/CaseFolding.txt', 'runtime/unicode-16/ReadMe.txt'})

    def test_corrupt_or_symlinked_official_input_is_an_integrity_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / 'runtime/unicode-16', root / 'runtime/unicode-16')
            file = root / 'runtime/unicode-16/UnicodeData.txt'
            before = file.read_bytes(); file.write_bytes(before.replace(b'LATIN', b'LatIN', 1))
            with self.assertRaisesRegex(ValueError, 'pinned receipt'):
                generator.generate(root)
            file.write_bytes(before)
            original = root / 'original-unicode.txt'; file.rename(original); file.symlink_to(original)
            with self.assertRaisesRegex(ValueError, 'pinned receipt'):
                generator.generate(root)


if __name__ == '__main__':
    unittest.main()
