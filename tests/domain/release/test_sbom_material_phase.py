import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('sbom_material_phase', ROOT / 'scripts/release/sbom.py')
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)
CREATED = '2026-11-10T00:00:00Z'


def fixture(root):
    (root / 'runtime').mkdir()
    (root / 'package.json').write_text(json.dumps({'name': 'fixture', 'version': '1', 'license': 'MIT'}))
    (root / 'package-lock.json').write_text('{"packages":{}}')
    for name in ['uv.lock', 'Cargo.lock']:
        (root / name).write_text('')
    for name in ['node-distributions', 'perl-deps', 'render-deps', 'core-image', 'ud-sources']:
        (root / 'runtime' / (name + '.lock.json')).write_text('{"sources":[]}' if name == 'ud-sources' else '{}')
    index = {'complete_product_coverage': False, 'parts': [], 'stream_sha256': 'b' * 64}
    body = json.dumps(index).encode()
    descriptor = {'path': 'selected-index.json', 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
    lock = root / 'runtime/source-materials.lock.json'
    lock.write_text(json.dumps({'schema_version': 1, 'index': descriptor, 'parts': []}))
    source = {'sha256': 'a' * 64, 'files': [{'path': 'runtime/source-materials.lock.json', 'sha256': hashlib.sha256(lock.read_bytes()).hexdigest(), 'size': lock.stat().st_size, 'executable': False}]}
    return source, body, descriptor


class SbomMaterialPhaseTests(unittest.TestCase):
    def test_default_material_phase_rejects_missing_actual_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _ = fixture(root)
            with self.assertRaises(FileNotFoundError):
                sbom.generate(root, source, CREATED)

    def test_explicit_provisional_phase_retains_inventory_and_asserts_only_pending_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, _ = fixture(root)
            result = sbom.generate(root, source, CREATED, provisional_materials=True)
            self.assertEqual(result['files'][0]['fileName'], './runtime/source-materials.lock.json')
            self.assertEqual(result['files'][0]['checksums'][0]['checksumValue'], source['files'][0]['sha256'])
            self.assertFalse(any(item['name'].startswith('Corresponding source ') for item in result['packages']))
            product = next(item for item in result['packages'] if item['name'] == 'fixture')
            self.assertIn('have not yet been selected', product['annotations'][0]['comment'])
            self.assertIn('does not authorize production promotion', product['annotations'][0]['comment'])

    def test_default_final_phase_requires_exact_real_index_and_declares_its_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, body, descriptor = fixture(root)
            file = root / descriptor['path']
            file.write_bytes(body)
            result = sbom.generate(root, source, CREATED)
            material = next(item for item in result['packages'] if item['name'] == 'Corresponding source corresponding-source-index')
            self.assertEqual(material['checksums'], [{'algorithm': 'SHA256', 'checksumValue': descriptor['sha256']}])
            self.assertFalse(any('have not yet been selected' in entry.get('comment', '') for item in result['packages'] for entry in item.get('annotations', [])))
            file.write_bytes(body + b' ')
            with self.assertRaisesRegex(ValueError, 'differs from its frozen receipt'):
                sbom.generate(root, source, CREATED)


if __name__ == '__main__':
    unittest.main()
