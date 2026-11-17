"""The material producer uses the same bounded, lossless report encoding."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_source_assembly', ROOT / 'scripts/release/assemble-component-sources.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture(root):
    body = b'original corresponding source\n'; (root / 'original').write_bytes(body)
    source = {'path': 'original', 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
    receipt = root / 'receipt.json'; receipt.write_text(json.dumps({'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'files': [source]}))
    facts = [f'{index:064x}' for index in range(437)]
    report = {'schema_version': 1, 'qualification': 'replayed-actual-shipped-component-source-license-closure', 'complete_available_shipped_component_coverage': True, 'complete_product_coverage': False, 'source_inventory_sha256': 'a' * 64, 'runtime_lock_sha256': 'b' * 64, 'missing_distribution_subjects': [{'code': 'REQUIRED_DISTRIBUTION_MISSING', 'artifact': 'native-unavailable'}], 'required_materials': [{'sha256': source['sha256'], 'size_bytes': source['size_bytes']}], 'subjects': [{'id': 'fixture', 'bindings': [{'path': f'member-{index}', 'sha256': 'c' * 64, 'size_bytes': 0, 'facts': facts} for index in range(100)]}]}
    return receipt, report


class ComponentSourceAssemblyTests(unittest.TestCase):
    def test_real_material_parts_and_intermediate_report_use_the_bounded_codec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt, report = fixture(root); output = root / 'selected'
            # Only source discovery is a fixture. Archive assembly and the
            # independent Node physical-member verifier execute their real code.
            with patch.object(m.closure, 'derive', return_value=report), patch.object(m.closure, 'source_inventory', return_value={'sha256': 'a' * 64}), patch.object(m.closure, 'REPORT_LIMIT', 65536):
                result = m.assemble(root, {}, {}, [('original', receipt)], output)
            descriptor = result['component_source_coverage']; encoded = (output / descriptor['path']).read_bytes()
            self.assertLessEqual(len(encoded), 65536)
            self.assertEqual(json.loads(encoded)['format_revision'], 2)
            self.assertEqual(m.closure.expanded_report(json.loads(encoded)), report)
            self.assertEqual(descriptor['sha256'], hashlib.sha256(encoded).hexdigest())
            self.assertEqual(result['physical_source_verification'], {'verified': True, 'original_source_materials': 1})
            self.assertFalse(result['complete_product_coverage'])

    def test_unencodable_report_cannot_publish_an_assembly_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt, report = fixture(root); output = root / 'selected'
            with patch.object(m.closure, 'derive', return_value=report), patch.object(m.closure, 'REPORT_LIMIT', 16), self.assertRaisesRegex(ValueError, 'bounded reader limit'):
                m.assemble(root, {}, {}, [('original', receipt)], output)
            self.assertFalse((output / 'ASSEMBLY.json').exists())
            self.assertFalse((output / 'component-source-coverage.json').exists())


if __name__ == '__main__': unittest.main()
