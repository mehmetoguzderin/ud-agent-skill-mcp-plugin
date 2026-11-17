import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('stl_review_binding', ROOT / 'scripts/release/stl-source-bindings.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class StlReviewBindingTests(unittest.TestCase):
    def fixtures(self):
        proof = json.loads((ROOT / 'runtime/materials/uv-stl-source-components.json').read_bytes()); review = json.loads((ROOT / 'quality/reviews/stl-source-correspondence-root-review.json').read_bytes()); contract = json.loads((ROOT / 'runtime/materials/stl-source-binding.lock.json').read_bytes()); declarations = json.loads((ROOT / 'runtime/materials/msvc-static-components.lock.json').read_bytes())['components']; return proof, review, contract, declarations

    def test_exact_independent_review_covers_the_real_ten_objects_and_source_rows(self):
        proof, review, contract, _ = self.fixtures(); binding.review_matches(proof, review, contract['proof']['sha256'], contract['source_contract']['sha256'])
        for modify in (lambda value: value.update(proof_sha256='a' * 64), lambda value: value['objects'].pop(), lambda value: value['objects'][0].update(source_rows=999), lambda value: value.update(linkage_receipt_sha256='f' * 64)):
            changed = json.loads(json.dumps(review)); modify(changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'stale|omits|changes'): binding.review_matches(proof, changed, contract['proof']['sha256'], contract['source_contract']['sha256'])

    def test_reviewed_open_sources_do_not_resolve_the_709_external_header_obligations(self):
        proof, _, _, declarations = self.fixtures(); declarations = [row for row in declarations if row.get('other_static_components')]; results = [binding.bind_declaration(proof, row) for row in declarations]
        self.assertEqual(len(results), 2); self.assertTrue(all(row['effective_open_source_correspondence'] for row in results)); self.assertEqual(sum(len(row['pending_declarations']) for row in results), 709)
        self.assertTrue(all(row['code'] == 'EXACT_STL_EXTERNAL_SDK_CRT_HEADER_SOURCE_DUTY_REQUIRED' for result in results for row in result['pending_declarations']))
        for mutate in (lambda value: value.update(binary_sha256='a' * 64), lambda value: value['other_static_components'][0]['members'].pop(), lambda value: value['other_static_components'][0].update(archive_sha256='f' * 64)):
            changed = json.loads(json.dumps(declarations[0])); mutate(changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'component|universe'): binding.bind_declaration(proof, changed)


if __name__ == '__main__': unittest.main()
