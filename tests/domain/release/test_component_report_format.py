import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_report_format', ROOT / 'scripts/release/component-closure.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture():
    return {'schema_version': 1, 'subjects': [
        {'id': 'one', 'bindings': [{'path': 'first', 'sha256': 'c' * 64, 'size_bytes': 4, 'facts': ['a' * 64, 'b' * 64]}, {'path': 'single', 'sha256': 'd' * 64, 'size_bytes': 5, 'facts': ['e' * 64]}]},
        {'id': 'two', 'bindings': [{'path': 'same-bytes-another-archive', 'sha256': 'c' * 64, 'size_bytes': 4, 'facts': ['a' * 64, 'b' * 64]}]},
    ], 'source_facts': [{'id': 'a' * 64, 'source': 'original source'}, {'id': 'b' * 64, 'source': 'independent source'}], 'inspection_inputs': {'inputs': [{'path': 'original', 'sha256': 'f' * 64, 'size_bytes': 6}]}, 'limitations': ['No publisher authority is inferred.']}


class ComponentReportFormatTests(unittest.TestCase):
    def test_indexed_facts_preserve_every_physical_binding_source_and_inspection_input(self):
        original = fixture(); before = copy.deepcopy(original); compact = m.compact_report(original)
        self.assertEqual(compact['format_revision'], 2)
        self.assertEqual(compact['binding_fact_sets'], [['a' * 64, 'b' * 64]])
        self.assertEqual(compact['subjects'][0]['bindings'][0]['facts'], 0)
        self.assertEqual(compact['subjects'][1]['bindings'][0]['facts'], 0)
        self.assertEqual(compact['subjects'][0]['bindings'][1]['facts'], ['e' * 64])
        self.assertEqual(m.expanded_report(compact), before)
        self.assertEqual(original, before)

    def test_legacy_array_reports_remain_readable_without_fabricating_new_fields(self):
        original = fixture(); self.assertEqual(m.expanded_report(original), original)
        self.assertNotIn('format_revision', original)

    def test_unknown_revision_or_malformed_duplicate_unused_and_dangling_sets_are_rejected(self):
        changes = [
            lambda r: r.update(format_revision=3),
            lambda r: r.update(format_revision=None),
            lambda r: r.update(format_revision=True),
            lambda r: r.update(binding_fact_sets=None),
            lambda r: r['binding_fact_sets'].append(r['binding_fact_sets'][0]),
            lambda r: r['binding_fact_sets'][0].reverse(),
            lambda r: r['binding_fact_sets'][0].__setitem__(0, 'not a source fact'),
            lambda r: r['binding_fact_sets'].append(['f' * 64, '0' * 64]),
            lambda r: r['subjects'][0]['bindings'][0].update(facts=1),
            lambda r: r['subjects'][0]['bindings'][0].update(facts=-1),
            lambda r: r['subjects'][0]['bindings'][0].update(facts=True),
            lambda r: [row.update(facts=['a' * 64]) for subject in r['subjects'] for row in subject['bindings']],
        ]
        for change in changes:
            report = m.compact_report(fixture()); change(report)
            with self.subTest(change=change), self.assertRaises(ValueError): m.expanded_report(report)
        legacy = fixture(); legacy['binding_fact_sets'] = []
        with self.assertRaises(ValueError): m.expanded_report(legacy)

    def test_expansion_does_not_discard_altered_non_encoding_evidence(self):
        report = m.compact_report(fixture()); report['inspection_inputs']['inputs'][0]['sha256'] = '0' * 64
        self.assertNotEqual(m.expanded_report(report), fixture())

    def test_writer_retains_the_existing_reader_limit_instead_of_emitting_an_unreadable_report(self):
        original = fixture(); encoded = m.report_bytes(original)
        self.assertEqual(m.expanded_report(json.loads(encoded)), original)
        self.assertTrue(encoded.endswith(b'\n'))
        with patch.object(m, 'REPORT_LIMIT', len(encoded)):
            self.assertEqual(m.report_bytes(original), encoded)
        with patch.object(m, 'REPORT_LIMIT', len(encoded) - 1), self.assertRaisesRegex(ValueError, 'bounded reader limit'):
            m.report_bytes(original)

    def test_repeated_large_fact_sets_are_lossless_and_materially_smaller(self):
        facts = [f'{index:064x}' for index in range(437)]
        report = {'subjects': [{'id': 'actual-archive', 'bindings': [{'path': f'member-{index}', 'facts': facts, 'sha256': 'e' * 64, 'size_bytes': 0} for index in range(100)]}], 'source_facts': [{'id': value} for value in facts]}
        encoded = m.report_bytes(report)
        self.assertLess(len(encoded), len(m.canonical(report)) // 4)
        self.assertEqual(m.expanded_report(json.loads(encoded)), report)


if __name__ == '__main__': unittest.main()
