import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('duty_proposals', ROOT / 'scripts/release/propose-component-duties.py')
proposal = importlib.util.module_from_spec(spec); spec.loader.exec_module(proposal)


class ComponentDutyProposalTests(unittest.TestCase):
    def fixture(self):
        rows = []
        for index, classification in enumerate(('import-metadata', 'linked-object', 'no-recorded-image-contribution')):
            row = {'id': str(index), 'family': 'exact-recorded-compiler-family', 'classification': classification, 'terms_group': 'original', 'platform': 'win32/arm64', 'binary_sha256': 'a' * 64, 'binary_size_bytes': 12}
            row['definition_sha256'] = proposal.sha_definition(row); rows.append(row)
        return {'components': rows, 'terms': {'original': [{'sha256': 'b' * 64}]}, 'binary_joins': [{'component_ids': ['0', '1', '2']}]}

    def test_imports_zero_contribution_and_actual_objects_have_distinct_duties(self):
        groups = proposal.perl_groups(self.fixture())
        self.assertEqual(len(groups), 3)
        for group in groups:
            if group['classification'] == 'linked-object': self.assertEqual(group['applicability'], 'pending-exact-original-installation-terms-applicability')
            else: self.assertEqual(group['proposed_duty'], 'no-separately-contributed-implementation-source-for-this-record')

    def test_omitted_duplicate_or_changed_actual_component_bindings_fail(self):
        for change in (lambda data: data['binary_joins'][0]['component_ids'].pop(), lambda data: data['components'].append(data['components'][0]), lambda data: data['components'][0].update(classification='linked-object')):
            data = self.fixture(); change(data)
            with self.assertRaises(ValueError): proposal.perl_groups(data)

    def test_open_source_stl_is_never_absorbed_into_a_proprietary_crt_declaration(self):
        prefix = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/lib/ARM64/'
        document = {'records': [{'platform': 'win32/arm64', 'binary': {'sha256': 'a' * 64, 'size_bytes': 10}, 'binary_archive': {'sha256': 'b' * 64}, 'runtime_compilands': [{'library': prefix + name, 'id': index} for index, name in enumerate(('libcmt.lib', 'libcpmt.lib'))]}]}
        groups = proposal.node_groups(document, {'msvc-2022': []}); stl = next(row for row in groups if row['family'].endswith('libcpmt'))
        self.assertEqual(stl['classification'], 'linked-open-source-STL-component'); self.assertIn('proprietary-terms-cannot-substitute', stl['applicability'])


if __name__ == '__main__': unittest.main()
