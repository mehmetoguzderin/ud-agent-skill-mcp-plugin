import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_duties', ROOT / 'scripts/release/component-source-duties.py')
duties = importlib.util.module_from_spec(spec); spec.loader.exec_module(duties)


class ComponentDutyReviewTests(unittest.TestCase):
    def fixture(self, root):
        (root / 'licenses').mkdir(); term = root / 'licenses/terms.txt'; term.write_text('Original conditional object-code terms\n')
        fingerprint = 'a' * 64; group = {'classification': 'linked-object', 'binary_sha256': fingerprint, 'terms': [{'path': 'licenses/terms.txt', 'sha256': hashlib.sha256(term.read_bytes()).hexdigest(), 'size_bytes': term.stat().st_size}]}
        group['definition_sha256'] = hashlib.sha256(duties.canonical(group)).hexdigest()
        proposal = root / duties.PROPOSAL; proposal.parent.mkdir(parents=True); proposal.write_text(json.dumps({'qualification': 'component-level-source-duty-review-proposal-not-approval', 'groups': [group]}))
        row = {'definition_sha256': group['definition_sha256'], 'binary_sha256': [fingerprint], 'terms': group['terms'], 'decision': 'conditional-object-code-source-treatment', 'source_availability': 'unspecified'}
        review = {'schema_version': 1, 'qualification': duties.QUALIFICATION, 'proposal': {'path': duties.PROPOSAL, 'sha256': hashlib.sha256(proposal.read_bytes()).hexdigest(), 'size_bytes': proposal.stat().st_size}, 'groups': [row]}
        file = root / duties.REVIEW; file.parent.mkdir(parents=True); file.write_text(json.dumps(review)); return fingerprint, file, review

    def test_exact_conditional_duty_does_not_authorize_distribution_or_unknown_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fingerprint, _, _ = self.fixture(root); result = duties.derive(root, root, [fingerprint, 'b' * 64])
            self.assertEqual(set(result), {fingerprint}); self.assertTrue(result[fingerprint]['complete_component_source_duties']); self.assertEqual(result[fingerprint]['publisher_redistribution_authority'], 'unverified-external')

    def test_missing_or_unresolved_reviews_cannot_approve_a_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fingerprint, file, review = self.fixture(root)
            review['groups'] = []; file.write_text(json.dumps(review)); self.assertFalse(duties.derive(root, root, [fingerprint])[fingerprint]['complete_component_source_duties'])
            file.unlink(); self.assertEqual(duties.derive(root, root, [fingerprint]), {})

    def test_changed_binary_terms_wrong_contribution_class_and_source_claim_fail(self):
        for change in (lambda data: data['groups'][0].update(binary_sha256=['b' * 64]), lambda data: data['groups'][0]['terms'].clear(), lambda data: data['groups'][0].update(decision='no-separate-source-object'), lambda data: data['groups'][0].update(source_availability='source-unavailable'), lambda data: data.update(proposal={})):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); fingerprint, file, review = self.fixture(root); change(review); file.write_text(json.dumps(review))
                with self.assertRaises(ValueError): duties.derive(root, root, [fingerprint])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fingerprint, _, _ = self.fixture(root); (root / 'licenses/terms.txt').write_text('Changed original terms')
            with self.assertRaises(ValueError): duties.derive(root, root, [fingerprint])


if __name__ == '__main__': unittest.main()
