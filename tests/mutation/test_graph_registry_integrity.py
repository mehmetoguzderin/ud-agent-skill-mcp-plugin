"""Synthetic review corruption tests; no generated graph program is executed."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('graph_registry_integrity', ROOT / 'scripts/quality/python-operators.py')
OPERATORS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPERATORS)
REGISTRY = json.loads((ROOT / 'quality/python-graph-operator-proposals.json').read_bytes())
REVIEW = json.loads((ROOT / 'quality/reviews/python-graph-operators-root-review.json').read_bytes())


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class GraphRegistryIntegrityTests(unittest.TestCase):
    def test_revision_two_activation_binds_exact_new_paths_and_bytes_without_reusing_legacy_approval(self):
        registry=copy.deepcopy(self.registry);registry['proposal_version']='ud-graph-typed-operators-proposal-2'
        registry_path='quality/python-graph-operator-proposals-v2.json';review_path='quality/reviews/python-graph-operators-root-review-v2.json'
        raw=json.dumps(registry).encode();(self.root/registry_path).write_bytes(raw)
        review=copy.deepcopy(self.review);review['proposal']={'path':registry_path,'sha256':digest(raw),'version':registry['proposal_version']}
        reviewed=json.dumps(review).encode();(self.root/review_path).write_bytes(reviewed)
        activation={'schema_version':1,'format_revision':2,'active':True,'operator_version':'ud-graph-typed-operators-2','registry':{'path':registry_path,'sha256':digest(raw)},'review':{'path':review_path,'sha256':digest(reviewed)}}
        file=self.root/'quality/python-graph-operators.activation.json';file.write_text(json.dumps(activation))
        selected=self.repair();row=registry['rows'][0];result=selected(row['file'],row['upstream_definition']['replacement_function'],row['upstream_definition'])
        self.assertEqual(result[1]['version'],'ud-graph-typed-operators-2');self.assertEqual(result[1]['review']['path'],review_path)
        for change in [{'path':'quality/../outside','sha256':digest(raw)},{'path':registry_path,'sha256':'0'*64}]:
            file.write_text(json.dumps({**activation,'registry':change}))
            with self.assertRaises(ValueError):self.repair()
        file.write_text(json.dumps(activation));(self.root/review_path).write_bytes(reviewed+b' ')
        with self.assertRaisesRegex(ValueError,'bytes changed'):self.repair()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ud-graph-review-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'quality/reviews').mkdir(parents=True)
        self.registry = copy.deepcopy(REGISTRY)
        self.review = copy.deepcopy(REVIEW)
        self.hashes = {row['file']: row['source_sha256'] for row in self.registry['rows']}

    def save(self, rebind=False):
        raw = json.dumps(self.registry, ensure_ascii=False, sort_keys=True).encode()
        (self.root / 'quality/python-graph-operator-proposals.json').write_bytes(raw)
        if rebind:
            # Synthetic re-signing lets each deeper invariant be tested without
            # pretending this fixture is an independent production review.
            self.review['proposal']['sha256'] = digest(raw)
        (self.root / 'quality/reviews/python-graph-operators-root-review.json').write_text(json.dumps(self.review))

    def repair(self):
        return OPERATORS._graph_typed_repairs(self.root, self.hashes)

    def approved(self, row):
        return next(item for item in self.review['reviews'] if item['id'] == row['id'])

    def rebind_program(self, row):
        changed = row['upstream_definition']['replacement_function'].replace(row['before'], row['after'], 1)
        row['proposed_function_sha256'] = digest(changed.encode())
        self.approved(row)['proposed_function_sha256'] = row['proposed_function_sha256']

    def test_review_byte_binding_rejects_changed_registry_and_foreign_review_identity(self):
        self.save(rebind=True)
        self.registry['rows'][0]['type_contract'] += ' forged'
        self.save()
        with self.assertRaisesRegex(ValueError, 'missing or stale'): self.repair()
        self.registry = copy.deepcopy(REGISTRY)
        self.review['reviewer'] = 'registry author'
        self.save(rebind=True)
        with self.assertRaisesRegex(ValueError, 'missing or stale'): self.repair()

    def test_review_requires_exact_one_to_one_inventory(self):
        for change in ('missing', 'duplicate'):
            with self.subTest(change=change):
                self.review = copy.deepcopy(REVIEW)
                if change == 'missing': self.review['reviews'].pop()
                else: self.review['reviews'].append(copy.deepcopy(self.review['reviews'][0]))
                self.save(rebind=True)
                with self.assertRaisesRegex(ValueError, 'incomplete or duplicated'): self.repair()

    def test_source_and_raw_definition_fingerprints_are_independently_enforced(self):
        for field in ('source_sha256', 'upstream_definition_sha256', 'replacement_function_sha256', 'before'):
            with self.subTest(field=field):
                self.registry = copy.deepcopy(REGISTRY); self.review = copy.deepcopy(REVIEW)
                self.registry['rows'][0][field] = 'absent source fragment' if field == 'before' else '0' * 64
                self.save(rebind=True)
                with self.assertRaisesRegex(ValueError, 'original operator identity'): self.repair()

    def test_proposed_program_and_independent_approval_must_agree_exactly(self):
        for field, value in [('decision','accept-as-kill'), ('source_sha256','0'*64), ('upstream_definition_sha256','0'*64), ('proposed_function_sha256','0'*64), ('type_contract','different ABI')]:
            with self.subTest(field=field):
                self.registry = copy.deepcopy(REGISTRY); self.review = copy.deepcopy(REVIEW)
                self.approved(self.registry['rows'][0])[field] = value
                self.save(rebind=True)
                with self.assertRaisesRegex(ValueError, 'exact independent review'): self.repair()

    def test_duplicate_original_cannot_be_claimed_by_another_repair_even_with_distinct_output(self):
        row = copy.deepcopy(self.registry['rows'][0]); approval = copy.deepcopy(self.approved(row))
        row['id'] += '-synthetic-duplicate'; approval['id'] = row['id']
        row['after'] = row['after'].replace('[:0]', '[2:]')
        self.registry['rows'].append(row); self.review['reviews'].append(approval)
        self.rebind_program(row); self.save(rebind=True)
        with self.assertRaisesRegex(ValueError, 'Duplicate graph original operator'): self.repair()

    def test_duplicate_proposed_program_is_rejected_before_scheduling(self):
        row = copy.deepcopy(self.registry['rows'][0]); approval = copy.deepcopy(self.approved(row))
        row['id'] += '-synthetic-program'; approval['id'] = row['id']
        self.registry['rows'].append(row); self.review['reviews'].append(approval)
        self.save(rebind=True)
        with self.assertRaisesRegex(ValueError, 'exact independent review'): self.repair()

    def test_full_raw_profile_and_source_location_remain_bound_at_application(self):
        self.save(rebind=True); repair = self.repair(); row = self.registry['rows'][0]
        definition = row['upstream_definition']; replacement = definition['replacement_function']
        for field in ('generation_profile','location'):
            forged = copy.deepcopy(definition)
            if field == 'generation_profile': forged[field]['version'] = 'unreviewed-generator'
            else: forged[field]['line'] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'complete definition'):
                repair(row['file'], replacement, forged)
        self.assertIsNone(repair(row['file'], replacement + '\n', definition))

    def test_repair_cannot_change_line_framing_and_required_scheduling_is_complete(self):
        row = self.registry['rows'][0]; row['after'] += '\n'
        self.rebind_program(row); self.save(rebind=True)
        repair = self.repair()
        with self.assertRaisesRegex(ValueError, 'source framing'):
            repair(row['file'], row['upstream_definition']['replacement_function'], row['upstream_definition'])
        self.registry = copy.deepcopy(REGISTRY); self.review = copy.deepcopy(REVIEW); self.save(rebind=True)
        repair = self.repair(); row = self.registry['rows'][0]
        with self.assertRaisesRegex(ValueError, 'omitted'): repair.complete({row['id']})
        repair(row['file'], row['upstream_definition']['replacement_function'], row['upstream_definition'])
        repair.complete({row['id']})
        with self.assertRaisesRegex(ValueError, 'omitted'): repair.complete(set())


if __name__ == '__main__': unittest.main()
