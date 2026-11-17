"""Independent tampering checks for the pre-outcome PPI reconstruction gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ppi_proof', ROOT / 'scripts/quality/prove-perl-generation.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class PerlGenerationProofTests(unittest.TestCase):
    def fixture(self, root):
        root = root.resolve()
        source = root / 'source'
        state = root / 'state'
        (source / 'scripts').mkdir(parents=True)
        (source / 'scripts/quality').mkdir()
        (source / 'quality').mkdir()
        (state / 'perl-generation/tokens/scripts').mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/quality/perl-mutation.py', source / 'scripts/quality/perl-mutation.py')
        shutil.copyfile(ROOT / 'quality/perl-operators.json', source / 'quality/perl-operators.json')
        (source / 'scripts/conditional.pl').write_bytes(b'if')
        (source / 'scripts/comment.pl').write_bytes(b'# none\r\n')
        for name in ('tests/domain/perl/test_bridge.py', 'tests/mutation/test_perl_inventory.py'):
            file = source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): self.assertEqual(1,1)\n')
        files = [{'path': file.relative_to(source).as_posix(), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}
                 for file in sorted(source.rglob('*')) if file.is_file()]
        hashes = {item['path']: item['sha256'] for item in files}
        subject = root / 'subject.json'
        subject.write_text(json.dumps({'sha256': 'a' * 64, 'files': files}))
        definition = {'tool': 'ppi-perl', 'version': '1.0.0', 'operator': 'keyword_if', 'start': 0, 'end': 2, 'original': 'if', 'replacement': 'unless'}
        mutant = {'id': 'scripts/conditional.pl#0:keyword_if', 'file': 'scripts/conditional.pl',
                  'source_sha256': hashes['scripts/conditional.pl'], 'definition': definition,
                  'definition_sha256': hashlib.sha256(proof.canonical(definition)).hexdigest()}
        operator_sha = hashes['quality/perl-operators.json']
        rows = []
        for name, kind in [('scripts/comment.pl', 'PPI::Token::Comment'), ('scripts/conditional.pl', 'PPI::Token::Word')]:
            raw = (source / name).read_bytes()
            data = {'schema_version': 1, 'parser_version': '1.291', 'source_sha256': hashes[name],
                    'tokens': [{'class': kind, 'start': 0, 'end': len(raw), 'content': raw.decode()}]}
            content = proof.canonical(data) + b'\n'
            token_name = 'tokens/' + name + '.json'
            (state / 'perl-generation' / token_name).write_bytes(content)
            rows.append({'source': name, 'source_sha256': hashes[name],
                         'mutant_ids': [mutant['id']] if name == mutant['file'] else [],
                         'tokens': {'path': token_name, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}})
        plan = {'scope_complete': True, 'source_tree_sha256': 'a' * 64, 'outcomes': [], 'baseline': {},
                'operator_sha256': operator_sha, 'sources': {item['source']: item['source_sha256'] for item in rows},
                'scheduled': 1, 'inventory': [mutant]}
        plan['tests'] = {name: fingerprint for name, fingerprint in hashes.items() if name.startswith('tests/')}
        plan['case_inventory'] = {suite: [{'id': Path(name).stem + '.Suite.test_one', 'source': name, 'source_sha256': hashes[name]}]
                                  for suite, name in [('bridge', 'tests/domain/perl/test_bridge.py'), ('tool', 'tests/mutation/test_perl_inventory.py')]}
        coverage = {}
        for row in rows:
            name = row['source']
            raw = (source / name).read_bytes()
            token_data = json.loads((state / 'perl-generation' / row['tokens']['path']).read_bytes())
            spec = importlib.util.spec_from_file_location('coverage_fixture_generator', source / 'scripts/quality/perl-mutation.py')
            generator = importlib.util.module_from_spec(spec); spec.loader.exec_module(generator)
            coverage[name] = []
            generator.inventory(raw, name, token_data, json.loads((source / 'quality/perl-operators.json').read_bytes()), coverage[name])
        plan['operator_coverage'] = coverage
        manifest = {'schema_version': 1, 'qualification': 'complete-ppi-token-materialization-no-outcomes',
                    'source_tree_sha256': 'a' * 64, 'parser_release': 'PPI-1.291', 'operator_sha256': operator_sha, 'operator_coverage': coverage, 'sources': rows}
        (state / 'perl-schedule.json').write_text(json.dumps(plan))
        (state / 'perl-generation/manifest.json').write_text(json.dumps(manifest))
        return source, state, subject, plan, manifest

    def test_reconstructs_exact_definition_and_zero_mutant_source_without_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            source, state, subject, plan, _ = self.fixture(Path(directory))
            result = proof.prove(source, state, subject)
            self.assertEqual(result['inventory'], [{key: plan['inventory'][0][key] for key in ('id', 'file', 'source_sha256', 'definition_sha256')}])
            self.assertEqual([item['mutant_ids'] for item in result['source_materializations']], [[], ['scripts/conditional.pl#0:keyword_if']])
            self.assertEqual(len(result['raw_artifacts']), 4)
            self.assertNotIn('outcomes', result)

    def test_rejects_truncation_supplied_outcomes_and_omitted_zero_source(self):
        for change in ('truncate', 'outcomes', 'zero-source'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                source, state, subject, plan, manifest = self.fixture(Path(directory))
                if change == 'truncate':
                    plan['inventory'] = []; plan['scheduled'] = 0
                elif change == 'outcomes':
                    plan['outcomes'] = [{'status': 'Killed'}]
                else:
                    manifest['sources'].pop(0)
                (state / 'perl-schedule.json').write_text(json.dumps(plan))
                (state / 'perl-generation/manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    proof.prove(source, state, subject)

    def test_complete_discoverer_traversal_order_is_canonicalized_but_duplicates_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, state, subject, _, manifest = self.fixture(Path(directory))
            original = proof.prove(source, state, subject)
            manifest['sources'].reverse()
            (state / 'perl-generation/manifest.json').write_text(json.dumps(manifest))
            reordered = proof.prove(source, state, subject)
            self.assertEqual(reordered['inventory'], original['inventory'])
            self.assertEqual(reordered['inventory_sha256'], original['inventory_sha256'])
            self.assertEqual(reordered['source_materializations'], original['source_materializations'])
            manifest['sources'][1] = manifest['sources'][0]
            (state / 'perl-generation/manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'omitted, duplicated or unexpected'):
                proof.prove(source, state, subject)

    def test_rejects_forged_tokens_and_symlinked_raw_evidence(self):
        for change in ('tokens', 'symlink'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                source, state, subject, _, manifest = self.fixture(Path(directory))
                row = manifest['sources'][1]
                file = state / 'perl-generation' / row['tokens']['path']
                raw = file.read_bytes()
                if change == 'tokens':
                    data = json.loads(raw); data['tokens'][0]['content'] = 'or'; raw = proof.canonical(data)
                    file.write_bytes(raw); row['tokens'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    (state / 'perl-generation/manifest.json').write_text(json.dumps(manifest))
                else:
                    outside = Path(directory) / 'outside.json'; outside.write_bytes(raw)
                    file.unlink(); file.symlink_to(outside)
                # Exercise the actual Windows fallback with real handles on
                # every platform, rather than relying on POSIX ELOOP.
                with patch.object(proof.os, 'O_NOFOLLOW', 0, create=True), self.assertRaises((ValueError, OSError)):
                    proof.prove(source, state, subject)


if __name__ == '__main__':
    unittest.main()
