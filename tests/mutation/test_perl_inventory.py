from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('perl_full_mutation', ROOT / 'scripts/quality/perl-mutation.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
OPERATORS = json.loads((ROOT / 'quality/perl-operators.json').read_text())


class PerlInventoryTests(unittest.TestCase):
    def test_windows_typed_writer_uses_exclusive_private_acl_authority_and_keeps_bounds(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        spec = importlib.util.spec_from_file_location('typed_perl_windows_writer_fixture', ROOT / 'scripts/quality/perl-test-evidence.py')
        evidence = importlib.util.module_from_spec(spec); spec.loader.exec_module(evidence)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.json'
            def exclusive(filename, kind, raw):
                self.assertEqual((filename, kind), (str(target.absolute()), 'file'))
                with open(filename, 'xb') as stream: stream.write(raw)
            authority = SimpleNamespace(create=Mock(side_effect=exclusive))
            native = SimpleNamespace(WindowsStorage=Mock(return_value=authority))
            selected = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
            with patch.object(evidence, 'os', SimpleNamespace(name='nt')), \
                    patch.object(evidence.importlib.util, 'spec_from_file_location', return_value=selected) as load, \
                    patch.object(evidence.importlib.util, 'module_from_spec', return_value=native):
                evidence.write_result(target, {'complete': True})
                self.assertEqual(target.read_bytes(), b'{"complete":true}\n')
                self.assertEqual(load.call_args.args[1], ROOT / 'scripts/quality/windows-storage-acl.py')
                with self.assertRaises(FileExistsError): evidence.write_result(target, {})
                self.assertEqual(target.read_bytes(), b'{"complete":true}\n')
                calls = authority.create.call_count
                with self.assertRaisesRegex(ValueError, 'bound'):
                    evidence.write_result(target, {'oversized': 'x' * (16 * 1024 * 1024)})
                self.assertEqual(authority.create.call_count, calls)

    def test_pre_outcome_materialization_records_every_parsed_source_including_zero_mutants(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'quality').mkdir()
            (root / 'quality/perl-operators.json').write_text(json.dumps(OPERATORS))
            (root / 'scripts').mkdir()
            (root / 'scripts/conditional.pl').write_bytes(b'if')
            (root / 'scripts/comment.pl').write_bytes(b'# no applicable expression\r\n')
            for directory in ('tests/domain/perl', 'tests/mutation'):
                (root / directory).mkdir(parents=True)
                (root / directory / 'test_perl_inventory.py').write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): self.assertEqual(1,1)\n')
            def parsed(_root, name, *_):
                content = (_root / name).read_bytes()
                return {'schema_version': 1, 'parser_version': '1.291', 'source_sha256': runner.sha(content),
                        'tokens': [{'class': 'PPI::Token::Word' if content == b'if' else 'PPI::Token::Comment',
                                    'content': content.decode(), 'start': 0, 'end': len(content)}]}
            output = root / 'materialization'
            with patch.object(runner, 'verify_parser', return_value={'parser_release': 'PPI-1.291'}), \
                 patch.object(runner, 'tokens', side_effect=parsed), \
                 patch.object(runner, 'source_receipt', return_value={'sha256': 'a' * 64, 'files': []}):
                report, _ = runner.schedule(root, root, '/unused/perl', output)
            self.assertEqual(report['scheduled'], 1)
            manifest = json.loads((output / 'manifest.json').read_bytes())
            self.assertEqual(manifest['qualification'], 'complete-ppi-token-materialization-no-outcomes')
            self.assertEqual([item['source'] for item in manifest['sources']], ['scripts/comment.pl', 'scripts/conditional.pl'])
            self.assertEqual(manifest['sources'][0]['mutant_ids'], [])
            self.assertEqual(manifest['sources'][1]['mutant_ids'], ['scripts/conditional.pl#0:keyword_if'])
            for item in manifest['sources']:
                raw = (output / item['tokens']['path']).read_bytes()
                self.assertEqual(item['tokens']['sha256'], runner.sha(raw))
                self.assertEqual(item['tokens']['size'], len(raw))
                self.assertEqual(json.loads(raw), parsed(root, item['source']))
                self.assertNotIn('outcomes', json.loads(raw))
            self.assertEqual((root / 'scripts/comment.pl').read_bytes(), b'# no applicable expression\r\n')

    def test_real_mutant_execution_requires_the_kernel_confined_coordinator(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {'UD_MUTATION_OCI_GUARD': '0'}):
            with self.assertRaisesRegex(ValueError, 'protected OCI coordinator'):
                runner.run(ROOT, ROOT, '/unused/perl', '/unused/python', ROOT / 'unused-report.json')

    def test_applicable_operator_inventory_is_exact_and_deterministic(self):
        values = [('PPI::Token::Word', 'if'), ('PPI::Token::Whitespace', ' '),
                  ('PPI::Token::Number', '0'), ('PPI::Token::Operator', '=='),
                  ('PPI::Token::Quote::Single', "'value'"), ('PPI::Token::Regexp::Match', r'/\Ax\z/')]
        source = ''.join(value for _, value in values).encode()
        position, tokens = 0, []
        for kind, content in values:
            tokens.append({'class': kind, 'content': content, 'start': position, 'end': position + len(content)})
            position += len(content)
        parsed = {'source_sha256': hashlib.sha256(source).hexdigest(), 'tokens': tokens}
        items = runner.inventory(source, 'scripts/example.pl', parsed, OPERATORS)
        self.assertEqual([(item['definition']['operator'], item['definition']['replacement']) for item in items], [
            ('keyword_if', 'unless'), ('integer_boundary_1', '1'), ('operator_==', '!='), ('string_value', "''"),
            ('regex_remove_start_anchor', r'/x\z/'), ('regex_remove_end_anchor', r'/\Ax/'), ('regex_match_any', '/(?:)/')])
        self.assertEqual(items, runner.inventory(source, 'scripts/example.pl', parsed, OPERATORS))
        self.assertEqual(len({item['id'] for item in items}), len(items))
        broken = {**parsed, 'tokens': [{**tokens[0], 'end': 1}, *tokens[1:]]}
        with self.assertRaisesRegex(ValueError, 'exactly cover'):
            runner.inventory(source, 'scripts/example.pl', broken, OPERATORS)

    def test_only_clean_assertion_failures_count_as_kills(self):
        output = b'FAIL: test_a (Suite)\nAssertionError: expected result\nRan 1 test in 0.1s\nFAILED (failures=1)\n'
        self.assertEqual(runner.classify(subprocess.CompletedProcess([], 1, b'', output)), ('Killed', ['test_a (Suite)']))
        for original in (output, output.replace(b'AssertionError: expected result', b'AssertionError')):
            self.assertEqual(runner.classify(subprocess.CompletedProcess([], 1, b'', original.replace(b'\n', b'\r\n'))), ('Killed', ['test_a (Suite)']))
        for invalid in [output.replace(b'AssertionError', b'ValueError'), output.replace(b'FAIL:', b'ERROR:'),
                        output + b"self.assertEqual(result.stderr, b'')\n"]:
            self.assertEqual(runner.classify(subprocess.CompletedProcess([], 1, b'', invalid))[0], 'RuntimeError')
        self.assertEqual(runner.classify(subprocess.CompletedProcess([], 0, b'', b'Ran 0 tests in 0.1s\nOK\n'))[0], 'RunnerError')

    def test_typed_evidence_distinguishes_real_assertions_errors_skips_and_incomplete_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bridge = root / 'tests/domain/perl/test_typed_fixture.py'
            tool = root / 'tests/mutation/test_perl_inventory.py'
            for file in (bridge, tool):
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): self.assertEqual(1,1)\n')
            for index, (statement, wanted) in enumerate([
                ('self.assertEqual(1,1)', 'Survived'),
                ('self.assertEqual(1,2)', 'Killed'),
                ('raise ValueError("AssertionError: forged output")', 'RuntimeError'),
                ('self.skipTest("required test")', 'RuntimeError'),
            ]):
                bridge.write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): ' + statement + '\n')
                files = {file.relative_to(root).as_posix(): runner.sha(file.read_bytes()) for file in (bridge, tool)}
                expected = runner.test_cases(root, files)['bridge']
                output = root / ('evidence-' + str(index) + '.json')
                completed = subprocess.run([sys.executable, str(ROOT / 'scripts/quality/perl-test-evidence.py'), '--root', str(root), '--suite', 'bridge', '--output', str(output)], capture_output=True, timeout=10, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                completed.unittest_evidence = json.loads(output.read_bytes())
                inventory = [{'path': name, 'sha256': fingerprint} for name, fingerprint in files.items()]
                self.assertEqual(runner.typed_classification(completed, expected, root, inventory)[0], wanted)
                completed.unittest_evidence['cases'][0]['completed'] = False
                self.assertEqual(runner.typed_classification(completed, expected, root, inventory)[0], 'RunnerError')
            with self.assertRaises(FileExistsError):
                spec = importlib.util.spec_from_file_location('typed_perl_result_fixture', ROOT / 'scripts/quality/perl-test-evidence.py')
                evidence = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(evidence)
                evidence.write_result(output, {'replacement': 'must not overwrite'})

    def test_independent_case_discovery_rejects_dynamic_inherited_decorated_and_empty_suites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ['tests/domain/perl/test_bridge.py', 'tests/mutation/test_perl_inventory.py']
            plain = 'import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): self.assertEqual(1,1)\n'
            for name in names:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(plain)
            def inventory():
                return runner.test_cases(root, {name: runner.sha((root / name).read_bytes()) for name in names})
            self.assertEqual(len(inventory()['bridge']), 1)
            for changed in [plain + '\ndef load_tests(*args): return []\n', plain.replace('unittest.TestCase', 'ForeignBase'), plain.replace(' def test_one', ' @unittest.skip("required")\n def test_one'), 'import unittest\n']:
                (root / names[0]).write_text(changed)
                with self.assertRaisesRegex(ValueError, 'discovery|collection'):
                    inventory()

    def test_source_discovery_covers_both_bridges_and_scanner(self):
        files = runner.discover_sources(ROOT)
        self.assertIn('workers/ud/src/ud_agent/perl/graph_bridge.pl', files)
        self.assertIn('workers/ud/src/ud_agent/perl/repository_bridge.pl', files)
        self.assertIn('scripts/quality/perl_tokens.pl', files)

    def test_scanner_protocol_uses_private_parser_and_preserves_bytes(self):
        # The deliberately small parser fixture isolates this owned scanner's
        # protocol. Real PPI parsing and its source identity are checked by the
        # full backend before any mutation is scheduled.
        fixture = r'''
package PPI; our $VERSION = '1.291';
package PPI::Document;
sub new { my ($class, $bytes) = @_; bless {bytes => $$bytes}, $class; }
sub serialize { $_[0]->{bytes} }
sub tokens { return bless({text => $_[0]->{bytes}}, 'PPI::Token::Comment'); }
package PPI::Token::Comment;
sub content { $_[0]->{text} }
sub location { [3, 7] }
1;
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'PPI.pm').write_text(fixture)
            source = root / 'input.pl'
            data = b'# independent source\r\n'
            source.write_bytes(data)
            perl = os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl'
            command = [perl, str(ROOT / 'scripts/quality/perl_tokens.pl'), str(source)]
            env = {**os.environ, 'PERL5LIB': '/nonexistent', 'PERL5OPT': '', 'UD_PERL_PARSER_LIB': str(root)}
            result = subprocess.run(command, capture_output=True, env=env, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b'')
            self.assertEqual(json.loads(result.stdout), {'schema_version': 1, 'parser': 'PPI', 'parser_version': '1.291',
                'source_sha256': hashlib.sha256(data).hexdigest(), 'tokens': [
                    {'class': 'PPI::Token::Comment', 'content': data.decode(), 'start': 0, 'end': len(data), 'line': 3, 'column': 7}]})
            env['UD_PERL_PARSER_LIB'] = 'relative'
            result = subprocess.run(command, capture_output=True, env=env, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), {'ok': False, 'error': 'parser_prerequisite_missing'})
            self.assertIn(b'verified private Perl parser library', result.stderr)

    def test_scanner_reports_each_bounded_failure_and_exact_source_limit(self):
        fixture = r'''package PPI; our $VERSION = '1.291';
package PPI::Document;
sub new { my ($class, $bytes) = @_; bless {bytes => $$bytes}, $class; }
sub serialize { $_[0]->{bytes} }
sub tokens { return bless({text => $_[0]->{bytes}}, 'PPI::Token::Comment'); }
package PPI::Token::Comment;
sub content { $_[0]->{text} }
sub location { [1, 1] }
1;
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser = root / 'PPI.pm'; parser.write_text(fixture)
            source = root / 'input.pl'; source.write_bytes(b'# source\n')
            perl = os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl'
            env = {**os.environ, 'PERL5LIB': '', 'PERL5OPT': '', 'UD_PERL_PARSER_LIB': str(root)}
            def call(arguments):
                return subprocess.run([perl, str(ROOT / 'scripts/quality/perl_tokens.pl'), *arguments], capture_output=True, env=env, timeout=10)
            for arguments, message in [([], b'one source path is required\n'), ([str(root / 'absent')], b'cannot open Perl mutation source\n')]:
                result = call(arguments)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout), {'ok': False, 'error': 'parser_execution_failed'})
                self.assertEqual(result.stderr, (b'Perl parser execution did not complete\n' + message).replace(b'\n', os.linesep.encode()))
            source.write_bytes(b'#' + b' ' * 1048575)
            self.assertEqual(call([str(source)]).returncode, 0)
            source.write_bytes(b'#' + b' ' * 1048576)
            result = call([str(source)])
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, b'Perl parser execution did not complete\nPerl mutation source exceeds its bound\n'.replace(b'\n', os.linesep.encode()))
            source.write_bytes(b'# source\n')
            variants = [
                (fixture.replace('bless {bytes => $$bytes}, $class', 'undef'), b'Perl mutation source could not be parsed\n'),
                (fixture.replace('sub serialize { $_[0]->{bytes} }', 'sub serialize { "changed" }'), b'Perl parser changed source bytes\n'),
                (fixture.replace('sub content { $_[0]->{text} }', 'sub content { "short" }'), b'Perl token inventory does not cover the complete source\n'),
                (fixture.replace('sub serialize { $_[0]->{bytes} }', 'sub serialize { warn "fixture warning"; $_[0]->{bytes} }'), b'parser execution warning\n'),
                (fixture.replace('sub serialize { $_[0]->{bytes} }', 'sub serialize { die(("x" x 5000) . "\\n"); }'), b'x' * 4096),
            ]
            for variant, message in variants:
                with self.subTest(message=message):
                    parser.write_text(variant)
                    result = call([str(source)])
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(json.loads(result.stdout), {'ok': False, 'error': 'parser_execution_failed'})
                    self.assertEqual(result.stderr, (b'Perl parser execution did not complete\n' + message).replace(b'\n', os.linesep.encode()))


if __name__ == '__main__':
    unittest.main()
