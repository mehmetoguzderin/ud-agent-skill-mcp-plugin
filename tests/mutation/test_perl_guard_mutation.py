from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('perl_guard_mutation', ROOT / 'scripts/quality/perl-guard-mutation.py')
assert spec and spec.loader
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PerlGuardMutationTests(unittest.TestCase):
    def test_inventory_is_deterministic_source_and_definition_bound(self):
        source = b"fail('one') if $a;\nfail('two') unless $b;\n"
        items = runner.inventory(source)
        self.assertEqual(len(items), 2)
        self.assertEqual(items, runner.inventory(source))
        self.assertEqual(items[0]['definition']['replacement'], 'unless')
        self.assertEqual(items[1]['definition']['replacement'], 'if')
        self.assertNotEqual(items[0]['definition_sha256'], items[1]['definition_sha256'])
        self.assertNotEqual(items[0]['source_sha256'], runner.inventory(source + b'\n')[0]['source_sha256'])

    def test_runner_never_counts_errors_timeouts_or_empty_suites_as_kills(self):
        assertion = 'FAIL: test_a (Suite)\nAssertionError: mismatch\nRan 1 test in 0.1s\nFAILED (failures=1)\n'
        def result(output, status=1):
            return {'stdout': '', 'stderr': output, 'status': status}
        self.assertEqual(runner.classify(result(assertion))[0], 'Killed')
        self.assertEqual(runner.classify(result(assertion.replace('FAIL:', 'ERROR:')))[0], 'RuntimeError')
        self.assertEqual(runner.classify(result(assertion.replace('AssertionError:', 'ValueError:')))[0], 'RuntimeError')
        self.assertEqual(runner.classify(result(assertion + "self.assertEqual(result.stderr, b'')\n"))[0], 'RuntimeError')
        self.assertEqual(runner.classify(result('Ran 0 tests in 0.1s\nOK\n', 0))[0], 'RunnerError')
        self.assertEqual(runner.classify({'timeout': True})[0], 'Timeout')

    def test_real_bridge_mutations_require_the_protected_backend_without_host_execution(self):
        bridge = ROOT / runner.BRIDGE
        before = bridge.read_bytes()
        with patch.object(runner.subprocess,'run') as execute:
            with self.assertRaisesRegex(ValueError,'host product mutations are forbidden'):
                runner.run(ROOT, sys.executable)
            execute.assert_not_called()
        self.assertEqual(bridge.read_bytes(), before)

    def test_protected_projection_requires_every_exact_guard_and_preserves_unresolved_outcomes(self):
        source=b"fail('one') if $a;\nfail('two') unless $b;\n";guards=runner.inventory(source);rows=[];outcomes=[]
        for index,item in enumerate(guards):
            definition={**item['definition'],'tool':'ppi-perl','version':'1.0.0','operator':'keyword_'+item['definition']['original']}
            fingerprint=runner.sha(__import__('json').dumps(definition,sort_keys=True,separators=(',',':')).encode());row={**item,'id':'raw-'+str(index),'definition':definition,'definition_sha256':fingerprint};rows.append(row)
            outcomes.append({'id':row['id'],'file':runner.BRIDGE,'definition_sha256':fingerprint,'status':'Killed','failure_kind':'assertion','tests':['independent fixture assertion']})
        report={'tool':'ppi-perl','scope_complete':True,'complete':True,'sources':{runner.BRIDGE:runner.sha(source)},'source_tree_sha256':'a'*64,'baseline':{'bridge':{'status':0,'passed':True},'tool':{'status':0,'passed':True}},'scheduled':len(rows),'inventory':rows,'outcomes':outcomes}
        projected=runner.project_protected(source,b'test fixture',report)
        self.assertTrue(projected['passed']);self.assertFalse(projected['scope_complete']);self.assertEqual(len(projected['outcomes']),len(guards))
        for invalid in [{**report,'complete':False},{**report,'outcomes':outcomes[:-1]},{**report,'inventory':rows[:-1]},{**report,'baseline':{'bridge':{'status':1,'passed':True},'tool':{'status':0,'passed':True}}}]:
            with self.assertRaises(ValueError):runner.project_protected(source,b'test fixture',invalid)
        bad=[{**outcomes[0],'failure_kind':'runtime'},outcomes[1]]
        with self.assertRaisesRegex(ValueError,'exact structured outcome'):runner.project_protected(source,b'test fixture',{**report,'outcomes':bad})
        unresolved=[{**outcomes[0],'status':'RuntimeError','failure_kind':None,'tests':[]},outcomes[1]]
        projected=runner.project_protected(source,b'test fixture',{**report,'outcomes':unresolved})
        self.assertFalse(projected['passed']);self.assertEqual(projected['outcomes'][0]['status'],'RuntimeError')


if __name__ == '__main__':
    unittest.main()
