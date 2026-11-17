from __future__ import annotations

import importlib.util
import json
import hashlib
from html import escape
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name("python_static.py")
spec = importlib.util.spec_from_file_location("ud_mutation_static", MODULE)
assert spec and spec.loader
static = importlib.util.module_from_spec(spec)
spec.loader.exec_module(static)


class StaticMutationTests(unittest.TestCase):
    def test_junit_requires_bound_test_origin_and_never_infers_assertions_from_messages(self):
        source,test_id='tests/test_policy.py','tests/test_policy.py::test_flag';body=b'def test_flag():\n    assert False\n';digest=hashlib.sha256(body).hexdigest()
        origin={'contract':'python-test-source-origin-v2','source':source,'source_sha256':digest,'line':2,'test_id':test_id,'test_source':source,'test_source_sha256':digest,'test_line':2}
        def report(binding):
            properties={'ud-test-id':test_id,'ud-source':source,'ud-source-sha256':digest,'ud-failure-kind':'assertion','ud-exception-type':'builtins.AssertionError','ud-assertion-origin':json.dumps(binding)}
            return '<testsuites><testcase><properties>'+''.join('<property name="'+name+'" value="'+escape(value,quote=True)+'"/>'for name,value in properties.items())+'</properties><failure message="AssertionError: production error">assert False</failure></testcase></testsuites>'
        with tempfile.TemporaryDirectory()as temp:
            (Path(temp)/'tests').mkdir();(Path(temp)/source).write_bytes(body)
            file=Path(temp)/'junit.xml';file.write_text(report(origin))
            self.assertEqual(static._junit(file,{source:digest},Path(temp)),(1,1,0,0))
            for changed in[{**origin,'source':'scripts/production.py'},{**origin,'source_sha256':'b'*64},{**origin,'test_id':'foreign'},{**origin,'line':0},{**origin,'line':3},{}]:
                file.write_text(report(changed));self.assertEqual(static._junit(file,{source:digest},Path(temp)),(1,0,1,0))

    def test_module_inventory_is_data_only_and_host_execution_is_refused_without_changing_bytes(self):
        with tempfile.TemporaryDirectory(prefix="static-mutation-test-") as temp:
            root = Path(temp)
            package = root / "workers/ud/src/ud_agent"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("")
            source = package / "policy.py"
            source.write_text("FLAG = True\n")
            tests = root / "tests/domain"
            tests.mkdir(parents=True)
            (tests / "test_policy.py").write_text("from ud_agent.policy import FLAG\ndef test_flag():\n    assert FLAG is True\n")
            output = root / "results.json"
            before = source.read_bytes()
            with patch.dict(os.environ, {"UD_MUTATION_ORIGINAL_ROOT": "/different/original/root"}), patch.object(static.subprocess, "run", side_effect=AssertionError('host variant execution forbidden')) as child:
                with self.assertRaisesRegex(ValueError,'protected OCI coordinator'):
                    static.run(root,output,sys.executable,30,1)
                self.assertFalse(output.exists())
                result=static.run(root,output,sys.executable,30,None,inventory_only=True)
                child.assert_not_called()
            report = json.loads(output.read_text())
            self.assertEqual(result, 0)
            self.assertFalse(report["complete"])
            self.assertEqual(report["scheduled"], 1)
            self.assertTrue(report['inventory_only'])
            self.assertEqual(report['outcomes'],[])
            self.assertEqual(report['inventory'][0]['definition']['replacement'],'False')
            self.assertEqual(source.read_bytes(), before)

    def test_original_tree_cannot_be_mutated(self):
        with tempfile.TemporaryDirectory(prefix="static-mutation-test-") as temp:
            with patch.dict(os.environ, {"UD_MUTATION_ORIGINAL_ROOT": temp}):
                with self.assertRaisesRegex(ValueError, "isolated"):
                    static.run(Path(temp), Path(temp) / "out.json", sys.executable, 30, 1)


if __name__ == "__main__":
    unittest.main()
