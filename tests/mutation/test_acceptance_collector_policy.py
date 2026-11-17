"""Portable request-policy tests, not a claim of native kernel isolation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('acceptance_collection_policy',ROOT/'scripts/quality/secondary-child.py')
child=importlib.util.module_from_spec(spec);spec.loader.exec_module(child)


class AcceptanceCollectionPolicyTests(unittest.TestCase):
    def test_only_the_full_pristine_catalog_request_is_admitted(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);request={'schema_version':1,'runner':'acceptance-collect','selection':'all','mutation':None}
            self.assertEqual(child.prepare(request,root),('acceptance-collect','all'))
            for change in ({'selection':'tests/selected.py'},{'mutation':{'path':'script.py'}},{'schema_version':True},{'runner':'shell-collect'},{'extra':'command'}):
                with self.subTest(change=change),self.assertRaises(ValueError):child.prepare({**request,**change},root)
            self.assertEqual(list(root.iterdir()),[])


if __name__=='__main__':unittest.main()
