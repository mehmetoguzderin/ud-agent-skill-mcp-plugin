"""Pristine bridge results independently cover comparator/file/conditional use."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_graph_bridge import FAKE
from test_repository_bridge import FIXTURE

ROOT=Path(__file__).resolve().parents[3]

class PerlOperatorSemanticsTests(unittest.TestCase):
    def call(self,bridge,library,payload,modules):
        for name,content in modules.items():(library/name).write_text(content)
        perl=os.environ.get('UD_AGENT_PERL')or shutil.which('perl')or'/usr/bin/perl'
        value=subprocess.run([perl,'-I',str(library),str(ROOT/'workers/ud/src/ud_agent/perl'/bridge)],input=json.dumps(payload).encode(),capture_output=True,timeout=10,env={**os.environ,'PERL5OPT':'','PERL5LIB':''})
        self.assertEqual(value.returncode,0,'pristine valid bridge request must complete before protocol comparison')
        return value

    def test_numeric_node_and_edge_order_and_lexical_relation_ties_are_independent_of_insertion(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);request={'operation':'inspect_enhanced','nodes':['10','3','2','1'],'edges':[{'head':'10','dependent':'3','relation':'zeta'},{'head':'2','dependent':'3','relation':'zeta'},{'head':'2','dependent':'3','relation':'alpha'},{'head':'1','dependent':'3','relation':'beta'}]}
            result=self.call('graph_bridge.pl',root,request,{'Graph.pm':FAKE,'Node.pm':'1;\n'})
            expected={'ok':True,'nodes':[{'id':'0','in_degree':0,'out_degree':0,'incoming':[]},{'id':'1','in_degree':0,'out_degree':1,'incoming':[]},{'id':'2','in_degree':0,'out_degree':2,'incoming':[]},{'id':'3','in_degree':4,'out_degree':0,'incoming':[{'head':'1','relation':'beta'},{'head':'2','relation':'alpha'},{'head':'2','relation':'zeta'},{'head':'10','relation':'zeta'}]},{'id':'10','in_degree':0,'out_degree':1,'incoming':[]}]}
            self.assertEqual(result.stdout,json.dumps(expected,sort_keys=True,separators=(',',':')).encode())

    def test_documentation_regular_file_and_exact_content_publish_zero_and_nonzero_incident_truth(self):
        for kind in ['file','directory','absent']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as folder:
                root=Path(folder);docs=root/'docs/_en';docs.mkdir(parents=True);layout=root/'layout';layout.mkdir();source=docs/'index.md';content=b'original documentation\r\n'
                if kind=='file':source.write_bytes(content)
                elif kind=='directory':source.mkdir()
                request={'repository_name':'UD_English-Sample','languages_path':str(root/'languages.yaml'),'layout_root':str(layout),'docs_path':str(root/'docs'),'check_families':['documentation']}
                result=self.call('repository_bridge.pl',root,request,{'udlib.pm':FIXTURE})
                expected={'reports':[{'family':'documentation','passed':kind=='file','error_count':0 if kind=='file'else 1,'incidents':[]if kind=='file'else['missing documentation']}]}
                self.assertEqual(result.stdout,json.dumps(expected,sort_keys=True,separators=(',',':')).encode())
                if kind=='file':self.assertEqual((layout/'docs/_en/index.md').read_bytes(),content)
                else:self.assertFalse((layout/'docs/_en/index.md').exists())

if __name__=='__main__':unittest.main()
