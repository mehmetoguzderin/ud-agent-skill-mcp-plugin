"""Trusted authored-code unit probes; production admission requires fresh OCI jobs."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from ud_agent.errors import WorkerError
from ud_agent.project_rules import run_project_rules, MAX_PROJECT_MODULE

SOURCE = '''import json
from udtools import Validator
class Incident:
 def __init__(self,value): self.value=value
 def json(self): return json.dumps(self.value)
class State:
 def __init__(self,value): self.error_tracker=[Incident(value)]
 def passed(self): return False
class Project(Validator):
 def __init__(self,**settings): self.settings=settings
 def validate_files(self,files):
  return State({'message':'project incident','files':files,'lang':self.settings['lang'],'level':self.settings['level'],'max_store':self.settings['max_store'],'output':self.settings['output'],'datapath':self.settings['datapath']})
'''


class ProjectRulesTests(unittest.TestCase):
    def successful(self,arguments):
        try: result=run_project_rules(arguments)
        except WorkerError as error: self.fail('valid trusted project fixture was rejected: '+error.code+' '+str(error))
        self.assertIsInstance(result,dict)
        for name,kind in {'passed':bool,'incidents':list,'scope':dict,'coverage':dict,'provenance':dict,'limitations':list}.items():
            self.assertIn(name,result);self.assertIsInstance(result[name],kind)
        for name,kind in {'validator_module_path':str,'validator_class_name':str,'source_sha256':str}.items():
            self.assertIn(name,result['provenance']);self.assertIsInstance(result['provenance'][name],kind)
        self.assertRegex(result['provenance']['source_sha256'],r'^[0-9a-f]{64}$')
        for name in ['content','repository','documentation','project_rules','release_policy']:
            self.assertIn(name,result['coverage']);self.assertIsInstance(result['coverage'][name],str)
        for item in result['limitations']:self.assertIsInstance(item,str)
        return result

    def failure(self,arguments,code,message=None):
        try:run_project_rules(arguments)
        except WorkerError as error:
            self.assertEqual(error.code,code)
            if message is not None:self.assertEqual(str(error),message)
            return error
        self.fail('invalid project request unexpectedly completed: '+code)

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ud-project-rules-');self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve(strict=True)
        (self.root/'data.conllu').write_text('# sent_id = project\n1\tA\t_\tNOUN\t_\t_\t0\troot\t_\t_\n\n', newline="")
        self.rules=self.root/'rules';self.rules.mkdir()
        for name in ('upos','feats','udeprels','deprels','edeprels','data','tospace'):(self.rules/(name+'.json')).write_text('{}', newline="")
        self.args={'working_tree_path':str(self.root),'file_paths':['data.conllu'],'validator_module_path':'project.py','validator_class_name':'Project','ud_context_path':str(self.rules),'options':{'language_code':'en','level':3}}
        self.module=self.root/'project.py';self.module.write_text(SOURCE, newline="")
        before=list(sys.path);self.addCleanup(lambda:sys.path.__setitem__(slice(None),before))

    def test_actual_upstream_subclass_runs_and_binds_complete_project_only_identity(self):
        before=list(sys.path);result=self.successful(self.args)
        self.assertEqual(sys.path,before)
        self.assertFalse(result['passed'])
        self.assertEqual(result['incidents'],[{'message':'project incident','files':[str(self.root/'data.conllu')],'lang':'en','level':3,'max_store':0,'output':None,'datapath':str(self.rules)}])
        self.assertEqual(result['scope'],{'file_paths':['data.conllu'],'sentence_only':False,'filtered':False})
        self.assertEqual(result['coverage'],{'content':'project_checks_only','repository':'not_requested','documentation':'not_requested','project_rules':'completed','release_policy':'not_requested'})
        self.assertEqual(result['provenance'],{'validator_module_path':'project.py','validator_class_name':'Project','source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest()})
        self.assertEqual(result['limitations'],['Local validation does not certify official online release acceptance.','Project results are not official UD validation; the coordinator must run official validation independently.'])

    def test_project_can_pass_without_impersonating_official_validation(self):
        self.module.write_text(SOURCE.replace('self.error_tracker=[Incident(value)]','self.error_tracker=[]').replace('return False','return True'), newline="")
        result=self.successful(self.args)
        self.assertTrue(result['passed']);self.assertEqual(result['incidents'],[]);self.assertEqual(result['coverage']['content'],'project_checks_only')

    def test_supported_python_identifiers_include_underscore_and_unicode_classes(self):
        for class_name in ['_Project','Πρόγραμμα']:
            source=SOURCE.replace('class Project(Validator):','class '+class_name+'(Validator):');self.module.write_text(source,encoding='utf-8', newline="")
            with self.subTest(class_name=class_name):
                result=self.successful({**self.args,'validator_class_name':class_name})
                self.assertFalse(result['passed']);self.assertEqual(result['incidents'][0]['message'],'project incident')
                self.assertEqual(result['provenance'],{'validator_module_path':'project.py','validator_class_name':class_name,'source_sha256':hashlib.sha256(source.encode()).hexdigest()})

    def test_workspace_directory_suffix_does_not_make_it_a_module_or_admit_parent_code(self):
        workspace=self.root/'workspace.py';workspace.mkdir();shutil.copytree(self.rules,workspace/'rules')
        (workspace/'data.conllu').write_bytes((self.root/'data.conllu').read_bytes());(workspace/'project.py').write_text(SOURCE, newline="")
        # A same-named ordinary parent file is outside the requested workspace.
        self.module.write_text(SOURCE.replace("'project incident'","'parent incident'"), newline="")
        result=self.successful({**self.args,'working_tree_path':str(workspace),'ud_context_path':str(workspace/'rules')})
        self.assertFalse(result['passed']);self.assertEqual(result['incidents'][0]['files'],[str(workspace/'data.conllu')]);self.assertEqual(result['incidents'][0]['message'],'project incident')
        self.assertEqual(result['provenance'],{'validator_module_path':'project.py','validator_class_name':'Project','source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest()})

    def test_explicit_supported_constructor_signature_and_filter_settings_are_forwarded(self):
        source=SOURCE.replace('def __init__(self,**settings): self.settings=settings','def __init__(self,lang,level,datapath,output,max_store): self.settings=dict(lang=lang,level=level,datapath=datapath,output=output,max_store=max_store)')
        self.module.write_text(source, newline="")
        self.assertFalse(self.successful(self.args)['passed'])
        source=SOURCE.replace("'message':'project incident'", "'message':'project incident','check_coref':self.settings['check_coref'],'included':self.settings['args'].include_only,'excluded':self.settings['args'].exclude")
        self.module.write_text(source, newline="")
        result=self.successful({**self.args,'options':{'language_code':'en','level':2,'coref':False,'test_filters':['A'],'exclude_filters':['B']}})
        self.assertEqual(result['incidents'],[{'message':'project incident','check_coref':False,'included':['A'],'excluded':['B'],'files':[str(self.root/'data.conllu')],'lang':'en','level':2,'max_store':0,'output':None,'datapath':str(self.rules)}])
        self.assertEqual(result['scope'],{'file_paths':['data.conllu'],'sentence_only':False,'filtered':True})

    def test_empty_selection_names_paths_and_module_size_fail_before_execution(self):
        for extra in [{'file_paths':[]},{'validator_class_name':'not-a-name'},{'validator_class_name':None},{'validator_module_path':None},{'validator_module_path':'../escape.py'},{'validator_module_path':'source.txt'}]:
            (self.root/'source.txt').write_text('raise RuntimeError("must not execute")', newline="")
            with self.subTest(extra=extra):self.failure({**self.args,**extra},'INVALID_INPUT')
        self.module.write_bytes(b'x'*(MAX_PROJECT_MODULE+1))
        self.failure(self.args,'INVALID_INPUT','project validator module exceeds its size limit')
        self.module.write_text(SOURCE, newline="")
        original=Path.read_bytes
        def growing(path):return b'x'*(MAX_PROJECT_MODULE+1) if path==self.module else original(path)
        with patch.object(Path,'read_bytes',growing):self.failure(self.args,'INVALID_INPUT','project validator module exceeds its size limit')

    def test_unavailable_official_dependency_and_invalid_class_contracts_are_distinct(self):
        with patch.dict(sys.modules,{'udtools':None}):self.failure(self.args,'PREREQUISITE_MISSING')
        for content in ['class Project: pass','Project=7',SOURCE.replace('class Project(Validator):','class Other(Validator):'),SOURCE.replace('def __init__(self,**settings): self.settings=settings','def __init__(self,lang): self.settings={}')]:
            self.module.write_text(content, newline="")
            with self.subTest(content=content):self.failure(self.args,'INVALID_INPUT')

    def test_compilation_runtime_and_incomplete_results_have_controlled_distinct_errors(self):
        for content,code in [('invalid syntax !','PROJECT_VALIDATOR_FAILED'),('raise RuntimeError("private detail")','PROJECT_VALIDATOR_FAILED'),(SOURCE.replace("return State({'message':", "raise RuntimeError({'message':"),'PROJECT_VALIDATOR_FAILED'),(SOURCE.replace('return False','raise ValueError("private detail")'),'VALIDATOR_INCOMPLETE')]:
            self.module.write_text(content, newline="")
            with self.subTest(code=code):
                error=self.failure(self.args,code)
                self.assertNotIn('private detail',str(error))
        self.module.write_text('from ud_agent.errors import WorkerError\nraise WorkerError("PROJECT_CONTROLLED","explicit")', newline="")
        self.failure(self.args,'PROJECT_CONTROLLED','explicit')

    def test_hostile_project_path_removal_cannot_break_finally_or_leak_an_entry(self):
        self.module.write_text('import sys\nsys.path.remove('+repr(str(self.root))+')\n'+SOURCE, newline="")
        before=list(sys.path);result=self.successful(self.args)
        self.assertFalse(result['passed']);self.assertEqual(sys.path,before)

    def test_exact_source_ceiling_and_module_compile_identity_preserve_sibling_precedence(self):
        with tempfile.TemporaryDirectory(prefix='ud-project-ambient-') as temporary:
            ambient=Path(temporary)
            (ambient/'ud_owned_fixture_sibling.py').write_text('TOKEN="ambient"', newline="")
            (self.root/'ud_owned_fixture_sibling.py').write_text('TOKEN="owned"', newline="")
            source=('from ud_owned_fixture_sibling import TOKEN\n'+SOURCE).replace("'message':'project incident'", "'message':'project incident','module_name':__name__,'module_file':__file__,'compile_file':self.validate_files.__code__.co_filename,'sibling':TOKEN")
            raw=source.encode();raw+=b'\n#'+b'x'*(MAX_PROJECT_MODULE-len(raw)-2)
            self.assertEqual(len(raw),MAX_PROJECT_MODULE);self.module.write_bytes(raw)
            sys.path.insert(0,str(ambient))
            old=sys.modules.pop('ud_owned_fixture_sibling',None)
            try: result=self.successful(self.args)
            finally:
                sys.modules.pop('ud_owned_fixture_sibling',None)
                if old is not None:sys.modules['ud_owned_fixture_sibling']=old
            self.assertEqual(result['incidents'],[{'message':'project incident','module_name':'_ud_agent_project_validator','module_file':str(self.module),'compile_file':str(self.module),'sibling':'owned','files':[str(self.root/'data.conllu')],'lang':'en','level':3,'max_store':0,'output':None,'datapath':str(self.rules)}])
            self.assertEqual(result['provenance']['source_sha256'],hashlib.sha256(raw).hexdigest())

    def test_prerequisite_and_guard_diagnostics_are_precise_and_stable(self):
        cases=[({'file_paths':[]},'at least one CoNLL-U file is required'),
               ({'validator_class_name':'invalid-name'},'project validator module and class names are invalid'),
               ({'validator_module_path':'source.txt'},'project validator module must be a Python file')]
        (self.root/'source.txt').write_text('unused', newline="")
        for arguments,message in cases:
            self.failure({**self.args,**arguments},'INVALID_INPUT',message)
        with patch.dict(sys.modules,{'udtools':None}):self.failure(self.args,'PREREQUISITE_MISSING','the official udtools validator is not installed')
        for source,message in [('class Project: pass','project validator class must inherit the official Validator'),
                               (SOURCE.replace('def __init__(self,**settings): self.settings=settings','def __init__(self,lang): self.settings={}'),'project validator does not support requested parameters: datapath, level, max_store, output')]:
            self.module.write_text(source, newline="")
            self.failure(self.args,'INVALID_INPUT',message)
        self.module.write_text('raise RuntimeError("private detail")', newline="")
        self.failure(self.args,'PROJECT_VALIDATOR_FAILED','project validator could not complete')


if __name__=='__main__':unittest.main()
