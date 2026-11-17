import importlib.util
from pathlib import Path
import unittest
import hashlib
import tempfile
from copy import deepcopy
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_rust_literal_test',ROOT/'scripts/quality/rust-literal.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class RustLiteralTests(unittest.TestCase):
    def test_original_compiler_queries_cover_every_target_and_both_profiles_before_outcomes(self):
        commands=[]
        def run(command):
            commands.append(command)
            return SimpleNamespace(returncode=0,stderr='',stdout='unix\ntarget_os="linux"\n'+('test\n'if command[-1]=='--test'else''))
        generation=runner.issue_cfg_generation('a'*64,'b'*64,'c'*64,run)
        self.assertEqual(len(commands),12)
        self.assertEqual([(row['target'],row['mode'])for row in generation['records']],[(target,mode)for target in runner.TARGETS for mode in('normal','test')])
        for row in generation['records']:
            expected=['/opt/mutation/rust/bin/rustc','--print','cfg','--target',row['target']]+(['--test']if row['mode']=='test'else[])
            self.assertEqual(row['command'],expected)
            definition={key:value for key,value in row.items()if key!='generation_sha256'}
            self.assertEqual(row['generation_sha256'],hashlib.sha256(runner.canonical(definition).encode()).hexdigest())
        self.assertEqual(generation['source_tree_sha256'],'a'*64)
        for failed in[SimpleNamespace(returncode=1,stderr='',stdout='unix\n'),SimpleNamespace(returncode=0,stderr='warning',stdout='unix\n'),SimpleNamespace(returncode=0,stderr='',stdout='unix'),SimpleNamespace(returncode=0,stderr='',stdout='x'*1024**2+'\n')]:
            with self.assertRaises(ValueError):runner.issue_cfg_generation('a'*64,'b'*64,'c'*64,lambda _:failed)
    def test_independent_workspace_paths_are_normalized_without_losing_upstream_definition(self):
        file='src/main.rs';raw={'file':file,'name':file+':8:5: original','package':'ud-rust-assertion-parser','diff':'--- '+file+'\n+++ original\n','span':{'start':{'line':8,'column':5},'end':{'line':8,'column':6}},'replacement':'false'}
        manifest='scripts/quality/rust-assertion-parser/Cargo.toml';workspaces={manifest:{'cwd':'scripts/quality/rust-assertion-parser','package':'ud-rust-assertion-parser'}}
        normalized=runner.normalize_definition(raw,manifest,workspaces)
        self.assertEqual(normalized['file'],'scripts/quality/rust-assertion-parser/src/main.rs');self.assertEqual(normalized['upstream_definition'],raw);self.assertEqual(normalized['workspace_manifest'],manifest);self.assertTrue(normalized['diff'].startswith('--- '+normalized['file']+'\n'));self.assertTrue(normalized['name'].startswith(normalized['file']+':'))
        for changed in [{'file':'../outside.rs'},{'package':'foreign'},{'name':'different:8:5'}]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):runner.normalize_definition({**raw,**changed},manifest,workspaces)

    def test_source_copy_rejects_escape_duplicates_and_symlinked_ancestors(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);source=root/'source';source.mkdir();(source/'file.rs').write_bytes(b'fn main(){}')
            entry={'path':'file.rs','sha256':hashlib.sha256(b'fn main(){}').hexdigest(),'executable':False}
            receipt={'copy':str(source),'files':[entry]}
            runner.copy_source(receipt,root/'valid');self.assertEqual((root/'valid/file.rs').read_bytes(),b'fn main(){}')
            for index,name in enumerate(['../escape','/absolute','a//b','a/./b','C:drive','a\\b','e\u0301']):
                with self.subTest(name=name),self.assertRaises(ValueError):runner.copy_source({**receipt,'files':[{**entry,'path':name}]},root/f'bad-{index}')
            with self.assertRaises(ValueError):runner.copy_source({**receipt,'files':[entry,entry]},root/'duplicate')
    def test_non_default_security_results_use_a_type_correct_error_operator(self):
        source=b'fn owned() -> io::Result<Dir> {\n    Ok(original)\n}\n'
        item={'file':'guard.rs','name':'original','genre':'FnValue','function':{'return_type':'-> io::Result<Dir>'},'replacement':'Ok(Default::default())','span':{'start':{'line':2,'column':5},'end':{'line':2,'column':17}},'diff':'original diff'}
        for returns,replacement,expected in [
            ('-> io::Result<Dir>','Ok(Default::default())','Err(std::io::Error::other("mutation error return").into())'),
            ('-> io::Result<Vec<Entry>>','Ok(vec![Default::default()])','Err(std::io::Error::other("mutation error return").into())'),
            ('-> io::Result<Option<Identity>>','Ok(Some(Default::default()))','Err(std::io::Error::other("mutation error return").into())'),
            ('-> io::Error','Default::default()','std::io::Error::other("mutation error return")')]:
            with self.subTest(returns=returns):
                original={**item,'replacement':replacement,'function':{'return_type':returns}}
                repaired=runner.definition(original,source)
                self.assertEqual(repaired['replacement'],expected)
                self.assertEqual(repaired['operator_repair']['original_definition'],original)
                self.assertIn('Ok(original)',repaired['diff'])
                self.assertIn(expected,repaired['diff'])
        operator={**item,'genre':'BinaryOperator','replacement':'=='}
        self.assertEqual(runner.definition(operator,source),operator)

    def test_rust_byte_spans_reject_unicode_slices_and_empty_locations(self):
        source='//é\nfalse\n'.encode()
        self.assertEqual(runner.offsets(source,{'start':{'line':2,'column':1},'end':{'line':2,'column':6}}),(5,10))
        with self.assertRaises(UnicodeDecodeError):runner.offsets(source,{'start':{'line':1,'column':3},'end':{'line':1,'column':4}})
        with self.assertRaises(ValueError):runner.offsets(source,{'start':{'line':2,'column':6},'end':{'line':2,'column':1}})

    def test_cast_comparisons_repair_both_actual_discovered_operator_forms_as_data(self):
        cases=[
            ('packages/launcher/src/linux_setup.rs',39,65,66,46,'>',
             b'    if bytes.len() as u64 != before.len() || bytes.len() as u64 > limit || before.len() != after.len() {}\n',
             b'    if bytes.len() as u64 != before.len() || (bytes.len() as u64) < limit || before.len() != after.len() {}\n',
             '(bytes.len() as u64) <','pin_file'),
            ('packages/launcher/src/stream_unix.rs',90,36,38,21,'>=',
             b'    if bytes < 0 || bytes as usize >= std::mem::size_of_val(&members) {}\n',
             b'    if bytes < 0 || (bytes as usize) < std::mem::size_of_val(&members) {}\n',
             '(bytes as usize) <','group_members'),
        ]
        for file,line,column,end_column,cast_column,operator,before,after,replacement,function in cases:
            with self.subTest(file=file):
                source=b'\n'*(line-1)+before
                upstream={'file':file,'name':f'{file}:{line}:{column}: replace {operator} with < in {function}',
                          'genre':'BinaryOperator','replacement':'<','span':{'start':{'line':line,'column':column},'end':{'line':line,'column':end_column}},'diff':'retained original upstream diff'}
                item={**upstream,'workspace_manifest':'Cargo.toml','upstream_definition':deepcopy(upstream),'raw_id':'retained-raw-id'}
                original=deepcopy(item);repaired=runner.definition(item,source)
                self.assertEqual(repaired['replacement'],replacement)
                self.assertEqual(repaired['span'],{'start':{'line':line,'column':cast_column},'end':{'line':line,'column':end_column}})
                start,end=runner.offsets(source,repaired['span'])
                self.assertEqual(source[:start]+repaired['replacement'].encode()+source[end:],b'\n'*(line-1)+after)
                self.assertEqual(repaired['operator_repair'],{'version':'ud-parenthesized-cast-comparison-1','original_definition':original})
                self.assertEqual(repaired['upstream_definition'],upstream)
                self.assertEqual(repaired['raw_id'],'retained-raw-id')
                self.assertEqual(repaired['name'],original['name']+' [ud-parenthesized-cast-comparison-1]')
                self.assertIn('-'+before.decode(),repaired['diff']);self.assertIn('+'+after.decode(),repaired['diff'])
                self.assertEqual(item,original)
                self.assertEqual(runner.definition(repaired,source),repaired)

    def test_cast_repair_preserves_utf8_byte_coordinates_and_exact_other_bytes(self):
        source='// é漢🙂\nfn f(){ let s="é漢🙂"; if bytes.len() as u64 > limit {} }\n'.encode()
        item={'file':'fixture.rs','name':'fixture.rs:2:50: replace > with < in f','genre':'BinaryOperator','replacement':'<',
              'span':{'start':{'line':2,'column':50},'end':{'line':2,'column':51}},'diff':'original'}
        repaired=runner.definition(item,source)
        self.assertEqual(repaired['span'],{'start':{'line':2,'column':31},'end':{'line':2,'column':51}})
        self.assertEqual(runner.offsets(source,repaired['span']),(43,63))
        start,end=runner.offsets(source,repaired['span'])
        self.assertEqual(source[:start]+repaired['replacement'].encode()+source[end:],
                         '// é漢🙂\nfn f(){ let s="é漢🙂"; if (bytes.len() as u64) < limit {} }\n'.encode())

    def test_parenthesized_noncast_and_unsupported_operands_stay_exact_and_stale_spans_refuse(self):
        for text in ['if (bytes.len() as u64) > limit {}','if count > limit {}','if *count as usize > limit {}','if count + 1 as usize > limit {}']:
            with self.subTest(text=text):
                source=text.encode();column=source.index(b'>')+1
                item={'file':'fixture.rs','name':f'fixture.rs:1:{column}: replace > with < in f','genre':'BinaryOperator','replacement':'<',
                      'span':{'start':{'line':1,'column':column},'end':{'line':1,'column':column+1}},'diff':'original'}
                self.assertEqual(runner.definition(item,source),item)
        source=b'if bytes as usize > limit {}';column=source.index(b'>')+1
        item={'file':'fixture.rs','name':f'fixture.rs:1:{column}: replace > with < in f','genre':'BinaryOperator','replacement':'<',
              'span':{'start':{'line':1,'column':column},'end':{'line':1,'column':column+1}},'diff':'original'}
        self.assertEqual(runner.definition({**item,'replacement':'=='},source),{**item,'replacement':'=='})
        for data,altered in [(source.replace(b'>',b'<'),item),(source,{**item,'name':item['name'].replace('replace >','replace >=')}),
                             (source,{**item,'span':{'start':{'line':1,'column':column-1},'end':{'line':1,'column':column}}})]:
            with self.subTest(data=data,item=altered),self.assertRaisesRegex(ValueError,'differs from its source span'):
                runner.definition(altered,data)

    def test_only_complete_assertion_failures_are_kills(self):
        assertion="thread 'case' panicked at src/main.rs:3:2:\nassertion failed: result.is_ok()\ntest result: FAILED. 2 passed; 1 failed; 0 ignored\n"
        self.assertTrue(runner.assertion_evidence(assertion)['valid'])
        for log in [assertion.replace('assertion failed: result.is_ok()',"called `Result::unwrap()` on an `Err` value"),assertion.replace('1 failed','2 failed'),assertion.replace('0 ignored','1 ignored'),assertion+'thread \'other\' panicked at x:1:1:\nindex out of bounds\n']:
            self.assertFalse(runner.assertion_evidence(log)['valid'])
        self.assertTrue(runner.baseline_evidence('test result: ok. 3 passed; 0 failed; 0 ignored\n'))
        self.assertFalse(runner.baseline_evidence('test result: ok. 0 passed; 0 failed; 0 ignored\n'))
        self.assertFalse(runner.baseline_evidence('test result: ok. 3 passed; 0 failed; 1 ignored\n'))


if __name__=='__main__':unittest.main()
