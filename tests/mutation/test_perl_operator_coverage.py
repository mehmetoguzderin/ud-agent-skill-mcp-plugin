"""Exact PPI-token recipes test operator coverage without executing variants."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('perl_operator_coverage',ROOT/'scripts/quality/perl-mutation.py');M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
OPERATORS=json.loads((ROOT/'quality/perl-operators.json').read_bytes())


def parsed(values):
    source=''.join(content for _,content in values).encode();tokens=[];cursor=0
    for kind,content in values:
        end=cursor+len(content.encode());tokens.append({'class':'PPI::Token::'+kind,'content':content,'start':cursor,'end':end});cursor=end
    return source,{'source_sha256':M.sha(source),'tokens':tokens}


class PerlOperatorCoverageTests(unittest.TestCase):
    def test_match_delimiters_modifiers_and_each_anchor_have_exact_distinct_definitions(self):
        for text,wanted in [
            ('/^x$/',['/x$/','/^x/','/(?:)/']),
            (r'm{^/|^[A-Za-z]:[\\/]}i',[r'm{/|^[A-Za-z]:[\\/]}i',r'm{^/|[A-Za-z]:[\\/]}i','m{(?:)}i']),
            (r'm!\Avalue\z!ms',[r'm!value\z!ms',r'm!\Avalue!ms','m!(?:)!ms']),
            (r'/[\A^$]x\^\$/',['/(?:)/']),
            (r'/\Q^$\E/',['/(?:)/']),
            (r'/[\\]^$/',[r'/[\\]$/',r'/[\\]^/','/(?:)/']),
            ('/[[:alpha:]^$]/',['/(?:)/']),
            ('m(^x$)i',['m(x$)i','m(^x)i','m((?:))i']),
        ]:
            with self.subTest(text=text):
                source,tokens=parsed([('Regexp::Match',text)]);coverage=[];rows=M.inventory(source,'scripts/example.pl',tokens,OPERATORS,coverage)
                self.assertEqual([row['definition']['replacement']for row in rows],wanted)
                self.assertEqual(len({row['id']for row in rows}),len(rows));self.assertEqual(coverage[0]['classification'],'scheduled');self.assertEqual(coverage[0]['mutant_ids'],[row['id']for row in rows])
                self.assertTrue(all(row['definition']['original']==text and row['definition']['start']==0 and row['definition']['end']==len(source)for row in rows))
        anchors=M.regex_anchors('^value # ^not-an-anchor\n$',True)
        self.assertEqual(anchors,[(0,1,'start'),(24,25,'end')])

    def test_live_compare_file_test_concat_and_conditional_rules_preserve_exact_spans(self):
        for original,wanted in [('<=>',['<']),('cmp',['lt']),('-f',['-d']),('-s',['-z']),('.',['||']),('?',['|| 1 ?','&& 0 ?'])]:
            with self.subTest(original=original):
                source,tokens=parsed([('Operator',original)]);rows=M.inventory(source,'scripts/example.pl',tokens,OPERATORS)
                self.assertEqual([row['definition']['replacement']for row in rows],wanted)
                self.assertTrue(all(row['definition']['original']==original for row in rows))
        for text in ['"$value/path"',"'literal'",'""']:
            source,tokens=parsed([('Quote::Double'if text.startswith('"')else'Quote::Single',text)])
            self.assertEqual([row['definition']['replacement']for row in M.inventory(source,'scripts/example.pl',tokens,OPERATORS)],[text[0]+('mutated'if len(text)==2 else'')+text[-1]])

    def test_unimplemented_operator_or_selected_literal_never_becomes_complete(self):
        for kind,text in [('Operator','**'),('Regexp::Match','m?^x$?'),('Regexp::Match','/(?{code})/'),('Number','1.25')]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as folder:
                root=Path(folder);(root/'scripts').mkdir();(root/'quality').mkdir();(root/'quality/perl-operators.json').write_text(json.dumps(OPERATORS))
                source,tokens=parsed([('Word','if'),('Whitespace',' '),(kind,text)]);(root/'scripts/example.pl').write_bytes(source)
                for name in ['tests/domain/perl/test_bridge.py','tests/mutation/test_perl_inventory.py','tests/mutation/test_perl_operator_fixture.py']:
                    file=root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): self.assertEqual(1,1)\n')
                with patch.object(M,'verify_parser',return_value={'parser_release':'PPI-1.291'}),patch.object(M,'tokens',return_value=tokens),patch.object(M,'source_receipt',return_value={'sha256':'a'*64,'files':[]}):
                    report,_=M.schedule(root,root,'/unused/perl',root/'materialization')
                self.assertFalse(report['scope_complete']);self.assertEqual(report['scheduled'],1)
                self.assertEqual(report['operator_coverage']['scripts/example.pl'][-1]['classification'],'unimplemented')
                self.assertIn('tests/mutation/test_perl_operator_fixture.py',report['tests']);self.assertEqual(len(report['case_inventory']['tool']),2)
                manifest=json.loads((root/'materialization/manifest.json').read_bytes());self.assertEqual(manifest['operator_coverage'],report['operator_coverage'])

    def test_independent_generation_rejects_supplied_coverage_labels(self):
        import test_perl_generation_proof as fixtures
        for classification in ['outside-selected-family','unimplemented']:
            with self.subTest(classification=classification),tempfile.TemporaryDirectory()as folder:
                source,state,subject,plan,manifest=fixtures.PerlGenerationProofTests().fixture(Path(folder))
                plan['operator_coverage']['scripts/conditional.pl'][0]['classification']=classification
                (state/'perl-schedule.json').write_text(json.dumps(plan))
                (state/'perl-generation/manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,'classification'):
                    fixtures.proof.prove(source,state,subject)

    def test_structural_tokens_are_explicit_and_all_source_bytes_are_reconciled(self):
        values=[('Operator',value)for value in ['=','->','=>',',',':']]
        source,tokens=parsed(values);coverage=[];self.assertEqual(M.inventory(source,'scripts/example.pl',tokens,OPERATORS,coverage),[])
        self.assertEqual([row['classification']for row in coverage],['structural']*5)
        self.assertEqual(''.join(row['content']for row in coverage).encode(),source)
        broken=copy.deepcopy(tokens);broken['tokens'][1]['start']+=1
        with self.assertRaisesRegex(ValueError,'exactly cover'):M.inventory(source,'scripts/example.pl',broken,OPERATORS,[])

if __name__=='__main__':unittest.main()
