"""Independent observed-feature and exact-text comparison tables."""
from pathlib import Path
import tempfile
import unittest
from ud_agent import wire


def sentence(identity,text,rows=None):
    metadata='# sent_id = '+identity+'\n'+(''if text is None else '# text = '+text+'\n')
    return metadata+(rows or '1\tword\t_\tNOUN\t_\t_\t0\troot\t_\t_\n')+'\n'


def where(file,identity,ordinal=0):return {'file_path':file,'sent_id':identity,'ordinal':ordinal}


class ComparisonDefinitions(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='ud-comparison-definitions-');self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        (self.root/'main.conllu').write_text(sentence('a','Straße  CAT')+sentence('b','STRASSE CAT')+sentence('c',None)+sentence('d','é')+sentence('e','e\u0301'))
        (self.root/'peer').mkdir();(self.root/'peer/data.conllu').write_text(sentence('peer','STRASSE CAT')+sentence('absent',None))
        self.args={'working_tree_path':str(self.root),'file_paths':['main.conllu']}

    def result(self,operation,args):
        response=wire.process({'operation':operation,'arguments':args})
        if response.get('error',{}).get('code')=='WORKER_FAILED':raise RuntimeError('unexpected comparison implementation failure')
        self.assertIs(response.get('ok'),True,repr(response));self.assertIsInstance(response.get('result'),dict);return response['result']

    def invalid(self,operation,args,message):
        response=wire.process({'operation':operation,'arguments':args})
        if response.get('error',{}).get('code')=='WORKER_FAILED':raise RuntimeError('unexpected comparison implementation failure')
        self.assertIs(response.get('ok'),False);self.assertEqual(response.get('error'),{'code':'INVALID_INPUT','message':message})

    def test_exact_matching_options_are_independent_and_do_not_normalize_unicode(self):
        missing=[where('main.conllu','c',2)]
        for options in [None,{}, {'casefold':True},{'normalize_whitespace':True}]:
            report=self.result('duplicate_report',{**self.args,'matching_options':options});self.assertEqual(report['groups'],[]);self.assertEqual(report['missing_text'],missing)
        report=self.result('duplicate_report',{**self.args,'matching_options':{'casefold':True,'normalize_whitespace':True}})
        self.assertEqual(report,{'groups':[{'text':'strasse cat','occurrences':[where('main.conllu','a'),where('main.conllu','b',1)]}], 'missing_text':missing,
            'method':{'source':'text metadata','casefold':True,'normalize_whitespace':True},'limitations':['Exact text matching does not establish plagiarism or semantic contamination.']})

    def test_peer_matches_preserve_all_evidence_and_never_infer_missing_metadata(self):
        report=self.result('overlap_report',{**self.args,'peer_treebank_paths':['peer'],'matching_options':{'casefold':True,'normalize_whitespace':True}})
        self.assertEqual(report,{'matches':[{'peer_treebank':'peer','text':'strasse cat','left':[where('main.conllu','a'),where('main.conllu','b',1)],'right':[where('data.conllu','peer')]}],
            'missing_text':[{'treebank':'.',**where('main.conllu','c',2)},{'treebank':'peer',**where('data.conllu','absent',1)}],
            'method':{'source':'text metadata','casefold':True,'normalize_whitespace':True},'limitations':['Exact text matching does not establish plagiarism or semantic contamination.']})

    def test_matching_and_peer_shape_diagnostics_are_explicit(self):
        for options in [[],True,{'unsupported':True}]:self.invalid('duplicate_report',{**self.args,'matching_options':options},'unsupported matching_options')
        for options in [{'casefold':1},{'normalize_whitespace':'true'}]:self.invalid('duplicate_report',{**self.args,'matching_options':options},'matching options must be boolean')
        for peers in ['peer',[1],{'x':1}]:self.invalid('overlap_report',{**self.args,'peer_treebank_paths':peers},'peer_treebank_paths must be an array of paths')
        self.invalid('overlap_report',self.args,'at least one peer treebank is required')
        self.invalid('overlap_report',{**self.args,'peer_treebank_paths':['main.conllu']},'peer treebank must be a staged directory')
        (self.root/'empty').mkdir();self.invalid('overlap_report',{**self.args,'peer_treebank_paths':['empty']},'peer treebank contains no CoNLL-U files: empty')

    def test_feature_value_counts_use_individual_values_on_integer_words_only(self):
        rows='1-2\tAB\t_\t_\t_\tNumber=Dual\t_\t_\t_\t_\n1\tA\ta\tNOUN\t_\tCase=Nom|Number=Plur,Sing\t0\troot\t_\t_\n1.1\tghost\t_\tX\t_\tNumber=Dual\t_\t_\t0:root\t_\n2\tB\tb\tVERB\t_\tNumber=Sing\t1\tdep\t_\t_\n3\tC\tc\tNOUN\t_\t_\t1\tobj\t_\t_\n'
        (self.root/'main.conllu').write_text(sentence('features','ABC',rows))
        (self.root/'peer/data.conllu').write_text(sentence('peer','P','1\tP\tp\tPRON\t_\tNumber=Dual\t0\troot\t_\t_\n'))
        self.assertEqual(self.result('feature_value_report',{**self.args,'peer_treebank_paths':['peer'],'feature_name':'Number'}),{'feature':'Number','corpora':[
            {'treebank':'.','words':3,'missing_feature':1,'values':[{'value':'Plur','count':1},{'value':'Sing','count':2}]},
            {'treebank':'peer','words':1,'missing_feature':0,'values':[{'value':'Dual','count':1}]}], 'definition':'counts individual feature values on integer-ID words'})
        self.assertEqual(self.result('conventions_compare',{**self.args,'peer_treebank_paths':['peer'],'dimensions':['features','deprel','upos']}),{'corpora':[
            {'treebank':'.','dimensions':{'features':{'Case=Nom':1,'Number=Plur':1,'Number=Sing':2},'deprel':{'dep':1,'obj':1,'root':1},'upos':{'NOUN':2,'VERB':1}}},
            {'treebank':'peer','dimensions':{'features':{'Number=Dual':1},'deprel':{'root':1},'upos':{'PRON':1}}}], 'dimensions':['features','deprel','upos'], 'limitations':['Counts describe observed annotation; they do not establish registered language rules.']})
        for value in ['',None,1,[]]:self.invalid('feature_value_report',{**self.args,'feature_name':value},'feature_name must be a nonempty string')
        for value in [[],None,['unknown'],['upos',1]]:self.invalid('conventions_compare',{**self.args,'dimensions':value},'dimensions must be a nonempty array of upos, deprel or features')


if __name__=='__main__':unittest.main()
