"""Independent sentence-reference, passage grammar, and coverage contracts."""
import json
from pathlib import Path
import tempfile
import unittest
from ud_agent import wire


def sentence(identity, text='Visible sentence', form='word'):
    return '# sent_id = '+identity+'\n# text = '+text+'\n1\t'+form+'\t_\tNOUN\t_\t_\t0\troot\t_\t_\n\n'


def location(file, identity, ordinal=0):
    return {'file_path':file,'sent_id':identity,'ordinal':ordinal}


class ParallelDefinitions(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='ud-parallel-definitions-');self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        (self.root/'main.conllu').write_text(sentence('source','Source α')+sentence('second','Second source'),encoding='utf-8')
        (self.root/'peer').mkdir();(self.root/'peer/target.conllu').write_text(sentence('target','Target β'),encoding='utf-8')
        self.args={'working_tree_path':str(self.root),'peer_treebank_paths':['peer'],'alignment_spec_path':'alignment.json'}
        self.source={'treebank':'.','file_path':'main.conllu','sent_id':'source'}
        self.target={'treebank':'peer','file_path':'target.conllu','sent_id':'target'}

    def write_spec(self,value):
        (self.root/'alignment.json').write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8')

    def call(self,operation,args,code=None,message=None):
        response=wire.process({'operation':operation,'arguments':args})
        if response.get('error',{}).get('code')=='WORKER_FAILED':raise RuntimeError('unexpected implementation failure: '+operation)
        self.assertIs(response.get('ok'),code is None,repr(response))
        if code:
            self.assertEqual(response.get('error',{}).get('code'),code)
            if message is not None:self.assertEqual(response['error']['message'],message)
        else:
            self.assertIsInstance(response.get('result'),dict);return response['result']

    def test_complete_incomplete_and_empty_alignments_keep_order_and_independent_coverage(self):
        absent_source={**self.source,'sent_id':'missing-source'};absent_target={**self.target,'sent_id':'missing-target'}
        self.write_spec({'alignments':[{'source':self.source,'targets':[self.target]}, {'source':absent_source,'targets':[self.target,absent_target]}]})
        source={'reference':self.source,'text':'Source α','location':location('main.conllu','source')}
        target={'reference':self.target,'text':'Target β','location':location('target.conllu','target')}
        before={file.relative_to(self.root).as_posix():file.read_bytes()for file in self.root.rglob('*')if file.is_file()}
        self.assertEqual(self.call('parallel_corpus_report',self.args),{
            'alignments':[{'source':source,'targets':[target]},{'source':None,'targets':[target,None]}],
            'missing_references':[{'alignment':1,'reference':absent_source},{'alignment':1,'reference':absent_target}],
            'coverage':{'requested':2,'complete':1},'limitations':['Only explicitly supplied sentence correspondences are reported.']})
        self.assertEqual(before,{file.relative_to(self.root).as_posix():file.read_bytes()for file in self.root.rglob('*')if file.is_file()})
        self.write_spec({'alignments':[]});self.assertEqual(self.call('parallel_corpus_report',self.args),{'alignments':[],'missing_references':[],'coverage':{'requested':0,'complete':0},'limitations':['Only explicitly supplied sentence correspondences are reported.']})

    def test_duplicate_sentence_ids_are_ambiguous_within_the_selected_file_only(self):
        self.write_spec({'alignments':[{'source':self.source,'targets':[self.target]}]})
        (self.root/'unselected.conllu').write_text(sentence('source'))
        self.assertEqual(self.call('parallel_corpus_report',self.args)['coverage'],{'requested':1,'complete':1})
        (self.root/'main.conllu').write_text(sentence('source')+sentence('source'))
        self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment sentence identity is ambiguous')

    def test_spec_and_reference_shapes_fail_with_precise_diagnostics(self):
        for spec in [[],None,{}, {'alignments':{}},{'alignments':[],'extra':True}]:
            self.write_spec(spec);self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment specification must contain alignments')
        for alignment in [None,{}, {'source':self.source,'targets':[]},{'source':self.source,'targets':{}},{'source':self.source,'targets':[self.target],'extra':True}]:
            self.write_spec({'alignments':[alignment]});self.call('parallel_corpus_report',self.args,'INVALID_INPUT','each alignment requires one source and nonempty targets')
        for reference in [None,[],{}, {**self.source,'extra':'field'}]:
            self.write_spec({'alignments':[{'source':reference,'targets':[self.target]}]});self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment references require treebank, file_path and sent_id')
        for reference in [{**self.source,'treebank':1},{**self.source,'file_path':None},{**self.source,'sent_id':''},{**self.source,'sent_id':2}]:
            self.write_spec({'alignments':[{'source':reference,'targets':[self.target]}]});self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment reference fields must be nonempty strings')
        (self.root/'alignment.json').write_bytes(b'\xff');self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment specification must be UTF-8 JSON')
        (self.root/'alignment.json').write_text('{');self.call('parallel_corpus_report',self.args,'INVALID_INPUT','alignment specification must be UTF-8 JSON')

    def test_peer_authority_is_explicit_and_a_peer_file_is_not_a_directory(self):
        self.write_spec({'alignments':[{'source':self.source,'targets':[self.target]}]})
        self.call('parallel_corpus_report',{**self.args,'peer_treebank_paths':[]},'INVALID_INPUT','alignment references an undeclared peer treebank')
        for value in ['peer',[1],{'peer':True},True]:self.call('parallel_corpus_report',{**self.args,'peer_treebank_paths':value},'INVALID_INPUT','peer_treebank_paths must be an array of paths')
        target={**self.target,'treebank':'main.conllu'};self.write_spec({'alignments':[{'source':self.source,'targets':[target]}]})
        self.call('parallel_corpus_report',{**self.args,'peer_treebank_paths':['main.conllu']},'INVALID_INPUT','peer treebank must be a directory')

    def test_passage_normalization_separator_grammar_numeric_order_and_many_to_many_evidence(self):
        source=[('prefix.gen_01:02-suffix','first'),('GEN.1.2','second'),('2Kgs-10-3','numbered book'),('xEXO.1.1','unparsed'),('GEN.2.1','only source')]
        peer=[('GEN:1:2','peer'),('2kgs_10_3','numbered peer'),('EXO.1.1','only peer'),('other','missing')]
        (self.root/'main.conllu').write_text(''.join(sentence(identity,text)for identity,text in source))
        (self.root/'peer.conllu').write_text(''.join(sentence(identity,text)for identity,text in peer))
        result=self.call('bible_passage_concordance',{'working_tree_path':str(self.root),'file_paths':['main.conllu'],'peer_file_paths':['peer.conllu']})
        self.assertEqual(result['passages'],[
            {'book':'2KGS','chapter':10,'verse':3,'source':[{**location('main.conllu','2Kgs-10-3',2),'text':'numbered book'}],'peer':[{**location('peer.conllu','2kgs_10_3',1),'text':'numbered peer'}],'correspondence_complete':True},
            {'book':'EXO','chapter':1,'verse':1,'source':[],'peer':[{**location('peer.conllu','EXO.1.1',2),'text':'only peer'}],'correspondence_complete':False},
            {'book':'GEN','chapter':1,'verse':2,'source':[{**location('main.conllu',source[0][0]),'text':'first'},{**location('main.conllu','GEN.1.2',1),'text':'second'}],'peer':[{**location('peer.conllu','GEN:1:2'),'text':'peer'}],'correspondence_complete':True},
            {'book':'GEN','chapter':2,'verse':1,'source':[{**location('main.conllu','GEN.2.1',4),'text':'only source'}],'peer':[],'correspondence_complete':False}])
        self.assertEqual(result['unparsed_references'],[{'role':'source',**location('main.conllu','xEXO.1.1',3)},{'role':'peer',**location('peer.conllu','other',3)}])
        self.assertEqual(result['definition'],'three-letter book, chapter and verse parsed from sentence IDs using period, colon, hyphen or underscore separators')
        self.assertEqual(result['limitations'],['Corpus-specific IDs outside this reference grammar are reported as unparsed; absent matches are not inferred.'])

    def test_concordance_requires_disjoint_nonempty_selections(self):
        args={'working_tree_path':str(self.root),'file_paths':['main.conllu'],'peer_file_paths':['peer/target.conllu']}
        for field in ['file_paths','peer_file_paths']:self.call('bible_passage_concordance',{**args,field:[]},'INVALID_INPUT','source and peer file lists must be nonempty')
        self.call('bible_passage_concordance',{**args,'peer_file_paths':['main.conllu']},'INVALID_INPUT','source and peer file lists must not overlap')


if __name__=='__main__':unittest.main()
