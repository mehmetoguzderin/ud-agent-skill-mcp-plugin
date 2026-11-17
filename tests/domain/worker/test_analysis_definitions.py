"""Independent complete metric tables, filters, and evidence locations."""
from pathlib import Path
import tempfile
import json
import hashlib
import unittest
from unittest.mock import patch
from ud_agent import wire
from ud_agent.domain import analysis
from ud_agent.errors import WorkerError

A = '# sent_id = a\n1-2\tAda-β\t_\t_\t_\t_\t_\t_\t_\t_\n1\tAda\tAda\tPROPN\tNNP\tNumber=Plur,Sing\t3\tnsubj\t_\t_\n2\tβ\tβ\tPROPN\tNNP\tNumber=Plur\t3\tobj\t_\t_\n2.1\tghost\tghost\tX\t_\t_\t_\t_\t3:dep\t_\n3\trun\trun\tVERB\tVB\tNumber=Sing\t0\troot\t_\t_\n4\tTail\ttail\tNOUN\tNN\t_\t3\tobl\t_\t_\n\n'
B = '# sent_id = b\n1\tAda\tAda\tPROPN\tNNP\tNumber=Sing\t0\troot\t_\t_\n2\truns\trun\tVERB\tVB\tNumber=Sing\t1\tdep\t_\t_\n\n'


def where(file,sentence,token=None):
    value={'file_path':file,'sent_id':sentence,'ordinal':0}
    if token is not None:value['token_id']=token
    return value


class AnalysisDefinitions(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ud-analysis-definitions-');self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve()
        (self.root/'a.conllu').write_text(A);(self.root/'b.conllu').write_text(B)
        self.args={'working_tree_path':str(self.root),'file_paths':['a.conllu','b.conllu']}

    def response(self,operation,arguments):
        response=wire.process({'operation':operation,'arguments':arguments})
        if response.get('error',{}).get('code')=='WORKER_FAILED':
            raise RuntimeError('unexpected implementation failure in '+operation)
        return response

    def report(self,operation,arguments):
        response=self.response(operation,arguments)
        self.assertIs(response.get('ok'),True,'valid metric fixture was rejected: '+repr(response))
        result=response.get('result');self.assertIsInstance(result,dict)
        required={'treebank_profile':{'upos':list},'lexeme_pos_report':{'entries':list,'filter':dict},'observed_paradigms':{'forms':list,'limitations':list},'relation_profile':{'relations':list},'feature_agreement_report':{'comparisons':list,'compared':int,'agreeing':int,'disagreeing':int,'skipped':dict},'dependency_order_profile':{'orders':list},'multiword_token_patterns':{'patterns':list},'proper_name_sequences':{'sequences':list},'script_composition_report':{'corpora':list,'limitations':list},'english_relative_clause_classify':{'artifacts':list,'clause_count':int,'limitations':list}}
        for name,kind in required[operation].items():
            self.assertIn(name,result);self.assertIsInstance(result[name],kind)
        return result

    def invalid(self,operation,arguments,message=None):
        response=self.response(operation,arguments)
        self.assertIs(response.get('ok'),False)
        self.assertEqual(response.get('error',{}).get('code'),'INVALID_INPUT')
        if message is not None:self.assertEqual(response.get('error',{}).get('message'),message)

    def test_profile_has_exact_denominators_tie_order_special_rows_scope_and_definition(self):
        self.assertEqual(self.report('treebank_profile',self.args),{'sentence_count':2,'word_count':6,'multiword_token_count':1,'empty_node_count':1,
            'upos':[{'value':'PROPN','count':3,'denominator':6,'proportion':0.5},{'value':'VERB','count':2,'denominator':6,'proportion':2/6},{'value':'NOUN','count':1,'denominator':6,'proportion':1/6}],
            'scope':['a.conllu','b.conllu'],'definition':'ordinary integer-ID words; no Unicode normalization'})
        (self.root/'empty.conllu').write_text('')
        self.assertEqual(self.report('treebank_profile',{**self.args,'file_paths':['empty.conllu']}),{'sentence_count':0,'word_count':0,'multiword_token_count':0,'empty_node_count':0,'upos':[],'scope':[],'definition':'ordinary integer-ID words; no Unicode normalization'})

    def test_lexeme_filters_intersect_all_fields_and_preserve_exact_occurrences(self):
        result=self.report('lexeme_pos_report',{**self.args,'lexeme_filter':{'lemma':'Ada','upos':'PROPN','form':'Ada','xpos':'NNP'}})
        self.assertEqual(result,{'entries':[{'lemma':'Ada','upos':'PROPN','count':2,'occurrences':[where('a.conllu','a','1'),where('b.conllu','b','1')]}],'filter':{'lemma':'Ada','upos':'PROPN','form':'Ada','xpos':'NNP'}})
        self.assertEqual(self.report('lexeme_pos_report',{**self.args,'lexeme_filter':{'lemma':'Ada','form':'runs'}})['entries'],[])
        self.assertEqual(self.report('lexeme_pos_report',{**self.args,'lexeme_filter':None})['filter'],{})
        for invalid in [[],False,{'unknown':'value'},{'lemma':None},{'lemma':1}]:
            with self.subTest(invalid=invalid):self.invalid('lexeme_pos_report',{**self.args,'lexeme_filter':invalid},'filter contains unsupported fields or non-string values')

    def test_paradigms_keep_observed_form_feature_combinations_without_filling_gaps(self):
        result=self.report('observed_paradigms',{**self.args,'paradigm_filter':{'lemma':'run','xpos':'VB'}})
        self.assertEqual(result['forms'],[{'lemma':'run','upos':'VERB','features':'Number=Sing','form':'run','count':1,'occurrences':[where('a.conllu','a','3')]},
                                         {'lemma':'run','upos':'VERB','features':'Number=Sing','form':'runs','count':1,'occurrences':[where('b.conllu','b','2')]}])
        self.assertEqual(result['limitations'],['Paradigms contain observed forms only; missing forms are not inferred.'])
        one=self.report('observed_paradigms',{**self.args,'paradigm_filter':{'lemma':'run','upos':'VERB','form':'runs','xpos':'VB'}})
        self.assertEqual(one,{'forms':[{'lemma':'run','upos':'VERB','features':'Number=Sing','form':'runs','count':1,'occurrences':[where('b.conllu','b','2')]}],'limitations':['Paradigms contain observed forms only; missing forms are not inferred.']})

    def test_relation_counts_use_only_filtered_words_and_sorted_labels(self):
        result=self.report('relation_profile',{**self.args,'relation_filter':{'head':'3'}})
        self.assertEqual(result,{'denominator':3,'relations':[{'relation':'nsubj','count':1,'occurrences':[where('a.conllu','a','1')],'order_counts':{'before_head':1,'after_head':0,'no_word_head':0},'order_examples':{'before_head':'a.conllu sent_id a token 1'}},{'relation':'obj','count':1,'occurrences':[where('a.conllu','a','2')],'order_counts':{'before_head':1,'after_head':0,'no_word_head':0},'order_examples':{'before_head':'a.conllu sent_id a token 2'}},{'relation':'obl','count':1,'occurrences':[where('a.conllu','a','4')],'order_counts':{'before_head':0,'after_head':1,'no_word_head':0},'order_examples':{'after_head':'a.conllu sent_id a token 4'}}],'filter':{'head':'3'},'order_definition':'before_head/after_head compare the word ID with its basic HEAD ID; no_word_head is HEAD 0 or non-numeric; by_sentence_metadata groups by # key = value comments'})
        self.assertEqual(self.report('relation_profile',{**self.args,'relation_filter':{'deprel':'missing'}}),{'denominator':0,'relations':[],'filter':{'deprel':'missing'},'order_definition':'before_head/after_head compare the word ID with its basic HEAD ID; no_word_head is HEAD 0 or non-numeric; by_sentence_metadata groups by # key = value comments'})
        self.assertEqual(self.report('relation_profile',{**self.args,'relation_filter':{'upos':'PROPN','head':'3'}}),{'denominator':2,'relations':[{'relation':'nsubj','count':1,'occurrences':[where('a.conllu','a','1')],'order_counts':{'before_head':1,'after_head':0,'no_word_head':0},'order_examples':{'before_head':'a.conllu sent_id a token 1'}},{'relation':'obj','count':1,'occurrences':[where('a.conllu','a','2')],'order_counts':{'before_head':1,'after_head':0,'no_word_head':0},'order_examples':{'before_head':'a.conllu sent_id a token 2'}}],'filter':{'upos':'PROPN','head':'3'},'order_definition':'before_head/after_head compare the word ID with its basic HEAD ID; no_word_head is HEAD 0 or non-numeric; by_sentence_metadata groups by # key = value comments'})

    def test_relation_orders_and_sentence_metadata_breakdown_give_subset_denominators(self):
        (self.root/'c.conllu').write_text('# sent_id = n1\n# genre = news\n1\tBirds\tbird\tNOUN\t_\t_\t2\tnsubj\t_\t_\n2\tfly\tfly\tVERB\t_\t_\t0\troot\t_\t_\n\n'
                                          '# sent_id = n2\n# genre = news\n1\tComes\tcome\tVERB\t_\t_\t0\troot\t_\t_\n2\tspring\tspring\tNOUN\t_\t_\t1\tnsubj\t_\t_\n\n'
                                          '# sent_id = f1\n# genre = fiction\n1\tArrived\tarrive\tVERB\t_\t_\t0\troot\t_\t_\n2\twinter\twinter\tNOUN\t_\t_\t1\tnsubj\t_\t_\n\n')
        result=self.report('relation_profile',{'working_tree_path':str(self.root),'file_paths':['c.conllu'],'relation_filter':{'deprel':'nsubj'}})
        nsubj=result['relations'][0]
        self.assertEqual((result['denominator'],nsubj['relation'],nsubj['count']),(3,'nsubj',3))
        self.assertEqual(nsubj['order_counts'],{'before_head':1,'after_head':2,'no_word_head':0})
        self.assertEqual(nsubj['order_examples'],{'after_head':'c.conllu sent_id n2 token 2','before_head':'c.conllu sent_id n1 token 1'})
        self.assertEqual(nsubj['by_sentence_metadata'],{'genre':{'fiction':{'count':1,'before_head':0,'after_head':1,'no_word_head':0,'after_head_example':'c.conllu sent_id f1 token 2'},
                                                                 'news':{'count':2,'before_head':1,'after_head':1,'no_word_head':0,'after_head_example':'c.conllu sent_id n2 token 2','before_head_example':'c.conllu sent_id n1 token 1'}}})
        self.assertEqual([item['sent_id'] for item in nsubj['occurrences']],['n1','n2','f1'])

    def test_agreement_compares_value_set_intersection_and_explains_every_skip(self):
        result=self.report('feature_agreement_report',{**self.args,'feature_name':'Number'})
        self.assertEqual(result,{'feature':'Number','comparisons':[
            {'dependent':where('a.conllu','a','1'),'head_id':'3','relation':'nsubj','dependent_values':['Plur','Sing'],'head_values':['Sing'],'agrees':True},
            {'dependent':where('a.conllu','a','2'),'head_id':'3','relation':'obj','dependent_values':['Plur'],'head_values':['Sing'],'agrees':False},
            {'dependent':where('b.conllu','b','2'),'head_id':'1','relation':'dep','dependent_values':['Sing'],'head_values':['Sing'],'agrees':True}],
            'compared':3,'agreeing':2,'disagreeing':1,'skipped':{'no_word_head':2,'missing_feature':1},
            'definition':'feature values agree when the explicitly annotated value sets intersect'})
        filtered=self.report('feature_agreement_report',{**self.args,'feature_name':'Number','relation_filter':{'deprel':'obj'}})
        self.assertEqual((filtered['compared'],filtered['agreeing'],filtered['disagreeing'],filtered['skipped']),(1,0,1,{}))
        for value in [None,'',3,[]]:
            self.invalid('feature_agreement_report',{**self.args,'feature_name':value},'feature_name must be a nonempty string')
        filtered=self.report('feature_agreement_report',{**self.args,'feature_name':'Number','relation_filter':{'upos':'PROPN','head':'3'}})
        self.assertEqual((filtered['compared'],filtered['agreeing'],filtered['disagreeing'],filtered['skipped']),(2,1,1,{}))

    def test_order_ties_are_sorted_and_occurrences_include_both_sides_of_head(self):
        result=self.report('dependency_order_profile',self.args)
        self.assertEqual(result,{'orders':[{'value':'after_head','count':2,'denominator':4,'proportion':0.5},{'value':'before_head','count':2,'denominator':4,'proportion':0.5}],
            'occurrences':{'before_head':[where('a.conllu','a','1'),where('a.conllu','a','2')],'after_head':[where('a.conllu','a','4'),where('b.conllu','b','2')]},
            'definition':'integer word position relative to its non-root basic head'})
        (self.root/'self.conllu').write_text('# sent_id = self\n1\tA\t_\tNOUN\t_\t_\t1\tdep\t_\t_\n2\tB\t_\tNOUN\t_\t_\t_\tdep\t_\t_\n\n')
        self.assertEqual(self.report('dependency_order_profile',{**self.args,'file_paths':['self.conllu']})['orders'],[{'value':'self','count':1,'denominator':1,'proportion':1.0}])

    def test_mwt_component_evidence_and_proper_name_runs_use_ordinary_rows(self):
        self.assertEqual(self.report('multiword_token_patterns',self.args),{'patterns':[{'form':'Ada-β','component_upos':['PROPN','PROPN'],'count':1,'occurrences':[where('a.conllu','a','1-2')]}]})
        self.assertEqual(self.report('proper_name_sequences',self.args),{'sequences':[{'location':where('a.conllu','a'),'token_ids':['1','2'],'forms':['Ada','β']},{'location':where('b.conllu','b'),'token_ids':['1'],'forms':['Ada']}],'limitations':['Consecutive PROPN runs are not named-entity recognition.']})
        (self.root/'missing.conllu').write_text(A.replace('1-2\tAda-β','1-3\tAda-β').replace('2\tβ\tβ\tPROPN\tNNP\tNumber=Plur\t3\tobj\t_\t_\n',''))
        self.assertEqual(self.report('multiword_token_patterns',{**self.args,'file_paths':['missing.conllu']})['patterns'][0]['component_upos'],['PROPN','MISSING','VERB'])
        (self.root/'later.conllu').write_text(B.replace('2\truns','2-2\truns\t_\t_\t_\t_\t_\t_\t_\t_\n2\truns'))
        self.assertEqual(self.report('multiword_token_patterns',{**self.args,'file_paths':['later.conllu']}),{'patterns':[{'form':'runs','component_upos':['VERB'],'count':1,'occurrences':[where('later.conllu','b','2-2')]}]})
        (self.root/'reverse.conllu').write_text(A.replace('1-2\tAda-β','3-1\tAda-β'))
        self.invalid('multiword_token_patterns',{**self.args,'file_paths':['reverse.conllu']},'invalid multiword token range')

    def test_all_named_script_families_han_other_and_nonletters_have_independent_counts(self):
        peer=self.root/'peer';peer.mkdir()
        (peer/'p.conllu').write_text('# sent_id = scripts\n1\tAЖΩشאअあア가กაԱሀঅஅఅ中Ꭰ-123\t_\tX\t_\t_\t0\troot\t_\t_\n\n')
        result=self.report('script_composition_report',{**self.args,'peer_treebank_paths':['peer']})
        self.assertEqual(len(result['corpora']),2)
        self.assertEqual(result['corpora'][0],{'treebank':'.','scripts':[{'value':'LATIN','count':17,'denominator':18,'proportion':17/18},{'value':'GREEK','count':1,'denominator':18,'proportion':1/18}]})
        names=['ARABIC','ARMENIAN','BENGALI','CYRILLIC','DEVANAGARI','ETHIOPIC','GEORGIAN','GREEK','HAN','HANGUL','HEBREW','HIRAGANA','KATAKANA','LATIN','OTHER','TAMIL','TELUGU','THAI']
        self.assertEqual(result['corpora'][1],{'treebank':'peer','scripts':[{'value':name,'count':1,'denominator':18,'proportion':1/18}for name in names]})
        self.assertEqual(result['limitations'],['Scripts are estimated from Unicode character names; unclassified letters are OTHER.'])
        for peer_paths in ['peer',['../escape'],['a.conllu']]:
            self.invalid('script_composition_report',{**self.args,'peer_treebank_paths':peer_paths})
        self.invalid('script_composition_report',{**self.args,'peer_treebank_paths':'peer'},'peer_treebank_paths must be an array')
        self.invalid('script_composition_report',{**self.args,'peer_treebank_paths':['a.conllu']},'peer paths must be directories')
        # Cherokee stays OTHER under this documented character-name heuristic;
        # 〆 has an IDEOGRAPHIC name and therefore contributes HAN. Tangut's
        # algorithmic name was added between the supported Python UCD versions,
        # so it cannot serve as a cross-version real-data missing-name fixture.
        (peer/'p.conllu').write_text('# sent_id = names\n1\tᎠ〆\t_\tX\t_\t_\t0\troot\t_\t_\n\n')
        self.assertEqual(self.report('script_composition_report',{'working_tree_path':str(peer)})['corpora'],[{'treebank':'.','scripts':[{'value':'HAN','count':1,'denominator':2,'proportion':0.5},{'value':'OTHER','count':1,'denominator':2,'proportion':0.5}]}])

    def test_missing_unicode_name_uses_the_explicit_empty_name_fallback(self):
        (self.root/'unnamed.conllu').write_text('# sent_id = unnamed\n1\t𗀀〆\t_\tX\t_\t_\t0\troot\t_\t_\n\n')
        original_name=analysis.unicodedata.name
        def missing_tangut_name(character,default):
            if character=='𗀀':return default
            return original_name(character,default)
        # A deterministic Unicode-data fixture, independent of whether this
        # interpreter already provides Tangut's algorithmic names.
        with patch.object(analysis.unicodedata,'name',side_effect=missing_tangut_name):
            result=self.report('script_composition_report',{**self.args,'file_paths':['unnamed.conllu']})
        self.assertEqual(result['corpora'],[{'treebank':'.','scripts':[{'value':'HAN','count':1,'denominator':2,'proportion':0.5},{'value':'OTHER','count':1,'denominator':2,'proportion':0.5}]}])


    def test_relative_clause_families_keep_numeric_marker_order_and_exact_export_bytes(self):
        for relation,category in [('acl:relcl','adnominal'),('advcl:relcl','adverbial'),('ccomp:relcl','other')]:
            rows=[]
            for identifier in range(1,11):
                form='whó' if identifier==3 else 'which' if identifier==10 else 'f'+str(identifier)
                head='0' if identifier==1 else '1' if identifier==2 else '4' if identifier==10 else '2'
                label='root' if identifier==1 else relation if identifier==2 else 'dep'
                features='PronType=Int,Rel' if identifier==3 else 'PronType=Rel' if identifier==10 else '_'
                rows.append('\t'.join([str(identifier),form,'_', 'PRON' if identifier in(3,10) else 'VERB','_',features,head,label,'_','_']))
            (self.root/'relative.conllu').write_text('# sent_id = clauses\n'+'\n'.join(rows)+'\n\n')
            result=self.report('english_relative_clause_classify',{**self.args,'file_paths':['relative.conllu'],'output_dir_path':'/requested','options':{'language_code':'en'}})
            expected={'language':'en','clauses':[{'location':where('relative.conllu','clauses'),'token_id':'2','form':'f2','relation':relation,'category':category,'head_id':'1','relative_markers':[{'token_id':'3','form':'whó','upos':'PRON'},{'token_id':'10','form':'which','upos':'PRON'}]}]}
            content=json.dumps(expected,ensure_ascii=False,indent=2)+'\n'
            self.assertEqual(result['clause_count'],1)
            self.assertEqual({key:result.get(key)for key in ['status','requires_host_export','output_dir_path','definition']},{'status':'candidate','requires_host_export':True,'output_dir_path':'/requested','definition':'explicit :relcl dependency labels and PronType=Rel markers among basic-tree descendants'})
            self.assertEqual(result['artifacts'],[{'filename':'english-relative-clauses.json','mime_type':'application/json','size_bytes':len(content.encode()),'sha256':hashlib.sha256(content.encode()).hexdigest(),'content':content}])
            self.assertEqual(result['limitations'],['This English-oriented annotation heuristic does not classify unlabeled clauses or imply a universal linguistic rule.'])
        for options in [[],{'language_code':'fr'},{'unknown':True}]:
            self.invalid('english_relative_clause_classify',{**self.args,'output_dir_path':'/requested','options':options},'this classifier accepts only English language data')

    def test_empty_selection_diagnostics_and_cyclic_relative_graph_work_are_bounded(self):
        self.invalid('treebank_profile',{**self.args,'file_paths':[]},'at least one CoNLL-U file is required')
        content='# sent_id = cycle\n1\twho\t_\tPRON\t_\tPronType=Rel\t2\tnsubj\t_\t_\n2\tsees\t_\tVERB\t_\t_\t4\tacl:relcl\t_\t_\n3\troot\t_\tNOUN\t_\t_\t0\troot\t_\t_\n4\tcycle\t_\tNOUN\t_\t_\t2\tdep\t_\t_\n\n'
        (self.root/'cycle.conllu').write_text(content)
        # Linguistic invalidity is validated separately. A report traversal
        # still has a finite work contract on cyclic project data.
        actual_attributes=analysis.attributes;calls=0
        def bounded_attributes(value):
            nonlocal calls
            calls+=1
            self.assertLessEqual(calls,40,'four-node clause traversal exceeded a generous linear work budget')
            return actual_attributes(value)
        with patch.object(analysis,'attributes',side_effect=bounded_attributes):
            try:result=analysis.english_relative_clause_classify({**self.args,'file_paths':['cycle.conllu'],'output_dir_path':'/requested'})
            except WorkerError as error:self.fail('valid bounded report fixture rejected: '+error.code)
        self.assertIsInstance(result,dict);self.assertEqual(result.get('clause_count'),1)
        self.assertIn('artifacts',result);self.assertEqual(len(result['artifacts']),1)
        self.assertEqual(json.loads(result['artifacts'][0]['content'])['clauses'][0]['relative_markers'],[{'token_id':'1','form':'who','upos':'PRON'}])


if __name__=='__main__':unittest.main()
