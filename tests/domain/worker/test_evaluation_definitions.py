"""Count/role contracts against the actual pinned official UD scorer."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from udtools import udeval
from ud_agent import wire


def row(ident,form,head,relation='dep'):
    return f'{ident}\t{form}\t{form}\tNOUN\t_\t_\t{head}\t{relation}\t{head}:{relation}\t_\n'


def metric(correct,gold,system,aligned):
    return {'correct':correct,'gold_total':gold,'system_total':system,'aligned_total':aligned,
            'precision':correct/system if system else 0.0,'recall':correct/gold if gold else 0.0,
            'f1':2*correct/(gold+system)if gold+system else 0.0,'aligned_accuracy':correct/aligned if aligned else None}


class EvaluationDefinitions(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='ud-evaluation-definitions-');self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        # The same character stream abcd has two gold words and four system
        # words. Only d aligns. Its root arc is independently correct.
        (self.root/'gold.conllu').write_text('# sent_id = gold\n'+row(1,'abc',2)+row(2,'d',0,'root')+'\n')
        (self.root/'system.conllu').write_text('# sent_id = system\n'+''.join(row(i,form,4)for i,form in enumerate('abc',1))+row(4,'d',0,'root')+'\n')
        (self.root/'one.conllu').write_text('# sent_id = one\n'+row(1,'x',0,'root')+'\n')
        self.args={'working_tree_path':str(self.root),'gold_file_paths':['gold.conllu','one.conllu'],'prediction_file_paths':['system.conllu','one.conllu']}

    def response(self,operation,args):
        response=wire.process({'operation':operation,'arguments':args})
        if response.get('error',{}).get('code')=='WORKER_FAILED':raise RuntimeError('unexpected scorer coordinator failure')
        return response

    def success(self,operation,args):
        response=self.response(operation,args);self.assertIs(response.get('ok'),True,repr(response));result=response.get('result');self.assertIsInstance(result,dict)
        for field,kind in {'scores':dict,'pair_count':int,'enhanced':bool,'treebank_type':dict,'roles':dict,'definition':str}.items():self.assertIn(field,result);self.assertIsInstance(result[field],kind)
        for name,score in result['scores'].items():
            self.assertIsInstance(name,str);self.assertIsInstance(score,dict)
            self.assertEqual(set(score),{'correct','gold_total','system_total','aligned_total','precision','recall','f1','aligned_accuracy'})
        return result

    def invalid(self,args,message):
        response=self.response('predictions_evaluate',args);self.assertIs(response.get('ok'),False);self.assertEqual(response.get('error'),{'code':'INVALID_INPUT','message':message})

    def test_unequal_tokenization_aggregates_counts_before_directional_metrics(self):
        before={path.name:path.read_bytes()for path in self.root.iterdir()}
        result=self.success('predictions_evaluate',self.args)
        self.assertEqual(result['roles'],{'gold':['gold.conllu','one.conllu'],'system':['system.conllu','one.conllu']})
        self.assertEqual((result['pair_count'],result['enhanced'],result['treebank_type']),(2,False,{}))
        for name in ['Tokens','Words']:self.assertEqual(result['scores'][name],metric(2,3,5,None))
        for name in ['UAS','LAS']:self.assertEqual(result['scores'][name],metric(2,3,5,2))
        self.assertEqual(result['scores']['Sentences'],metric(2,2,2,None))
        self.assertEqual(result['definition'],'official scorer counts summed across file pairs before metric calculation')
        self.assertNotIn('ELAS',result['scores']);self.assertNotIn('EULAS',result['scores'])
        self.assertEqual(before,{path.name:path.read_bytes()for path in self.root.iterdir()})
        # Reversing roles swaps the precision/recall denominators, while the
        # symmetric F1 and matched count remain the same.
        swapped=self.success('predictions_evaluate',{**self.args,'gold_file_paths':self.args['prediction_file_paths'],'prediction_file_paths':self.args['gold_file_paths']})
        self.assertEqual(swapped['scores']['LAS'],metric(2,5,3,2))

    def test_predictions_list_head_and_relation_mismatches_by_sentence_and_token(self):
        (self.root/'g.conllu').write_text('# sent_id = compare-1\n1\tSmall\tsmall\tADJ\t_\t_\t2\tamod\t_\t_\n2\tbirds\tbird\tNOUN\t_\t_\t3\tnsubj\t_\t_\n3\tsee\tsee\tVERB\t_\t_\t0\troot\t_\t_\n\n')
        (self.root/'p.conllu').write_text('# sent_id = compare-1\n1\tSmall\tsmall\tADJ\t_\t_\t3\tamod\t_\t_\n2\tbirds\tbird\tNOUN\t_\t_\t3\tobj\t_\t_\n3\tsee\tsee\tVERB\t_\t_\t0\troot\t_\t_\n\n')
        result=self.success('predictions_evaluate',{**self.args,'gold_file_paths':['g.conllu'],'prediction_file_paths':['p.conllu']})
        self.assertEqual(result['mismatch_count'],2);self.assertEqual(result['unaligned_sentences'],[])
        self.assertEqual(result['mismatches'],[
            {'file':'g.conllu','sent_id':'compare-1','token_id':1,'form':'Small','kind':'attachment','gold_head':'2','system_head':'3','gold_deprel':'amod','system_deprel':'amod'},
            {'file':'g.conllu','sent_id':'compare-1','token_id':2,'form':'birds','kind':'relation','gold_head':'3','system_head':'3','gold_deprel':'nsubj','system_deprel':'obj'}])

    def test_differently_tokenized_sentences_are_reported_unaligned_not_compared(self):
        result=self.success('predictions_evaluate',self.args)
        self.assertTrue(result['unaligned_sentences']);self.assertIn('not part of official scoring',result['mismatch_definition'])

    def test_pair_scoring_keeps_directional_roles_limits_and_enhanced_option(self):
        args={'working_tree_path':str(self.root),'reference_annotation_path':'gold.conllu','comparison_annotation_path':'system.conllu','options':{'enhanced':True,'treebank_type':{'no_case_info':False,'no_empty_nodes':False}}}
        result=self.success('annotation_pair_scores',args)
        self.assertEqual(result['roles'],{'gold':'gold.conllu','system':'system.conllu'})
        self.assertEqual((result['pair_count'],result['enhanced'],result['treebank_type']),(1,True,args['options']['treebank_type']))
        for name in ['UAS','LAS','ELAS','EULAS']:self.assertEqual(result['scores'][name],metric(1,2,4,1)if name in ['UAS','LAS']else metric(1,2,4,None))
        self.assertEqual(result['limitations'],['These directional scores are not chance-corrected annotator agreement.'])

    def test_official_stream_handles_are_owned_and_closed_on_success_and_failure(self):
        original=udeval.load_conllu;streams=[]
        def observed(stream,path,settings):
            self.assertFalse(stream.closed);streams.append(stream);return original(stream,path,settings)
        with patch.object(udeval,'load_conllu',side_effect=observed):self.success('predictions_evaluate',self.args)
        self.assertEqual(len(streams),4);self.assertTrue(all(stream.closed for stream in streams))
        (self.root/'system.conllu').write_text('not conllu\n')
        streams.clear()
        with patch.object(udeval,'load_conllu',side_effect=observed):response=self.response('predictions_evaluate',self.args)
        self.assertIs(response.get('ok'),False);self.assertEqual(response.get('error',{}).get('code'),'SCORER_FAILED');self.assertTrue(all(stream.closed for stream in streams))

    def test_option_types_and_unsupported_flags_are_rejected_before_scorer_execution(self):
        for options in [[],True,{'unknown':True}]:self.invalid({**self.args,'options':options},'unsupported scoring options')
        for options in [{'enhanced':1},{'enhanced':'true'},{'treebank_type':[]},{'treebank_type':{'unknown':True}},{'treebank_type':{'no_control':1}}]:self.invalid({**self.args,'options':options},'invalid enhanced or treebank_type scoring options')
        for arguments in [{'gold_file_paths':[]},{'prediction_file_paths':[]},{'prediction_file_paths':['one.conllu']}]:self.invalid({**self.args,**arguments},'gold and prediction file lists must have equal nonzero length')

    def test_empty_corpora_have_zero_metrics_without_invented_alignment_or_nan(self):
        (self.root/'empty.conllu').write_text('')
        args={**self.args,'gold_file_paths':['empty.conllu'],'prediction_file_paths':['empty.conllu'],'options':{'enhanced':True}}
        result=self.success('predictions_evaluate',args)
        unaligned={'ELAS','EULAS','Sentences','Tokens','Words'}
        aligned={'AllTags','BLEX','CLAS','LAS','Lemmas','MLAS','UAS','UFeats','UPOS','XPOS'}
        self.assertEqual(set(result['scores']),unaligned|aligned)
        for name in sorted(unaligned):self.assertEqual(result['scores'][name],metric(0,0,0,None))
        for name in sorted(aligned):self.assertEqual(result['scores'][name],metric(0,0,0,0))
        # Real protocol serialization must remain strict finite JSON.
        self.assertIn(b'"aligned_accuracy":null',wire.encode({'ok':True,'result':result}))

    def test_missing_scorer_is_a_prerequisite_failure_not_linguistic_invalidity(self):
        with patch.dict(sys.modules,{'udtools':None}):response=self.response('predictions_evaluate',self.args)
        self.assertEqual(response,{'ok':False,'error':{'code':'PREREQUISITE_MISSING','message':'the official udtools scorer is not installed'}})


if __name__=='__main__':unittest.main()
