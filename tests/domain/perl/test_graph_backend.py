"""Real Perl IPC and lossless maps with explicit fake modules, not native evidence."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_graph_bridge import FAKE, BRIDGE
from ud_agent.domain.enhanced import enhanced_graph_report
from ud_agent.errors import PrerequisiteMissing, WorkerError
from ud_agent.graph_backend import inspect_graphs, _partitions


class GraphBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ud-graph-backend-'); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root/'tools'; self.tools.mkdir()
        (self.tools/'Graph.pm').write_text(FAKE); (self.tools/'Node.pm').write_text('1;\n')
        environment = {key:value for key,value in os.environ.items() if not key.startswith('UD_AGENT_PERL_')}
        environment.update(UD_AGENT_PERL=shutil.which('perl') or '/usr/bin/perl', UD_AGENT_UDTOOLS=str(self.tools))
        self.enterContext(patch.dict(os.environ,environment,clear=True))

    def completed(self, operation, *arguments):
        try:
            return operation(*arguments)
        except WorkerError as error:
            self.fail('valid graph fixture must complete: ' + error.code + ': ' + str(error))

    def backend_contract(self, proof):
        self.assertIsInstance(proof,dict)
        self.assertEqual(set(proof), {'implementation','protocol','partitions','executed','bridge_sha256','modules'})
        self.assertEqual(proof['implementation'],'UDTools Graph/Node')
        self.assertEqual(proof['protocol'],'partitioned-incidence-v1')
        self.assertIs(type(proof['partitions']),int)
        self.assertGreater(proof['partitions'],0)
        self.assertIs(proof['executed'],True)
        self.assertIsInstance(proof['bridge_sha256'],str)
        self.assertRegex(proof['bridge_sha256'],r'^[0-9a-f]{64}$')
        self.assertEqual(proof['bridge_sha256'],hashlib.sha256(BRIDGE.read_bytes()).hexdigest())
        self.assertIsInstance(proof['modules'],dict)
        self.assertEqual(set(proof['modules']),{'Graph.pm','Node.pm'})
        self.assertEqual(proof['modules'],{name:hashlib.sha256((self.tools/name).read_bytes()).hexdigest() for name in ('Graph.pm','Node.pm')})

    def test_public_handler_preserves_empty_nodes_self_edges_duplicates_and_labels(self):
        text = '# sent_id = graph\n1\tA\t_\tNOUN\t_\t_\t0\troot\t0:root|1:Self :λ|1:Self :λ\t_\n1.1\tghost\t_\tX\t_\t_\t_\t_\t1:Empty:日本語\t_\n2\tB\t_\tNOUN\t_\t_\t1\tdep\t2:loop\t_\n\n'
        (self.root/'graph.conllu').write_text(text)
        result = self.completed(enhanced_graph_report, {'working_tree_path':str(self.root),'file_paths':['graph.conllu']})
        self.assertIsInstance(result,dict)
        self.assertEqual(set(result),{'sentences','backend','definition'})
        self.backend_contract(result['backend'])
        sentence = result['sentences'][0]
        self.assertEqual(sentence['nodes'],3)
        self.assertEqual(sentence['unreachable_from_root'],['2'])
        self.assertEqual(sentence['edges'],[
            {'head_id':'0','dependent_id':'1','deprel':'root'},
            {'head_id':'1','dependent_id':'1','deprel':'Self :λ'},
            {'head_id':'1','dependent_id':'1','deprel':'Self :λ'},
            {'head_id':'1','dependent_id':'1.1','deprel':'Empty:日本語'},
            {'head_id':'2','dependent_id':'2','deprel':'loop'}])
        self.assertTrue(result['backend']['executed'])
        self.assertEqual(result['backend']['implementation'],'UDTools Graph/Node')
        self.assertEqual(set(result['backend']['modules']),{'Graph.pm','Node.pm'})
        self.assertEqual((self.root/'graph.conllu').read_text(),text)

    def test_long_and_dense_graphs_use_one_perl_process_without_lowering_input_limits(self):
        chain = [{'head_id':str(i),'dependent_id':str(i+1),'deprel':'root' if i==0 else 'dep'} for i in range(800)]
        dense = [{'head_id':'0','dependent_id':'1','deprel':'relation:'+str(i)} for i in range(2050)]
        partitions = list(_partitions([chain,dense]))
        self.assertGreater(len(partitions),5)
        for part in partitions:
            self.assertIsInstance(part,tuple); self.assertEqual(len(part),4)
            self.assertIsInstance(part[1],dict)
            self.assertEqual(set(part[1]),{'operation','nodes','edges'})
            self.assertIsInstance(part[1]['nodes'],list); self.assertIsInstance(part[1]['edges'],list)
        self.assertTrue(all(len(request['nodes'])<=256 and len(request['edges'])<=1024 for _,request,_,_ in partitions))
        original = subprocess.run
        with patch('ud_agent.graph_backend.subprocess.run', wraps=original) as run:
            inspected = self.completed(inspect_graphs, [chain,dense])
        self.assertIsInstance(inspected,tuple); self.assertEqual(len(inspected),2)
        adjacency, proof = inspected; self.backend_contract(proof)
        self.assertEqual(run.call_count,1)
        self.assertEqual(run.call_args.args[0][-1],'--stream')
        self.assertEqual({k:set(v) for k,v in adjacency[0].items()}, {str(i):{str(i+1)} for i in range(800)})
        self.assertEqual({k:set(v) for k,v in adjacency[1].items()}, {'0':{'1'}})
        self.assertEqual(proof['partitions'],len(partitions))

    def test_partition_contract_has_exact_role_maps_labels_deduplication_and_empty_graph(self):
        edges = [
            {'head_id':'0','dependent_id':'1','deprel':'root'},
            {'head_id':'1','dependent_id':'1','deprel':'self:λ'},
            {'head_id':'1.1','dependent_id':'2','deprel':'empty:日本語'},
            {'head_id':'0','dependent_id':'1','deprel':'root'},
        ]
        self.assertEqual(list(_partitions([edges,[]])), [
            (0, {'operation':'inspect_enhanced','nodes':['1','2','3','4'],'edges':[
                {'head':'0','dependent':'1','relation':'r0'},
                {'head':'2','dependent':'1','relation':'r1'},
                {'head':'4','dependent':'3','relation':'r2'}]},
             {'0':'0','1':'1','2':'1','3':'2','4':'1.1'},
             {'r0':'root','r1':'self:λ','r2':'empty:日本語'}),
            (1, {'operation':'inspect_enhanced','nodes':[],'edges':[]}, {'0':'0'}, {}),
        ])

    def test_partition_boundaries_use_full_node_and_edge_capacity_and_reset_maps(self):
        chain = [{'head_id':str(index+1),'dependent_id':str(index+2),'deprel':'dep'} for index in range(129)]
        dense = [{'head_id':'0','dependent_id':'1','deprel':'label:'+str(index)} for index in range(1025)]
        parts = list(_partitions([chain,dense]))
        self.assertEqual([(index,len(request['nodes']),len(request['edges'])) for index,request,_,_ in parts],
                         [(0,256,128),(0,2,1),(1,1,1024),(1,1,1)])
        self.assertEqual(parts[1][2], {'0':'0','1':'130','2':'129'})
        self.assertEqual(parts[1][1]['edges'], [{'head':'2','dependent':'1','relation':'r0'}])
        self.assertEqual(parts[2][3], {'r'+str(index):'label:'+str(index) for index in range(1024)})
        self.assertEqual(parts[3][3], {'r0':'label:1024'})
        star = [{'head_id':'5','dependent_id':str(index+10),'deprel':'dep'} for index in range(256)]
        self.assertEqual([(len(request['nodes']),len(request['edges'])) for _,request,_,_ in _partitions([star])],
                         [(256,255),(2,1)])

    def test_reused_head_incidence_is_independent_of_input_and_alias_creation_order(self):
        graph = [
            {'head_id':'0','dependent_id':'1','deprel':'root'},
            {'head_id':'5','dependent_id':'1','deprel':'first'},
            {'head_id':'6','dependent_id':'1','deprel':'second'},
            {'head_id':'7','dependent_id':'1','deprel':'third-head'},
            {'head_id':'6','dependent_id':'2','deprel':'third'},
            {'head_id':'5','dependent_id':'2','deprel':'fourth'},
        ]
        inspected = self.completed(inspect_graphs,[graph])
        self.assertIsInstance(inspected,tuple); self.assertEqual(len(inspected),2)
        adjacency, proof = inspected; self.backend_contract(proof)
        self.assertEqual([{head:set(dependents) for head,dependents in current.items()} for current in adjacency],
                         [{'0':{'1'},'5':{'1','2'},'6':{'1','2'},'7':{'1'}}])

    def test_backend_rejects_incomplete_incidence_framing_and_process_failures(self):
        graph = [[{'head_id':'0','dependent_id':'1','deprel':'root'}]]
        valid = {'ok':True,'nodes':[
            {'id':'0','in_degree':0,'out_degree':1,'incoming':[]},
            {'id':'1','in_degree':1,'out_degree':0,'incoming':[{'head':'0','relation':'r0'}]},
        ]}
        encoded = json.dumps(valid).encode()+b'\n'
        cases = [
            (b'', b'', 0, 'GRAPH_INCOMPLETE'),
            (encoded[:-1], b'', 0, 'GRAPH_INCOMPLETE'),
            (b'not-json\n', b'', 0, 'GRAPH_INCOMPLETE'),
            (b'\xff\n', b'', 0, 'GRAPH_INCOMPLETE'),
            (encoded+b'\n', b'', 0, 'GRAPH_INCOMPLETE'),
            (encoded, b'warning', 0, 'GRAPH_EXECUTION_FAILED'),
            (encoded, b'', 1, 'GRAPH_EXECUTION_FAILED'),
        ]
        for payload, diagnostic, status, expected in cases:
            with self.subTest(payload=payload, diagnostic=diagnostic, status=status):
                def invoke(*_args, **kwargs):
                    kwargs['stdout'].write(payload); kwargs['stderr'].write(diagnostic)
                    return subprocess.CompletedProcess([],status)
                with patch('ud_agent.graph_backend.subprocess.run',side_effect=invoke):
                    with self.assertRaises(WorkerError) as caught: inspect_graphs(graph)
                self.assertEqual(caught.exception.code,expected)
        for exception, expected in [(subprocess.TimeoutExpired('perl',120),'GRAPH_TIMEOUT'), (OSError('unavailable'),'GRAPH_EXECUTION_FAILED')]:
            with self.subTest(exception=exception), patch('ud_agent.graph_backend.subprocess.run',side_effect=exception):
                with self.assertRaises(WorkerError) as caught: inspect_graphs(graph)
                self.assertEqual(caught.exception.code,expected)

    def test_response_frames_accept_lf_crlf_and_exact_one_mib_but_reject_one_extra_byte(self):
        graph = [[{'head_id':'0','dependent_id':'1','deprel':'root'}]]
        valid = {'ok':True,'nodes':[
            {'id':'0','in_degree':0,'out_degree':1,'incoming':[]},
            {'id':'1','in_degree':1,'out_degree':0,'incoming':[{'head':'0','relation':'r0'}]},
        ]}
        encoded = json.dumps(valid).encode()
        boundary = encoded + b' ' * (1048576 - len(encoded) - 1) + b'\n'
        self.assertEqual(len(boundary),1048576)
        for payload in (encoded+b'\n',encoded+b'\r\n',boundary):
            with self.subTest(size=len(payload),ending=payload[-2:]):
                def invoke(*_args, **kwargs):
                    kwargs['stdout'].write(payload)
                    return subprocess.CompletedProcess([],0)
                with patch('ud_agent.graph_backend.subprocess.run',side_effect=invoke):
                    result = self.completed(inspect_graphs,graph)
                self.assertIsInstance(result,tuple); self.assertEqual(len(result),2)
                adjacency, proof = result; self.backend_contract(proof)
                self.assertEqual([{head:set(dependents) for head,dependents in current.items()} for current in adjacency],[{'0':{'1'}}])
        oversized = boundary[:-1] + b' \n'
        self.assertEqual(len(oversized),1048577)
        def oversized_response(*_args, **kwargs):
            kwargs['stdout'].write(oversized)
            return subprocess.CompletedProcess([],0)
        with patch('ud_agent.graph_backend.subprocess.run',side_effect=oversized_response):
            with self.assertRaises(WorkerError) as caught: inspect_graphs(graph)
        self.assertEqual(caught.exception.code,'GRAPH_INCOMPLETE')

    def test_stream_has_independent_graph_state_and_strict_complete_framing(self):
        first = {'operation':'inspect_enhanced','nodes':['1'],'edges':[{'head':'0','dependent':'1','relation':'root'}]}
        second = {'operation':'inspect_enhanced','nodes':[],'edges':[]}
        command = [os.environ['UD_AGENT_PERL'],'-I',str(self.tools),str(BRIDGE),'--stream']
        encoded = (json.dumps(first)+'\n'+json.dumps(second)+'\n').encode()
        result = subprocess.run(command,input=encoded,capture_output=True,check=False,timeout=10)
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        expected_frames = [
            {'ok':True,'nodes':[{'id':'0','in_degree':0,'out_degree':1,'incoming':[]},
                              {'id':'1','in_degree':1,'out_degree':0,'incoming':[{'head':'0','relation':'root'}]}]},
            {'ok':True,'nodes':[{'id':'0','in_degree':0,'out_degree':0,'incoming':[]}]},
        ]
        self.assertEqual(result.stdout, b'\n'.join(json.dumps(frame,sort_keys=True,separators=(',',':')).encode() for frame in expected_frames)+b'\n')
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(frames[0]['nodes'][0]['out_degree'],1)
        self.assertEqual(frames[1],{'ok':True,'nodes':[{'id':'0','in_degree':0,'out_degree':0,'incoming':[]}]})
        for payload, code in [(b'','invalid_stream'), (json.dumps(first).encode(),'invalid_stream'), (b'{}\n','unsupported_request'), (b'x'*262145+b'\n','input_too_large')]:
            result = subprocess.run(command,input=payload,capture_output=True,check=False,timeout=10)
            self.assertEqual((result.returncode,result.stderr),(1,b''))
            self.assertEqual(result.stdout,json.dumps({'ok':False,'error':code},sort_keys=True,separators=(',',':')).encode())
            self.assertEqual(json.loads(result.stdout),{'ok':False,'error':code})

    def test_stream_releases_all_upstream_node_graph_ownership_cycles(self):
        marker = self.root/'released'
        escaped = str(marker).replace('\\','\\\\').replace("'","\\'")
        instrumented = FAKE.replace('sub set_graph { $_[0]->{graph} = $_[1] }',
            "sub set_graph { die 'not released' if defined $_[1]; open(my $log, '>>', '"+escaped+"') or die; print $log qq(released\\n); close($log) or die; $_[0]->{graph} = $_[1]; }")
        self.assertNotEqual(instrumented,FAKE)
        (self.tools/'Graph.pm').write_text(instrumented)
        graphs = [[{'head_id':'0','dependent_id':'1','deprel':'root'}], [],
                  [{'head_id':str(i),'dependent_id':str(i+1),'deprel':'dep'} for i in range(300)]]
        expected = sum(len(request['nodes'])+1 for _,request,_,_ in _partitions(graphs))
        inspected = self.completed(inspect_graphs, graphs)
        self.assertIsInstance(inspected,tuple); self.assertEqual(len(inspected),2)
        _, proof = inspected; self.backend_contract(proof)
        self.assertGreater(proof['partitions'],3)
        self.assertEqual(marker.read_text().splitlines(),['released']*expected)

    def test_inconsistent_or_missing_upstream_backend_cannot_report_success(self):
        (self.tools/'Graph.pm').write_text(FAKE.replace('scalar @{$_[0]->{iedges}}','99'))
        with self.assertRaisesRegex(WorkerError,'did not complete|inconsistent'):
            inspect_graphs([[{'head_id':'0','dependent_id':'1','deprel':'root'}]])
        (self.tools/'Graph.pm').unlink()
        with self.assertRaises(PrerequisiteMissing): inspect_graphs([[]])
        self.assertEqual(inspect_graphs([]),([],{ 'implementation':'UDTools Graph/Node','protocol':'partitioned-incidence-v1','partitions':0,'executed':False}))


if __name__ == '__main__': unittest.main()
