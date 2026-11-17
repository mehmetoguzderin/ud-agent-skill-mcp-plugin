"""Bridge protocol tests with an explicit fake Graph/Node, not upstream evidence.

Run locally with a Perl interpreter containing core JSON::PP. These tests do not
qualify a worker image or claim that the upstream Graph module was exercised.
"""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
BRIDGE = ROOT / 'workers/ud/src/ud_agent/perl/graph_bridge.pl'
FAKE = r'''
package Node;
sub new { my ($class, %args) = @_; bless {id => $args{id}, iedges => [], oedges => []}, $class }
sub iedges { $_[0]->{iedges} }
sub get_in_degree { scalar @{$_[0]->{iedges}} }
sub get_out_degree { scalar @{$_[0]->{oedges}} }
sub set_graph { $_[0]->{graph} = $_[1] }
package Graph;
sub new { bless {nodes => {0 => Node->new(id => 0)}}, $_[0] }
sub add_node { $_[0]->{nodes}{$_[1]->{id}} = $_[1] }
sub get_node { $_[0]->{nodes}{$_[1]} }
sub add_edge {
    my ($self, $src, $dst, $rel) = @_;
    push @{$self->{nodes}{$src}{oedges}}, {id => $dst, deprel => $rel};
    push @{$self->{nodes}{$dst}{iedges}}, {id => $src, deprel => $rel};
}
1;
'''


class GraphBridgeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        Path(self.directory.name, 'Graph.pm').write_text(FAKE)
        Path(self.directory.name, 'Node.pm').write_text('1;\n')

    def call(self, request, *, libraries=True, reader_script=None):
        payload = request if isinstance(request, bytes) else json.dumps(request).encode()
        command = [os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl']
        if libraries:
            command += ['-I', self.directory.name]
        command += ['-e', reader_script, str(BRIDGE)] if reader_script else [str(BRIDGE)]
        env = {**os.environ, 'PERL5OPT': '', 'PERL5LIB': ''}
        result = subprocess.run(command, input=payload, capture_output=True, timeout=10, env=env)
        self.assertEqual(result.stderr, b'')
        if result.returncode not in (0, 1):
            print('UD_COMPONENT_UNEXPECTED_EXIT:' + str(result.returncode))
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError:
            self.fail('bridge response must contain exactly one valid JSON value')
        self.assertIsInstance(response, dict)
        self.assertIn('ok', response)
        self.assertIsInstance(response['ok'], bool)
        if response['ok']:
            self.assertEqual(set(response), {'ok', 'nodes'})
            self.assertIsInstance(response['nodes'], list)
        else:
            self.assertEqual(set(response), {'ok', 'error'})
            self.assertIsInstance(response['error'], str)
        return result.returncode, response

    def stream(self, payload, *, reader_script=None, timeout=120):
        perl = os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl'
        command = [perl, '-I', self.directory.name]
        command += ['-e', reader_script, str(BRIDGE), '--stream'] if reader_script else [str(BRIDGE), '--stream']
        result = subprocess.run(command, input=payload, capture_output=True, timeout=timeout,
                                env={**os.environ, 'PERL5OPT': '', 'PERL5LIB': ''})
        self.assertEqual(result.stderr, b'')
        if result.returncode not in (0, 1): print('UD_COMPONENT_UNEXPECTED_EXIT:' + str(result.returncode))
        return result

    def stream_bytes(self, result, code, expected):
        self.assertEqual(result.returncode, code)
        self.assertEqual(len(result.stdout), len(expected))
        # Large boundary cases must report compact assertion evidence, rather
        # than dump megabytes of expected protocol bytes into the runner log.
        self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), hashlib.sha256(expected).hexdigest())

    @staticmethod
    def error_bytes(code):
        return json.dumps({'ok': False, 'error': code}, sort_keys=True, separators=(',', ':')).encode()

    @staticmethod
    def empty_graph_bytes():
        return json.dumps({'ok': True, 'nodes': [{'id': '0', 'in_degree': 0, 'out_degree': 0, 'incoming': []}]}, sort_keys=True, separators=(',', ':')).encode() + b'\n'

    def test_stream_resets_inherited_text_layers_before_counting_protocol_bytes(self):
        bootstrap = 'binmode(STDIN, ":crlf"); binmode(STDOUT, ":crlf"); my $file=shift @ARGV; do $file;'
        request = json.dumps({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}).encode()
        result = self.stream(request + b'\r\n' + request + b'\n', reader_script=bootstrap)
        self.stream_bytes(result, 0, self.empty_graph_bytes() * 2)

    def test_degrees_and_incoming_edges_come_from_graph_fixture(self):
        code, result = self.call({'operation': 'inspect_enhanced', 'nodes': ['2', '1'], 'edges': [
            {'head': '1', 'dependent': '2', 'relation': 'nsubj'},
            {'head': '0', 'dependent': '1', 'relation': 'root'},
        ]})
        self.assertEqual(code, 0)
        self.assertEqual(result, {'ok': True, 'nodes': [
            {'id': '0', 'in_degree': 0, 'out_degree': 1, 'incoming': []},
            {'id': '1', 'in_degree': 1, 'out_degree': 1, 'incoming': [{'head': '0', 'relation': 'root'}]},
            {'id': '2', 'in_degree': 1, 'out_degree': 0, 'incoming': [{'head': '1', 'relation': 'nsubj'}]},
        ]})

    def test_streams_independent_graphs_with_exact_frame_boundaries(self):
        request = {'operation': 'inspect_enhanced', 'nodes': ['1'], 'edges': [{'head': '0', 'dependent': '1', 'relation': 'root'}]}
        payload = (json.dumps(request) + '\n' + json.dumps(request) + '\n').encode()
        perl = os.environ.get('UD_AGENT_PERL') or shutil.which('perl') or '/usr/bin/perl'
        result = subprocess.run([perl, '-I', self.directory.name, str(BRIDGE), '--stream'], input=payload,
                                capture_output=True, timeout=10, env={**os.environ, 'PERL5OPT': '', 'PERL5LIB': ''})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        expected = {'ok': True, 'nodes': [
            {'id': '0', 'in_degree': 0, 'out_degree': 1, 'incoming': []},
            {'id': '1', 'in_degree': 1, 'out_degree': 0, 'incoming': [{'head': '0', 'relation': 'root'}]},
        ]}
        self.assertEqual(result.stdout, b'\n'.join(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode() for _ in range(2)) + b'\n')

    def test_stream_fragmentation_eof_and_reader_failures_preserve_exact_protocol(self):
        frame = json.dumps({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}).encode() + b'\n'
        expected = self.empty_graph_bytes()
        one_byte = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle,$buffer)=@_; return CORE::read($handle,$$buffer,1); }; } do shift @ARGV;'''
        self.stream_bytes(self.stream(frame + frame, reader_script=one_byte), 0, expected + expected)
        bounded = r'''BEGIN { my $eof=0; *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle,$buffer,$length)=@_; die "read beyond first EOF" if $eof; my $n=CORE::read($handle,$$buffer,$length); $eof=1 if defined($n) && $n==0; return $n; }; } do shift @ARGV;'''
        self.stream_bytes(self.stream(frame, reader_script=bounded), 0, expected)
        failed = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { return undef; }; } do shift @ARGV;'''
        self.stream_bytes(self.stream(b'', reader_script=failed), 1, self.error_bytes('input_read_failed'))
        self.stream_bytes(self.stream(b'', reader_script='close STDIN; do shift @ARGV;'), 1, self.error_bytes('input_read_failed'))
        unexpected = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { die "unexpected reader failure\n"; }; } do shift @ARGV;'''
        self.stream_bytes(self.stream(b'', reader_script=unexpected), 1, self.error_bytes('graph_execution_failed'))
        self.stream_bytes(self.stream(b''), 1, self.error_bytes('invalid_stream'))
        self.stream_bytes(self.stream(b'\n'), 1, self.error_bytes('invalid_json'))

    def test_stream_read_fault_preserves_only_frames_completed_before_the_fixed_read_budget(self):
        encoded = json.dumps({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}).encode()
        fails_second = r'''BEGIN { my $calls=0; *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle,$buffer,$length)=@_; return undef if ++$calls==2; return CORE::read($handle,$$buffer,$length); }; } do shift @ARGV;'''
        # The bridge's bounded read is 8 KiB. A frame fitting that read is
        # observable before a later read fault; a one-byte-longer frame is not.
        complete = encoded + b' ' * (8191 - len(encoded)) + b'\n'
        incomplete = encoded + b' ' * (8192 - len(encoded)) + b'\n'
        self.stream_bytes(self.stream(complete, reader_script=fails_second), 1, self.empty_graph_bytes() + self.error_bytes('input_read_failed'))
        self.stream_bytes(self.stream(incomplete, reader_script=fails_second), 1, self.error_bytes('input_read_failed'))

    def test_stream_exact_frame_and_unterminated_pending_bounds(self):
        encoded = json.dumps({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}).encode()
        frame = encoded + b' ' * (262144 - len(encoded))
        self.stream_bytes(self.stream(frame + b'\n'), 0, self.empty_graph_bytes())
        self.stream_bytes(self.stream(frame + b' \n'), 1, self.error_bytes('input_too_large'))
        self.stream_bytes(self.stream(frame), 1, self.error_bytes('invalid_stream'))
        self.stream_bytes(self.stream(frame + b' '), 1, self.error_bytes('input_too_large'))

    def test_stream_exact_aggregate_bytes_and_one_byte_overflow(self):
        encoded = json.dumps({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}).encode()
        frame = encoded + b' ' * (262143 - len(encoded)) + b'\n'
        payload = frame * 512
        self.assertEqual(len(payload), 134217728)
        expected = self.empty_graph_bytes() * 512
        # Exercise the real 128 MiB transport/accounting boundary. An explicit
        # codec fixture avoids repeatedly parsing padding; real codec/frame
        # limits and exact graph bytes are independently exercised above.
        codec = r'''BEGIN { require JSON::PP; no warnings 'redefine'; *JSON::PP::decode=sub { return {operation=>'inspect_enhanced',nodes=>[],edges=>[]}; }; } do shift @ARGV;'''
        self.stream_bytes(self.stream(payload, reader_script=codec), 0, expected)
        self.stream_bytes(self.stream(payload + b' ', reader_script=codec), 1, expected + self.error_bytes('input_too_large'))

    def test_stream_exact_million_frame_budget_without_upstream_codec_cost(self):
        # Explicit authored codec/Graph fixtures isolate framing accounting.
        # The actual unmodified bridge still performs every stream/main call;
        # no threshold, source byte or selected mutation is patched for tests.
        Path(self.directory.name, 'Graph.pm').write_text('''package Node; my $node=bless {},'Node'; sub iedges { [] } sub get_in_degree { 0 } sub get_out_degree { 0 } sub set_graph {}\npackage Graph; my $graph=bless {},'Graph'; sub new { $graph } sub get_node { $node } 1;\n''')
        codec = r'''BEGIN { require JSON::PP; my $encode=JSON::PP->can('encode'); no warnings 'redefine'; *JSON::PP::decode=sub { return {operation=>'inspect_enhanced',nodes=>[],edges=>[]}; }; *JSON::PP::encode=sub { my ($self,$value)=@_; return '' if $value->{ok}; return $encode->(@_); }; } do shift @ARGV;'''
        payload = b'{}\n' * 1000000
        # One execution proves that exactly a million frames completed before
        # the next frame is rejected, including both boundary directions.
        self.stream_bytes(self.stream(payload + b'{}\n', reader_script=codec), 1, b'\n' * 1000000 + self.error_bytes('input_too_large'))

    def test_rejects_bad_graphs_before_loading_dependencies(self):
        base = {'operation': 'inspect_enhanced', 'nodes': ['1'], 'edges': []}
        cases = [
            ({**base, 'nodes': ['1', '1']}, 'invalid_node'),
            ({**base, 'nodes': ['1.1']}, 'invalid_node'),
            ({**base, 'extra': 1}, 'unsupported_request'),
            ({**base, 'edges': [{'head': '2', 'dependent': '1', 'relation': 'dep'}]}, 'invalid_edge'),
            ({**base, 'edges': [{'head': '0', 'dependent': '1', 'relation': 'dep;system'}]}, 'invalid_edge'),
            ({**base, 'edges': [{'head': '1', 'dependent': '1', 'relation': 'dep'}]}, 'invalid_edge'),
            ({**base, 'edges': [{'head': '0', 'dependent': '1', 'relation': 'dep'}] * 2}, 'duplicate_edge'),
            ({**base, 'nodes': [str(i) for i in range(1, 258)]}, 'invalid_nodes'),
        ]
        for request, expected in cases:
            with self.subTest(expected=expected, request=request):
                code, result = self.call(request, libraries=False)
                self.assertEqual((code, result), (1, {'ok': False, 'error': expected}))

    def test_invalid_json_large_input_and_missing_modules_fail_closed(self):
        for payload, expected in [(b'{', 'invalid_json'), (b'x' * 262145, 'input_too_large')]:
            self.assertEqual(self.call(payload, libraries=False), (1, {'ok': False, 'error': expected}))
        self.assertEqual(self.call({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}, libraries=False),
                         (1, {'ok': False, 'error': 'graph_prerequisites_unavailable'}))

    def test_exact_input_node_and_edge_boundaries(self):
        base = {'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}
        encoded = json.dumps(base).encode()
        payload = encoded + b' ' * (262144 - len(encoded))
        self.assertEqual(self.call(payload), (0, {'ok': True, 'nodes': [
            {'id': '0', 'in_degree': 0, 'out_degree': 0, 'incoming': []}]}))
        self.assertEqual(self.call(payload + b' '), (1, {'ok': False, 'error': 'input_too_large'}))
        nodes = [str(index) for index in range(1, 257)]
        edges = [{'head': '0', 'dependent': node, 'relation': relation}
                 for node in nodes for relation in ('dep', 'acl', 'nmod', 'xcomp')]
        code, result = self.call({**base, 'nodes': nodes, 'edges': edges})
        self.assertEqual(code, 0)
        self.assertEqual(len(result['nodes']), 257)
        self.assertEqual(result['nodes'][0]['out_degree'], 1024)
        self.assertTrue(all(node['in_degree'] == 4 for node in result['nodes'][1:]))
        self.assertEqual(self.call({**base, 'nodes': nodes, 'edges': edges + [edges[0]]}),
                         (1, {'ok': False, 'error': 'invalid_edges'}))

    def test_wrong_types_missing_fields_and_root_dependents_reject(self):
        base = {'operation': 'inspect_enhanced', 'nodes': ['1'], 'edges': []}
        cases = [(b'null', 'invalid_json'), (b'[]', 'invalid_json'), (b'"scalar"', 'invalid_json'),
                 ({**base, 'nodes': {}}, 'invalid_nodes'), ({**base, 'edges': {}}, 'invalid_edges')]
        for node in (None, [], {}, '0', '-1', '1000000', '1\n'):
            cases.append(({**base, 'nodes': [node]}, 'invalid_node'))
        edge = {'head': '0', 'dependent': '1', 'relation': 'dep'}
        for value in (None, [], {}, ''):
            for field in ('head', 'dependent', 'relation'):
                cases.append(({**base, 'edges': [{**edge, field: value}]}, 'invalid_edge'))
        for field in ('head', 'dependent', 'relation'):
            cases.append(({**base, 'edges': [{key: value for key, value in edge.items() if key != field}]}, 'invalid_edge'))
        cases.extend([({**base, 'edges': [{'head': '1', 'dependent': '0', 'relation': 'dep'}]}, 'invalid_edge'),
                      ({**base, 'edges': [None]}, 'invalid_edge'),
                      ({**base, 'edges': [{**edge, 'unexpected': True}]}, 'invalid_edge'),
                      ({'operation': None, 'nodes': [], 'edges': []}, 'unsupported_request'),
                      ({'nodes': [], 'edges': []}, 'unsupported_request')])
        for request, error in cases:
            with self.subTest(request=request):
                self.assertEqual(self.call(request, libraries=False), (1, {'ok': False, 'error': error}))

    def test_upstream_execution_failure_is_a_structured_bridge_result(self):
        Path(self.directory.name, 'Graph.pm').write_text('package Graph; sub new { die "fixture failure"; } 1;\n')
        self.assertEqual(self.call({'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}),
                         (1, {'ok': False, 'error': 'graph_execution_failed'}))

    def test_fragmented_exact_limit_input_and_eof_progress(self):
        request = {'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}
        encoded = json.dumps(request).encode()
        payload = encoded + b' ' * (262144 - len(encoded))
        fragmented = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle, $buffer) = @_; return CORE::read($handle, $$buffer, 1); }; } do $ARGV[0];'''
        expected = (0, {'ok': True, 'nodes': [{'id': '0', 'in_degree': 0, 'out_degree': 0, 'incoming': []}]})
        self.assertEqual(self.call(payload, reader_script=fragmented), expected)
        bounded = r'''BEGIN { my $calls = 0; *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle, $buffer, $length) = @_; die "read after EOF" if ++$calls > 2; return CORE::read($handle, $$buffer, $length); }; } do $ARGV[0];'''
        self.assertEqual(self.call(request, reader_script=bounded), expected)
        failed = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { return undef; }; } do $ARGV[0];'''
        self.assertEqual(self.call(b'', reader_script=failed), (1, {'ok': False, 'error': 'input_read_failed'}))

    def test_warning_and_reader_fault_boundaries_remain_structured(self):
        request = {'operation': 'inspect_enhanced', 'nodes': [], 'edges': []}
        encoded = json.dumps(request).encode()
        payload = encoded + b' ' * (262144 - len(encoded))
        expected = (0, {'ok': True, 'nodes': [{'id': '0', 'in_degree': 0, 'out_degree': 0, 'incoming': []}]})
        # A finite stream that completes before its next possible failing read.
        fails_on_34 = r'''BEGIN { my $calls=0; *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle,$buffer,$length)=@_; return undef if ++$calls==34; return CORE::read($handle,$$buffer,$length); }; } do $ARGV[0];'''
        self.assertEqual(self.call(payload, reader_script=fails_on_34), expected)
        self.assertEqual(self.call(payload + b' ', reader_script=fails_on_34), (1, {'ok': False, 'error': 'input_too_large'}))
        self.assertEqual(self.call(b'', reader_script='close STDIN; do $ARGV[0];'), (1, {'ok': False, 'error': 'input_read_failed'}))
        unexpected = r'''BEGIN { *CORE::GLOBAL::read = sub (*\$$;$) { die "unexpected owned reader failure\n"; }; } do $ARGV[0];'''
        self.assertEqual(self.call(b'', reader_script=unexpected), (1, {'ok': False, 'error': 'graph_execution_failed'}))
        fails_on_33 = r'''BEGIN { my $calls=0; *CORE::GLOBAL::read = sub (*\$$;$) { my ($handle,$buffer,$length)=@_; return undef if ++$calls==33; return CORE::read($handle,$$buffer,$length); }; } do $ARGV[0];'''
        self.assertEqual(self.call(payload + b' ', reader_script=fails_on_33), (1, {'ok': False, 'error': 'input_read_failed'}))
        # A corrupted reader claiming progress without bytes has a finite budget.
        nonprogress = r'''BEGIN { my $calls=0; *CORE::GLOBAL::read = sub (*\$$;$) { die "reader exceeded its independent attempt budget" if ++$calls>262145; ${$_[1]}=''; return 1; }; } do $ARGV[0];'''
        self.assertEqual(self.call(b'', reader_script=nonprogress), (1, {'ok': False, 'error': 'input_read_failed'}))
        Path(self.directory.name, 'Graph.pm').write_text('package Graph; sub new { warn "fixture warning"; bless {}, $_[0]; } 1;\n')
        self.assertEqual(self.call(request), (1, {'ok': False, 'error': 'graph_execution_failed'}))

    def test_decimal_node_keys_do_not_collide_when_edge_fields_join(self):
        code, result = self.call({'operation': 'inspect_enhanced', 'nodes': ['1', '23', '12', '3'], 'edges': [
            {'head': '1', 'dependent': '23', 'relation': 'dep'},
            {'head': '12', 'dependent': '3', 'relation': 'dep'},
        ]})
        self.assertEqual(code, 0)
        self.assertEqual(result['nodes'][2]['incoming'], [{'head': '12', 'relation': 'dep'}])
        self.assertEqual(result['nodes'][4]['incoming'], [{'head': '1', 'relation': 'dep'}])

    def test_multiple_incoming_heads_and_relation_sort_have_independent_order(self):
        request = {'operation': 'inspect_enhanced', 'nodes': ['12', '1', '2'], 'edges': [
            {'head': '2', 'dependent': '12', 'relation': 'zdep'},
            {'head': '1', 'dependent': '12', 'relation': 'bdep'},
            {'head': '1', 'dependent': '12', 'relation': 'adep'},
        ]}
        code, result = self.call(request)
        self.assertEqual(code, 0)
        self.assertEqual([item['id'] for item in result['nodes']], ['0', '1', '2', '12'])
        self.assertEqual(result['nodes'][3]['incoming'], [{'head': '1', 'relation': 'adep'}, {'head': '1', 'relation': 'bdep'}, {'head': '2', 'relation': 'zdep'}])


if __name__ == '__main__':
    unittest.main()
