"""Pinned Graph/Node incidence inspection with lossless bounded graph partitions."""
from __future__ import annotations
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from .errors import PrerequisiteMissing, WorkerError
from .perl_runtime import command, oci_runtime

MAX_TRANSFER = 128 * 1024**2


def _partitions(graphs):
    """Use local role identities so even a self-edge remains representable.

    The public graph keeps word/empty-node IDs, all original labels and duplicate
    annotations. Backend partitions represent each unique incidence exactly once;
    root remains 0. Role aliases prevent an upstream simple-graph guard from
    narrowing existing self-edge reporting. Recomposition restores original IDs.
    """
    for index, edges in enumerate(graphs):
        unique = dict.fromkeys((item['head_id'], item['dependent_id'], item['deprel']) for item in edges)
        aliases, reverse, labels, mapped = {}, {'0':'0'}, {}, []
        for head, dependent, relation in unique:
            keys = [('dependent', dependent)] + ([] if head == '0' else [('head', head)])
            needed = sum(key not in aliases for key in keys)
            if mapped and (len(aliases) + needed > 256 or len(mapped) >= 1024):
                yield index, {'operation':'inspect_enhanced','nodes':list(reverse)[1:],'edges':mapped}, reverse, labels
                aliases, reverse, labels, mapped = {}, {'0':'0'}, {}, []
            for key in keys:
                if key not in aliases:
                    value = str(len(aliases) + 1); aliases[key] = value; reverse[value] = key[1]
            label = 'r' + str(len(labels))
            labels[label] = relation
            mapped.append({'head':'0' if head == '0' else aliases[('head',head)], 'dependent':aliases[('dependent',dependent)], 'relation':label})
        # An empty graph still imports and exercises the verified module closure.
        if mapped or not unique:
            yield index, {'operation':'inspect_enhanced','nodes':list(reverse)[1:],'edges':mapped}, reverse, labels


def inspect_graphs(graphs):
    if not graphs:
        return [], {'implementation':'UDTools Graph/Node', 'protocol':'partitioned-incidence-v1', 'partitions':0, 'executed':False}
    tools = Path(os.environ.get('UD_AGENT_UDTOOLS', '/opt/ud-agent/upstream'))
    image = oci_runtime() if 'UD_AGENT_PERL' not in os.environ else None
    perl = Path(os.environ.get('UD_AGENT_PERL', image['executable'] if image else '/usr/bin/perl'))
    bridge = Path(__file__).resolve().parent / 'perl/graph_bridge.pl'
    if (not tools.is_absolute() or not perl.is_absolute() or not perl.is_file()
            or any(not (tools / name).is_file() for name in ('Graph.pm','Node.pm'))):
        raise PrerequisiteMissing('enhanced graph inspection requires the pinned Perl Graph/Node runtime')
    invocations = []
    adjacency = [defaultdict(set) for _ in graphs]
    with tempfile.TemporaryDirectory(prefix='ud-graph-') as temporary:
        env = {'PATH':'/usr/bin:/bin','HOME':temporary,'LANG':'C','LC_ALL':'C'}
        if os.name == 'nt' and 'SystemRoot' in os.environ:
            env['SystemRoot'] = os.environ['SystemRoot']; env['PATH'] = str(Path(env['SystemRoot']) / 'System32')
        with tempfile.TemporaryFile(dir=temporary) as requests, tempfile.TemporaryFile(dir=temporary) as responses, tempfile.TemporaryFile(dir=temporary) as diagnostics:
            total = 0
            for index, request, reverse, labels in _partitions(graphs):
                frame = json.dumps(request, separators=(',',':')).encode('utf-8') + b'\n'; total += len(frame)
                if total > MAX_TRANSFER: raise WorkerError('GRAPH_LIMIT_EXCEEDED','enhanced graph adapter transfer exceeds its worker budget')
                requests.write(frame); invocations.append((index,request,reverse,labels))
            requests.seek(0)
            try:
                process = subprocess.run([*command(perl,bridge,tools),'--stream'], stdin=requests, stdout=responses, stderr=diagnostics, cwd=temporary, env=env, timeout=120, check=False)
            except subprocess.TimeoutExpired as error:
                raise WorkerError('GRAPH_TIMEOUT','pinned enhanced graph inspection timed out') from error
            except OSError as error:
                raise WorkerError('GRAPH_EXECUTION_FAILED','pinned enhanced graph inspection could not start') from error
            if process.returncode != 0 or responses.tell() > MAX_TRANSFER or diagnostics.tell() != 0:
                raise WorkerError('GRAPH_EXECUTION_FAILED','pinned enhanced graph inspection did not complete')
            responses.seek(0)
            for index, request, reverse, labels in invocations:
                raw = responses.readline(1024**2 + 1)
                if len(raw) > 1024**2 or not raw.endswith(b'\n'):
                    raise WorkerError('GRAPH_INCOMPLETE','enhanced graph adapter returned an incomplete or oversized frame')
                try: result = json.loads(raw)
                except (ValueError,UnicodeError) as error: raise WorkerError('GRAPH_INCOMPLETE','enhanced graph adapter returned an invalid frame') from error
                expected_in = {node:[] for node in reverse}; expected_out = {node:0 for node in reverse}
                for edge in request['edges']:
                    expected_in[edge['dependent']].append({'head':edge['head'],'relation':edge['relation']}); expected_out[edge['head']] += 1
                expected = [{'id':node, 'in_degree':len(expected_in[node]), 'out_degree':expected_out[node],
                             'incoming':sorted(expected_in[node], key=lambda value:(int(value['head']), value['relation']))} for node in sorted(reverse,key=int)]
                if (not isinstance(result,dict) or set(result) != {'ok','nodes'} or result['ok'] is not True or result['nodes'] != expected
                        or any(type(node.get(field)) is not int for node in result['nodes'] for field in ('in_degree','out_degree'))):
                    raise WorkerError('GRAPH_INCOMPLETE','enhanced graph adapter returned inconsistent node incidence')
                # Reachability consumes actual Graph/Node incidence, independently
                # compared above against the lossless transport annotation map.
                for node in result['nodes']:
                    for edge in node['incoming']:
                        adjacency[index][reverse[edge['head']]].add(reverse[node['id']])
            if responses.read(1): raise WorkerError('GRAPH_INCOMPLETE','enhanced graph adapter returned extra frames')
    provenance = {'implementation':'UDTools Graph/Node', 'protocol':'partitioned-incidence-v1', 'partitions':len(invocations), 'executed':True,
                  'bridge_sha256':hashlib.sha256(bridge.read_bytes()).hexdigest(),
                  'modules':{name:hashlib.sha256((tools/name).read_bytes()).hexdigest() for name in ('Graph.pm','Node.pm')}}
    return adjacency, provenance
