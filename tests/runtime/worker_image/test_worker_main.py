"""Exercise the actual worker transport entry point without child coverage gaps."""
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from ud_agent import worker, wire


class Output(io.BytesIO):
    def __init__(self): super().__init__(); self.flushes=0
    def flush(self): self.flushes+=1; super().flush()


class WorkerMainTests(unittest.TestCase):
    def call(self,data,limit=None):
        incoming,outgoing=io.BytesIO(data),Output()
        with patch.object(worker.sys,'stdin',types.SimpleNamespace(buffer=incoming)),patch.object(worker.sys,'stdout',types.SimpleNamespace(buffer=outgoing)):
            if limit is None: code=worker.main()
            else:
                with patch.object(worker,'MAX_REQUEST_BYTES',limit): code=worker.main()
        return code,[json.loads(line)for line in outgoing.getvalue().splitlines()],outgoing.flushes,incoming

    def test_multiple_real_operations_invalid_frames_and_eof_keep_independent_responses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'a.conllu').write_text('# sent_id = independent\n1\tA\t_\tNOUN\t_\t_\t0\troot\t_\t_\n\n')
            request={'operation':'tree_list','arguments':{'working_tree_path':str(root),'file_paths':['a.conllu']}}
            code,responses,flushes,_=self.call(json.dumps(request).encode()+b'\n{\n\xff\n'+json.dumps(request).encode())
        self.assertEqual(code,0);self.assertEqual(flushes,4);self.assertEqual(len(responses),4)
        self.assertTrue(responses[0]['ok']);self.assertEqual(responses[0]['result']['trees'][0]['sent_id'],'independent')
        self.assertEqual(responses[0],responses[3])
        for response in responses[1:3]: self.assertEqual(response,{'ok':False,'error':{'code':'INVALID_JSON','message':'worker request is not valid JSON'}})
        self.assertEqual(self.call(b'')[:3],(0,[],0))

    def test_oversized_line_stops_before_processing_any_following_request(self):
        code,responses,flushes,incoming=self.call(b'x'*33+b'\n{}\n',32)
        self.assertEqual((code,flushes),(1,1))
        self.assertEqual(responses,[{'ok':False,'error':{'code':'REQUEST_TOO_LARGE','message':'worker request exceeds the size limit'}}])
        self.assertEqual(incoming.read(),b'\n{}\n')

    def test_exact_request_byte_ceiling_is_admitted_before_shape_validation(self):
        code,responses,flushes,_=self.call(b'{}'+b' '*29+b'\n',32)
        self.assertEqual((code,flushes),(0,1))
        self.assertEqual(responses,[{'ok':False,'error':{'code':'INVALID_INPUT','message':'request must contain exactly operation and arguments'}}])

    def test_response_budget_failure_becomes_a_small_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'a.conllu').write_text('# sent_id = independent\n1\tA\t_\tNOUN\t_\t_\t0\troot\t_\t_\n\n')
            request={'operation':'tree_list','arguments':{'working_tree_path':str(root),'file_paths':['a.conllu']}}
            with patch.object(wire,'MAX_RESPONSE_BYTES',128): code,responses,flushes,_=self.call(json.dumps(request).encode()+b'\n')
        self.assertEqual((code,flushes),(0,1))
        self.assertEqual(responses,[{'ok':False,'error':{'code':'RESULT_TOO_LARGE','message':'worker result exceeds the configured size limit'}}])


if __name__=='__main__':unittest.main()
