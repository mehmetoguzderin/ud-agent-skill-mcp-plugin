"""Exercise child-mode selection and bounded FD transport without coverage loss."""
import importlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import MagicMock, patch
from ud_agent.errors import WorkerError


class ProjectChildTests(unittest.TestCase):
    def setUp(self):
        self.resource=types.SimpleNamespace(RLIMIT_FSIZE=1,RLIM_INFINITY=-1,getrlimit=MagicMock(return_value=(-1,-1)),setrlimit=MagicMock())
        # main() imports resource lazily. Keep the model installed through the
        # call so these policy cases never alter the test runner's real limits.
        self.enterContext(patch.dict(sys.modules,{'resource':self.resource}))
        sys.modules.pop('ud_agent.project_child',None)
        self.module=importlib.import_module('ud_agent.project_child')
        # Model POSIX resource policy on every host without changing global os;
        # the real Windows stdout transport is exercised by validation tests.
        modeled_os=types.SimpleNamespace(**vars(os));modeled_os.name='posix'
        self.enterContext(patch.object(self.module,'os',modeled_os))
        before=list(sys.path);self.addCleanup(lambda:sys.path.__setitem__(slice(None),before))

    def call(self,mode,raw=b'{"independent":"arguments"}',*,failure=None,hard=-1,partial=False):
        read,write=os.pipe();self.addCleanup(lambda:os.close(read));self.addCleanup(lambda:os.close(write))
        arguments=json.loads(raw)
        official=MagicMock(return_value={'origin':'official','passed':False})
        custom=MagicMock(return_value={'origin':'project','passed':True})
        if failure is not None:(official if mode=='official' else custom).side_effect=failure
        self.resource.getrlimit.return_value=(-1,hard)
        write_real=os.write
        written=[]
        class Input(io.BytesIO):
            def __init__(self,data):super().__init__(data);self.calls=[]
            def read(self,size=-1):self.calls.append(size);return super().read(size)
        incoming=Input(raw);before_path=list(sys.path)
        def bounded(fd,data):
            written.append((fd,len(data)))
            return write_real(fd,data[:1] if partial else data)
        with patch.object(self.module.sys,'argv',['project_child','/verified/worker','/verified/upstream',str(write),mode]),patch.object(self.module.sys,'stdin',types.SimpleNamespace(buffer=incoming)),patch('ud_agent.domain.validation.validation_report',official),patch('ud_agent.project_rules.run_project_rules',custom),patch.object(self.module.os,'write',side_effect=bounded):
            try:result=self.module.main()
            except RuntimeError as error:
                if str(error) in {'PROJECT_CHILD_INVALID','PROJECT_CHILD_OUTPUT_FAILED'}:self.fail('valid child protocol fixture was rejected: '+str(error))
                raise
        response=json.loads(os.read(read,65536))
        self.assertEqual(result,0)
        (official if mode=='official' else custom).assert_called_once_with(arguments)
        (custom if mode=='official' else official).assert_not_called()
        self.assertEqual(sys.path,['/verified/worker','/verified/upstream',*before_path])
        from ud_agent import wire
        self.assertEqual(incoming.calls,[wire.MAX_REQUEST_BYTES+1])
        if self.module.os.name=='nt':
            self.resource.getrlimit.assert_not_called();self.resource.setrlimit.assert_not_called()
        else:self.resource.getrlimit.assert_called_with(self.resource.RLIMIT_FSIZE)
        self.assertTrue(written);self.assertTrue(all(fd==write for fd,_ in written))
        return response,written

    def test_modes_remain_separate_and_partial_fd_writes_preserve_complete_json(self):
        self.assertEqual(self.call('official',partial=True)[0],{'ok':True,'result':{'origin':'official','passed':False}})
        self.assertEqual(self.call('project')[0],{'ok':True,'result':{'origin':'project','passed':True}})
        self.resource.setrlimit.assert_called_with(1,(32*1024*1024,-1))

    def test_existing_fsize_hard_limit_is_respected(self):
        self.call('official',hard=8192)
        self.resource.setrlimit.assert_called_once_with(1,(8192,8192))

    def test_windows_policy_does_not_call_unavailable_posix_resource_api(self):
        self.module.os.name='nt'
        self.assertEqual(self.call('official')[0],{'ok':True,'result':{'origin':'official','passed':False}})

    def test_exact_request_ceiling_is_admitted_without_consuming_beyond_the_bound(self):
        from ud_agent import wire
        with patch.object(wire,'MAX_REQUEST_BYTES',32):
            self.assertEqual(self.call('official',raw=b'{}'+b' '*30)[0],{'ok':True,'result':{'origin':'official','passed':False}})

    def test_controlled_and_unexpected_validation_failures_have_distinct_envelopes(self):
        self.assertEqual(self.call('official',failure=WorkerError('CONTROLLED','explicit'))[0],{'ok':False,'error':{'code':'CONTROLLED','message':'explicit'}})
        self.assertEqual(self.call('project',failure=RuntimeError('private traceback'))[0],{'ok':False,'error':{'code':'PROJECT_CHILD_FAILED','message':'validation subprocess failed'}})

    def test_bad_mode_framing_empty_oversized_and_nondict_requests_never_call_validators(self):
        from ud_agent import wire
        for argv in [['child'],['child','worker','upstream','3','wrong']]:
            with patch.object(self.module.sys,'argv',argv),self.assertRaisesRegex(RuntimeError,'^PROJECT_CHILD_INVALID$'):self.module.main()
        for raw in [b'',b'x'*33,b'[]']:
            with patch.object(self.module.sys,'argv',['child','worker','upstream','3','official']),patch.object(self.module.sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(raw))),patch.object(wire,'MAX_REQUEST_BYTES',32),patch('ud_agent.domain.validation.validation_report') as official:
                with self.assertRaisesRegex(RuntimeError,'^PROJECT_CHILD_INVALID$'):self.module.main()
                official.assert_not_called()

    def test_failed_fd_progress_does_not_claim_a_complete_child_report(self):
        attempts=0
        def no_progress(_descriptor,_data):
            nonlocal attempts
            attempts+=1
            self.assertEqual(attempts,1,'child must abort immediately after a zero-progress write')
            return 0
        with patch.object(self.module.sys,'argv',['child','worker','upstream','3','official']),patch.object(self.module.sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'{}'))),patch('ud_agent.domain.validation.validation_report',return_value={'passed':True}),patch.object(self.module.os,'write',side_effect=no_progress):
            with self.assertRaisesRegex(RuntimeError,'^PROJECT_CHILD_OUTPUT_FAILED$'):self.module.main()
        self.assertEqual(attempts,1)


if __name__=='__main__':unittest.main()
