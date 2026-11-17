import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from ud_agent.errors import PrerequisiteMissing
from ud_agent.perl_runtime import command


class PerlRuntimeTests(unittest.TestCase):
    def test_private_inc_replaces_ambient_modules_before_bridge_imports(self):
        perl=Path(os.environ.get('UD_AGENT_PERL')or shutil.which('perl')or'/usr/bin/perl')
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);owned=root/'owned';owned.mkdir();ambient=root/'ambient';ambient.mkdir();tools=root/'tools';tools.mkdir()
            (owned/'OwnedFixture.pm').write_text('package OwnedFixture; sub value { "owned" } 1;\n')
            (ambient/'OwnedFixture.pm').write_text('die "ambient module executed";\n')
            (ambient/'AmbientOnly.pm').write_text('package AmbientOnly; 1;\n')
            bridge=root/'bridge.pl';bridge.write_text('use OwnedFixture; print OwnedFixture::value(); eval { require AmbientOnly; }; print $@ ? ":blocked" : ":leaked"; 1;\n')
            with patch.dict(os.environ,{'UD_AGENT_PERL_LIB_PATHS':json.dumps([str(owned)])},clear=True):arguments=command(perl,bridge,tools)
            result=subprocess.run(arguments,env={'PATH':'/usr/bin:/bin','PERL5LIB':str(ambient)},capture_output=True,timeout=10)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'owned:blocked',b''))

    def test_library_contract_and_private_loader_prefix_are_bounded(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);loader=root/'ld.so';loader.write_bytes(b'fixture');loader.chmod(0o700)
            for raw in ['[]','{}','["relative"]',json.dumps([str(root/'missing')]),json.dumps([str(root),str(root)])]:
                with self.subTest(raw=raw),patch.dict(os.environ,{'UD_AGENT_PERL_LIB_PATHS':raw},clear=True):
                    with self.assertRaises(PrerequisiteMissing):command(root/'perl',root/'bridge',root)
            env={'UD_AGENT_PERL_LIB_PATHS':json.dumps([str(root)]),'UD_AGENT_PERL_LOADER':str(loader),'UD_AGENT_PERL_LOADER_LIB_PATHS':json.dumps([str(root)])}
            with patch.dict(os.environ,env,clear=True),patch('ud_agent.perl_runtime.sys.platform','linux'):
                arguments=command(root/'perl',root/'bridge',root)
                self.assertEqual(arguments[:5],[str(loader),'--inhibit-cache','--library-path',str(root),str(root/'perl')])
                self.assertEqual(arguments[-1],str(root/'bridge'))
            with patch.dict(os.environ,env,clear=True),patch('ud_agent.perl_runtime.sys.platform','darwin'):
                with self.assertRaises(PrerequisiteMissing):command(root/'perl',root/'bridge',root)


if __name__=='__main__':unittest.main()
