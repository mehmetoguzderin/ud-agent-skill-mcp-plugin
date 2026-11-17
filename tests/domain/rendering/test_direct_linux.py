"""Portable private-loader policy fixtures; actual browser acceptance is separate."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch
from ud_agent import render_browser
from ud_agent.errors import WorkerError
from test_browser_export import font


def elf(interpreter=None,needed=None):
    data=bytearray(1024);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',data,18,183);struct.pack_into('<Q',data,32,64);struct.pack_into('<HH',data,54,56,3)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x1000,0,1024,1024,4096)
    struct.pack_into('<IIQQQQQQ',data,120,2,6,256,0x1100,0,64,64,8)
    strings=(needed or 'unused').encode()+b'\0';data[512:512+len(strings)]=strings
    entries=[(5,0x1200),(10,len(strings)),*(([(1,0)]if needed else[])),(0,0)]
    for index,pair in enumerate(entries):struct.pack_into('<qQ',data,256+index*16,*pair)
    if interpreter is not None:
        raw=interpreter.encode()+b'\0';data[800:800+len(raw)]=raw;struct.pack_into('<IIQQQQQQ',data,176,3,4,800,0x1320,0,len(raw),len(raw),1)
    return bytes(data)


class DirectLinuxRendererTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ud-direct-linux-policy-');self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve()
        self.manifest=self.root/'manifest.json';self.binary=self.root/'browser/chrome-headless-shell'
        self.files={'fonts/fixture.ttf':font(),'elf/loader/ld.so':elf(),'elf/lib/libc.so.6':elf(),'fontconfig/fonts.conf':b'<fontconfig></fontconfig>'}
        self.receipt={'schema_version':1,'executable':'browser/chrome-headless-shell','fonts':['fonts/fixture.ttf'],'fontconfig':'fontconfig/fonts.conf','loader':{'executable':'elf/loader/ld.so','library_dirs':['elf/lib'],'mode':'direct','installed_root':str(self.root)}}
        self.enterContext(patch.object(render_browser.sys,'platform','linux'));self.enterContext(patch.object(render_browser.platform,'machine',return_value='aarch64'))
        self.enterContext(patch.dict(os.environ,{'UD_AGENT_RENDER_MANIFEST':str(self.manifest),'LD_LIBRARY_PATH':'/ambient','LD_PRELOAD':'/ambient/code.so','FONTCONFIG_FILE':'/ambient/fonts.conf'}))
        self.sync()

    def sync(self,*,installed_root=None,needed='libc.so.6'):
        if installed_root is not None:self.receipt['loader']['installed_root']=str(installed_root)
        self.files['browser/chrome-headless-shell']=elf(str(Path(self.receipt['loader']['installed_root'])/'elf/loader/ld.so'),needed)
        for name,data in self.files.items():
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            if path.exists():path.chmod(0o600)
            path.write_bytes(data);path.chmod(0o555 if name.startswith(('browser/','elf/'))else 0o444)
        self.receipt['files']=[{'path':name,'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)}for name,data in self.files.items()]
        self.manifest.write_text(json.dumps(self.receipt))

    def test_browser_child_gets_verified_libraries_but_python_supervisor_never_does(self):
        self.assertEqual(render_browser.verified_renderer()[0],str(self.binary))
        def execute(command,**options):
            framing=json.loads(command[-1])
            self.assertEqual(set(framing),{'command','library_dirs'})
            self.assertEqual(framing['library_dirs'],[str(self.root/'elf/lib')])
            self.assertEqual(framing['command'][0],str(self.binary))
            self.assertNotIn('LD_LIBRARY_PATH',options['env']);self.assertNotIn('LD_PRELOAD',options['env'])
            self.assertEqual(options['env']['FONTCONFIG_FILE'],str(self.root/'fontconfig/fonts.conf'))
            self.assertEqual(options['env']['FONTCONFIG_PATH'],str(self.root/'fontconfig'))
            target=next(value.split('=',1)[1]for value in framing['command']if value.startswith('--print-to-pdf='))
            Path(target).write_bytes(b'%PDF-1.7\nfixture\n%%EOF\n');return types.SimpleNamespace(returncode=0)
        with patch.object(render_browser.subprocess,'run',side_effect=execute):
            data,_=render_browser.browser_export(b'<html><head></head><body>A</body></html>','pdf',100,100)
        self.assertEqual(data,b'%PDF-1.7\nfixture\n%%EOF\n')

    def test_projected_root_verifies_staging_bytes_but_cannot_execute_them(self):
        target=self.root/'planned-final';self.sync(installed_root=target)
        self.assertEqual(render_browser.verified_renderer(installation_root=str(target))[0],str(self.binary))
        with self.assertRaisesRegex(WorkerError,'another installation root'):render_browser.verified_renderer()
        with patch.object(render_browser.subprocess,'run')as execute:
            with self.assertRaisesRegex(WorkerError,'another installation root'):render_browser.browser_export(b'<body>A</body>','pdf',100,100)
            execute.assert_not_called()

    def test_missing_elf_dependencies_fontconfig_or_unlisted_libraries_block_admission(self):
        self.sync(needed='missing.so')
        with self.assertRaisesRegex(WorkerError,'dependency is absent'):render_browser.verified_renderer()
        self.sync();(self.root/'elf/lib/unlisted.so').write_bytes(elf())
        with self.assertRaisesRegex(WorkerError,'unverified entry'):render_browser.verified_renderer()
        (self.root/'elf/lib/unlisted.so').unlink();self.receipt.pop('fontconfig');self.manifest.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(WorkerError,'configuration is required'):render_browser.verified_renderer()
        self.receipt['fontconfig']='outside.conf';self.manifest.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(WorkerError,'configuration is absent'):render_browser.verified_renderer()

    def test_foreign_architecture_or_interpreter_is_rejected_even_with_matching_file_hash(self):
        data=bytearray(self.files['browser/chrome-headless-shell']);struct.pack_into('<H',data,18,62);self.files['browser/chrome-headless-shell']=bytes(data)
        self.binary.chmod(0o600);self.binary.write_bytes(data);self.binary.chmod(0o555);record=next(row for row in self.receipt['files']if row['path']=='browser/chrome-headless-shell');record['sha256']=hashlib.sha256(data).hexdigest();self.manifest.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(WorkerError,'architecture'):render_browser.verified_renderer()
        self.sync();data=elf('/unowned/ld.so','libc.so.6');self.binary.chmod(0o600);self.binary.write_bytes(data);self.binary.chmod(0o555);record=next(row for row in self.receipt['files']if row['path']=='browser/chrome-headless-shell');record['sha256']=hashlib.sha256(data).hexdigest();self.manifest.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(WorkerError,'interpreter'):render_browser.verified_renderer()


if __name__=='__main__':unittest.main()
