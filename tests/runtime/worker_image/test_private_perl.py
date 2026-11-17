import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
def module(name):
    spec=importlib.util.spec_from_file_location('ud_'+name,ROOT/'scripts/runtime'/f'{name}.py');value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
perl=module('private_perl');elf=module('elf_dependencies')


class PrivatePerlTests(unittest.TestCase):
    def test_elf_relocation_removes_only_search_paths_and_preserves_needed_names(self):
        data=bytearray(1024);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',data,18,183);struct.pack_into('<Q',data,32,64);struct.pack_into('<HH',data,54,56,2)
        struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x1000,0,1024,1024,4096)
        struct.pack_into('<IIQQQQQQ',data,120,2,6,256,0x1100,0,96,96,8)
        table=b'libc.so.6\0/temporary/compiler/prefix\0';data[512:512+len(table)]=table
        for index,(kind,value)in enumerate([(5,0x1200),(10,len(table)),(1,0),(15,10),(29,10),(0,0)]):struct.pack_into('<qQ',data,256+index*16,kind,value)
        original=elf.inspect(data);self.assertEqual(original,{'machine':183,'interpreter':None,'needed':['libc.so.6'],'search_paths':['/temporary/compiler/prefix','/temporary/compiler/prefix']})
        transformed=elf.without_search_paths(bytes(data));self.assertEqual(len(transformed),1024);self.assertEqual(transformed[:256],data[:256]);self.assertEqual(transformed[352:],data[352:]);self.assertEqual(elf.inspect(transformed),{**original,'search_paths':[]});self.assertEqual(elf.without_search_paths(transformed),transformed)

    def test_both_oci_architectures_use_the_same_source_modules_and_closed_files(self):
        import hashlib
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'runtime').mkdir()
            source={'version':'5.044000'};modules={'releases':{'fixture':{'version':'1'}}};interset={'commit':'a'*40}
            for name,value in [('native-perl-source',source),('native-perl-modules',modules),('perl-deps',{'interset':interset})]:(root/'runtime'/f'{name}.lock.json').write_text(json.dumps(value))
            receipts={}
            for slug in ['arm64','x64']:
                base=root/'.artifacts/native-perl'/f'linux-{slug}-source';files=[]
                for name,content in [('bin/perl',b'private Perl'),('lib/core/strict.pm',b'private core'),('lib/elf/libc.so.6',b'private libc'),('loader/ld.so',b'private loader')]:
                    path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);path.chmod(0o555 if name.startswith(('bin/','loader/'))else 0o444);files.append({'path':name,'size':len(content),'sha256':'sha256:'+hashlib.sha256(content).hexdigest()})
                receipt={'source_sha256':perl.canonical_hash(source),'modules_sha256':perl.canonical_hash(modules),'interset_commit':interset['commit'],'executable':'bin/perl','library_dirs':['lib/core'],'loader':{'executable':'loader/ld.so','library_dirs':['lib/elf']},'probe':{'status':'passed','ambient_modules':False,'ambient_elf':False,'version':'v5.44.0'},'files':files};receipts[slug]=(base,receipt);base.with_name(base.name+'-receipt.json').write_text(json.dumps(receipt))
            result=perl.stage(root,root/'stage');self.assertEqual(set(result['platforms']),{'linux/arm64','linux/amd64'});self.assertEqual((root/'stage/amd64/lib/core/strict.pm').read_bytes(),b'private core');self.assertEqual(json.loads((root/'stage/arm64/runtime.json').read_text())['loader'],{'executable':'loader/ld.so','library_dirs':['lib/elf']})
            base,receipt=receipts['arm64'];receipt['probe']['ambient_elf']=True;base.with_name(base.name+'-receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,'shared source'):perl.stage(root,root/'bad-probe')
            receipt['probe']['ambient_elf']=False;base.with_name(base.name+'-receipt.json').write_text(json.dumps(receipt));(base/'bin/perl').chmod(0o644);(base/'bin/perl').write_bytes(b'damaged')
            with self.assertRaisesRegex(ValueError,'damaged'):perl.stage(root,root/'bad-bytes')


if __name__=='__main__':unittest.main()
