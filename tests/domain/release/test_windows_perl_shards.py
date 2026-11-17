"""A compact attribution index must reproduce every original contributor."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('windows_perl_shards',ROOT/'scripts/release/shard-windows-perl-components.py');M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class WindowsPerlShards(unittest.TestCase):
    def source(self,root):
        modules=[{'id':i,'source_files':[{'path':'original/header-'+str(i),'checksum':str(i)*220}]}for i in range(8)]
        document={'schema_version':1,'records':[{'platform':'win32/arm64','pdbs':[{'path':'perl.pdb','modules':modules}],'binaries':[{'path':'perl.exe','origin':'supplier','runtime_compilands':modules[:3]},{'path':'own.dll','origin':'authored-reproduced-XS','libraries':[]}]}]}
        source=root/'raw.json';source.write_bytes(M.original_bytes(document));return source,document
    def test_complete_original_is_losslessly_sharded_and_readonly_replayed(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);source,document=self.source(root);before=source.read_bytes();index=M.shard(source,root/'shards',max_part=1024)
            result=M.verify(root/'shards/index.json')
            self.assertGreater(result['parts'],1);self.assertEqual(result['source_receipt'],M.digest(before));self.assertEqual(result['records'],[{'platform':'win32/arm64','pdbs':1,'binaries':2}]);self.assertEqual(source.read_bytes(),before)
            self.assertTrue(all(row['size_bytes']<=1024 for row in index['parts']));self.assertEqual(index['document']['records'][0]['pdbs'][0]['modules']['count'],8)
    def test_omission_duplicate_count_corruption_and_extra_bytes_are_refused(self):
        for case in ['omission','duplicate','count','corrupt','extra','source-binding']:
            with self.subTest(case=case),tempfile.TemporaryDirectory()as directory:
                root=Path(directory);source,_=self.source(root);out=root/'shards';index=M.shard(source,out,max_part=1024);item=index['document']['records'][0]['pdbs'][0]['modules']
                if case=='omission':item['parts'].pop()
                elif case=='duplicate':item['parts'].append(item['parts'][0])
                elif case=='count':item['count']-=1
                elif case=='corrupt':(out/index['parts'][0]['path']).write_bytes(b'[]\n')
                elif case=='extra':(out/'unknown').write_bytes(b'not evidence')
                elif case=='source-binding':index['source_receipt']['sha256']='0'*64
                (out/'index.json').write_bytes(M.encoded(index))
                with self.assertRaises(ValueError):M.verify(out/'index.json')
    def test_limits_and_noncanonical_source_fail_instead_of_truncation(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);source,_=self.source(root)
            for limit in [True,255,M.MAX_PART+1]:
                with self.subTest(limit=limit),self.assertRaises(ValueError):M.shard(source,root/str(limit),max_part=limit)
            with self.assertRaises(ValueError):M.shard(source,root/'oversize',max_part=256)
            source.write_bytes(source.read_bytes().rstrip(b'\n'))
            with self.assertRaises(ValueError):M.shard(source,root/'noncanonical')

if __name__=='__main__':unittest.main()
