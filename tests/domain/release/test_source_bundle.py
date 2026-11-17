import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('source_bundle',ROOT/'scripts/release/source-bundle.py');bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)


class SourceBundleTests(unittest.TestCase):
    def test_named_and_held_checks_preserve_change_time_when_path_ctime_is_birthtime(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);file=root/'source';file.write_bytes(b'original')
            row={'path':'source','sha256':hashlib.sha256(b'original').hexdigest(),'size_bytes':8}
            actual_lstat=Path.lstat
            def legacy_path_ctime(path,*args,**kwargs):
                value=actual_lstat(path,*args,**kwargs)
                fields={key:getattr(value,key)for key in dir(value)if key.startswith('st_')}
                if path==file:fields['st_ctime_ns']-=1000000
                return SimpleNamespace(**fields)
            with mock.patch.object(Path,'lstat',legacy_path_ctime):
                stream,identity,_=bundle.opened(root,row)
                try:
                    self.assertEqual(stream.read(),b'original')
                    bundle.verify_held_path(stream,file,identity)
                    other=root/'other';other.write_bytes(b'original')
                    with self.assertRaisesRegex(ValueError,'changed during'):bundle.verify_held_path(stream,other,identity)
                    alias=root/'alias';alias.symlink_to(file)
                    with self.assertRaisesRegex(ValueError,'ordinary'):bundle.verify_held_path(stream,alias,identity)
                    file.write_bytes(b'changed bytes')
                    with self.assertRaisesRegex(ValueError,'changed during'):bundle.verify_held_path(stream,file,identity)
                finally:stream.close()

    def test_material_scope_is_exact_and_unshipped_prebuilt_tools_are_not_opened(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary); original=b'original corresponding source';(root/'source').write_bytes(original);fingerprint=hashlib.sha256(original).hexdigest();wanted=[{'sha256':fingerprint,'size_bytes':len(original)}]
            data={'schema_version':1,'qualification':'pinned-source-and-notices','status':'passed','files':[{'path':'source','sha256':fingerprint,'size_bytes':len(original)},{'path':'unshipped-tool-does-not-exist','sha256':'f'*64,'size_bytes':99}]};receipt=root/'receipt.json';receipt.write_text(json.dumps(data))
            model={'qualification':'replayed-actual-shipped-component-source-license-closure','complete_available_shipped_component_coverage':True,'complete_product_coverage':False,'required_materials':wanted}
            result=bundle.bundle([('actual',receipt)],root/'selected',4096,wanted,model);self.assertEqual(result['unique_source_files'],1);self.assertFalse(result['complete_product_coverage'])
            raw=b''.join((root/'selected'/row['path']).read_bytes()for row in result['parts'])
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
                manifest=json.load(archive.extractfile('MATERIALS.json'));self.assertEqual(manifest['files'],[{'path':'blobs/'+fingerprint,**wanted[0]}]);self.assertEqual(len(manifest['collections'][0]['members']),1)
            for number,required in enumerate(([{'sha256':'a'*64,'size_bytes':1}],wanted+[{'sha256':'a'*64,'size_bytes':1}],[{'sha256':fingerprint,'size_bytes':1}])):
                with self.subTest(required=required),self.assertRaisesRegex(ValueError,'empty|omit|size'):bundle.bundle([('actual',receipt)],root/('missing'+str(number)),4096,required)
            with self.assertRaisesRegex(ValueError,'replayed component'):bundle.bundle([('actual',receipt)],root/'fake-claim',4096,wanted,{**model,'required_materials':[]})

    def test_actual_pinned_source_is_byte_preserved_deduplicated_and_bounded(self):
        body=(ROOT/'tests/fixtures/source-materials/go-units-v0.5.0.zip').read_bytes();fingerprint=hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'source.zip').write_bytes(body)
            record={'path':'source.zip','sha256':fingerprint,'size_bytes':len(body)}
            receipt=root/'receipt.json';receipt.write_text(json.dumps({'schema_version':1,'qualification':'pinned-source-and-notices','status':'passed','files':[record,record]}))
            first=bundle.bundle([('actual-source',receipt)],root/'first',4096);second=bundle.bundle([('actual-source',receipt)],root/'second',4096)
            self.assertEqual(first,second);self.assertFalse(first['complete_product_coverage']);self.assertEqual(first['unique_source_files'],1);self.assertGreater(len(first['parts']),1)
            raw=b''.join((root/'first'/row['path']).read_bytes()for row in first['parts']);self.assertEqual(hashlib.sha256(raw).hexdigest(),first['stream_sha256']);self.assertEqual(len(raw),first['stream_size_bytes'])
            for row in first['parts']:
                actual=(root/'first'/row['path']).read_bytes();self.assertLessEqual(len(actual),4096);self.assertEqual(hashlib.sha256(actual).hexdigest(),row['sha256'])
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as source:
                self.assertEqual(source.getnames(),['MATERIALS.json','receipts/actual-source.json','blobs/'+fingerprint]);self.assertEqual(source.extractfile('blobs/'+fingerprint).read(),body)
                self.assertTrue(all(member.mtime==0 and member.uid==0 and member.gid==0 and member.mode==0o644 for member in source))
            self.assertFalse((root/'first/INCOMPLETE').exists())

    def test_go_inspection_subject_binaries_are_never_packaged(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'source').write_bytes(b'source bytes');record={'path':'source','sha256':hashlib.sha256(b'source bytes').hexdigest(),'size_bytes':12}
            data={'schema_version':1,'qualification':'binary-bound-go-module-source-inventory','status':'passed','modules':[{'archive':record}],'main_sources':[],'standard_libraries':[],'derived_runtime_sources':[],'binaries':[{'path':'subjects/forbidden-executable'}]}
            receipt=root/'receipt.json';receipt.write_text(json.dumps(data));result=bundle.bundle([('go',receipt)],root/'output',4096)
            raw=b''.join((root/'output'/row['path']).read_bytes()for row in result['parts'])
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as source:self.assertFalse(any('subjects/'in member.name for member in source))
            data['static_c_dependencies_pending']=['unknown libc'];receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'missing dependencies'):bundle.bundle([('go',receipt)],root/'failed',4096)

    def test_partial_corrupt_linked_and_unsafe_inputs_do_not_produce_index(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'source').write_bytes(b'x');record={'path':'source','sha256':'a'*64,'size_bytes':1};data={'schema_version':1,'qualification':'pinned-source-and-notices','status':'passed','files':[record]};receipt=root/'receipt.json'
            for number,(status,relative,digest)in enumerate([('incomplete','source','a'*64),('passed','../escape','a'*64),('passed','source','a'*64)]):
                data['status']=status;record.update(path=relative,sha256=digest);receipt.write_text(json.dumps(data));output=root/str(number)
                with self.subTest(number=number),self.assertRaises(ValueError):bundle.bundle([('source',receipt)],output,4096)
                self.assertFalse((output/'ud-agent-corresponding-source-index.json').exists())
            record.update(path='link',sha256=hashlib.sha256(b'x').hexdigest());(root/'link').symlink_to(root/'source');receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'link'):bundle.bundle([('source',receipt)],root/'linked',4096)
