import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('provider_sources',ROOT/'scripts/release/collect-provider-sources.py');collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)


def archive(files):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz')as target:
        for name,body in files.items():
            member=tarfile.TarInfo('root/'+name);member.size=len(body);target.addfile(member,io.BytesIO(body))
    return output.getvalue()


class ProviderSourceTests(unittest.TestCase):
    def test_frozen_replay_closes_swift_sources_without_revalidating_mutable_tags(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);(root/'runtime/materials').mkdir(parents=True)
            def write(name,value):(root/name).write_text(json.dumps(value))
            write('runtime/provider-assets.lock.json',{'apple_container':{'source_commit':'a'*40,'version':'1.7.1','init_image':{'version':'0.34.0'}},'wslc':{'source_commit':'b'*40,'version':'3.0.3'}})
            write('runtime/lima-inputs.lock.json',{'sources':{'lima':{'commit':'d'*40}}});write('runtime/userspace-inputs.lock.json',{'platforms':{'darwin/arm64':{'uv_archive':{'url':'https://github.com/astral-sh/uv/releases/download/0.13.7/uv.tar.gz'}}}})
            names=[('apple/container','a','Apple Container1.7.1'),('microsoft/WSL','b','WSL3.0.3'),('apple/containerization','c','pinned offline init image0.34.0'),('lima-vm/lima','d','Lima2.3.0'),('astral-sh/uv','e','uv bootstrap0.13.7'),('example/swift','f','resolved Swift dependency')]
            originals={};sources=[]
            for repository,character,origin in names:
                files={'LICENSE':b'Original upstream license\n'}
                if repository=='apple/container':files['Package.resolved']=json.dumps({'pins':[{'location':'https://github.com/example/swift.git','state':{'revision':'f'*40}}]}).encode()
                if repository=='astral-sh/uv':files['Cargo.lock']=b'version=4\n[[package]]\nname="local"\nversion="1.0.0"\n'
                body=archive(files);url='https://codeload.github.com/'+repository+'/tar.gz/'+character*40;originals[url]=body;sources.append({'name':repository,'version':character*40,'origins':[origin],'url':url,'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)})
            write('runtime/materials/provider-source-mappings.lock.json',{'schema_version':1,'qualification':'frozen-provider-bootstrap-source-commits','sources':sources,'release_metadata':[]})
            calls=[]
            def acquire(url,target,size=None,sha256=None,maximum=None):
                calls.append(url);body=originals[url]
                if len(body)!=size or hashlib.sha256(body).hexdigest()!=sha256:raise ValueError('exact frozen source differs')
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
            with patch.object(collector.acquisition,'acquire',acquire):result=collector.collect(root,root/'output')
            self.assertEqual(result['status'],'passed');self.assertEqual(len(result['files']),6);self.assertFalse(result['target_execution']);self.assertTrue(all(url.startswith('https://codeload.github.com/')for url in calls));self.assertEqual((root/'output/locks/uv.Cargo.lock').read_bytes(),b'version=4\n[[package]]\nname="local"\nversion="1.0.0"\n')
            self.assertEqual(next(row for row in result['files']if row['name']=='apple/container')['resolved_swift_sources'][0]['repository'],'example/swift')
            originals[sources[0]['url']]=b'changed'
            with patch.object(collector.acquisition,'acquire',acquire),self.assertRaisesRegex(ValueError,'frozen source differs'):collector.collect(root,root/'corrupt')
