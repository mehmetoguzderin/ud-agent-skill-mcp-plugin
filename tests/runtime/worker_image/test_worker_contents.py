import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('worker_contents_tests',ROOT/'scripts/runtime/verify-worker-contents.py')
contents=importlib.util.module_from_spec(spec);spec.loader.exec_module(contents)


def sha(value):return hashlib.sha256(value).hexdigest()
def layer(entries):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w')as target:
        for name,data in entries:
            info=tarfile.TarInfo(name)
            if data is None:info.type=tarfile.SYMTYPE;info.linkname='/outside'
            else:info.size=len(data)
            target.addfile(info,io.BytesIO(data)if data is not None else None)
    return output.getvalue()


class WorkerContentsTests(unittest.TestCase):
    def test_verifies_final_layer_bytes_and_rejects_overrides_whiteouts_links_and_escapes(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);context=root/'context';context.mkdir()
            worker=b'print("worker")\n'
            manifest=json.dumps({'files':{'worker/ud_agent/worker.py':sha(worker)}}).encode()
            (context/'input-manifest.json').write_bytes(manifest)
            initial=layer([('opt/ud-agent/input-manifest.json',manifest),('opt/ud-agent/worker/ud_agent/worker.py',worker)])
            def archive(layers):
                configuration=json.dumps({'architecture':'arm64'}).encode()
                data={'config':{'digest':'sha256:'+sha(configuration)},'layers':[{'digest':'sha256:'+sha(item)}for item in layers]}
                raw=json.dumps(data).encode();identity='sha256:'+sha(raw);file=root/'image.tar'
                with tarfile.open(file,'w')as target:
                    for content in [raw,configuration,*layers]:
                        info=tarfile.TarInfo('blobs/sha256/'+sha(content));info.size=len(content);target.addfile(info,io.BytesIO(content))
                return file,identity
            file,identity=archive([initial]);self.assertEqual(contents.verify(file,identity,context)['source_files_verified'],1)
            for replacement in [[('opt/ud-agent/worker/ud_agent/worker.py',b'changed')],[('opt/ud-agent/worker/ud_agent/.wh.worker.py',b'')],[('opt/ud-agent/worker/.wh..wh..opq',b'')],[('opt/ud-agent/worker/ud_agent/worker.py',None)],[('../escape',b'x')]]:
                with self.subTest(replacement=replacement):
                    file,identity=archive([initial,layer(replacement)])
                    with self.assertRaises(ValueError):contents.verify(file,identity,context)
            file,identity=archive([initial,layer([('opt/ud-agent/worker/ud_agent/worker.py',worker)])]);self.assertEqual(contents.verify(file,identity,context)['status'],'passed')
            font=b'verified font';browser=b'verified browser'
            render={'schema_version':1,'fonts':['/fonts/font.ttf'],'files':[{'path':'/fonts/font.ttf','sha256':sha(font),'size_bytes':len(font)},{'path':'/browser/chromium','sha256':sha(browser),'size_bytes':len(browser)}]}
            file,identity=archive([initial,layer([('opt/ud-agent/render/manifest.json',json.dumps(render).encode()),('fonts/font.ttf',font),('browser/chromium',browser)])])
            self.assertEqual(contents.verify(file,identity,context,True)['source_files_verified'],3)
            file,identity=archive([initial,layer([('opt/ud-agent/render/manifest.json',json.dumps(render).encode()),('fonts/font.ttf',b'changed'),('browser/chromium',browser)])])
            with self.assertRaisesRegex(ValueError,'browser or font'):contents.verify(file,identity,context,True)


if __name__=='__main__':unittest.main()
