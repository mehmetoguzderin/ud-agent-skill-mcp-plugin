"""Closed vendor ZIP fixtures are data; these tests do not certify native binaries."""
import hashlib
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from ud_agent import vendor_browser as vendor


def receipt(data):return {'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)}

def macho(cpu=0x100000c):
    data=bytearray(64);data[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',data,4,cpu);return bytes(data)


class VendorBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ud-vendor-browser-');self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve();self.source_root='chrome-headless-shell-mac-arm64'

    def archive(self,entries):
        path=self.root/'vendor.zip'
        with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED)as bundle:
            for name,kind,data in entries:
                member=zipfile.ZipInfo(self.source_root+'/'+name);member.create_system=3
                # ZipInfo's constructor normalizes backslashes on Windows;
                # retain the actual hostile ZIP spelling under test.
                member.filename=self.source_root+'/'+name
                member.external_attr=({'file':stat.S_IFREG|0o755,'dir':stat.S_IFDIR|0o755,'link':stat.S_IFLNK|0o777,'device':stat.S_IFCHR|0o600}[kind])<<16
                if kind=='dir':member.filename=member.filename.rstrip('/')+'/'
                bundle.writestr(member,data)
        return path

    def base(self,archive,files):
        root=self.root/'pack';root.mkdir();(root/'fonts').mkdir();(root/'fonts/owned.ttf').write_bytes(b'owned fixture font')
        recipe={'schema_version':1,'provider':vendor.PROVIDER,'platform':'darwin/arm64','source_root':self.source_root,'archive':{'url':'https://storage.googleapis.com/chrome-for-testing-public/157.0.0.1/mac-arm64/chrome-headless-shell-mac-arm64.zip',**receipt(archive.read_bytes())},'files':[{'path':name,**receipt(data)}for name,data in sorted(files.items())]}
        name='vendor-browser-recipe.json';(root/name).write_text(json.dumps(recipe))
        base=[{'path':'fonts/owned.ttf',**receipt(b'owned fixture font')},{'path':name,**receipt((root/name).read_bytes())}]
        manifest={'schema_version':1,'executable':'browser/chrome-headless-shell','files':base,'fonts':['fonts/owned.ttf'],'deferred_browser':{'provider':vendor.PROVIDER,'recipe':name,'directory':'browser'}}
        (root/'manifest.json').write_text(json.dumps(manifest));return root,recipe,manifest

    def test_internal_framework_aliases_flatten_to_exact_independent_file_inventory(self):
        entries=[('chrome-headless-shell','file',macho()),('Framework/Versions/A/data','file',b'asset'),('Framework/Versions/Current','link',b'A'),('Framework/Resources','link',b'Versions/Current')]
        archive=self.archive(entries)
        wanted={'chrome-headless-shell':macho(),'Framework/Versions/A/data':b'asset','Framework/Versions/Current/data':b'asset','Framework/Resources/data':b'asset'}
        with zipfile.ZipFile(archive)as bundle:
            closed=vendor.ClosedZip(bundle,self.source_root)
            self.assertEqual(closed.inventory,[{'path':name,**receipt(data)}for name,data in sorted(wanted.items())])
            output=self.root/'flat';closed.extract(output)
        for name,data in wanted.items():self.assertEqual((output/name).read_bytes(),data);self.assertFalse((output/name).is_symlink())
        self.assertFalse((output/'Framework/Versions/Current').is_symlink())

    def test_materialization_preserves_base_assets_and_atomically_replaces_only_manifest(self):
        files={'chrome-headless-shell':macho(),'assets/data':b'locked asset'};archive=self.archive([(name,'file',data)for name,data in files.items()]);root,recipe,before=self.base(archive,files)
        archive_before=archive.read_bytes()
        vendor.materialize_pack(root,archive,'vendor-browser-recipe.json','browser','manifest.json')
        result=json.loads((root/'manifest.json').read_text());self.assertNotIn('deferred_browser',result)
        self.assertEqual(result['executable'],'browser/chrome-headless-shell');self.assertEqual(result['fonts'],['fonts/owned.ttf'])
        self.assertEqual(result['files'],sorted([*before['files'],*[{'path':'browser/'+name,**receipt(data)}for name,data in files.items()]],key=lambda item:item['path']))
        self.assertEqual((root/'fonts/owned.ttf').read_bytes(),b'owned fixture font');self.assertFalse((root/'manifest.json.materialized').exists())
        self.assertEqual(archive.read_bytes(),archive_before)

    def test_hostile_paths_kinds_links_and_canonical_collisions_fail_without_output(self):
        cases=[[('../escape','file',b'bad')],[('CON','file',b'bad')],[('bad\\name','file',b'bad')],[('link','link',b'../../outside')],[('link','link',b'/etc/passwd')],[('a','link',b'b'),('b','link',b'a')],[('a','link',b'.')],[('device','device',b'')],[('e\u0301','file',b'a'),('É','file',b'b')],[('x','file',b'a'),('x/child','file',b'b')],[('d/a','file',b'expected'),('link','link',b'd'),('link/a','file',b'other')]]
        for extra in cases:
            archive=self.archive([('chrome-headless-shell','file',macho()),*extra])
            with self.subTest(extra=extra),zipfile.ZipFile(archive)as bundle,self.assertRaises(ValueError):vendor.ClosedZip(bundle,self.source_root)
            self.assertFalse((self.root/'escape').exists())

    def test_limits_and_foreign_zip_roots_are_checked_before_extraction(self):
        archive=self.archive([('chrome-headless-shell','file',macho()),('extra','file',b'bytes')])
        with zipfile.ZipFile(archive)as bundle:
            # Model ZipInfo's Windows read-time separator normalization.
            bundle.infolist()[-1].orig_filename=self.source_root+'\\extra'
            with self.assertRaisesRegex(ValueError,'VENDOR_ZIP_MEMBER_INVALID'):vendor.ClosedZip(bundle,self.source_root)
        for limits in [{'MAX_FILES':1},{'MAX_TOTAL':1},{'MAX_FILE':1}]:
            with patch.multiple(vendor,**limits),zipfile.ZipFile(archive)as bundle,self.assertRaises(ValueError):vendor.ClosedZip(bundle,self.source_root)
        with zipfile.ZipFile(archive)as bundle,self.assertRaises(ValueError):vendor.ClosedZip(bundle,'other-root')

    def test_frozen_new_unicode_marks_remain_distinct_archive_names(self):
        a='A\u0315\u1acf';b='A\u1acf\u0315';archive=self.archive([(a,'file',b'A'),(b,'file',b'B')])
        with zipfile.ZipFile(archive)as bundle:closed=vendor.ClosedZip(bundle,self.source_root)
        self.assertEqual([item['path']for item in closed.inventory],sorted([a,b]))

    def test_corrupt_archive_or_incorrect_expected_bytes_never_create_browser_directory(self):
        for failure in ['archive','inventory','platform','provider','executable','url']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory(prefix='ud-vendor-failure-')as temporary:
                previous=self.root;self.root=Path(temporary).resolve()
                try:
                    files={'chrome-headless-shell':macho()};archive=self.archive([('chrome-headless-shell','file',macho())]);root,recipe,manifest=self.base(archive,files)
                    if failure=='archive':recipe['archive']['sha256']='0'*64
                    if failure=='inventory':recipe['files'][0]['sha256']='0'*64
                    if failure=='platform':recipe['platform']='unknown'
                    if failure=='provider':manifest['deferred_browser']['provider']='other'
                    if failure=='executable':manifest['executable']='fonts/owned.ttf'
                    if failure=='url':recipe['archive']['url']='https://untrusted.invalid/browser.zip'
                    (root/'vendor-browser-recipe.json').write_text(json.dumps(recipe));manifest['files'][1].update(receipt((root/'vendor-browser-recipe.json').read_bytes()));(root/'manifest.json').write_text(json.dumps(manifest))
                    with self.assertRaises(ValueError):vendor.materialize_pack(root,archive,'vendor-browser-recipe.json','browser','manifest.json')
                    self.assertFalse((root/'browser').exists())
                finally:self.root=previous

    def test_output_parent_symlinks_are_rejected_before_any_external_write(self):
        files={'chrome-headless-shell':macho()};archive=self.archive([('chrome-headless-shell','file',macho())]);root,_,manifest=self.base(archive,files);outside=self.root/'outside';outside.mkdir();(root/'alias').symlink_to(outside,target_is_directory=True)
        manifest['deferred_browser']['directory']='alias/browser';manifest['executable']='alias/browser/chrome-headless-shell';(root/'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):vendor.materialize_pack(root,archive,'vendor-browser-recipe.json','alias/browser','manifest.json')
        self.assertEqual(list(outside.iterdir()),[])

    def test_executable_architecture_is_checked_before_publishing_vendor_bytes(self):
        data=macho(0x1000007);archive=self.archive([('chrome-headless-shell','file',data)]);root,_,_=self.base(archive,{'chrome-headless-shell':data})
        with self.assertRaisesRegex(ValueError,'ARCHITECTURE'):vendor.materialize_pack(root,archive,'vendor-browser-recipe.json','browser','manifest.json')
        self.assertFalse((root/'browser').exists())


if __name__=='__main__':unittest.main()
