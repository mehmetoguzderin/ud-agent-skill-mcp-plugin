import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile
import zlib

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('source_materials',ROOT/'scripts/release/source_materials.py');materials=importlib.util.module_from_spec(spec);spec.loader.exec_module(materials)
spec=importlib.util.spec_from_file_location('extract_guest_materials',ROOT/'scripts/release/extract-guest-materials.py');extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)


def gpt(file, *, overlap=False, bad_crc=False):
    raw=bytearray(100*512);entries=bytearray(4*128)
    for index,start,end,name in [(0,34,50,'cloudimg-rootfs')]+([(1,45,55,'second')]if overlap else[]):
        offset=index*128;entries[offset:offset+16]=uuid.UUID('b921b045-1df0-41c3-af44-4c6f280d3fae').bytes_le
        struct.pack_into('<QQ',entries,offset+32,start,end);encoded=name.encode('utf-16-le');entries[offset+56:offset+56+len(encoded)]=encoded
    raw[2*512:3*512]=entries;header=bytearray(512);header[:8]=b'EFI PART';struct.pack_into('<III',header,8,0x10000,92,0)
    struct.pack_into('<QQQQ',header,24,1,99,34,98);struct.pack_into('<QIII',header,72,2,4,128,zlib.crc32(entries));struct.pack_into('<I',header,16,zlib.crc32(header[:92])^(1 if bad_crc else 0));raw[512:1024]=header;file.write_bytes(raw)


class SourceMaterialsTests(unittest.TestCase):
    def test_exact_installed_source_and_static_link_closure(self):
        status=b'Package: binary\nStatus: install ok installed\nVersion: 2:1.0-2\nArchitecture: arm64\nSource: original (2:1.0-1)\nBuilt-Using: static-one (= 1.2), static-two (= 3~beta)\nStatic-Built-Using: third (= 4+ds)\nDescription: first\n second\n\nPackage: removed\nStatus: deinstall ok config-files\n'
        result=materials.installed_packages(status,b'binary\t2:1.0-2\n','arm64')
        self.assertEqual(result[0]['source'],{'name':'original','version':'2:1.0-1'})
        self.assertEqual(result[0]['built_using'],[{'name':'static-one','version':'1.2'},{'name':'static-two','version':'3~beta'},{'name':'third','version':'4+ds'}])
        self.assertEqual(result[0]['notice_guest_path'],'/usr/share/doc/binary/copyright')
        for invalid in [b'binary\twrong\n',b'binary\t2:1.0-2\nmissing\t1\n',b'binary\t2:1.0-2\nbinary\t2:1.0-2\n']:
            with self.subTest(manifest=invalid),self.assertRaises(ValueError):materials.installed_packages(status,invalid,'arm64')
        with self.assertRaises(ValueError):materials.installed_packages(status.replace(b'arm64',b'amd64'),b'binary\t2:1.0-2\n','arm64')

    def test_control_records_reject_ambiguous_and_unbound_inputs(self):
        self.assertEqual(materials.control_records(b'Name: first\n continued\n\nName: second\n'),[{'Name':'first\ncontinued'},{'Name':'second'}])
        for data in [b'Key: one\nKey: two\n',b' no-owner\n',b'no-colon\n',b'Key: \0',b'Key: \xff']:
            with self.subTest(data=data),self.assertRaises((ValueError,UnicodeError)):materials.control_records(data)
        for value in ['source (>= 1)','source (= latest)','../escape (= 1)','source']:
            with self.subTest(value=value),self.assertRaises(ValueError):materials.source_identity(value,dependency=True)

    def test_gpt_crc_bounds_and_architecture_identity_are_data_only(self):
        with tempfile.TemporaryDirectory()as temporary:
            file=Path(temporary)/'disk';gpt(file)
            self.assertEqual(materials.guest_partition(file),{'partition':1,'type_guid':'b921b045-1df0-41c3-af44-4c6f280d3fae','first_lba':34,'last_lba':50,'name':'cloudimg-rootfs','offset':17408,'size':8704,'raw_size':51200})
            for options in [{'bad_crc':True},{'overlap':True}]:
                gpt(file,**options)
                with self.subTest(options=options),self.assertRaises(ValueError):materials.guest_partition(file)
            gpt(file);data=bytearray(file.read_bytes());data[2*512]^=1;file.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'table checksum'):materials.guest_partition(file)

    def test_real_pinned_go_source_hash_and_license_are_verified(self):
        root=ROOT/'tests/fixtures/source-materials';receipt=json.loads((root/'go-units-v0.5.0.json').read_bytes());archive=root/'go-units-v0.5.0.zip'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),receipt['sha256']);self.assertEqual(archive.stat().st_size,receipt['size_bytes'])
        self.assertEqual(materials.go_zip_hash(archive,receipt['module'],receipt['version']),receipt['h1'])
        with zipfile.ZipFile(archive)as source:
            license=source.read(receipt['module']+'@'+receipt['version']+'/LICENSE')
        self.assertIn(b'Apache License',license);self.assertIn(b'Version 2.0',license)

    def test_go_source_zip_identity_is_byte_exact_and_rejects_hostile_members(self):
        with tempfile.TemporaryDirectory()as temporary:
            archive=Path(temporary)/'source.zip'
            with zipfile.ZipFile(archive,'w')as source:source.writestr('example.org/module@v1.0.0/a.go',b'package a\n')
            lines=hashlib.sha256(b'package a\n').hexdigest()+'  example.org/module@v1.0.0/a.go\n'
            expected='h1:'+base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()
            self.assertEqual(materials.go_zip_hash(archive,'example.org/module','v1.0.0'),expected)
            for name in ['example.org/module@v1.0.0/../escape','foreign/a.go','example.org/module@v1.0.0/a\nb']:
                with zipfile.ZipFile(archive,'w')as source:source.writestr(name,b'x')
                with self.subTest(name=name),self.assertRaises(ValueError):materials.go_zip_hash(archive,'example.org/module','v1.0.0')

    def test_cleanup_attempts_every_planned_resource_and_persists_failure(self):
        owner='a'*32;resources=[{'kind':'container','name':'ud-source-metadata-'+owner+'-'+suffix}for suffix in('status','notices','lookup')]+[{'kind':'volume','name':'ud-source-metadata-'+owner}]
        report={'owner':owner,'resources':resources,'cleanup':[]};seen=[]
        def inspect(kind,name,selected):
            seen.append(name)
            if name.endswith('status'):raise ValueError('ownership changed')
            return None
        with tempfile.TemporaryDirectory()as temporary,patch.object(extract,'inspect_owned',inspect):
            output=Path(temporary)/'private-output'
            if os.name=='nt':
                spec=importlib.util.spec_from_file_location('source_cleanup_windows_acl_fixture',ROOT/'scripts/quality/windows-storage-acl.py')
                storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage);storage.WindowsStorage().create(str(output),'directory')
            else:output.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'cleanup failed'):extract.cleanup(output,report)
            persisted=json.loads((output/'receipt.json').read_bytes())
        self.assertEqual(seen,[row['name']for row in resources]);self.assertEqual([row['status']for row in persisted['cleanup']],['failed','absent','absent','absent'])
        with self.assertRaisesRegex(ValueError,'owner-bound'):
            extract.cleanup(Path('/not-used'),{'owner':owner,'resources':[{'kind':'volume','name':'unrelated'}],'cleanup':[]})

    def test_complete_source_components_include_descriptor_orig_and_debian_patches(self):
        prefix=b'Package: example\nVersion: 2:1.0-3\nDirectory: pool/main/e/example\nChecksums-Sha256:\n'
        rows=b''.join((' '+fingerprint+' '+str(size)+' '+name+'\n').encode()for fingerprint,size,name in [('a'*64,10,'example_1.0-3.dsc'),('b'*64,20,'example_1.0.orig.tar.xz'),('c'*64,30,'example_1.0-3.debian.tar.xz')])
        found=materials.source_index(prefix+rows)['example\0'+'2:1.0-3']
        self.assertEqual(found['name'],'example');self.assertEqual(len(found['files']),3)
        self.assertEqual(found['files'][2],{'path':'pool/main/e/example/example_1.0-3.debian.tar.xz','sha256':'c'*64,'size_bytes':30})
        for changed in [prefix+rows.replace(b'example_1.0-3.dsc',b'../escape.dsc'),prefix+rows.replace(b'example_1.0-3.dsc',b'example_1.0-3.txt'),prefix+rows+rows,(prefix+rows)*2,prefix+rows.replace(b'30 ',b'0 ')]:
            with self.subTest(data=changed[-60:]),self.assertRaises(ValueError):materials.source_index(changed)
        packages=[{'name':'consumer','version':'1','architecture':'arm64','source':{'name':'example','version':'2:1.0-3'},'built_using':[{'name':'other','version':'4'}]}]
        requirements=materials.source_requirements(packages)
        self.assertEqual([(row['name'],row['version'],row['consumers'][0]['relationship'])for row in requirements],[('example','2:1.0-3','source'),('other','4','built-using')])
