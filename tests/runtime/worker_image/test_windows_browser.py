import ctypes
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import io
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib

from ud_agent import windows_browser as edge


def receipt(data): return {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}


def pe_fixture():
    data = bytearray(768); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128); data[128:132] = b'PE\0\0'
    struct.pack_into('<HH', data, 132, 0xaa64, 1); struct.pack_into('<H', data, 148, 224); struct.pack_into('<H', data, 152, 0x10b)
    struct.pack_into('<I', data, 152 + 92, 16); struct.pack_into('<II', data, 152 + 112, 0x1000, 256)
    struct.pack_into('<III', data, 376 + 12, 0x1000, 256, 512)
    for offset, name, destination in [(0, 0x80000080, 0x80000020), (32, 102, 0x80000040), (64, 0, 96)]:
        struct.pack_into('<H', data, 512 + offset + 14, 1); struct.pack_into('<II', data, 512 + offset + 16, name, destination)
    struct.pack_into('<II', data, 512 + 96, 0x10a0, 4); struct.pack_into('<H', data, 512 + 128, 1); data[642:644] = 'B'.encode('utf-16le'); data[672:676] = b'DATA'
    return bytes(data)


class Function:
    def __init__(self, name, api): self.name, self.api = name, api
    def __call__(self, *args): return self.api.call(self.name, *args)


class MsiApi:
    def __init__(self, payload):
        self.payload, self.offset, self.fetch, self.calls = payload, 0, 0, []
        for name in ['MsiOpenDatabaseW','MsiDatabaseOpenViewW','MsiCreateRecord','MsiRecordSetStringW','MsiViewExecute','MsiViewFetch','MsiRecordReadStream','MsiCloseHandle']:
            setattr(self, name, Function(name, self))
    def call(self, name, *args):
        self.calls.append((name, args))
        if name == 'MsiOpenDatabaseW': args[2]._obj.value = 11
        elif name == 'MsiDatabaseOpenViewW': args[2]._obj.value = 12
        elif name == 'MsiCreateRecord': return 13
        elif name == 'MsiViewFetch':
            self.fetch += 1
            if self.fetch > 1: return 259
            args[1]._obj.value = 14
        elif name == 'MsiRecordReadStream':
            chunk = self.payload[self.offset:self.offset + args[3]._obj.value]; self.offset += len(chunk)
            ctypes.memmove(args[2], chunk, len(chunk)); args[3]._obj.value = len(chunk)
        return 0


class WindowsBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ud-edge-tests-'); self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)

    def test_pe_resource_walk_reads_only_the_expected_data_and_keeps_source_bytes(self):
        source, target = self.root / 'source.exe', self.root / 'resource'; data = pe_fixture(); source.write_bytes(data)
        edge.pe_resource(source, ['B', 102, 0], target)
        self.assertEqual(target.read_bytes(), b'DATA'); self.assertEqual(source.read_bytes(), data); self.assertEqual(edge._machine(source), 0xaa64)
        for identifiers in [[], ['B', 102, True], ['B', 101, 0], ['C', 102, 0]]:
            with self.assertRaises(ValueError): edge.pe_resource(source, identifiers, self.root / 'missing')

    def test_hostile_or_truncated_pe_bounds_are_rejected_before_extraction(self):
        for mutation in ['signature','header','rva','cycle','truncated']:
            data = bytearray(pe_fixture())
            if mutation == 'signature': data[:2] = b'NO'
            if mutation == 'header': struct.pack_into('<I', data, 60, 0xffffffff)
            if mutation == 'rva': struct.pack_into('<I', data, 512 + 96, 0xffffffff)
            if mutation == 'cycle': struct.pack_into('<I', data, 512 + 20, 0x80000000)
            if mutation == 'truncated': data = data[:100]
            source = self.root / (mutation + '.exe'); source.write_bytes(data)
            with self.assertRaises(ValueError): edge.pe_resource(source, ['B', 102, 0], self.root / ('out-' + mutation))

    def test_lzma_is_bounded_and_rejects_trailing_bytes_truncation_and_wrong_hash(self):
        expected = b'independent browser layer\0\xff'; data = lzma.compress(expected, format=lzma.FORMAT_ALONE)
        source = self.root / 'layer'; source.write_bytes(data); output = self.root / 'decoded'
        edge.lzma_layer(source, output, receipt(expected)); self.assertEqual(output.read_bytes(), expected)
        for content, wanted in [(data + b'junk', receipt(expected)), (data[:-1], receipt(expected)), (data, receipt(expected[:-1])), (data, {**receipt(expected), 'sha256':'0'*64})]:
            source.write_bytes(content); output.unlink()
            with self.assertRaises((ValueError, lzma.LZMAError)): edge.lzma_layer(source, output, wanted)

    def test_bcj2_reframing_preserves_all_streams_and_exact_7z_header_checksums(self):
        source = self.root / 'bcj2'; source.write_bytes(struct.pack('<5I', 3, 3, 0, 0, 5) + b'abc' + b'\0'*5)
        target = self.root / 'framed.7z'; edge.frame_bcj2(source, target); data = target.read_bytes()
        self.assertEqual(data[:8], b"7z\xbc\xaf\x27\x1c\x00\x04")
        offset, size, checksum = struct.unpack_from('<QQI', data, 12)
        self.assertEqual(data[32:32+offset], b'abc' + b'\0'*5)
        self.assertEqual(zlib.crc32(data[12:32]) & 0xffffffff, struct.unpack_from('<I', data, 8)[0])
        self.assertEqual(zlib.crc32(data[32+offset:32+offset+size]) & 0xffffffff, checksum)
        self.assertTrue(data.endswith('layer.tar\0'.encode('utf-16le') + b'\0\0'))
        for bad in [b'', struct.pack('<5I', 4, 3, 0, 0, 5) + b'abc' + b'\0'*5, struct.pack('<5I', 3, 1, 1, 1, 0) + b'abc']:
            source.write_bytes(bad)
            with self.assertRaises(ValueError): edge.frame_bcj2(source, self.root / 'invalid')

    def test_7z_integer_encoding_has_independent_boundary_vectors(self):
        for value, expected in [(0,b'\0'),(127,b'\x7f'),(128,b'\x80\x80'),(16383,b'\xbf\xff'),(16384,b'\xc0\x00\x40'),(2**64-1,b'\xff'*9)]:
            self.assertEqual(edge.number7z(value), expected)
        for value in [-1, 2**64, True, '1']:
            with self.assertRaises(ValueError): edge.number7z(value)

    def test_decoder_listing_validates_windows_controls_collisions_and_closed_file_kinds(self):
        valid = b'Path = Chrome-bin\nSize = 0\nAttributes = D\nEncrypted = -\n\nPath = Chrome-bin\\msedge.exe\nSize = 4\nAttributes = A\nEncrypted = -\n'
        self.assertEqual(edge._listed(valid), [{'path':'Chrome-bin','size_bytes':0,'directory':True},{'path':'Chrome-bin/msedge.exe','size_bytes':4,'directory':False}])
        for data in [valid.replace(b'Chrome-bin\\msedge.exe',b'../escape'), valid.replace(b'Chrome-bin\\msedge.exe',b'Chrome-bin/CON.exe'), valid + b'junk\n', valid.replace(b'Chrome-bin\\msedge.exe',b'Chrome-bin/evil:name'), valid.replace(b'Attributes = D',b'Attributes = A'), valid.replace(b'Encrypted = -',b'Encrypted = +'), valid.replace(b'Attributes = A',b'Attributes = l'), valid + valid, valid.replace(b'Size = 4',b'Size = -1'), valid.replace(b'Size = 4',b'Size = 4\nSymbolic Link = target')]:
            with self.assertRaises(ValueError): edge._listed(data)

    def test_decoder_uses_technical_utf8_listing_and_noninteractive_bounded_extract(self):
        class Child:
            returncode = 0
            def wait(self, timeout): self.timeout = timeout
        for command, flags in [('l',['l','-slt','-ba','-sccUTF-8']), ('x',['x','-y','-bd','-bb0','-sccUTF-8'])]:
            child = Child()
            with patch.object(edge.subprocess, 'Popen', return_value=child) as spawn:
                self.assertEqual(edge._decoder_run(self.root/'decoder.exe', command, self.root), b'')
            self.assertEqual(spawn.call_args.args[0], [str(self.root/'decoder.exe'), *flags, '--', 'archive.7z'])
            self.assertEqual(child.timeout, 120)
            self.assertEqual(spawn.call_args.kwargs['stdin'], edge.subprocess.DEVNULL)
            self.assertNotIn('LD_LIBRARY_PATH', spawn.call_args.kwargs['env'])
        with patch.object(edge.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError): edge._decoder_run(self.root/'decoder.exe','run',self.root)
            spawn.assert_not_called()

    def test_msi_uses_only_parameterized_readonly_apis_and_closes_all_handles(self):
        data = b'verified vendor stream' * 10000; api = MsiApi(data); output = self.root / 'stream'
        with patch.object(edge.sys, 'platform', 'win32'), patch.object(edge.ctypes, 'WinDLL', return_value=api, create=True) as loader:
            edge.msi_stream(self.root / 'input.msi', 'MicrosoftEdgeInstaller', output, receipt(data))
        self.assertEqual(output.read_bytes(), data)
        self.assertEqual(loader.call_args.kwargs['winmode'], 0x800)
        opening = next(args for name,args in api.calls if name == 'MsiOpenDatabaseW'); self.assertIsNone(opening[1])
        query = next(args for name,args in api.calls if name == 'MsiDatabaseOpenViewW'); self.assertEqual(query[1], 'SELECT `Data` FROM `Binary` WHERE `Name` = ?')
        self.assertEqual([args[0] for name,args in api.calls if name == 'MsiCloseHandle'], [14,13,12,11])
        self.assertFalse(any('Install' in name or 'Action' in name for name,_ in api.calls))

    def test_integrity_and_architecture_failures_do_not_start_a_decoder(self):
        file = self.root / 'asset'; file.write_bytes(b'bytes')
        for record in [receipt(b'wrong'), {'sha256':'z'*64,'size_bytes':5}, {'sha256':'0'*64,'size_bytes':True}]:
            with self.assertRaises(ValueError): edge.verify(file, record)
        with patch.object(edge.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError): edge.materialize(file,file,{},self.root/'browser')
            spawn.assert_not_called()

    def test_tar_checks_all_members_before_selecting_the_fixed_payload(self):
        payload = b'independent mini installer bytes'
        def archive(entries):
            path = self.root/'installer.tar'
            with tarfile.open(path,'w') as target:
                for name,data,kind in entries:
                    member = tarfile.TarInfo(name); member.size = len(data); member.type = kind
                    target.addfile(member,io.BytesIO(data))
            return path
        selected = {'member':'mini.exe',**receipt(payload)}
        source = archive([('mini.exe',payload,tarfile.REGTYPE),('notes',b'note',tarfile.REGTYPE)])
        edge._tar_member(source,self.root/'mini',selected)
        self.assertEqual((self.root/'mini').read_bytes(),payload)
        for name,kind in [('../escape',tarfile.REGTYPE),('MINI.EXE',tarfile.REGTYPE),('CON',tarfile.REGTYPE),('link',tarfile.SYMTYPE)]:
            source = archive([('mini.exe',payload,tarfile.REGTYPE),(name,b'',kind)])
            output = self.root/'bad-mini'
            with self.assertRaises(ValueError): edge._tar_member(source,output,selected)
            self.assertFalse(output.exists())

    def test_materialized_manifest_binds_base_and_browser_bytes_and_removes_deferred_state(self):
        pack = self.root/'pack'; pack.mkdir(); (pack/'decoder').mkdir()
        decoder, recipe = b'fixed decoder', b'{"provider":"microsoft-edge"}'
        (pack/'decoder/7zdec.exe').write_bytes(decoder); (pack/'recipe.json').write_bytes(recipe)
        base = [{'path':'decoder/7zdec.exe',**receipt(decoder)},{'path':'recipe.json',**receipt(recipe)}]
        manifest = {'schema_version':1,'executable':'browser/msedge.exe','files':base,'fonts':[],
                    'deferred_browser':{'provider':'microsoft-edge','recipe':'recipe.json','decoder':'decoder/7zdec.exe','directory':'browser'}}
        (pack/'manifest.json').write_text(json.dumps(manifest))
        browser = b'independent native browser bytes'
        def materialize(msi,decoder_path,configuration,output):
            self.assertEqual(msi,self.root/'vendor.msi')
            self.assertEqual(decoder_path,pack/'decoder/7zdec.exe')
            output.mkdir(); (output/'msedge.exe').write_bytes(browser)
            return {'files':[{'path':'msedge.exe',**receipt(browser)}]}
        with patch.object(edge,'materialize',side_effect=materialize):
            edge.materialize_pack(pack,self.root/'vendor.msi','recipe.json','decoder/7zdec.exe','browser','manifest.json')
        final = json.loads((pack/'manifest.json').read_text())
        self.assertNotIn('deferred_browser',final)
        self.assertEqual(final['executable'],'browser/msedge.exe')
        self.assertEqual(final['files'],sorted([*base,{'path':'browser/msedge.exe',**receipt(browser)}],key=lambda item:item['path']))
        self.assertFalse((pack/'manifest.json.materialized').exists())
        self.assertEqual((pack/'recipe.json').read_bytes(),recipe)

    def test_deferred_manifest_integrity_and_foreign_paths_fail_before_vendor_materialization(self):
        pack = self.root/'pack'; pack.mkdir(); (pack/'decoder').mkdir()
        (pack/'decoder/7zdec.exe').write_bytes(b'decoder'); (pack/'recipe.json').write_bytes(b'{}')
        base = [{'path':'decoder/7zdec.exe',**receipt(b'decoder')},{'path':'recipe.json',**receipt(b'{}')}]
        manifest = {'schema_version':1,'executable':'browser/msedge.exe','files':base,
                    'deferred_browser':{'provider':'microsoft-edge','recipe':'recipe.json','decoder':'decoder/7zdec.exe','directory':'browser'}}
        for change in ['foreign','hash','executable','vendor-in-base','missing-decoder']:
            candidate = json.loads(json.dumps(manifest))
            if change=='foreign': candidate['deferred_browser']['provider']='other'
            if change=='hash': candidate['files'][0]['sha256']='0'*64
            if change=='executable': candidate['executable']='outside.exe'
            if change=='vendor-in-base': candidate['files'].append({'path':'browser/msedge.exe',**receipt(b'')})
            if change=='missing-decoder': candidate['files']=candidate['files'][1:]
            (pack/'manifest.json').write_text(json.dumps(candidate))
            with patch.object(edge,'materialize') as run:
                with self.assertRaises(ValueError): edge.materialize_pack(pack,self.root/'vendor.msi','recipe.json','decoder/7zdec.exe','browser','manifest.json')
                run.assert_not_called()
        for path in ['../escape','C:/escape','CON','x\\escape']:
            with self.assertRaises(ValueError): edge.materialize_pack(pack,self.root/'vendor.msi',path,'decoder/7zdec.exe','browser','manifest.json')


if __name__ == '__main__': unittest.main()
