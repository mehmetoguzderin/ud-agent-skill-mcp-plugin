"""Original data-only Mach-O/dSYM/source attribution policy."""
import importlib.util
from pathlib import Path
import struct
import unittest
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import types
import zipfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('apple_binary_components',ROOT/'scripts/release/apple-binary-components.py');M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
def image(commands,cpu=0x100000c):
    payload=b''.join(commands)
    return struct.pack('<8I',0xfeedfacf,cpu,0,2,len(commands),len(payload),0,0)+payload
def identity():return struct.pack('<II',0x1b,24)+bytes(range(16))
def dylib(name,weak=False):
    data=name.encode()+b'\0';size=(24+len(data)+7)//8*8
    return struct.pack('<6I',0x80000018 if weak else 0xc,size,24,0,0,0)+data+b'\0'*(size-24-len(data))

class AppleBinaryComponents(unittest.TestCase):
    def test_complete_released_symbol_inventory_joins_sources_and_scopes_missing_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sources=root/'sources';sources.mkdir();provider=root/'provider';provider.mkdir();archive=sources/'source.tar.gz';commit='a'*40
            with tarfile.open(archive,'w:gz')as tar:
                for name,data in [('release/Package.resolved',b'{"pins":[]}'),('release/Sources/CLI/Main.swift',b'original source')]:
                    member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
            (sources/'receipt.json').write_text(json.dumps({'files':[{'name':'apple/container','version':commit,'path':'source.tar.gz',**M.receipt(archive)}]}))
            symbols=root/'symbols.zip';products=['container','container-apiserver','builder','build','cluster','container-network-vmnet','container-runtime-linux','container-core-images','machine-apiserver']
            with zipfile.ZipFile(symbols,'w')as stream:
                for name in products:
                    data=image([identity()]);(provider/name).write_bytes(data+commit.encode()+b'1.7.1');product={'builder':'container-builder','build':'container-build'}.get(name,name);stream.writestr(f'container-dSYM/{product}.dSYM/Contents/Resources/DWARF/{product}',data)
            for name in ['cluster-hoststore','container-core-clusters']:(provider/name).write_bytes(image([identity()])+commit.encode()+b'1.7.1')
            tool=root/'dwarfdump';tool.write_bytes(image([identity()]));lock={'archive':M.receipt(symbols),'repository':'apple/container','source_commit':commit,'version':'1.7.1'}
            text='DW_TAG_compile_unit\n DW_AT_producer ("Apple Swift")\n DW_AT_name ("/Users/runner/actions-runner/_work/container/container/Sources/CLI/Main.swift")\nDW_TAG_compile_unit\n DW_AT_producer ("Apple clang")\n DW_AT_name ("SwiftShims")\n'
            def run(argv,stdout,**kwargs):self.assertEqual(argv[1:3],['--debug-info','--recurse-depth=0']);stdout.write((argv[-1]+':\tfile format Mach-O arm64\n'+text).encode());return types.SimpleNamespace(returncode=0,stderr=b'')
            with patch.object(M.subprocess,'run',run):
                result=M.collect(provider,sources,symbols,lock,tool,root/'output.json');replay=M.collect(provider,sources,symbols,lock,tool,root/'replay.json')
            self.assertEqual(result,replay)
            self.assertEqual(len(result['provider_files']),11);self.assertEqual(len(result['sources']),1);self.assertEqual(result['unresolved_source_units'],[])
            matched=[r for r in result['provider_files']if r['debug_evidence']=='uuid-matched-official-symbols'];self.assertEqual(len(matched),9)
            self.assertEqual(matched[0]['source_units'][0]['sha256'],hashlib.sha256(b'original source').hexdigest());self.assertEqual(matched[0]['imported_module_metadata'][0]['name'],'SwiftShims')
            self.assertEqual(sum(row['debug_evidence']=='not-in-official-symbol-archive'for row in result['provider_files']),2)
            self.assertFalse(any(root.glob('ud-apple-dsym-*')))
            replaced={}
            def substitute(argv,stdout,**kwargs):
                file=Path(argv[-1]);body=file.read_bytes();file.chmod(0o600)
                retained=file.with_name('retained-original');file.rename(retained);file.write_bytes(body)
                replaced.update(file=file,retained=retained,body=body)
                return run(argv,stdout,**kwargs)
            with patch.object(M.subprocess,'run',substitute),self.assertRaisesRegex(M.PrivateInputChanged,'preserved workspace'):
                M.collect(provider,sources,symbols,lock,tool,root/'substituted.json')
            self.assertEqual(replaced['file'].read_bytes(),replaced['body']);self.assertEqual(replaced['retained'].read_bytes(),replaced['body'])
            self.assertNotEqual(replaced['file'].stat().st_ino,replaced['retained'].stat().st_ino)
            self.assertFalse((root/'substituted.json').exists())
            shutil.rmtree(replaced['file'].parent)
            for failure in ('failed', 'timeout', 'invalid-header'):
                def failing_substitute(argv,stdout,**kwargs):
                    substitute(argv,stdout,**kwargs)
                    if failure=='timeout':raise M.subprocess.TimeoutExpired(argv,60)
                    if failure=='invalid-header':stdout.seek(0);stdout.truncate();stdout.write(b'wrong diagnostic header')
                    return types.SimpleNamespace(returncode=1 if failure=='failed'else 0,stderr=b'')
                with self.subTest(failure=failure),patch.object(M.subprocess,'run',failing_substitute),self.assertRaisesRegex(M.PrivateInputChanged,'preserved workspace'):
                    M.collect(provider,sources,symbols,lock,tool,root/'failed-substitution.json')
                self.assertEqual(replaced['file'].read_bytes(),replaced['body']);self.assertEqual(replaced['retained'].read_bytes(),replaced['body'])
                shutil.rmtree(replaced['file'].parent)
            with patch.object(M.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stderr=b'owned parser failed')),self.assertRaisesRegex(ValueError,'parser failed'):
                M.collect(provider,sources,symbols,lock,tool,root/'owned-parser-failed.json')
            self.assertFalse(any(root.glob('ud-apple-dsym-*')))
            (provider/'container').write_bytes(image([struct.pack('<II',0x1b,24)+bytes(reversed(range(16)))]))
            with patch.object(M.subprocess,'run',run),self.assertRaisesRegex(ValueError,'UUID'):M.collect(provider,sources,symbols,lock,tool,root/'bad.json')
            self.assertFalse((root/'bad.json').exists())

    def test_actual_uuid_weak_import_and_build_version_semantics(self):
        build=struct.pack('<8I',0x32,32,1,15<<16,(26<<16)|(5<<8),1,3,1267<<16)
        result=M.macho(image([identity(),dylib('/usr/lib/swift/libswiftCore.dylib'),dylib('@rpath/libswiftCompatibilitySpan.dylib',True),build]))
        self.assertEqual(result['uuid'],'00010203-0405-0607-0809-0A0B0C0D0E0F')
        self.assertEqual(result['dylibs'],[{'name':'/usr/lib/swift/libswiftCore.dylib','weak':False},{'name':'@rpath/libswiftCompatibilitySpan.dylib','weak':True}])
        self.assertEqual(result['build_versions'],[{'platform':1,'minimum_os':'15.0.0','sdk':'26.5.0','tools':[{'tool':3,'version':'1267.0.0'}]}])

    def test_wrong_architecture_duplicate_uuid_truncation_and_malformed_commands_fail(self):
        good=image([identity()])
        for data in [b'MZwrong',image([identity()],0x1000007),image([identity(),identity()]),good[:-1],image([struct.pack('<II',0x1b,16)+b'\0'*8]),image([struct.pack('<II',0xc,24)+struct.pack('<I',200)+b'\0'*12]),image([struct.pack('<8I',0x32,32,1,0,0,2,3,0)])]:
            with self.subTest(data=data[:32]),self.assertRaises(ValueError):M.macho(data)

    def test_compilation_unit_parser_distinguishes_imported_modules_from_source_files(self):
        text='''0x0: DW_TAG_compile_unit
 DW_AT_producer ("Apple Swift version 6.3.3")
 DW_AT_name ("/Users/runner/actions-runner/_work/container/container/.build/checkouts/swift-nio/Sources/NIO/ByteBuffer.swift")
 DW_AT_comp_dir ("/Users/runner/actions-runner/_work/container/container")
0x1: DW_TAG_compile_unit
 DW_AT_producer ("Apple clang version 21.0.0")
 DW_AT_name ("SwiftShims")
'''
        units=M.compilation_units(text);self.assertEqual(len(units),2)
        self.assertEqual(M.source_location(units[0]['name']),('swift-nio','Sources/NIO/ByteBuffer.swift'))
        self.assertIsNone(M.source_location(units[1]['name']))
        self.assertEqual(M.source_location('/Users/runner/actions-runner/_work/container/container/Sources/CLI/Main.swift'),('apple/container','Sources/CLI/Main.swift'))
        self.assertIsNone(M.source_location('/different/source.swift'))
        for text in ['', 'DW_TAG_compile_unit\nDW_AT_name ("file.swift")', 'DW_TAG_compile_unit\nDW_AT_name ("a")\nDW_AT_name ("b")\nDW_AT_producer ("x")']:
            with self.assertRaises(ValueError):M.compilation_units(text)

if __name__=='__main__':unittest.main()
