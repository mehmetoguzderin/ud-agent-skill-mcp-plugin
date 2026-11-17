import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('ud_windows_pe',ROOT/'scripts/runtime/windows_pe.py')
pe=importlib.util.module_from_spec(spec);spec.loader.exec_module(pe)

def binary(imports=(),delay=(),machine=0xAA64):
    body=bytearray(2048);body[:2]=b'MZ';struct.pack_into('<I',body,60,128);body[128:132]=b'PE\0\0'
    struct.pack_into('<HH',body,132,machine,1);struct.pack_into('<H',body,148,240)
    at=152;struct.pack_into('<H',body,at,0x20b);struct.pack_into('<Q',body,at+24,0x180000000);struct.pack_into('<I',body,at+60,1024);struct.pack_into('<I',body,at+108,16)
    section=at+240;struct.pack_into('<IIII',body,section+8,1024,4096,1024,1024)
    cursor=0x1300
    for directory,stride,names,table in [(1,20,imports,0x1000),(13,32,delay,0x1100)]:
        if names:struct.pack_into('<II',body,at+112+8*directory,table,(len(names)+1)*stride)
        for i,name in enumerate(names):
            index=1024+table-4096+i*stride
            if directory==13:struct.pack_into('<II',body,index,1,cursor)
            else:struct.pack_into('<I',body,index+12,cursor)
            value=name.encode()+b'\0';off=1024+cursor-4096;body[off:off+len(value)]=value;cursor+=len(value)
    return bytes(body)

class WindowsPeClosure(unittest.TestCase):
    def test_exact_machine_and_normal_delay_imports(self):
        value=pe.inspect_pe(binary(['KERNEL32.dll','vcruntime140.dll'],['vcruntime140_1.dll']),'arm64')
        self.assertEqual(value['imports'],['kernel32.dll','vcruntime140.dll','vcruntime140_1.dll'])
        self.assertEqual(pe.inspect_pe(binary(machine=0x8664),'x64')['architecture'],'x64')
        for arch in ['x64','unknown']:
            with self.assertRaises(ValueError):pe.inspect_pe(binary(),arch)
    def test_malformed_extents_names_headers_and_unterminated_tables(self):
        values=[b'',binary()[:100],binary(['../escape.dll']),binary(['unsafe\\name.dll'])]
        for offset,value,fmt in [(60,0xffffffff,'I'),(134,0,'H'),(148,10,'H'),(152,0x10b,'H'),(260,17,'I'),(212,5,'I'),(152+240+20,2047,'I'),(152+112+8,0x1800,'I'),(152+116+8,19,'I')]:
            changed=bytearray(binary(['private.dll']));struct.pack_into('<'+fmt,changed,offset,value);values.append(bytes(changed))
        changed=bytearray(binary(['private.dll']));struct.pack_into('<I',changed,152+116+8,20);values.append(bytes(changed))
        for value in values:
            with self.assertRaises(ValueError):pe.inspect_pe(value,'arm64')
    def test_closes_only_needed_private_dependencies_without_ambient_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'runtime';providers=Path(temporary)/'verified';(root/'bin').mkdir(parents=True);providers.mkdir()
            (root/'bin/perl.exe').write_bytes(binary(['perl544.dll']))
            (providers/'perl544.dll').write_bytes(binary(['vcruntime140.dll']))
            (providers/'vcruntime140.dll').write_bytes(binary(['kernel32.dll','api-ms-win-crt-runtime-l1-1-0.dll']))
            (providers/'unused.dll').write_bytes(binary())
            # Multiple XS modules may legitimately share a filename; they are
            # loaded by full path, never confused with import-search candidates.
            for name in ['A','B']:
                target=root/'lib'/name;target.mkdir(parents=True);(target/'XS.dll').write_bytes(binary(['perl544.dll'],delay=['vcruntime140.dll'] if name=='A' else []))
            receipt=pe.close_runtime_imports(root,'arm64',[providers]);self.assertEqual(len(receipt),5)
            self.assertFalse((root/'bin/unused.dll').exists());self.assertEqual((root/'bin/perl544.dll').read_bytes(),(providers/'perl544.dll').read_bytes())
            (root/'bin/unknown.exe').write_bytes(binary(['missing.dll']))
            with self.assertRaisesRegex(ValueError,'missing private runtime DLL'):pe.close_runtime_imports(root,'arm64',[providers])
    def test_rejects_provider_architecture_aliases_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'runtime';providers=Path(temporary)/'verified';(root/'bin').mkdir(parents=True);providers.mkdir();(root/'bin/perl.exe').write_bytes(binary(['wrong.dll']))
            (providers/'wrong.dll').write_bytes(binary(machine=0x8664))
            with self.assertRaisesRegex(ValueError,'architecture'):pe.close_runtime_imports(root,'arm64',[providers])
            (providers/'wrong.dll').unlink();(providers/'real.dll').write_bytes(binary());(providers/'alias.dll').symlink_to(providers/'real.dll')
            with self.assertRaisesRegex(ValueError,'links'):pe.close_runtime_imports(root,'arm64',[providers])
