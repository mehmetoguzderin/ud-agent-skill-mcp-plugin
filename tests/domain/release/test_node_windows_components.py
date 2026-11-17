"""PDB attribution uses exact original facts, never native-target execution."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3];S=importlib.util.spec_from_file_location('node_windows_components',ROOT/'scripts/release/node-windows-components.py');M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
FIXTURE='''Modules
============================================================
Mod 0000 | `new_scalar.obj`:
 Obj: `C:\\VS\\libcmt.lib`:
 debug stream: 4, # files: 1, has ec info: false
Files
============================================================
Mod 0000 | `new_scalar.obj`:
- (SHA-256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) D:\\src\\new_scalar.cpp
Section Headers
============================================================
 SECTION HEADER #1
 .text name
Section Contributions
============================================================
 SC[.text] | mod = 0, 0001:0002, size = 4, data crc = 12, reloc crc = 0
'''
class NodePdbComponents(unittest.TestCase):
    def test_complete_compiland_file_and_linked_range_inventory(self):
        result=M.parse_modules(FIXTURE);self.assertEqual(list(result),[0]);row=result[0]
        self.assertEqual(row['object'],'new_scalar.obj');self.assertEqual(row['library'],'C:\\VS\\libcmt.lib');self.assertEqual(row['debug_stream'],4)
        self.assertEqual(row['source_files'],[{'path':'D:\\src\\new_scalar.cpp','algorithm':'sha256','checksum':'a'*64}])
        self.assertEqual(row['contributions'],[{'section_name':'.text','section':1,'offset':2,'size_bytes':4,'data_crc':12,'relocation_crc':0}])
    def test_omitted_duplicated_and_misattributed_facts_fail(self):
        for value in [FIXTURE.replace('# files: 1','# files: 2'),FIXTURE.replace('mod = 0','mod = 1'),FIXTURE.replace('Mod 0000 |','Mod 0001 |'),FIXTURE.replace('SHA-256: '+'A'*64,'SHA-256: AA'),FIXTURE.replace('size = 4','size = -4'),FIXTURE.replace('Files\n','Absent\n',1),FIXTURE+FIXTURE]:
            with self.subTest(value=value),self.assertRaises(ValueError):M.parse_modules(value)
    def test_explicit_absent_checksum_is_preserved_as_absence_not_invented_hash(self):
        value=FIXTURE.replace('(SHA-256: '+'A'*64+')','(None: )');rows=M.parse_modules(value)
        self.assertEqual(rows[0]['source_files'],[{'path':'D:\\src\\new_scalar.cpp','algorithm':'none','checksum':None}])
    def test_guid_and_age_are_exact_not_filename_based(self):
        value='283F9F7A-08B3-D5FD-4C4C-44205044422E';self.assertEqual(M.parse_guid('GUID: {'+value+'}\nAge: 1\n',True),M.parse_guid('PDBGUID: {'+value+'}\nPDBAge: 1\n'))
        for text in ['', 'PDBGUID: {'+value+'}\n','PDBGUID: {'+value+'}\nPDBGUID: {'+value+'}\nPDBAge: 1\n']:
            with self.assertRaises(ValueError):M.parse_guid(text)
    def test_linked_bytes_and_virtual_zero_fill_are_distinguished(self):
        section={1:{'name':'.data','raw_size':6,'virtual_size':10,'raw_offset':2,'rva':4096}};data=b'--ABCDEF';value={'section_name':'.data','section':1,'offset':4,'size_bytes':5,'data_crc':0,'relocation_crc':0}
        result=M.contribution_bytes(data,section,value);self.assertEqual(result['file_bytes'],2);self.assertEqual(result['zero_fill_bytes'],3);self.assertEqual(result['linked_image_sha256'],hashlib.sha256(b'EF\0\0\0').hexdigest())
        for changes in [{'section':2},{'offset':9,'size_bytes':2},{'section_name':'.text'}]:
            with self.assertRaises(ValueError):M.contribution_bytes(data,section,{**value,**changes})
        empty=M.contribution_bytes(data,section,{**value,'size_bytes':0});self.assertEqual(empty['file_bytes'],0);self.assertEqual(empty['linked_image_sha256'],hashlib.sha256(b'').hexdigest())
        # A wholly virtual .data tail has no file position to read. Its mapped
        # bytes are zero even when raw_offset+offset exceeds the file length.
        tail=M.contribution_bytes(data,section,{**value,'offset':8,'size_bytes':2})
        self.assertEqual((tail['file_bytes'],tail['zero_fill_bytes'],tail['linked_image_sha256']),(0,2,hashlib.sha256(b'\0\0').hexdigest()))
        with self.assertRaises(ValueError):M.contribution_bytes(data,{1:{**section[1],'raw_offset':20}},value)

if __name__=='__main__':unittest.main()
