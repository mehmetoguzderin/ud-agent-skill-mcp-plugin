"""Compiler terms are classified from original byte facts, never imports alone."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('windows_perl_declarations',ROOT/'scripts/release/declare-windows-perl-components.py');M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


def document():
    records=[]
    for arch,target in [('arm64','aarch64'),('x64','x86_64')]:
        supplier_name='ARM64'if arch=='arm64'else'x64'
        modules=[{'id':0,'library':f'C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.44.35207\\lib\\{supplier_name}\\msvcrt.lib','object':'startup.obj','contributions':[{'linked_image_sha256':'f'*64}]},{'id':1,'library':f'C:\\Program Files (x86)\\Windows Kits\\10\\lib\\10.0.26100.0\\ucrt\\{arch}\\ucrt.lib','object':'Import:api-ms-win-crt-runtime-l1-1-0.dll','contributions':[{'linked_image_sha256':'1'*64}]},{'id':2,'library':f'C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.44.35207\\lib\\{supplier_name}\\msvcrt.lib','object':'unlinked.obj','contributions':[]}]
        library={'library':'odbccp32','archive':{'path':f'.artifacts/xwin-cache/xwin/sdk/lib/um/{target}/odbccp32.lib','sha256':'c'*64,'size_bytes':123},'members':[{'name':'guard_dispatch.obj','archive_header_offset':100,'sha256':'d'*64,'size_bytes':99,'member_kind':'COFF-object','map_symbols':['guard_dispatch']},{'name':'ODBC.dll','archive_header_offset':200,'sha256':'9'*64,'size_bytes':30,'member_kind':'short-COFF-import','map_symbols':['import_odbc']}]}
        records.append({'platform':'win32/'+arch,'pdbs':[{'path':'perl.pdb','sha256':'b'*64}],'binaries':[{'path':'bin/perl.exe','sha256':'a'*64,'size_bytes':1000,'origin':'supplier','pdb_path':'perl.pdb','debug_identity':{'guid':'01234567-89AB-CDEF-0123-456789ABCDEF','age':1},'runtime_compilands':modules},{'path':'own.dll','sha256':'e'*64,'size_bytes':900,'origin':'authored-reproduced-XS','libraries':[library]}]})
    return {'records':records}


class WindowsPerlDeclarations(unittest.TestCase):
    def test_every_binary_joins_exact_components_with_distinct_terms_families(self):
        components,joins=M.derive(document(),lambda value:value)
        self.assertEqual(len(joins),4);self.assertEqual(len(components),10)
        self.assertEqual([(c['family'],c['classification'])for c in components], [('msvc-2022-14.44.35207','linked-object'),('msvc-2022-14.44.35207','no-recorded-image-contribution'),('windows-sdk-10.0.26100.0-ucrt','import-metadata'),('windows-sdk-xwin-version-unverified-um','import-metadata'),('windows-sdk-xwin-version-unverified-um','linked-object')]*2)
        self.assertTrue(all(c['corresponding_source_review']=='pending-independent-exact-terms-review'and c['publisher_redistribution_authority']=='unverified-external'for c in components))
        self.assertEqual(components[0]['attribution']['module_ids'],[0]);self.assertEqual(components[1]['attribution']['module_ids'],[2]);self.assertEqual(components[3]['attribution']['archives'][0]['members'][0]['name'],'ODBC.dll');self.assertEqual(components[4]['attribution']['archives'][0]['members'][0]['name'],'guard_dispatch.obj')
        self.assertEqual([c['source_availability']for c in components[:5]],['unresolved-needs-exact-source-and-notices','not-a-linked-source-object','not-a-linked-source-object','not-a-linked-source-object','unresolved-needs-exact-source-and-notices'])
        self.assertEqual({key for j in joins for key in j['component_ids']},{c['id']for c in components})
        changed=document();changed['records'][0]['binaries'][0]['runtime_compilands'][0]['contributions'][0]['linked_image_sha256']='0'*64
        other,_=M.derive(changed,lambda value:value);self.assertNotEqual(other[0]['attribution']['canonical_sha256'],components[0]['attribution']['canonical_sha256'])

    def test_wrong_versions_architectures_and_filename_only_inferences_are_rejected(self):
        exact=document()['records'][0]['binaries'][0]['runtime_compilands'][0]['library']
        for library in ['msvcrt.lib',exact.replace('14.44.35207','14.51.36244'),exact.replace('ARM64','x64'),exact.replace('Microsoft Visual Studio','unrelated')]:
            with self.subTest(library=library),self.assertRaises(ValueError):M.supplier_family(library,'arm64')
        for path in ['.artifacts/foreign/odbccp32.lib','.artifacts/xwin-cache/xwin/sdk/lib/um/x86_64/odbccp32.lib']:
            library=document()['records'][0]['binaries'][1]['libraries'][0];library['archive']['path']=path
            with self.assertRaises(ValueError):M.authored_family(library,'arm64')

    def test_unknown_member_kind_never_becomes_a_proprietary_object(self):
        library=document()['records'][0]['binaries'][1]['libraries'][0]
        library['members'][0]['member_kind']='unrecognized'
        with self.assertRaises(ValueError):M.authored_contributions(library)

    def test_import_without_image_contribution_is_not_a_contributing_import(self):
        self.assertEqual(M.supplier_contribution({'object':'Import:kernel32.dll','contributions':[]}), 'no-recorded-image-contribution')

    def test_edition_term_paragraphs_are_bound_to_the_original_document(self):
        xml=b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Exact terms</w:t></w:r></w:p></w:body></w:document>'
        with tempfile.TemporaryDirectory() as folder:
            docx=Path(folder)/'terms.docx';text=Path(folder)/'terms.txt'
            with zipfile.ZipFile(docx,'w') as z:z.writestr('word/document.xml',xml)
            text.write_text('Exact terms\n');M.verify_original_paragraphs(docx,text)
            text.write_text('Altered terms\n')
            with self.assertRaises(ValueError):M.verify_original_paragraphs(docx,text)

    def test_missing_platform_pdb_unclassified_binary_and_duplicate_joins_fail(self):
        for case in ['platform','pdb','unclassified','duplicate']:
            value=document()
            if case=='platform':value['records'].pop()
            elif case=='pdb':value['records'][0]['pdbs']=[]
            elif case=='unclassified':value['records'][0]['binaries'][0]['runtime_compilands']=[]
            else:value['records'][0]['binaries'].append(copy.deepcopy(value['records'][0]['binaries'][0]))
            with self.subTest(case=case),self.assertRaises(ValueError):M.derive(value,lambda rows:rows)

if __name__=='__main__':unittest.main()
