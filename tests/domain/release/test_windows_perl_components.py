"""Original COFF recipes independently check Windows Perl attribution joins."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('windows_perl_components',ROOT/'scripts/release/windows-perl-components.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


def member(name,body):
    header=(name.ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'0'.ljust(8)+str(len(body)).ljust(10)+'`\n').encode('ascii')
    return header+body+(b'\n'if len(body)%2 else b'')


def recipe():
    # The same DLL-name occurs twice. Only the first linker index distinguishes
    # the concrete import members selected by their actual map public symbols.
    long=b'very-long-producer-path/startup.obj\0'
    names=[b'first\0',b'second\0',b'guard\0']
    size=4+12+sum(map(len,names));index_end=8+60+size+(size%2)
    long_member=member('//',long);first=index_end+len(long_member)
    one=b'\0\0\xff\xff\0\0'+b'A'*14
    two=b'\0\0\xff\xff\0\0'+b'B'*14
    three=b'original-COFF-object'
    second=first+len(member('RUNTIME.dll/',one));third=second+len(member('RUNTIME.dll/',two))
    index=struct.pack('>I3I',3,first,second,third)+b''.join(names)
    data=b'!<arch>\n'+member('/',index)+long_member+member('RUNTIME.dll/',one)+member('RUNTIME.dll/',two)+member('/0',three)
    return data,[(first,one),(second,two),(third,three)]


class WindowsPerlComponents(unittest.TestCase):
    def test_actual_map_rows_bind_public_symbol_section_and_exact_archive_label(self):
        text=''' Preferred load address is 0000000180000000
 0001:00000020       first                    0000000180001020 f   runtime:RUNTIME.dll
 0002:0000000000000030 second                  0000000180002030 i   runtime:RUNTIME.dll
 0001:00000040       guard                    0000000180001040 f i runtime:very-long-producer-path/startup.obj
 0001:00000000 00000020H .text CODE
'''
        rows=M.map_rows(text)
        self.assertEqual(rows,[{'symbol':'first','library':'runtime','member':'RUNTIME.dll','section':1,'offset':32,'address':0x180001020},{'symbol':'second','library':'runtime','member':'RUNTIME.dll','section':2,'offset':48,'address':0x180002030},{'symbol':'guard','library':'runtime','member':'very-long-producer-path/startup.obj','section':1,'offset':64,'address':0x180001040}])
        data,expected=recipe();result=M.resolve_members(data,rows)
        self.assertEqual([(r['archive_header_offset'],r['sha256'],r['size_bytes'])for r in result],[(offset,hashlib.sha256(body).hexdigest(),len(body))for offset,body in expected])
        self.assertEqual([r['member_kind']for r in result],['short-COFF-import','short-COFF-import','COFF-object'])
        self.assertEqual([r['map_symbols']for r in result],[['first'],['second'],['guard']])
        self.assertEqual(M.resolve_members(data,rows+rows),result)

    def test_ambiguous_missing_and_unindexed_import_member_are_not_guessed(self):
        data,_=recipe()
        for symbol,name in [('absent','RUNTIME.dll'),('first','missing.obj')]:
            with self.subTest(symbol=symbol),self.assertRaises(ValueError):M.resolve_members(data,[{'symbol':symbol,'member':name}])
        # Both symbols now point at the first duplicate; asking for the second
        # symbol must select that actual member, never merely ordinal matching.
        changed=data[:76]+struct.pack('>I',struct.unpack_from('>I',data,72)[0])+data[80:]
        selected=M.resolve_members(changed,[{'symbol':'second','member':'RUNTIME.dll'}])
        self.assertEqual(selected[0]['map_symbols'],['second'])
        self.assertEqual(selected[0]['sha256'],hashlib.sha256(recipe()[1][0][1]).hexdigest())

    def test_closed_coff_index_and_member_bounds_reject_damage(self):
        data,_=recipe()
        variants=[data[:7],data[:-1],data[:66]+b'xx'+data[68:],data[:68]+struct.pack('>I',2000001)+data[72:],data[:72]+struct.pack('>I',1)+data[76:],data.replace(b'/0              ',b'/999999         ',1),data.replace(b'first\x00',b'firstx',1)]
        for value in variants:
            with self.subTest(value=value[:80]),self.assertRaises(ValueError):M.archive_members(value)
        with self.assertRaises(ValueError):M.map_rows('no actual archive contribution')
        # COFF defines even alignment, not an LF-only padding value.
        padded=data[:103]+b'\x00'+data[104:]
        self.assertEqual(M.archive_members(padded),M.archive_members(data))

    def test_case_alias_binds_original_ordinary_archive_and_rejects_foreign_target(self):
        (ROOT/'.artifacts').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'.artifacts')as folder:
            root=Path(folder);library=root/'kernel32.Lib';library.write_bytes(b'original archive')
            # xwin adds case aliases on case-sensitive hosts. On a case-insensitive
            # filesystem (default macOS APFS) 'kernel32.lib' is the archive itself,
            # so the same same-directory alias rule is exercised under another name.
            alias=root/('kernel32.lib'if not(root/'KERNEL32.LIB').exists()else'kernel32-alias.lib');alias.symlink_to(library.name)
            with patch.object(M,'ROOT',root):
                actual,identity=M.library_identity(alias)
                self.assertEqual(actual,library);self.assertEqual(identity,{'path':alias.name,'resolved_path':'kernel32.Lib','sha256':hashlib.sha256(b'original archive').hexdigest(),'size_bytes':16,'alias_target':'kernel32.Lib'})
                foreign=root/'other';foreign.mkdir();(foreign/'foreign.lib').write_bytes(b'foreign');alias.unlink();alias.symlink_to(Path('other')/'foreign.lib')
                with self.assertRaises(ValueError):M.library_identity(alias)

if __name__=='__main__':unittest.main()
