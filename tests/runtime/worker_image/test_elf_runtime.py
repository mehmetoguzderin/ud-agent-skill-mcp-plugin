import struct
import unittest
from ud_agent.elf_runtime import inspect,with_interpreter


def executable(interpreter='/source/ld.so',needed=None):
    data=bytearray(1024);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',data,18,183);struct.pack_into('<Q',data,32,64);struct.pack_into('<HH',data,54,56,3)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x1000,0,1024,1024,4096)
    struct.pack_into('<IIQQQQQQ',data,120,2,6,256,0x1100,0,64,64,8)
    strings=(needed or 'unused').encode()+b'\0';data[512:512+len(strings)]=strings
    entries=[(5,0x1200),(10,len(strings)),*(([(1,0)]if needed else[])),(0,0)]
    for index,pair in enumerate(entries):struct.pack_into('<qQ',data,256+index*16,*pair)
    if interpreter is not None:
        raw=interpreter.encode()+b'\0';data[800:800+len(raw)]=raw;struct.pack_into('<IIQQQQQQ',data,176,3,4,800,0x1320,0,len(raw),len(raw),1)
    else:struct.pack_into('<IIQQQQQQ',data,176,0,0,0,0,0,0,0,0)
    return bytes(data)


class ElfRuntimeTests(unittest.TestCase):
    def test_interpreter_append_changes_only_program_header_location_lengths_and_appended_path(self):
        original=executable(needed='libc.so.6');target='/private/product/elf/ld-linux-aarch64.so.1';actual=with_interpreter(original,target)
        self.assertEqual(inspect(actual),{'machine':183,'interpreter':target,'needed':['libc.so.6'],'search_paths':[]})
        self.assertEqual(actual[1024:],target.encode()+b'\0')
        self.assertEqual(struct.unpack_from('<Q',actual,184)[0],1024)
        self.assertEqual(struct.unpack_from('<QQ',actual,208),(len(target)+1,len(target)+1))
        for left,right in [(0,184),(192,208),(224,1024)]:self.assertEqual(actual[left:right],original[left:right])

    def test_invalid_or_unbounded_interpreters_and_static_elf_are_rejected(self):
        for path in ['relative','/a/../b','/nul\0path','/'+('x'*4096),None]:
            with self.assertRaises(ValueError):with_interpreter(executable(),path)
        with self.assertRaises(ValueError):with_interpreter(executable(None),'/private/ld.so')
        for data in [b'',b'not ELF',executable()[:100]]:
            with self.assertRaises(ValueError):with_interpreter(data,'/private/ld.so')


if __name__=='__main__':unittest.main()
