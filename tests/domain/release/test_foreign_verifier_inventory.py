import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('foreign_verifier', ROOT / 'scripts/release/prepare-foreign-verifier-runtime.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class ForeignVerifierInventoryTests(unittest.TestCase):
    def image(self, terminated=True):
        body = bytearray(640)
        body[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', body, 18, 62)
        struct.pack_into('<Q', body, 32, 64)
        struct.pack_into('<HH', body, 54, 56, 3)
        # The dynamic string table crosses the PT_LOAD boundary. File offsets
        # deliberately differ from virtual addresses and between segments.
        for i, row in enumerate(((1, 4, 256, 4096, 0, 8, 8, 1), (1, 4, 300, 4104, 0, 16, 16, 1), (2, 4, 400, 8192, 0, 64, 64, 1))):
            struct.pack_into('<IIQQQQQQ', body, 64 + i * 56, *row)
        strings = b'xxlibfixture.so\0'
        body[262:264] = strings[:2]; body[300:300 + len(strings) - 2] = strings[2:]
        for i, row in enumerate(((5, 4102), (10, len(strings)), (1, 2), (0 if terminated else 21, 0))):
            struct.pack_into('<qQ', body, 400 + 16 * i, *row)
        return bytes(body)

    def test_multisegment_dynamic_strings_use_actual_virtual_mapping(self):
        result = module.elf.inspect(self.image())
        self.assertEqual(result, {'machine': 62, 'interpreter': None, 'needed': ['libfixture.so'], 'search_paths': []})
        self.assertEqual(module.elf.virtual_bytes(b'abcdefghij', [(100, 0, 3), (103, 7, 3)], 101, 4), b'bchi')

    def test_virtual_reads_reject_holes_conflicting_overlap_zero_fill_and_overflow(self):
        for loads, address, size in (([(100, 0, 2), (103, 3, 2)], 100, 5), ([(100, 0, 5), (102, 7, 3)], 100, 5), ([(100, 0, 2)], 100, 3), ([(100, 9, 2)], 100, 2), ([], (1 << 64) - 1, 2)):
            with self.subTest(loads=loads), self.assertRaises(ValueError):
                module.elf.virtual_bytes(b'0123456789', loads, address, size)
        self.assertEqual(module.elf.virtual_bytes(b'abcde', [(100, 0, 5), (102, 2, 3)], 100, 5), b'abcde')

    def test_dynamic_table_requires_terminator_and_file_backed_segments(self):
        with self.assertRaisesRegex(ValueError, 'unavailable'): module.elf.inspect(self.image(False))
        invalid = bytearray(self.image()); struct.pack_into('<Q', invalid, 64 + 40, 1)
        with self.assertRaisesRegex(ValueError, 'segment bounds'): module.elf.inspect(invalid)

    def test_disabled_packaging_pe_classification_reads_all_three_cpus(self):
        for cpu, architecture, magic in ((0x14c, 'x86', 0x10b), (0x8664, 'x64', 0x20b), (0xaa64, 'arm64', 0x20b)):
            body = bytearray(128); body[:2] = b'MZ'; struct.pack_into('<I', body, 60, 64); body[64:68] = b'PE\0\0'; struct.pack_into('<H', body, 68, cpu); struct.pack_into('<H', body, 88, magic)
            self.assertEqual(module.disabled_pe_architecture(body), architecture)
            struct.pack_into('<H', body, 88, 0)
            with self.assertRaisesRegex(ValueError, 'CPU'): module.disabled_pe_architecture(body)
        with self.assertRaisesRegex(ValueError, 'header'): module.disabled_pe_architecture(b'MZ' + bytes(62))

    def test_origin_resolution_never_expands_partial_tokens_or_ambient_paths(self):
        self.assertEqual(module.origin_path('lib/python3.15/lib-dynload/module.so', '${ORIGIN}/../../libx.so'), 'lib/libx.so')
        self.assertEqual(module.origin_path('bin/python', '$ORIGIN/../lib'), 'lib')
        for path in ('', '/tools/deps/lib', 'relative', '$ORIGINelse/lib', '$ORIGIN/../../lib', '${ORIGIN}/$LIB', '$ORIGIN\\evil'):
            with self.subTest(path=path): self.assertIsNone(module.origin_path('bin/python', path))

    def test_unused_foreign_dll_exclusion_is_hash_bound_and_rejects_a_real_import(self):
        native = {'python.exe': {'architectures': ['win32-arm64'], 'imports': ['vcruntime140.dll']}, 'vcruntime140_1.dll': {'architectures': ['win32-x64'], 'imports': []}}
        files = {'vcruntime140_1.dll': {'sha256': 'a' * 64, 'size': 123}}
        result = module.optional_native_exclusions('win32-arm64', native, files)
        self.assertEqual([(row['path'], row['sha256'], row['size']) for row in result], [('vcruntime140_1.dll', 'a' * 64, 123)])
        native['python.exe']['imports'].append('VCRUNTIME140_1.DLL')
        with self.assertRaisesRegex(ValueError, 'required by retained native'): module.optional_native_exclusions('win32-arm64', native, files)

    def test_gui_exclusion_requires_complete_named_set_and_no_retained_consumer(self):
        names = ['lib/libtcl9.0.so', 'lib/libtcl9tk9.0.so', 'lib/itcl4.3.8/libtcl9itcl4.3.8.so', 'lib/thread3.0.6/libtcl9thread3.0.6.so', 'lib/python3.15/lib-dynload/_tkinter.cpython-315-aarch64-linux-gnu.so']
        native = {name: {'needed': ['libtcl9.0.so']} for name in names}
        files = {name: {'sha256': 'b' * 64, 'size': 1} for name in names}
        self.assertEqual(len(module.optional_native_exclusions('linux-arm64', native, files)), 5)
        native['bin/python3.15'] = {'needed': ['libtcl9.0.so']}
        with self.assertRaisesRegex(ValueError, 'required by retained native'): module.optional_native_exclusions('linux-arm64', native, files)
        del native['bin/python3.15']; del native[names[-1]]
        with self.assertRaisesRegex(ValueError, 'incomplete'): module.optional_native_exclusions('linux-arm64', native, files)


if __name__ == '__main__': unittest.main()
