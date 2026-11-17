import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('ud_architecture_availability_test', ROOT / 'scripts/quality/architecture-availability.py')
availability = importlib.util.module_from_spec(spec)
spec.loader.exec_module(availability)


def elf(machine):
    data = bytearray(64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, machine)
    return bytes(data)


def macho(machine):
    data = bytearray(64)
    data[:4] = b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I', data, 4, machine)
    return bytes(data)


class AvailabilityTests(unittest.TestCase):
    def test_machine_inventory_reads_executable_headers_without_running_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data, machine in [('a', elf(183), 'arm64'), ('b', elf(62), 'amd64'), ('c', macho(0x100000C), 'arm64'), ('d', macho(0x1000007), 'amd64')]:
                file = root / name
                file.write_bytes(data)
                self.assertEqual(availability.binary_architecture(file), machine)
            data = bytearray(128)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 80)
            data[80:84] = b'PE\0\0'
            struct.pack_into('<H', data, 84, 0xAA64)
            (root / 'pe').write_bytes(data)
            self.assertEqual(availability.binary_architecture(root / 'pe'), 'arm64')
            data[80:84] = b'BAD!'
            (root / 'pe').write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'PE signature'):
                availability.binary_architecture(root / 'pe')

    def test_lima_assets_require_both_machine_closures_and_exact_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'runtime').mkdir()
            assets = root / '.artifacts/lima-product'
            assets.mkdir(parents=True)
            lock = {'sources': {'lima': {'tag': 'v2.3.0', 'commit': '800a96b14e96b5d2ceb20ab2602147c1e79224ea'}, 'nerdctl': {'tag': 'v2.4.2', 'commit': '94bc03df5247ece1781c4b115a44ef3d4b1e0e65'}}, 'assets': []}
            for name, machine in [('lima-2.3.0-Darwin-arm64.tar.gz', 0x100000C), ('lima-2.3.0-Darwin-x86_64.tar.gz', 0x1000007), ('nerdctl-full-2.4.2-linux-arm64.tar.gz', 183), ('nerdctl-full-2.4.2-linux-amd64.tar.gz', 62)]:
                file = assets / name
                with tarfile.open(file, 'w:gz') as archive:
                    for command in ['limactl'] if name.startswith('lima-') else ['nerdctl', 'containerd', 'runc']:
                        data = macho(machine) if name.startswith('lima-') else elf(machine)
                        item = tarfile.TarInfo('bin/' + command)
                        item.size = len(data)
                        archive.addfile(item, io.BytesIO(data))
                lock['assets'].append({'name': name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size': file.stat().st_size})
            receipt = root / 'runtime/lima-inputs.lock.json'
            receipt.write_text(json.dumps(lock))
            rows = availability.lima_assets(root)
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(item['executed'] is False for item in rows))
            self.assertEqual([len(item['binaries']) for item in rows], [1, 1, 3, 3])
            (assets / lock['assets'][0]['name']).write_bytes(b'corruption')
            with self.assertRaisesRegex(ValueError, 'frozen receipt'):
                availability.lima_assets(root)


if __name__ == '__main__':
    unittest.main()
