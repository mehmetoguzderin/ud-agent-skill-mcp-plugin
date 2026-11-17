import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/runtime'))
spec = importlib.util.spec_from_file_location('verify_wsl_sdk', ROOT / 'scripts/runtime/verify-wsl-sdk.py')
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)
fixture_spec = importlib.util.spec_from_file_location('wsl_pe_fixture', Path(__file__).with_name('test_windows_pe.py'))
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


class WslSdkIdentity(unittest.TestCase):
    def test_checks_both_native_machines_exact_opaque_abi_and_required_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native = root / 'packages/launcher/src/wsl_session.rs'
            native.parent.mkdir(parents=True)
            native.write_text('#[repr(C, align(8))]\nstruct Settings([u8; 72]);\n')
            reader = root / 'llvm-readobj'
            reader.write_bytes(b'locked tool')
            for architecture, machine in [('arm64', 0xAA64), ('x64', 0x8664)]:
                target = root / f'runtime/providers/wslc/win32-{architecture}'
                (target / 'bin').mkdir(parents=True)
                (target / 'include').mkdir()
                (target / 'bin/wslcsdk.dll').write_bytes(fixtures.binary(machine=machine))
                (target / 'include/wslcsdk.h').write_bytes(b'#define WSLC_SESSION_OPTIONS_SIZE 72\r\n#define WSLC_SESSION_OPTIONS_ALIGNMENT 8\r\n')
            exported = sdk.REQUIRED + ['UnrelatedUpstreamExport']
            def execute(arguments, **options):
                self.assertEqual(arguments[:2], [str(reader), '--coff-exports'])
                self.assertEqual(Path(arguments[2]).parts[-2:], ('bin', 'wslcsdk.dll'))
                self.assertEqual(options, dict(check=True, capture_output=True, text=True, timeout=30))
                return SimpleNamespace(stdout='\n'.join('  Name: ' + name for name in exported))
            with mock.patch.object(sdk, 'ROOT', root), mock.patch.object(sdk.subprocess, 'run', side_effect=execute):
                result = sdk.verify(root, reader)
                self.assertEqual([row['architecture'] for row in result['rows']], ['arm64', 'x64'])
                self.assertTrue(all(row['session_settings_size'] == 72 and row['session_settings_alignment'] == 8 and row['status'] == 'passed_static' and row['native_execution'] == 'pending_native' for row in result['rows']))
                exported.remove('WslcCreateSession')
                with self.assertRaisesRegex(ValueError, 'exports'):
                    sdk.verify(root, reader)
                exported.append('WslcCreateSession')
                exported.append('WslcCreateSession')
                with self.assertRaisesRegex(ValueError, 'exports'):
                    sdk.verify(root, reader)
                exported.pop()
                header = root / 'runtime/providers/wslc/win32-arm64/include/wslcsdk.h'
                for body in [b'#define WSLC_SESSION_OPTIONS_SIZE 80\n#define WSLC_SESSION_OPTIONS_ALIGNMENT 8', b'#define WSLC_SESSION_OPTIONS_SIZE 72\n#define WSLC_SESSION_OPTIONS_ALIGNMENT 4', b'absent declarations']:
                    header.write_bytes(body)
                    with self.assertRaisesRegex(ValueError, 'ABI'):
                        sdk.verify(root, reader)
                native.write_text('struct SettingsWithoutAbi;')
                with self.assertRaisesRegex(ValueError, 'declaration'):
                    sdk.verify(root, reader)


if __name__ == '__main__':
    unittest.main()
