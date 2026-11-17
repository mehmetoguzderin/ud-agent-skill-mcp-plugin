import importlib.util
from pathlib import Path
import subprocess
import hashlib
import json
import stat
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('private_git_runtime', ROOT / 'scripts/quality/prepare-git-runtime.py')
git = importlib.util.module_from_spec(spec); spec.loader.exec_module(git)
builder_spec = importlib.util.spec_from_file_location('git_runtime_sdk_consumer', ROOT / 'scripts/quality/prepare-mutation-runtime.py')
builder = importlib.util.module_from_spec(builder_spec); builder_spec.loader.exec_module(builder)


class GitFixtureRuntimeTests(unittest.TestCase):
    def test_required_original_fixture_profiles_cover_both_hash_and_ref_formats_without_ambient_config(self):
        calls = []
        def run(argv, **options):
            calls.append((argv, options))
            stdout = b'git version 2.55.0\ncpu: aarch64\n' if '--version' in argv else b'/usr/lib/git-core\n' if '--exec-path' in argv else b''
            return subprocess.CompletedProcess(argv, 0, stdout, b'')
        with patch.object(git.subprocess, 'run', side_effect=run): result = git.git_probe(Path('/original/git'))
        self.assertEqual(len(result), 6)
        profiles = {(next(arg for arg in argv if arg.startswith('--object-format=')), next(arg for arg in argv if arg.startswith('--ref-format='))) for argv, _ in calls if 'init' in argv}
        self.assertEqual(profiles, {('--object-format=sha1', '--ref-format=files'), ('--object-format=sha1', '--ref-format=reftable'), ('--object-format=sha256', '--ref-format=files'), ('--object-format=sha256', '--ref-format=reftable')})
        for _, options in calls:
            self.assertEqual(options['env']['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertEqual(options['env']['GIT_CONFIG_SYSTEM'], '/dev/null')
            self.assertEqual(options['env']['GIT_CONFIG_NOSYSTEM'], '1')
            self.assertNotIn('LD_LIBRARY_PATH', options['env'])

    def test_incompatible_reftable_or_non_arm_original_cannot_be_declared_ready(self):
        def incompatible(argv, **_):
            return subprocess.CompletedProcess(argv, 129 if '--ref-format=reftable' in argv else 0, b'git version 2.43.0\ncpu: aarch64\n', b'unsupported ref format' if '--ref-format=reftable' in argv else b'')
        with patch.object(git.subprocess, 'run', side_effect=incompatible), self.assertRaisesRegex(ValueError, 'required fixture features'):
            git.git_probe(Path('/original/git'))
        with patch.object(git.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'git version 2.55.0\ncpu: x86_64\n', b'')), self.assertRaisesRegex(ValueError, 'native ARM'):
            git.git_probe(Path('/original/git'))

    def test_launcher_constrains_only_git_paths_and_loader_without_global_library_search(self):
        body = git.launcher('programs/original-hash', 'bin/git', 'loader/ld-linux-aarch64.so.1').decode()
        self.assertIn('export GIT_EXEC_PATH=/opt/mutation/git/libexec\n', body)
        self.assertIn('export GIT_TEMPLATE_DIR=/opt/mutation/git/share/templates\n', body)
        self.assertIn('export GIT_CONFIG_GLOBAL=/dev/null\n', body)
        self.assertIn('exec /opt/mutation/git/loader/ld-linux-aarch64.so.1 --inhibit-cache --library-path /opt/mutation/git/lib --argv0 /opt/mutation/git/bin/git /opt/mutation/git/programs/original-hash "$@"', body)
        self.assertNotIn('LD_LIBRARY_PATH', body)

    def pack(self, root):
        source = root / 'source'; source.mkdir()
        native = bytearray(64); native[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', native, 18, 183)
        files = []
        for name, body in [('bin/git', b'#!/bin/sh\nexec /private/fixed-loader "$@"\n'), ('programs/original', bytes(native)), ('loader/original', bytes(native)), ('lib/fixture', bytes(native)), ('licenses/copyright', b'Original provider copyright and terms\n')]:
            file = source / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body); file.chmod(0o555 if not name.startswith('licenses/') else 0o444)
            files.append({'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'mode': stat.S_IMODE(file.stat().st_mode)})
        provider = json.loads((ROOT / 'quality/act.lock.json').read_bytes())['linux_runner']['nonroot_image']
        receipt = {'schema_version': 1, 'qualification': 'private-native-arm-Git-fixture-tool-not-product-runtime', 'platform': 'linux/arm64', 'provider': provider, 'generator_sha256': builder.digest(ROOT / 'scripts/quality/prepare-git-runtime.py'), 'elf_generator_sha256': builder.digest(ROOT / 'workers/ud/src/ud_agent/elf_runtime.py'), 'probe': [{'status': 0}] * 6, 'notices': [files[-1]], 'packages': [{'package': 'fixture-original'}], 'executable': 'bin/git', 'loader': 'loader/original', 'libraries': {'fixture': 'original'}, 'programs': {'bin/git': 'programs/original'}, 'version': '2.55.0', 'files': files}
        file = root / 'receipt.json'; file.write_text(json.dumps(receipt)); return source, file

    def test_sdk_copy_checks_the_full_original_pack_and_preserves_private_immutable_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, receipt = self.pack(root)
            chmod = Path.chmod
            modes = []
            def retain_mode(path, mode, **options):
                modes.append((path, mode)); return chmod(path, mode, **options)
            with patch.object(Path, 'chmod', retain_mode):
                admitted = builder.copy_git(source, receipt, root / 'copied')
            self.assertEqual(admitted['files'], 5)
            self.assertEqual(admitted['sha256'], builder.digest(receipt))
            self.assertEqual((root / 'copied/licenses/copyright').read_bytes(), b'Original provider copyright and terms\n')
            target = root / 'copied/programs/original'
            self.assertIn((target, 0o444 if os.name == 'nt' else 0o555), modes)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o444 if os.name == 'nt' else 0o555)

    def test_sdk_copy_rejects_changed_unlisted_writable_linked_and_foreign_native_inputs(self):
        for mode in ('changed', 'unlisted', 'writable', 'link', 'foreign', 'producer', 'missing-library'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source, receipt = self.pack(root); value = json.loads(receipt.read_bytes())
                if mode == 'unlisted': (source / 'foreign').write_bytes(b'unlisted input')
                elif mode == 'writable': (source / 'bin/git').chmod(0o755)
                elif mode == 'link': (source / 'bin/git').chmod(0o755); (source / 'bin/git').unlink(); (source / 'bin/git').symlink_to(source / 'programs/original')
                elif mode == 'producer': value['generator_sha256'] = '0' * 64; receipt.write_text(json.dumps(value))
                elif mode == 'missing-library':
                    (source / 'lib/fixture').chmod(0o755); (source / 'lib/fixture').unlink(); value['files'] = [row for row in value['files'] if row['path'] != 'lib/fixture']; receipt.write_text(json.dumps(value))
                else:
                    file = source / 'programs/original'; file.chmod(0o755); body = bytearray(file.read_bytes())
                    if mode == 'foreign': struct.pack_into('<H', body, 18, 62)
                    else: body[-1] = 1
                    file.write_bytes(body); file.chmod(0o555)
                    if mode == 'foreign':
                        next(row for row in value['files'] if row['path'] == 'programs/original')['sha256'] = hashlib.sha256(body).hexdigest(); receipt.write_text(json.dumps(value))
                with self.assertRaises(ValueError): builder.copy_git(source, receipt, root / 'rejected')


if __name__ == '__main__': unittest.main()
