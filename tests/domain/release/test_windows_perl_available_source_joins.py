import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('windows_perl_available_joins', ROOT / 'scripts/release/bind-private-perl-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class WindowsPerlAvailableJoinTests(unittest.TestCase):
    def test_original_windows_provider_notices_join_the_exact_copied_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'source.tar'; expected = {}
            with tarfile.open(archive, 'w') as tar:
                for name, body in [('Artistic', b'Original Artistic terms'), ('Copying', b'Original Perl GPL terms')]:
                    entry = tarfile.TarInfo('perl-5.44.0/' + name); entry.size = len(body); tar.addfile(entry, io.BytesIO(body))
                    path = 'share/licenses/perl-provider/' + name
                    expected[path] = {'path': path, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            identity = ('perl', 'perl-5.44.0-windows-provider-source', '5.44.0', binding.sha(archive))
            joined = binding.original_notice_joins(archive, identity, expected)
            self.assertEqual({row['source_member'] for row in joined}, {'perl-5.44.0/Artistic', 'perl-5.44.0/Copying'})
            self.assertEqual({row['distributed']['path'] for row in joined}, {'share/licenses/perl-provider/Artistic', 'share/licenses/perl-provider/Copying'})
            expected['share/licenses/perl-provider/Copying']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'copied notice differs'): binding.original_notice_joins(archive, identity, expected)

    def test_windows_source_identity_is_exact_and_vendor_runtime_dlls_gain_no_source_waiver(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'runtime').mkdir()
            modules = {'releases': {'Fixture-1.0': {'name': 'Fixture-1.0', 'version': '1.0', 'sha256': '1' * 64}}}
            for name, value in [('native-perl-source.lock.json', {}), ('native-perl-modules.lock.json', modules), ('perl-deps.lock.json', {'interset': {'commit': 'a' * 40, 'archive_sha256': '2' * 64}})]: (root / 'runtime' / name).write_text(json.dumps(value))
            definition = {'platform': 'win32/arm64', 'upstream_source_sha256': 'sha256:505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91', 'modules_sha256': 'sha256:' + binding.sha(root / 'runtime/native-perl-modules.lock.json'), 'deferred_runtime': {'recipe': 'vendor-runtime.json'}, 'files': [{'path': 'bin/perl.exe'}]}
            self.assertEqual(binding.source_requirements(root, definition), [('perl', 'perl-5.44.0-windows-provider-source', '5.44.0', '505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91'), ('cpan', 'Fixture-1.0', '1.0', '1' * 64), ('ud', 'dan-zeman/interset', 'a' * 40, '2' * 64)])
            for field, value in [('upstream_source_sha256', 'sha256:' + '3' * 64), ('modules_sha256', 'sha256:' + '4' * 64), ('files', [{'path': 'bin/vcruntime140.dll'}])]:
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source recipe or vendor payload exclusion'): binding.source_requirements(root, {**definition, field: value})


if __name__ == '__main__': unittest.main()
