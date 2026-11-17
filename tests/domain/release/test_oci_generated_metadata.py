import base64
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/release' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


os_binding = load('generated_os', 'bind-oci-package-files.py')
python_binding = load('generated_python', 'bind-oci-python-runtime.py')


def add(filesystem, rows):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name, body in rows:
            entry = tarfile.TarInfo(name); entry.size = len(body); archive.addfile(entry, io.BytesIO(body))
    data.seek(0)
    with tarfile.open(fileobj=data, mode='r:') as archive: filesystem.add_layer(archive)


class GeneratedOsMetadataTests(unittest.TestCase):
    def test_recognized_font_and_glib_cache_require_the_actual_installed_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            font = b'\x04\xfc\x02\xfc\x09\0\0\0' + struct.pack('<Q', 24) + bytes(8)
            name = 'var/cache/fontconfig/' + 'a' * 32 + '-le64.cache-9'
            add(fs, [(name, font), ('usr/share/glib-2.0/schemas/gschemas.compiled', b'GVariant' + bytes(24)), ('var/cache/fontconfig/unknown.so', b'\x7fELFunknown')])
            packages = [{'name': name, 'version': '1', 'architecture': 'arm64'} for name in ('fontconfig', 'libglib2.0-0t64')]
            self.assertEqual(os_binding.generated_ownership(fs, packages, {}), {})
            owners = {'usr/bin/fc-cache': {('fontconfig', '1', 'arm64')}, 'usr/lib/aarch64-linux-gnu/glib-2.0/glib-compile-schemas': {('libglib2.0-0t64', '1', 'arm64')}}
            result = os_binding.generated_ownership(fs, packages, owners)
            self.assertEqual(set(result), {name, 'usr/share/glib-2.0/schemas/gschemas.compiled'})
            self.assertEqual(result[name]['component'], ('fontconfig', '1', 'arm64'))
            add(fs, [(name, font + b'altered'), ('usr/share/glib-2.0/schemas/gschemas.compiled', b'\x7fELFfake')])
            self.assertEqual(os_binding.generated_ownership(fs, packages, owners), {})

    def test_account_and_pam_state_is_finite_and_bound_to_the_actual_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('etc/group', b'root:x:0:\n'), ('var/lib/pam/seen', b'unix\n'), ('var/lib/pam/unrelated', b'arbitrary'), ('etc/machine-id', b'a' * 32 + b'\n')])
            packages = [{'name': name, 'version': '2', 'architecture': 'arm64'} for name in ('base-passwd', 'libpam-runtime', 'dbus-bin')]
            owners = {path: {(name, '2', 'arm64')} for path, name in [('usr/sbin/update-passwd', 'base-passwd'), ('usr/sbin/pam-auth-update', 'libpam-runtime'), ('usr/bin/dbus-uuidgen', 'dbus-bin')]}
            self.assertEqual(set(os_binding.generated_ownership(fs, packages, owners)), {'etc/group', 'var/lib/pam/seen', 'etc/machine-id'})
            add(fs, [('etc/machine-id', b'not a machine identity\n'), ('var/lib/pam/seen', b'MZunrelated executable')])
            self.assertEqual(set(os_binding.generated_ownership(fs, packages, owners)), {'etc/group'})

    def test_control_templates_and_colon_architecture_members_keep_exact_package_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('var/lib/dpkg/info/libc6:arm64.list', b'/usr/lib/actual\n')])
            result = os_binding.ownership(fs, [{'name': 'libc6', 'version': '2.41-12', 'architecture': 'arm64'}])
            self.assertEqual(result['var/lib/dpkg/info/libc6:arm64.config'], {('libc6', '2.41-12', 'arm64')})
            self.assertEqual(result['var/lib/dpkg/info/libc6:arm64.templates'], {('libc6', '2.41-12', 'arm64')})
            self.assertNotIn('var/lib/dpkg/info/libc6:amd64.templates', result)

    def test_new_mime_categories_still_require_the_real_postinstall_recipe(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('usr/share/mime/chemical/example.xml', b'<mime-type/>'), ('usr/share/mime/globs', b'text/plain:*.txt\n'), ('usr/share/mime/globs2', b'50:text/plain:*.txt\n'), ('var/lib/dpkg/info/shared-mime-info.postinst', b'update-mime-database /usr/share/mime')])
            packages = [{'name': 'shared-mime-info', 'version': '2.4-5', 'architecture': 'arm64'}]
            self.assertEqual(set(os_binding.generated_ownership(fs, packages, {})), {'usr/share/mime/chemical/example.xml', 'usr/share/mime/globs', 'usr/share/mime/globs2'})
            add(fs, [('var/lib/dpkg/info/shared-mime-info.postinst', b'not a generator')])
            self.assertEqual(os_binding.generated_ownership(fs, packages, {}), {})

    def test_mime_names_cannot_attribute_foreign_binaries_or_invalid_cache_formats(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('usr/share/mime/application/foreign.xml', b'\x7fELFforeign'), ('usr/share/mime/globs', b'MZforeign'), ('usr/share/mime/mime.cache', b'\x7fELFwrong-cache'), ('usr/share/mime/magic', b'MIME-Magic\0\n[50:text/plain]\n'), ('var/lib/dpkg/info/shared-mime-info.postinst', b'update-mime-database /usr/share/mime')])
            result = os_binding.generated_ownership(fs, [{'name': 'shared-mime-info', 'version': '2.4-5', 'architecture': 'arm64'}], {})
            self.assertEqual(set(result), {'usr/share/mime/magic'})


class GeneratedPythonMetadataTests(unittest.TestCase):
    def fixture(self, directory):
        fs = os_binding.oci.Filesystem(directory / 'opaque'); site = 'usr/local/lib/python3.15/site-packages'; stem = 'colorama-0.4.6.dist-info'
        body = b'original readable module\n'; installer = b'pip\n'
        rows = []
        for name, data in [('colorama/__init__.py', body), (stem + '/INSTALLER', installer)]:
            rows.append([name, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='), str(len(data))])
        rows.append([stem + '/RECORD', '', '']); output = io.StringIO(); csv.writer(output, lineterminator='\n').writerows(rows)
        add(fs, [(site + '/colorama/__init__.py', body), (site + '/' + stem + '/INSTALLER', installer), (site + '/' + stem + '/RECORD', output.getvalue().encode())])
        return fs, site, stem, output.getvalue().encode()

    def test_receipts_verify_actual_bytes_and_do_not_authorize_the_recorded_program(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs, site, stem, record = self.fixture(Path(temporary))
            result = python_binding.installed_metadata(fs, {'colorama': '0.4.6'}, '3.15.2', '')
            self.assertEqual([row['image_path'] for row in result], [site + '/' + stem + '/RECORD', site + '/' + stem + '/INSTALLER'])
            self.assertTrue(all(row['package'] == {'name': 'colorama', 'version': '0.4.6'} for row in result))
            add(fs, [(site + '/colorama/__init__.py', b'altered module')])
            with self.assertRaisesRegex(ValueError, 'referenced bytes'): python_binding.installed_metadata(fs, {'colorama': '0.4.6'}, '3.15.2', '')

    def test_duplicate_escape_and_missing_self_records_are_rejected(self):
        for change in (lambda body: body + body.splitlines(keepends=True)[0], lambda body: body.replace(b'colorama/__init__.py', b'../../../../../../outside'), lambda body: b'\n'.join(line for line in body.splitlines() if b'/RECORD,' not in line) + b'\n'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fs, site, stem, record = self.fixture(Path(temporary)); add(fs, [(site + '/' + stem + '/RECORD', change(record))])
                with self.assertRaises(ValueError): python_binding.installed_metadata(fs, {'colorama': '0.4.6'}, '3.15.2', '')

    def test_recorded_symlink_cannot_resolve_outside_the_python_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs, site, stem, record = self.fixture(Path(temporary)); add(fs, [('outside.py', b'original readable module\n')])
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                row = tarfile.TarInfo(site + '/colorama/__init__.py'); row.type = tarfile.SYMTYPE; row.linkname = '/outside.py'; archive.addfile(row)
            data.seek(0)
            with tarfile.open(fileobj=data, mode='r:') as archive: fs.add_layer(archive)
            with self.assertRaisesRegex(ValueError, 'resolves outside'): python_binding.installed_metadata(fs, {'colorama': '0.4.6'}, '3.15.2', '')

    def test_readable_provider_configs_are_not_an_arbitrary_path_or_binary_exception(self):
        self.assertTrue(python_binding.provider_source_form('etc/hostname', b'debuerreotype\n', 0))
        self.assertTrue(python_binding.provider_source_form('etc/networks', b'default 0.0.0.0\n', 1))
        self.assertFalse(python_binding.provider_source_form('etc/networks', b'default 0.0.0.0\n', 0))
        for path, body, index in [('etc/hostname', b'debuerreotype\n', 1), ('etc/foreign', b'plain text', 0), ('etc/hostname', b'MZbinary', 0), ('etc/hostname', b'\xff', 0)]:
            self.assertFalse(python_binding.provider_source_form(path, body, index))

    def test_entry_point_requires_the_original_literal_template(self):
        template = "import sys\nfrom %(module)s import %(import_name)s\nif __name__ == '__main__':\n    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n    sys.exit(%(func)s())\n"
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('usr/local/bin/udapy', b"#!/usr/local/bin/python\nimport sys\nfrom udapi.cli import main\nif __name__ == '__main__':\n    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n    sys.exit(main())\n")])
            result = python_binding.installed_metadata(fs, {'udapi': '0.5.2'}, '3.15.2', template)
            self.assertEqual([row['image_path'] for row in result], ['usr/local/bin/udapy'])
            add(fs, [('usr/local/bin/udapy', b'#!/usr/local/bin/python\nraise RuntimeError("foreign")\n')])
            with self.assertRaisesRegex(ValueError, 'original pip template'): python_binding.installed_metadata(fs, {'udapi': '0.5.2'}, '3.15.2', template)

    def test_only_the_authenticated_provider_bytecode_removal_can_explain_stale_pip_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque'); site = 'usr/local/lib/python3.15/site-packages'
            record = ('pip/__pycache__/__init__.cpython-315.pyc,sha256=' + 'a' * 43 + ',120\npip-26.2.2.dist-info/RECORD,,\n').encode()
            add(fs, [(site + '/pip/__init__.py', b'# original source remains\n'), (site + '/pip-26.2.2.dist-info/RECORD', record)])
            with self.assertRaises(ValueError): python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '')
            result = python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_bytecode=True)
            self.assertEqual(result[0]['absent_provider_removed_bytecode'], [{'path': site + '/pip/__pycache__/__init__.cpython-315.pyc', 'recorded_hash': 'sha256=' + 'a' * 43, 'recorded_size_bytes': 120}])
            add(fs, [(site + '/pip-26.2.2.dist-info/RECORD', record.replace(('sha256=' + 'a' * 43 + ',120').encode(), b','))])
            result = python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_bytecode=True)
            self.assertEqual(result[0]['absent_provider_removed_bytecode'][0]['recorded_hash'], None)
            self.assertEqual(result[0]['absent_provider_removed_bytecode'][0]['recorded_size_bytes'], None)
            add(fs, [(site + '/pip-26.2.2.dist-info/RECORD', record.replace(b'.cpython-315.pyc', b'.cpython-314.pyc'))])
            with self.assertRaises(ValueError): python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_bytecode=True)

    def test_pip_generator_is_read_from_verified_original_literal_source_without_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'pip.whl'
            def source(body):
                with zipfile.ZipFile(file, 'w') as archive: archive.writestr('pip/_internal/operations/install/wheel.py', body)
                return {'path': file.name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size_bytes': file.stat().st_size}
            original = source('raise RuntimeError("must not import vendor")\nclass PipScriptMaker:\n    script_template = textwrap.dedent("import sys\\n")\n')
            template, identity = python_binding.pip_script_template(root, original)
            self.assertEqual(template, 'import sys\n'); self.assertEqual(identity['source_archive_sha256'], original['sha256'])
            changed = source('class PipScriptMaker:\n    script_template = arbitrary_code()\n')
            with self.assertRaisesRegex(ValueError, 'not literal'): python_binding.pip_script_template(root, changed)
            with self.assertRaises(ValueError): python_binding.pip_script_template(root, original)

    def test_removed_provider_tests_need_original_wheel_hashes_and_never_hide_live_path_escapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = os_binding.oci.Filesystem(Path(temporary) / 'opaque'); site = 'usr/local/lib/python3.15/site-packages'; name = 'pip/_vendor/certifi/tests/__init__.py'; body = b'# original test source\n'
            original = {'member_path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            fingerprint = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip('=')
            record = (name + ',sha256=' + fingerprint + ',' + str(len(body)) + '\npip-26.2.2.dist-info/RECORD,,\n').encode(); add(fs, [(site + '/pip-26.2.2.dist-info/RECORD', record)])
            with self.assertRaises(ValueError): python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '')
            result = python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_tests=[original])
            self.assertEqual(result[0]['absent_provider_removed_test_files'], [{'path': site + '/' + name, 'original_wheel_member': original}])
            with self.assertRaisesRegex(ValueError, 'exact original wheel'): python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_tests=[{**original, 'sha256': 'a' * 64}])
            add(fs, [('outside.py', body)]); data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                row = tarfile.TarInfo(site + '/' + name); row.type = tarfile.SYMTYPE; row.linkname = '/outside.py'; archive.addfile(row)
            data.seek(0)
            with tarfile.open(fileobj=data, mode='r:') as archive: fs.add_layer(archive)
            with self.assertRaisesRegex(ValueError, 'resolves outside'): python_binding.installed_metadata(fs, {'pip': '26.2.2'}, '3.15.2', '', removed_pip_tests=[original])


if __name__ == '__main__': unittest.main()
