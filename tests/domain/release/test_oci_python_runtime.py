import copy
import importlib.util
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]
# Load the sibling fixtures by path: the tests tree is not an importable package
# when unittest discovers this directory in isolation.
_sibling = importlib.util.spec_from_file_location('managed_python_source_binding_fixtures', Path(__file__).with_name('test_managed_python_source_binding.py'))
_fixtures = importlib.util.module_from_spec(_sibling); _sibling.loader.exec_module(_fixtures)
SourceParts, Recorder = _fixtures.SourceParts, _fixtures.Recorder
spec = importlib.util.spec_from_file_location('oci_python', ROOT / 'scripts/release/bind-oci-python-runtime.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class OciPythonProviderTests(unittest.TestCase):
    def fixture(self):
        instructions = 'RUN wget https://www.python.org/ftp/python/ ${PYTHON_SHA256}; sha256sum -c; ./configure --enable-shared --with-ensurepip; make install'
        original = {'os': 'linux', 'architecture': 'arm64', 'config': {'Env': ['PYTHON_VERSION=3.15.2', 'PYTHON_SHA256=' + 'a' * 64]}, 'rootfs': {'diff_ids': ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]}, 'history': [{'created_by': 'original base'}, {'created_by': instructions}]}
        manifest = {'layers': [{'digest': value} for value in original['rootfs']['diff_ids']]}; current = copy.deepcopy(original); current['rootfs']['diff_ids'].append('sha256:' + '3' * 64); current['history'].append({'created_by': 'COPY authored worker'}); worker = copy.deepcopy(manifest); worker['layers'].append({'digest': 'sha256:' + '3' * 64})
        return original, manifest, current, worker, {'python_version': '3.15.2'}

    def test_only_an_exact_provider_prefix_can_identify_the_cpython_build_layer(self):
        original, manifest, current, worker, lock = self.fixture(); result = binding.bind_provider(manifest, original, worker, current, lock, 'linux/arm64')
        self.assertEqual(result['version'], '3.15.2'); self.assertEqual(result['source_sha256'], 'a' * 64); self.assertEqual(result['layer_index'], 1)
        self.assertEqual(result['instructions'], original['history'][1]['created_by'])

    def test_extra_or_replaced_provider_layer_and_forged_history_or_cpu_fail(self):
        for change in (lambda original, current, worker: current['rootfs']['diff_ids'].__setitem__(1, 'sha256:' + 'f' * 64), lambda original, current, worker: worker['layers'].__setitem__(1, {'digest': 'sha256:' + 'f' * 64}), lambda original, current, worker: current['history'][1].update(created_by='forged CPython build'), lambda original, current, worker: original.update(architecture='amd64'), lambda original, current, worker: current['config']['Env'].append('PYTHON_VERSION=3.15.2')):
            original, manifest, current, worker, lock = self.fixture(); change(original, current, worker)
            with self.assertRaises(ValueError): binding.bind_provider(manifest, original, worker, current, lock, 'linux/arm64')

    def test_package_installations_and_unrelated_prefixes_are_never_cpython_source_claims(self):
        for name in ('usr/local/bin/python3.15', 'usr/local/lib/libpython3.15.so.1.0', 'usr/local/lib/python3.15/lib-dynload/_ssl.cpython-315-aarch64-linux-gnu.so', 'usr/local/lib/python3.15/config-3.15-aarch64-linux-gnu/Makefile'):
            self.assertTrue(binding.owned_path(name, '3.15.2'))
        for name in ('usr/local/lib/python3.15/site-packages/foreign.so', 'usr/local/lib/python3.15/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl', 'usr/local/lib/python3.15/foreign.exe', 'usr/local/lib/python3.14/foreign.so', 'usr/local/bin/foreign', 'opt/ud-agent/worker.py', 'usr/lib/x86_64-linux-gnu/libssl.so'):
            self.assertFalse(binding.owned_path(name, '3.15.2'))

    def test_flattened_runtime_preserves_cpython_bytes_and_aliases_with_metadata(self):
        runtime = 'usr/local/lib/python3.15/'
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            donor = binding.oci.Filesystem(folder / 'donor')
            actual = binding.oci.Filesystem(folder / 'actual')
            def add(filesystem, entries):
                image = io.BytesIO()
                with tarfile.open(fileobj=image, mode='w') as store:
                    for name, body, mode in entries:
                        entry = tarfile.TarInfo(name)
                        entry.mode = mode
                        if isinstance(body, str):
                            entry.type = tarfile.SYMTYPE
                            entry.linkname = body
                            store.addfile(entry)
                        else:
                            entry.size = len(body)
                            store.addfile(entry, io.BytesIO(body))
                image.seek(0)
                with tarfile.open(fileobj=image) as source:
                    filesystem.add_layer(source)
            members = [
                ('usr/local/bin/python3', 'python3.15', 0o777),
                ('usr/local/bin/python3.15', b'original interpreter', 0o755),
                (runtime + 'pathlib.py', b'original Python module', 0o644),
            ]
            add(donor, [*members, (runtime + 'ensurepip/_bundled/pip.whl', b'omitted wheel', 0o644)])
            add(actual, [*members, (runtime + 'site-packages/example.py', b'new wheel package', 0o644)])
            self.assertEqual(binding.compare_flattened_python(donor, actual, '3.15.2'), 3)
            for i, change in enumerate((
                ('usr/local/bin/python3', 'different', 0o777),
                ('usr/local/bin/python3.15', b'original interpreter', 0o644),
                (runtime + 'pathlib.py', b'unrelated module', 0o644),
                (runtime + 'extra.py', b'foreign module', 0o644),
            )):
                mutated = binding.oci.Filesystem(folder / ('mutated-' + str(i)))
                add(mutated, members)
                add(mutated, [change])
                with self.assertRaisesRegex(ValueError, 'flattened CPython'):
                    binding.compare_flattened_python(donor, mutated, '3.15.2')
            self.assertTrue(binding.installer_member(runtime + 'ensurepip/_bundled/pip.whl', '3.15.2'))
            self.assertTrue(binding.installer_member(runtime + 'site-packages/pip/_vendor/distlib/t64.exe', '3.15.2'))

    def test_cpython_notices_and_pip_template_replay_from_verified_source_parts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = io.BytesIO(); license_bytes = b'original Python license'
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                entry = tarfile.TarInfo('Python-3.15.2/LICENSE'); entry.size = len(license_bytes); archive.addfile(entry, io.BytesIO(license_bytes))
            python = output.getvalue(); py_sha = hashlib.sha256(python).hexdigest(); py_row = {'path':'sources/python.tar.gz', 'sha256':py_sha, 'size_bytes':len(python)}
            wheel = io.BytesIO(); module = b'class PipScriptMaker:\n    script_template = textwrap.dedent("import sys\\n")\n'
            with zipfile.ZipFile(wheel, 'w') as archive: archive.writestr('pip/_internal/operations/install/wheel.py', module)
            pip = wheel.getvalue(); pip_sha = hashlib.sha256(pip).hexdigest(); pip_row = {'path':'sources/pip.whl', 'sha256':pip_sha, 'size_bytes':len(pip)}
            parts = SourceParts({py_sha:python, pip_sha:pip}); recorder = Recorder()
            original, notices = binding.source_notices(root, py_row, '3.15.2', parts, recorder)
            template, identity = binding.pip_script_template(root, pip_row, parts, recorder)
            self.assertEqual(original, {'path':py_row['path'], 'sha256':py_sha, 'size_bytes':len(python)})
            self.assertEqual(notices[0]['sha256'], hashlib.sha256(license_bytes).hexdigest())
            self.assertEqual((template, identity['source_archive_sha256']), ('import sys\n', pip_sha))
            self.assertEqual({row[1] for row in recorder.rows}, {py_sha, pip_sha}); self.assertFalse((root/'sources').exists())
            with self.assertRaisesRegex(ValueError, 'missing or altered'): binding.source_notices(root, py_row, '3.15.2', SourceParts({py_sha:b'wrong'}), Recorder())


if __name__ == '__main__': unittest.main()
