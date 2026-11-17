import copy
import importlib.util
from pathlib import Path, PurePosixPath
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_rust_test_adapter', ROOT / 'scripts/quality/rust-test-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RustTestRuntimeTests(unittest.TestCase):
    def environment(self):
        root = '/state/rust-work/0'
        return {'UD_MUTATION_RUST_SOURCE_ROOT': root, 'CARGO_PKG_NAME': 'ud-agent-launcher', 'CARGO_MANIFEST_DIR': root + '/packages/launcher', 'CARGO_BIN_EXE_ud-agent': root + '/target/aarch64-unknown-linux-gnu/debug/ud-agent', 'CARGO_BIN_EXE_ud-agent-guard': root + '/target/aarch64-unknown-linux-gnu/debug/ud-agent-guard', 'PATH': '/trusted'}

    def receipt(self):
        name = 'target/aarch64-unknown-linux-gnu/debug/deps/fs_guard-abc'
        return {'schema_version': 1, 'source_root': '/state/rust-candidates/variant', 'phase_id': 'a' * 32, 'cwd': 'packages/launcher', 'files': [{'path': name, 'sha256': 'b' * 64, 'size': 9, 'mode': 0o555}], 'artifacts': [{'source_path': '/state/rust-work/0/' + name, 'path': name, 'sha256': 'b' * 64, 'size': 9, 'kind': 'test'}]}

    def test_only_test_compilation_relocates_exact_same_variant_binary_constants(self):
        original = self.environment()
        result = runtime.compiler_environment(original, ['--test', 'tests/fs_guard.rs'])
        self.assertEqual(result, {**original, 'CARGO_MANIFEST_DIR': '.', 'CARGO_BIN_EXE_ud-agent': '../../target/aarch64-unknown-linux-gnu/debug/ud-agent', 'CARGO_BIN_EXE_ud-agent-guard': '../../target/aarch64-unknown-linux-gnu/debug/ud-agent-guard'})
        self.assertEqual(original, self.environment())
        self.assertEqual(runtime.compiler_environment(original, ['src/main.rs']), original)
        parser={**original,'UD_MUTATION_RUST_WORKSPACE':'scripts/quality/rust-assertion-parser/Cargo.toml','CARGO_PKG_NAME':'ud-rust-assertion-parser','CARGO_MANIFEST_DIR':original['UD_MUTATION_RUST_SOURCE_ROOT']+'/scripts/quality/rust-assertion-parser'}
        parser.pop('CARGO_BIN_EXE_ud-agent');parser.pop('CARGO_BIN_EXE_ud-agent-guard');parser['CARGO_BIN_EXE_ud-rust-assertion-parser']=parser['UD_MUTATION_RUST_SOURCE_ROOT']+'/target/aarch64-unknown-linux-gnu/debug/ud-rust-assertion-parser'
        self.assertEqual(runtime.compiler_environment(parser,['--test'])['CARGO_BIN_EXE_ud-rust-assertion-parser'],'../../../target/aarch64-unknown-linux-gnu/debug/ud-rust-assertion-parser')

    def test_compiler_rejects_foreign_package_variants_and_unregistered_binaries(self):
        for change in [{'UD_MUTATION_RUST_SOURCE_ROOT': '/host/source'}, {'UD_MUTATION_RUST_SOURCE_ROOT': '/state/../host'}, {'CARGO_PKG_NAME': 'foreign'}, {'CARGO_MANIFEST_DIR': '/state/other/packages/launcher'}, {'CARGO_BIN_EXE_ud-agent': '/state/other/target/aarch64-unknown-linux-gnu/debug/ud-agent'}, {'CARGO_BIN_EXE_future-binary': '/state/rust-work/0/target/aarch64-unknown-linux-gnu/debug/future-binary'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runtime.compiler_environment({**self.environment(), **change}, ['--test'])

    def test_candidate_binds_every_test_executable_to_the_closed_file_inventory(self):
        receipt = self.receipt()
        self.assertEqual(runtime.candidate(receipt), receipt)
        for change in [{'schema_version': True}, {'cwd': '../outside'}, {'source_root': '/host/source'}, {'phase_id': '../outside'}, {'artifacts': []}, {'files': []}, {'unknown': 1}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runtime.candidate({**receipt, **change})

    def test_candidate_rejects_substitution_duplicates_collisions_and_unbounded_entries(self):
        for case in ['artifact-hash', 'artifact-size', 'artifact-path', 'artifact-kind', 'duplicate-artifact', 'duplicate-file', 'collision', 'mode', 'size', 'path', 'sha', 'extra']:
            value = copy.deepcopy(self.receipt())
            if case == 'artifact-hash': value['artifacts'][0]['sha256'] = 'c' * 64
            elif case == 'artifact-size': value['artifacts'][0]['size'] += 1
            elif case == 'artifact-path': value['artifacts'][0]['source_path'] = '/outside/test'
            elif case == 'artifact-kind': value['artifacts'][0]['kind'] = 'unknown'
            elif case == 'duplicate-artifact': value['artifacts'].append(value['artifacts'][0])
            elif case == 'duplicate-file': value['files'].append(value['files'][0])
            elif case == 'collision': value['files'].append({**value['files'][0], 'path': value['files'][0]['path'].upper()})
            elif case == 'mode': value['files'][0]['mode'] = 0o4755
            elif case == 'size': value['files'][0]['size'] = True
            elif case == 'path': value['files'][0]['path'] = '../outside'
            elif case == 'sha': value['files'][0]['sha256'] = 'f' * 63
            else: value['files'][0]['extra'] = 1
            with self.subTest(case=case), self.assertRaises(ValueError):
                runtime.candidate(value)

    def test_paths_reject_escapes_aliases_and_noncanonical_unicode(self):
        for name in ['', '/absolute', 'C:drive', 'a\\b', 'a//b', 'a/../b', 'a/./b', 'e\u0301', 'nul\0byte']:
            with self.subTest(name=name), self.assertRaises(ValueError): runtime.relative(name)
        self.assertEqual(runtime.relative('target/é'), 'target/é')

    def test_test_execution_preserves_sealed_inputs_without_a_file_write_quota(self):
        receipt = self.receipt()
        boundary = mock.Mock()
        boundary.execute.return_value = {'status': 0, 'stderr': '', 'timed_out': False, 'owned_descendants_cancelled': []}
        library = mock.Mock(); library.prctl.return_value = 0
        with mock.patch.object(runtime.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(runtime.os, 'getppid', return_value=123), \
                mock.patch.object(runtime.signal, 'signal'), \
                mock.patch.object(runtime.ctypes, 'CDLL', return_value=library), \
                mock.patch.dict(runtime.os.environ, {'UD_MUTATION_RUST_CANDIDATE': '/state/candidate.json'}), \
                mock.patch.object(runtime, 'read_json', return_value=receipt), \
                mock.patch.object(runtime, 'file_hash', return_value=('b' * 64, 9)), \
                mock.patch.object(runtime.importlib.util, 'spec_from_file_location', return_value=mock.Mock()), \
                mock.patch.object(runtime.importlib.util, 'module_from_spec', return_value=boundary), \
                mock.patch.object(Path, 'is_absolute', lambda value: PurePosixPath(str(value).replace('\\', '/')).is_absolute()), \
                mock.patch.object(Path, 'mkdir'), mock.patch.object(Path, 'write_text'):
            self.assertEqual(runtime.run([receipt['artifacts'][0]['source_path'], '--test-threads=1']), 0)
        arguments = boundary.execute.call_args.kwargs
        self.assertNotIn('max_file_bytes', arguments)
        self.assertEqual(arguments['workspace'], {'root': receipt['source_root'], 'cwd': receipt['cwd'], 'files': receipt['files'], 'readonly_links': [], 'readonly_tree': True})
        self.assertEqual(arguments['timeout'], 120)
        self.assertNotIn('result', arguments)
        self.assertEqual(runtime.MAX_JSON, 32 * 1024**2)


if __name__ == '__main__': unittest.main()
