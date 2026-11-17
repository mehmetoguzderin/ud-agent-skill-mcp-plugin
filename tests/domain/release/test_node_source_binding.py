import importlib.util
import io
import copy
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('node_sources', ROOT / 'scripts/release/bind-node-sources.py')
node = importlib.util.module_from_spec(spec); spec.loader.exec_module(node)


class NodeSourceBindingTests(unittest.TestCase):
    def test_linux_producer_join_requires_exact_actual_binary_archive_and_authenticated_source_scope(self):
        commit = '6b00bc3880198600130e1cf62b8f8a93494488cc'
        archive = {'sha256': 'a' * 64, 'size_bytes': 123}; executable = {'sha256': 'b' * 64, 'size_bytes': 456}
        source = {'sha256': 'c' * 64, 'size_bytes': 789}; runtime = {'source': source, 'dependencies': [], 'verification_materials': []}
        row = {'platform': 'linux/arm64', 'binary': executable, 'node_archive': archive, 'rust_commit': commit, 'sources': [source], 'notices': [{'sha256': 'd' * 64}], 'verification_materials': [{'sha256': 'e' * 64}]}
        proof = {'qualification': 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction', 'target_execution': False, 'pending_declarations': [], 'bindings': [row], 'input_lock_sha256': 'f' * 64, 'generator_sha256': '0' * 64}
        joined = node.join_linux_runtime('linux/arm64', archive, executable, {commit: runtime}, proof)
        self.assertIsNone(joined['pending']); self.assertEqual(joined['producer_sources'], [source]); self.assertEqual(joined['commits'], [commit])
        for change in (lambda value: value['bindings'][0]['binary'].update(sha256='1' * 64), lambda value: value['bindings'][0]['node_archive'].update(size_bytes=124), lambda value: value['bindings'].append(copy.deepcopy(row)), lambda value: value['bindings'][0].update(rust_commit='2' * 40), lambda value: value['bindings'][0].update(notices=[]), lambda value: value.update(pending_declarations=['unverified'])):
            altered = copy.deepcopy(proof); change(altered)
            with self.subTest(altered=altered), self.assertRaises(ValueError): node.join_linux_runtime('linux/arm64', archive, executable, {commit: runtime}, altered)

    def test_observed_compiler_identity_cannot_be_inferred_from_platform_or_version(self):
        mac = '6b00bc3880198600130e1cf62b8f8a93494488cc'; windows = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'; original = {'source': {'sha256': 'a' * 64}, 'dependencies': [{'sha256': 'b' * 64}]}
        actual = node.observed_rust(('/rustc/' + mac + '/library/std/src/lib.rs').encode(), {mac: original})
        self.assertIsNone(actual['pending']); self.assertEqual(actual['source'], original['source']); self.assertEqual(actual['dependencies'], original['dependencies'])
        for body, code in [(b'stripped executable', 'NODE_STATIC_RUST_PRODUCER_IDENTITY_UNRESOLVED'), (('/rustc/' + windows + '/library/std/').encode(), 'NODE_OBSERVED_RUST_STANDARD_LIBRARY_SOURCE_REQUIRED'), (('/rustc/' + mac + '/ /rustc/' + windows + '/').encode(), 'NODE_STATIC_RUST_PRODUCER_IDENTITY_UNRESOLVED')]:
            self.assertEqual(node.observed_rust(body, {mac: original})['pending'], code)

    def test_every_actual_locked_crate_needs_one_original_source_and_notice(self):
        lock = b'[[package]]\nname="demo"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + b'a' * 64 + b'"\n'
        manifest = b'[package]\nname="demo"\nversion="1.0.0"\n'
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'source.tar.gz'; prefix = 'node-v26.13.0/deps/crates/'
            def write(rows):
                with tarfile.open(archive, 'w:gz') as target:
                    for name, body in rows:
                        entry = tarfile.TarInfo(prefix + name); entry.size = len(body); target.addfile(entry, io.BytesIO(body))
            original = [('Cargo.lock', lock), ('vendor/demo/Cargo.toml', manifest), ('vendor/demo/LICENSE', b'Original declared terms\n')]
            write(original); result = node.vendored_rust_sources(archive)
            self.assertEqual([(row['name'], row['version']) for row in result], [('demo', '1.0.0')]); self.assertEqual(result[0]['original_notices'][0]['size_bytes'], 24)
            for rows in (original[:1], original[:2], original + [original[1]], original + [('vendor/alias/Cargo.toml', manifest)]):
                write(rows)
                with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, 'omit|duplicate|notices'): node.vendored_rust_sources(archive)


if __name__ == '__main__': unittest.main()
