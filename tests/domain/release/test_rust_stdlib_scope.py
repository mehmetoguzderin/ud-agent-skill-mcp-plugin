import importlib.util
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('rust_std_scope', ROOT / 'scripts/release/rust-stdlib-scope.py')
scope = importlib.util.module_from_spec(spec); spec.loader.exec_module(scope)


def archive(file, rows, mode):
    with tarfile.open(file, mode) as target:
        for name, body in rows:
            body = body.encode(); member = tarfile.TarInfo(name); member.size = len(body); target.addfile(member, io.BytesIO(body))


class RustStdScopeTests(unittest.TestCase):
    def test_unknown_predicates_retain_edges_and_foreign_targets_are_proven_false(self):
        for profile in scope.TARGETS.values():
            self.assertFalse(scope.cfg('cfg(target_os = "vexos")', profile)); self.assertFalse(scope.cfg('cfg(all(target_vendor="fortanix", target_env="sgx"))', profile))
            self.assertIsNone(scope.cfg('cfg(not(unrecognized_capability))', profile)); self.assertIsNone(scope.cfg('cfg(any(target_os="vexos", custom="new"))', profile))
        windows = scope.TARGETS['aarch64-pc-windows-msvc']; unix = scope.TARGETS['aarch64-apple-darwin']
        self.assertTrue(scope.cfg('cfg(all(windows,target_env="msvc",not(target_vendor="uwp")))', windows)); self.assertFalse(scope.cfg('cfg(windows)', unix))
        for value in ('cfg(not(windows,unix)) trailing', 'cfg(target_os = bad)', 'cfg(all(windows)'):
            with self.subTest(value=value), self.assertRaises(ValueError): scope.cfg(value, windows)

    def test_reachability_keeps_normal_build_and_uncertain_edges_but_not_foreign_or_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'rust-src.tar.xz'; prefix = 'rust-src/rust-src/lib/rustlib/src/rust/library/'
            manifest = '[package]\nname="std"\nversion="1.0.0"\n[dependencies]\nnormal="1"\n[build-dependencies]\nbuild="1"\n[dev-dependencies]\ndev="1"\n[target.\'cfg(custom_predicate)\'.dependencies]\nuncertain="1"\n[target.\'cfg(target_os="vexos")\'.dependencies]\nforeign="1"\n'
            crates = {}
            for name in ('normal', 'build', 'uncertain', 'foreign', 'dev'):
                crates[(name, '1.0.0')] = root / (name + '.crate'); archive(crates[(name, '1.0.0')], [(name + '-1.0.0/Cargo.toml', '[package]\nname="' + name + '"\nversion="1.0.0"\n')], 'w:gz')
            lock = ''.join('[[package]]\nname="' + name + '"\nversion="1.0.0"\n' + ('source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + hashlib.sha256(crates[(name, '1.0.0')].read_bytes()).hexdigest() + '"\n' if name != 'std' else 'dependencies=["normal","build","uncertain","foreign","dev"]\n') for name in ('std', 'normal', 'build', 'uncertain', 'foreign', 'dev'))
            archive(original, [(prefix + 'Cargo.lock', lock), (prefix + 'std/Cargo.toml', manifest)], 'w:xz')
            result = scope.derive(original, crates)
            self.assertEqual({row['name'] for row in result['selected_registry_packages']}, {'normal', 'build', 'uncertain'})
            self.assertEqual({row['name'] for row in result['unselected_registry_packages']}, {'foreign', 'dev'})
            self.assertEqual({row['reason'] for row in result['excluded_edges']}, {'foreign-target-only-edge', 'dev-only-edge'})
            for name in ('foreign', 'dev'): crates[(name, '1.0.0')].unlink()
            self.assertEqual(scope.derive(original, crates), result)
            selected = crates[('normal', '1.0.0')]; selected.write_bytes(b'tampered source')
            with self.assertRaisesRegex(ValueError, 'checksum'): scope.derive(original, crates)
            crates.pop(('normal', '1.0.0'))
            with self.assertRaisesRegex(ValueError, 'metadata is absent'): scope.derive(original, crates)


if __name__ == '__main__': unittest.main()
