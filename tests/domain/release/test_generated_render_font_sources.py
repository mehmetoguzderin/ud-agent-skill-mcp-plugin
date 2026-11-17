import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('generated_font_metadata_fixture', Path(__file__).with_name('test_worker_metadata.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
metadata = fixture.m


def identity(body): return {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}


class GeneratedRenderFontSourceTests(unittest.TestCase):
    def setup_derivation(self, root):
        filesystem, generator = fixture.render_fixture(root)
        derivations = []
        metadata.render_form(filesystem, generator, derivations)
        self.assertEqual(len(derivations), 1)
        self.assertEqual(derivations[0]['input'], {'image_path': 'usr/share/fonts/NotoSansCJK-Regular.ttc', **identity(b'collection')})
        self.assertEqual(derivations[0]['content'], {'image_path': 'opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf', **identity(b'derived collection')})
        return filesystem, generator, derivations

    def origin(self, derivation):
        return {'content': {**derivation['input'], 'platform': 'linux/arm64', 'layer_digest': 'sha256:' + 'c' * 64},
                'sources': [{'source_package': 'fonts-noto-cjk', 'version': 'exact-original', 'sha256': 'a' * 64}],
                'notices': [{'path': 'original-font-copyright', **identity(b'Original font copyright and license')}],
                'required_materials': [{'sha256': 'a' * 64, 'size_bytes': 321}, identity(b'Original font copyright and license')]}

    def test_generated_font_inherits_the_exact_collection_sources_and_original_font_license(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, derivations = self.setup_derivation(Path(temporary))
            origin = self.origin(derivations[0]); recipes = [{'path': 'scripts/runtime/render_manifest.py', 'sha256': 'b' * 64}]
            wanted = {(identity(b'derived collection')['sha256'], len(b'derived collection'))}
            rows = metadata.generated_font_bindings(derivations, [origin], 'linux/arm64', 'sha256:' + 'd' * 64, recipes, wanted)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['content'], derivations[0]['content'])
            self.assertEqual(rows[0]['sources'][0], origin['sources'][0])
            self.assertEqual(rows[0]['notices'], origin['notices'])
            self.assertEqual(rows[0]['required_materials'], origin['required_materials'])
            self.assertEqual(rows[0]['sources'][1], {'form': 'exact-standalone-font-zero-derived-from-authenticated-original-collection', 'input': {**derivations[0]['input'], 'platform': 'linux/arm64'}, 'image_digest': 'sha256:' + 'd' * 64, 'source_generators': recipes})

    def test_matching_output_does_not_accept_a_foreign_or_changed_collection_source_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, derivations = self.setup_derivation(Path(temporary))
            wanted = {(identity(b'derived collection')['sha256'], len(b'derived collection'))}
            for field, value in [('image_path', 'usr/share/fonts/other.ttc'), ('platform', 'linux/amd64'), ('sha256', 'e' * 64), ('size_bytes', 1)]:
                with self.subTest(field=field):
                    changed = copy.deepcopy(self.origin(derivations[0])); changed['content'][field] = value
                    with self.assertRaisesRegex(ValueError, 'exact original TTC source and notice'):
                        metadata.generated_font_bindings(derivations, [changed], 'linux/arm64', 'sha256:' + 'd' * 64, [], wanted)

    def test_missing_original_source_license_or_retained_materials_does_not_close_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, derivations = self.setup_derivation(Path(temporary))
            wanted = {(identity(b'derived collection')['sha256'], len(b'derived collection'))}
            for field in ('sources', 'notices', 'required_materials'):
                with self.subTest(field=field):
                    changed = self.origin(derivations[0]); changed[field] = []
                    with self.assertRaisesRegex(ValueError, 'exact original TTC source and notice'):
                        metadata.generated_font_bindings(derivations, [changed], 'linux/arm64', 'sha256:' + 'd' * 64, [], wanted)

    def test_changed_standalone_bytes_fail_before_a_derivation_is_emitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            filesystem, generator, _ = self.setup_derivation(Path(temporary))
            filesystem.resolve('opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf')[1].write_bytes(b'forged standalone font')
            derivations = []
            with self.assertRaisesRegex(ValueError, 'generated font differs'):
                metadata.render_form(filesystem, generator, derivations)
            self.assertEqual(derivations, [])

    def test_unrequested_font_does_not_issue_an_unrelated_source_fact(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, derivations = self.setup_derivation(Path(temporary))
            self.assertEqual(metadata.generated_font_bindings(derivations, [], 'linux/arm64', 'sha256:' + 'd' * 64, [], set()), [])


if __name__ == '__main__': unittest.main()
