import hashlib
import importlib.util
from pathlib import Path
import tempfile
import struct
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("render_manifest_test", ROOT / "scripts/runtime/render_manifest.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)
model_spec = importlib.util.spec_from_file_location('render_manifest_posix_model', ROOT / 'tests/mutation/posix_file_model.py')
model = importlib.util.module_from_spec(model_spec); model_spec.loader.exec_module(model)


class RenderManifestTests(unittest.TestCase):
    def test_collection_materialization_preserves_tables_and_rebuilds_checksum(self):
        header = b'OTTO' + struct.pack('>HHHH', 1, 16, 0, 0)
        collection = b'ttcf' + struct.pack('>IIII', 0x10000, 1, 20, 0)
        collection += header + struct.pack('>4sIII', b'head', 0, 48, 12) + bytes(12)
        font = render.standalone_font(collection)
        self.assertEqual(font[:12], header)
        self.assertEqual(struct.unpack_from('>4sIII', font, 12), (b'head', 0, 28, 12))
        self.assertEqual(font[28:36], bytes(8))
        self.assertEqual(sum(value[0] for value in struct.iter_unpack('>I', font)) & 0xFFFFFFFF, 0xB1B0AFBA)
        with self.assertRaisesRegex(ValueError, 'out of bounds'):
            render.standalone_font(collection[:-1])
        with self.assertRaisesRegex(ValueError, 'invalid bounded'):
            render.standalone_font(b'OTTO')

    def test_exact_browser_font_and_asset_hashes_are_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.enterContext(model.posix_files(render, root))
            files = {"usr/lib/chromium/chromium": b"browser", "usr/lib/chromium/resources.pak": b"assets", "usr/share/fonts/noto.ttf": b"font", "usr/share/fontconfig/conf.avail/config.conf": b"font configuration", "etc/fonts/fonts.conf": b"fonts", "opt/ud-agent/render/dependency-lock.json": b"{}"}
            for name, content in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            (root / "usr/lib/chromium/chromium").chmod(0o755)
            result = render.manifest(root)
            self.assertEqual(result["executable"], "/usr/lib/chromium/chromium")
            self.assertEqual({item["path"]: (item["sha256"], item["size_bytes"]) for item in result["files"]}, {"/" + name: (hashlib.sha256(content).hexdigest(), len(content)) for name, content in files.items()})
            (root / "usr/lib/chromium/chromium").chmod(0o777)
            with self.assertRaisesRegex(ValueError, "writable"):
                render.manifest(root)

    def test_missing_closure_never_yields_a_partial_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "missing"):
                render.manifest(Path(temporary))


if __name__ == "__main__":
    unittest.main()
