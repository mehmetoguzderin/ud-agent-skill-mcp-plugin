import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zlib

from ud_agent.domain import rendering
from ud_agent.errors import WorkerError
from ud_agent.render_browser import _png, browser_export, verified_renderer
from ud_agent.render_fonts import embed_fonts


def png(width, height):
    def chunk(kind, value):
        return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xFFFFFFFF)
    pixels = (b"\x00" + b"\xff\xff\xff" * width) * height
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def font(first=32, last=0x10FFFF):
    """Minimal cmap fixture; this is not a real browser/font acceptance test."""
    cmap = struct.pack(">HHHHIHHIIII", 0, 1, 3, 10, 12, 13, 0, 28, 0, 1, first) + struct.pack(">II", last, 1)
    return (struct.pack(">IHHHH", 0x10000, 2, 0, 0, 0) + b"cmap" + struct.pack(">III", 0, 44, len(cmap))
            + b"maxp" + struct.pack(">III", 0, 44 + len(cmap), 6) + cmap + struct.pack(">IH", 0x5000, 2))


class BrowserExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-browser-export-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.binary = self.root / "chromium"
        self.binary.write_bytes(b"verified browser fixture\n")
        self.binary.chmod(0o700)
        self.receipt = self.root / "manifest.json"
        self.font = self.root / "fixture.ttf"
        self.font.write_bytes(font())
        self.receipt.write_text(json.dumps({"schema_version": 1, "executable": str(self.binary), "files": [
            {"path": str(self.binary), "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(), "size_bytes": self.binary.stat().st_size},
            {"path": "fixture.ttf", "sha256": hashlib.sha256(self.font.read_bytes()).hexdigest(), "size_bytes": self.font.stat().st_size}], "fonts": ["fixture.ttf"]}))
        self.env = patch.dict(os.environ, {"UD_AGENT_RENDER_MANIFEST": str(self.receipt), "LD_PRELOAD": "hostile", "PYTHONPATH": "hostile"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def browser(self, command, **options):
        if sys.platform == "linux":
            self.assertEqual(command[:4], [sys.executable, "-I", "-B", "-c"])
            self.assertIn("from ud_agent.render_process import main", command[4])
            self.assertEqual(len(command), 6)
            command = json.loads(command[5])
            self.assertIsInstance(command, list)
        return self.browser_command(command, **options)

    def browser_command(self, command, **options):
        self.assertEqual(command[0], str(self.binary))
        self.assertNotIn("--no-sandbox", command)
        self.assertIn("--disable-background-networking", command)
        for flag in ["--disable-gpu", "--disable-software-rasterizer", "--renderer-process-limit=1", "--num-raster-threads=1"]:
            self.assertIn(flag, command)
        self.assertNotIn("--single-process", command)
        self.assertNotIn("LD_PRELOAD", options["env"])
        self.assertNotIn("PYTHONPATH", options["env"])
        source = Path.from_uri(command[-1])
        self.assertIn(b"default-src", source.read_bytes())
        self.assertIn(b"data:font/sfnt;base64,", source.read_bytes())
        self.assertIn(b'font-family:"ud-agent-font-0"!important', source.read_bytes())
        if destination := next((arg.split("=", 1)[1] for arg in command if arg.startswith("--screenshot=")), None):
            width, height = map(int, next(arg.split("=", 1)[1] for arg in command if arg.startswith("--window-size=")).split(","))
            Path(destination).write_bytes(png(width, height))
        else:
            destination = next(arg.split("=", 1)[1] for arg in command if arg.startswith("--print-to-pdf="))
            Path(destination).write_bytes(b"%PDF-1.7\nfixture\n%%EOF\n")
        return types.SimpleNamespace(returncode=0)

    def test_real_adapter_verifies_receipt_and_exports_bounded_png_and_pdf(self):
        sentence = "# sent_id = a\n1\tBird\t_\tNOUN\t_\t_\t0\troot\t_\t_\n\n"
        with patch("ud_agent.render_browser.subprocess.run", side_effect=self.browser) as run:
            for fmt, signature in [("png", b"\x89PNG"), ("pdf", b"%PDF-")]:
                result = rendering.sentence_render({"working_tree_path": str(self.root), "sentence_conllu": sentence, "output_format": fmt, "output_path": "/out/result." + fmt})
                data = base64.b64decode(result["artifacts"][0]["content_base64"])
                self.assertTrue(data.startswith(signature))
                self.assertEqual(result["provenance"]["render_manifest_sha256"], hashlib.sha256(self.receipt.read_bytes()).hexdigest())
            self.assertEqual(run.call_count, 2)

    def test_changed_renderer_is_rejected_before_execution(self):
        self.binary.write_bytes(b"changed")
        with patch("ud_agent.render_browser.subprocess.run") as run:
            with self.assertRaisesRegex(WorkerError, "does not match"):
                verified_renderer()
            run.assert_not_called()

    def test_png_parser_requires_valid_crc_complete_pixels_and_exact_size(self):
        valid = png(2, 2)
        self.assertTrue(_png(valid, 2, 2))
        self.assertFalse(_png(valid, 3, 2))
        self.assertFalse(_png(valid[:-1], 2, 2))
        corrupt = bytearray(valid)
        corrupt[30] ^= 1
        self.assertFalse(_png(bytes(corrupt), 2, 2))

    def test_browser_failure_never_returns_a_successful_artifact(self):
        with patch("ud_agent.render_browser.subprocess.run", return_value=types.SimpleNamespace(returncode=133)):
            with self.assertRaisesRegex(WorkerError, "sandbox enabled"):
                browser_export(b"static", "pdf", 100, 100)

    def test_font_coverage_is_explicit_and_unknown_glyphs_cannot_use_ambient_fonts(self):
        html = b'<html><head><style>not glyph data</style></head><body>A&amp;</body></html>'
        embedded = embed_fonts(html, [font(32, 127)])
        self.assertIn(b'data:font/sfnt;base64,', embedded)
        with self.assertRaisesRegex(WorkerError, "U\\+4E2D"):
            embed_fonts('<body>\u4e2d</body>'.encode(), [font(32, 127)])
        with self.assertRaisesRegex(WorkerError, "pinned offline fonts"):
            embed_fonts(html, [])
        with self.assertRaisesRegex(WorkerError, "character map"):
            embed_fonts(html, [b"invalid font"])

    def test_font_selection_must_be_bound_to_the_receipt_inventory(self):
        receipt = json.loads(self.receipt.read_text())
        receipt["fonts"] = ["absent.ttf"]
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(WorkerError, "absent from"):
            verified_renderer()

    def test_private_linux_loader_is_verified_and_invoked_without_ambient_libraries(self):
        library = self.root / "private-libs"
        library.mkdir()
        loader = library / "ld-owned.so"
        loader.write_bytes(b"verified loader fixture")
        loader.chmod(0o500)
        receipt = json.loads(self.receipt.read_text())
        receipt["loader"] = {"executable": "private-libs/ld-owned.so", "library_dirs": ["private-libs"]}
        receipt["files"].append({"path":"private-libs/ld-owned.so", "sha256":hashlib.sha256(loader.read_bytes()).hexdigest(), "size_bytes":loader.stat().st_size})
        self.receipt.write_text(json.dumps(receipt))
        def browser(command, **options):
            launched = json.loads(command[-1])
            self.assertEqual(launched[:4], [str(loader), "--inhibit-cache", "--library-path", str(library)])
            self.assertNotIn("LD_LIBRARY_PATH", options["env"])
            self.assertEqual(command[:4], [sys.executable, "-I", "-B", "-c"])
            self.assertIn("from ud_agent.render_process import main", command[4])
            return self.browser_command(launched[4:], **options)
        with patch("ud_agent.render_browser.sys.platform", "linux"), patch("ud_agent.render_browser.subprocess.run", side_effect=browser):
            data, _ = browser_export(b'<html><head><meta content="default-src"></head><body>A</body></html>', "pdf", 100, 100)
        self.assertTrue(data.startswith(b"%PDF-"))
        (library / "ambient.so").write_bytes(b"unverified")
        with patch("ud_agent.render_browser.sys.platform", "linux"):
            with self.assertRaisesRegex(WorkerError, "unverified entry"): verified_renderer()

    def test_loader_receipt_rejects_wrong_platform_absolute_escape_and_missing_inventory(self):
        original = json.loads(self.receipt.read_text())
        for loader, platform in [({"executable":"loader", "library_dirs":["lib"]}, "darwin"),
                                 ({"executable":"/outside", "library_dirs":["lib"]}, "linux"),
                                 ({"executable":"loader", "library_dirs":["../lib"]}, "linux"),
                                 ({"executable":"loader", "library_dirs":[]}, "linux"),
                                 ({"executable":"loader", "library_dirs":["lib", "lib"]}, "linux"),
                                 ({"executable":"loader", "library_dirs":["lib"]}, "linux")]:
            self.receipt.write_text(json.dumps({**original, "loader":loader}))
            with patch("ud_agent.render_browser.sys.platform", platform):
                with self.assertRaises(WorkerError): verified_renderer()


if __name__ == "__main__":
    unittest.main()
