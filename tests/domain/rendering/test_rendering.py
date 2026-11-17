from __future__ import annotations

import base64
import hashlib
import os
from html.parser import HTMLParser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from ud_agent.domain import rendering
from ud_agent.errors import InvalidInput, PrerequisiteMissing


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class RenderingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sentence = ("# sent_id = example\n"
                         "1\tBirds\tbird\tNOUN\t_\tNumber=Plur\t2\tnsubj\t2:nsubj\t_\n"
                         "2\tfly\tfly\tVERB\t_\t_\t0\troot\t0:root\t_\n\n")
        self.base = {"working_tree_path": str(self.root), "ud_context_path": "/context", "sentence_conllu": self.sentence,
                     "output_format": "svg", "output_path": "/requested/result.svg"}

    def tearDown(self):
        self.temp.cleanup()

    def data(self, result):
        item = result["artifacts"][0]
        content = base64.b64decode(item["content_base64"], validate=True)
        self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(item["size_bytes"], len(content))
        return content

    def test_svg_contains_real_token_labels_and_dependency_arcs(self):
        result = rendering.sentence_render(self.base)
        svg = self.data(result)
        root = ElementTree.fromstring(svg)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        text = " ".join(root.itertext())
        self.assertIn("Birds", text)
        self.assertIn("fly", text)
        self.assertIn("nsubj", text)
        self.assertIn("root", text)
        self.assertGreaterEqual(len(root.findall(".//{http://www.w3.org/2000/svg}path")), 3)
        self.assertEqual(result["output_path"], "/requested/result.svg")
        self.assertTrue(result["requires_broker_export"])
        self.assertFalse((self.root / "result.svg").exists())

    def test_svg_escapes_malicious_form_and_relation(self):
        sentence = self.sentence.replace("Birds", "</text><script>alert(1)</script>")
        content = self.data(rendering.sentence_render({**self.base, "sentence_conllu": sentence})).decode()
        self.assertIn("&lt;/text&gt;&lt;script&gt;", content)
        self.assertNotIn("<script>", content)
        ElementTree.fromstring(content)

    def test_html_is_self_contained_and_disables_external_resources(self):
        result = rendering.sentence_render({**self.base, "output_format": "html", "output_path": "C:\\Users\\test\\result.html"})
        html = self.data(result).decode()
        parser = Tags()
        parser.feed(html)
        self.assertNotIn("script", [tag for tag, _ in parser.tags])
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("default-src &#39;none&#39;", html)
        self.assertNotIn("http://", html.replace('xmlns="http://www.w3.org/2000/svg"', ""))
        self.assertEqual(result["output_path"], "C:\\Users\\test\\result.html")

    def test_raster_outputs_require_browser_and_unknown_is_invalid(self):
        with patch.dict(os.environ, {"UD_AGENT_RENDER_MANIFEST": str(self.root.resolve(strict=True) / "missing-render-receipt.json")}):
            for fmt in ["png", "pdf", "jpeg", "webp"]:
                with self.subTest(fmt=fmt), self.assertRaises(PrerequisiteMissing):
                    rendering.sentence_render({**self.base, "output_format": fmt})
        with self.assertRaises(InvalidInput):
            rendering.sentence_render({**self.base, "output_format": "gif"})
        with self.assertRaises(InvalidInput):
            rendering.sentence_render({**self.base, "output_format": []})

    def test_bad_graphs_are_rejected(self):
        for bad in [self.sentence.replace("2\tnsubj", "9\tnsubj"),
                    self.sentence.replace("0\troot", "1\tdep"),
                    self.sentence + self.sentence,
                    self.sentence.replace("Birds", "bad\x00char")]:
            with self.subTest(bad=bad), self.assertRaises(InvalidInput):
                rendering.sentence_render({**self.base, "sentence_conllu": bad})

    def test_special_rows_and_enhanced_edges_are_reported_as_omitted(self):
        special = self.sentence.replace("1\tBirds", "1-2\tBirdsfly\t_\t_\t_\t_\t_\t_\t_\t_\n1\tBirds").replace("\n\n", "\n2.1\tx\t_\tX\t_\t_\t_\t_\t2:dep\t_\n\n")
        result = rendering.sentence_render({**self.base, "sentence_conllu": special})
        self.assertEqual(result["coverage"]["multiword_rows_not_drawn"], 1)
        self.assertEqual(result["coverage"]["empty_nodes_not_drawn"], 1)
        self.assertTrue(result["coverage"]["enhanced_edges_not_drawn"])

    def test_documentation_preview_renders_fenced_graph_and_escapes_html(self):
        source = '# Guide\n<script>alert(1)</script>\n\n```conllu\n' + self.sentence + '```\n'
        (self.root / "README.md").write_text(source, newline="")
        result = rendering.documentation_preview({"working_tree_path": str(self.root), "output_dir_path": "/out"})
        html = self.data(result).decode()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["files"][0]["examples"]), 1)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("nsubj", html)
        self.assertFalse((self.root / "index.html").exists())

    def test_bad_fenced_example_is_incomplete_with_diagnostic(self):
        (self.root / "README.md").write_text("```conllu\ninvalid\n```\n", newline="")
        result = rendering.documentation_preview({"working_tree_path": str(self.root), "output_dir_path": "/out"})
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["diagnostics"])
        self.assertIn(b"invalid", self.data(result))

    def test_guideline_sdparse_is_rendered_offline(self):
        source = "~~~ sdparse\nBirds fly\nnsubj(fly-2, Birds-1)\n~~~\n"
        (self.root / "example.md").write_text(source, newline="")
        result = rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "example.md", "output_dir_path": "/out"})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["examples"][0]["word_count"], 2)
        self.assertIn(b"nsubj", self.data(result))
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(source.encode()).hexdigest())

    def test_html_sdparse_with_br_is_rendered(self):
        source = '<div class="sd-parse">Birds fly<br>nsubj(fly-2, Birds-1)</div>'
        (self.root / "example.html").write_text(source, newline="")
        result = rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "example.html", "output_dir_path": "/out"})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["examples"][0]["html_example"], 1)
        self.assertIn(b"nsubj", self.data(result))

    def test_html_self_closing_tags_preserve_only_breaks_inside_sdparse_blocks(self):
        source = '<br/><div class="sd-parse">Birds fly<img/><br/>nsubj(fly-2, Birds-1)<hr/></div><br/>'
        (self.root / "example.html").write_text(source, newline="")
        result = rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "example.html", "output_dir_path": "/out"})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["examples"]), 1)
        self.assertEqual(result["examples"][0]["word_count"], 2)
        self.assertIn(b"nsubj", self.data(result))
        parser = rendering._SdparseHTML()
        parser.feed('<br/><span/><div class="sd-parse">A<br/>B<img/>C</div><br/>')
        self.assertEqual(parser.blocks, ['A\nBC'])

    def test_bare_sdparse_and_conllu_examples(self):
        for name, source in [("bare.sd", "Birds fly\nnsubj(fly-2, Birds-1)\n"), ("bare.conllu", self.sentence)]:
            with self.subTest(name=name):
                (self.root / name).write_text(source, newline="")
                result = rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": name, "output_dir_path": "/out"})
                self.assertEqual(len(result["examples"]), 1)
                self.assertEqual(result["status"], "complete")

    def test_ambiguous_sdparse_does_not_invent_root(self):
        (self.root / "example.md").write_text("~~~ sdparse\nA B C\ndep(A-1, B-2)\n~~~\n", newline="")
        result = rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "example.md", "output_dir_path": "/out"})
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("ambiguous", result["diagnostics"][0])

    def test_markup_without_any_supported_example_is_rejected(self):
        (self.root / "example.md").write_text("No example here.", newline="")
        with self.assertRaises(InvalidInput):
            rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "example.md", "output_dir_path": "/out"})

    def test_paths_and_size_are_bounded(self):
        (self.root / "big.md").write_bytes(b"x" * (rendering.MAX_SOURCE_BYTES + 1))
        with self.assertRaises(InvalidInput):
            rendering.documentation_preview({"working_tree_path": str(self.root), "output_dir_path": "/out", "options": {"file_paths": ["big.md"]}})
        with self.assertRaises(InvalidInput):
            rendering.guideline_example_preview({"working_tree_path": str(self.root), "example_markup_path": "../outside.md", "output_dir_path": "/out"})


if __name__ == "__main__":
    unittest.main()
