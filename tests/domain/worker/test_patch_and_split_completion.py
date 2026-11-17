"""Independent expectations for contribution file actions and split leakage."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from ud_agent.domain import comparison, plans, review
from ud_agent.errors import InvalidInput
from ud_agent.conllu.core import StaleInputError


class ContributionAndSplitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-contribution-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = {"working_tree_path": str(self.root)}

    def plan(self, patch):
        (self.root / "change.patch").write_text(patch, encoding="utf-8", newline="")
        result = review.contribution_plan({**self.args, "patch_path": "change.patch"})
        (self.root / "plan.json").write_text(json.dumps(result), encoding="utf-8", newline="")
        applied = plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [action["id"] for action in result["actions"]]})
        return result, applied

    def test_new_and_deleted_files_produce_absence_and_byte_bound_actions(self):
        (self.root / "old.txt").write_bytes(b"old\n")
        result, applied = self.plan("diff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n"
                                    "diff --git a/old.txt b/old.txt\ndeleted file mode 100644\n--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n")
        self.assertEqual([item["type"] for item in result["actions"]], ["create_file", "delete_file"])
        self.assertEqual(applied["file_operations"], [{"operation": "create", "file_path": "new.txt", "before_sha256": None,
                            "after_sha256": hashlib.sha256(b"new\n").hexdigest(), "content": "new\n"},
                            {"operation": "delete", "file_path": "old.txt", "before_sha256": hashlib.sha256(b"old\n").hexdigest(), "after_sha256": None}])
        self.assertFalse((self.root / "new.txt").exists())
        self.assertEqual((self.root / "old.txt").read_bytes(), b"old\n")

    def test_rename_with_hunks_and_no_newline_markers_preserves_exact_bytes(self):
        (self.root / "old.txt").write_bytes(b"old")
        result, applied = self.plan("diff --git a/old.txt b/new.txt\nsimilarity index 50%\nrename from old.txt\nrename to new.txt\n--- a/old.txt\n+++ b/new.txt\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n")
        self.assertEqual(result["actions"][0]["type"], "rename_file")
        self.assertEqual([(item["operation"], item["file_path"]) for item in applied["file_operations"]], [("create", "new.txt"), ("delete", "old.txt")])
        self.assertEqual(applied["file_operations"][0]["content"], "new")
        self.assertEqual((self.root / "old.txt").read_bytes(), b"old")

    def test_exact_binary_rename_does_not_decode_or_change_contents(self):
        original = b"\x00\xff\r\n"
        (self.root / "old.bin").write_bytes(original)
        result, applied = self.plan("diff --git a/old.bin b/new.bin\nsimilarity index 100%\nrename from old.bin\nrename to new.bin\n")
        self.assertEqual(result["actions"][0]["before_sha256"], hashlib.sha256(original).hexdigest())
        self.assertNotIn("content", result["actions"][0])
        self.assertEqual(base64.b64decode(applied["file_operations"][0]["content_base64"]), original)

    def test_creation_conflicts_partial_deletions_and_executable_modes_are_rejected(self):
        (self.root / "old.txt").write_bytes(b"first\nsecond\n")
        with self.assertRaisesRegex(StaleInputError, "absent"):
            self.plan("--- /dev/null\n+++ b/old.txt\n@@ -0,0 +1 @@\n+new\n")
        with self.assertRaisesRegex(InvalidInput, "complete"):
            self.plan("--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-first\n")
        with self.assertRaisesRegex(InvalidInput, "non-executable"):
            self.plan("diff --git a/new b/new\nnew file mode 100755\n--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+executable\n")
        with self.assertRaisesRegex(InvalidInput, "traversal"):
            self.plan("--- /dev/null\n+++ b/../escape\n@@ -0,0 +1 @@\n+escape\n")

    def sentence(self, ident, text):
        return f"# sent_id = {ident}\n# text = {text}\n1\t{text}\t_\tX\t_\t_\t0\troot\t_\t_\n\n"

    def overlap(self, spec, **kwargs):
        (self.root / "split.json").write_text(json.dumps(spec), encoding="utf-8", newline="")
        return comparison.overlap_report({**self.args, "peer_treebank_paths": [], "split_spec_path": "split.json", **kwargs})

    def test_overlap_reports_explicit_split_leakage_without_peer_treebanks(self):
        (self.root / "train.conllu").write_text(self.sentence("a", "Same") + self.sentence("b", "Other"), newline="")
        (self.root / "test.conllu").write_text(self.sentence("c", "same"), newline="")
        result = self.overlap({"splits": {"train": ["train.conllu"], "test": [{"file_path": "test.conllu", "sent_id": "c"}]}}, matching_options={"casefold": True})
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["split_matches"], [{"left_split": "train", "right_split": "test", "text": "same",
            "left": [{"file_path": "train.conllu", "sent_id": "a", "ordinal": 0}],
            "right": [{"file_path": "test.conllu", "sent_id": "c", "ordinal": 0}]}])
        self.assertEqual(result["splits"], [{"name": "train", "sentence_count": 2}, {"name": "test", "sentence_count": 1}])
        self.assertEqual(result["split_spec_sha256"], hashlib.sha256((self.root / "split.json").read_bytes()).hexdigest())

    def test_overlap_preserves_peer_comparison_and_bounds_split_selectors(self):
        (self.root / "main.conllu").write_text(self.sentence("a", "same") + self.sentence("b", "other"), newline="")
        (self.root / "peer").mkdir()
        (self.root / "peer/p.conllu").write_text(self.sentence("p", "same"), newline="")
        spec = {"splits": {"train": [{"file_path": "main.conllu", "sent_id": "a"}], "test": [{"file_path": "main.conllu", "sent_id": "b"}]}}
        result = self.overlap(spec, peer_treebank_paths=["peer"])
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["peer_treebank"], "peer")
        self.assertEqual(result["split_matches"], [])
        for bad in ["missing.conllu", "peer/p.conllu", "../escape"]:
            with self.assertRaises(InvalidInput):
                self.overlap({"splits": {"train": ["main.conllu"], "test": [bad]}}, peer_treebank_paths=["peer"])
        with self.assertRaisesRegex(InvalidInput, "repeats"):
            self.overlap({"splits": {"train": ["main.conllu", "main.conllu"], "test": ["main.conllu"]}})
