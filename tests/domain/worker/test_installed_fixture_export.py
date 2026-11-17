import base64
import hashlib
import json
from io import BytesIO
import tarfile
from pathlib import Path
import tempfile
import unittest

from export_installed_cases import export
from ud_agent.contexts import resolve_snapshot_context
from ud_agent import wire


class InstalledFixtureExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = export()
        cls.cases = {case["operation"]: case for case in cls.manifest["cases"]}

    def test_fixture_inventory_has_real_inputs_and_independent_expectations_for_all102(self):
        self.assertEqual(self.manifest["scheduled_operations"], 102)
        self.assertEqual(len(self.cases), 102)
        for case in self.cases.values():
            self.assertTrue(case["expected_fields"])
            self.assertNotIn("child_reports", case)
            self.assertNotIn("evidence", case["arguments"])
            for item in case["files"]:
                data = base64.b64decode(item["content_base64"], validate=True)
                self.assertEqual(len(data), item["size_bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
                self.assertFalse(item["path"].startswith(".ud-agent-inputs/"))

    def test_exported_context_is_complete_and_worker_admissible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for item in self.cases["validation_report"]["files"]:
                file = root / item["path"]
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(base64.b64decode(item["content_base64"]))
            context = resolve_snapshot_context(str(root), "context.json", "/unused")
            response = wire.process({"operation": "validation_report", "arguments": {"working_tree_path": str(root), "file_paths": ["main.conllu"], "ud_context_path": context, "options": {"language_code": "ud", "level": 2}}})
            self.assertTrue(response["ok"], response)
            self.assertTrue(response["result"]["passed"], response)

    def test_release_inputs_bind_the_final_complete_context_before_export(self):
        required = {"data.json", "deprels.json", "edeprels.json", "feats.json", "tospace.json", "udeprels.json", "upos.json"}
        for operation in ["release_candidate_build", "release_deposit_prepare"]:
            with self.subTest(operation=operation):
                files = {item["path"]: base64.b64decode(item["content_base64"], validate=True) for item in self.cases[operation]["files"]}
                context_bytes = files["context.json"]
                context = json.loads(context_bytes)
                self.assertEqual(set(context["rules"]), required)
                actual_rules = {name: hashlib.sha256(files["rules/" + name]).hexdigest() for name in required}
                self.assertEqual(context["rules"], actual_rules)
                identity = hashlib.sha256(json.dumps(actual_rules, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(context["context_sha256"], identity)
                plan = json.loads(files["release-plan.json"])
                with tarfile.open(fileobj=BytesIO(files["candidate.tar"]), mode="r:*") as archive:
                    candidate = json.loads(archive.extractfile(".ud-agent-release-manifest.json").read())
                for artifact in [plan, candidate]:
                    bound = artifact["provenance"]["context"]
                    self.assertEqual(bound["manifest_sha256"], hashlib.sha256(context_bytes).hexdigest())
                    self.assertEqual(bound["sha256"], identity)
                    self.assertEqual(bound["identity"], "urn:ud-agent:context:sha256:" + identity)
                    self.assertEqual(artifact["context"], bound["identity"])
                    self.assertEqual({row["path"]: row["sha256"] for row in bound["rules"]}, actual_rules)
                    self.assertEqual({row["path"]: row["size_bytes"] for row in bound["rules"]}, {name: len(files["rules/" + name]) for name in required})

    def test_project_and_revision_cases_require_genuine_broker_execution(self):
        project = self.cases["project_consistency_report"]
        self.assertEqual(project["execution_profile"], "fresh_oci_project_jobs")
        self.assertEqual(project["expected_fields"], {"passed": True, "official.passed": True, "project.passed": True})
        for name in ["treebank_review", "changes_review"]:
            self.assertEqual(self.cases[name]["prerequisites"][0]["type"], "existing_git_repository")
            self.assertIn("no public evidence injection", self.cases[name]["prerequisites"][0]["requirements"])
            self.assertIn("no new commits or refs", self.cases[name]["prerequisites"][0]["requirements"])

    def test_public_artifact_expectations_bind_exported_bytes_after_resource_projection(self):
        converted = self.cases["format_convert"]
        self.assertIs(converted["expected_fields"]["requires_host_export"], False)
        self.assertNotIn("artifacts.0.content", converted["expected_fields"])
        self.assertEqual(base64.b64decode(converted["expected_artifacts"][0]["content_base64"]), b"Birds fly\n")


if __name__ == "__main__":
    unittest.main()
