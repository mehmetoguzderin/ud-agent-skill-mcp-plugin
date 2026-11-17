from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from ud_agent.domain import maintenance, release, workspace
from ud_agent.domain._artifacts import archive, read_archive
from ud_agent.errors import InvalidInput, PrerequisiteMissing, WorkerError


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tree = self.root / "en_test-ud-train.conllu"
        self.tree.write_text("# sent_id = 1\n1\tHello\thello\tINTJ\t_\t_\t0\troot\t0:root\t_\n2\tworld\tworld\tNOUN\t_\tNumber=Sing\t1\tdep\t1:dep\t_\n\n")
        self.readme = self.root / "README.md"
        self.readme.write_text("# Metadata\nIncludes text: yes\nGenre: news web\nLemmas: manual native\nUPOS: manual native\nFeatures: manual native\nRelations: manual native\n")
        self.context = self.root / "context"
        self.context.mkdir()
        for name in ("data.json", "deprels.json", "edeprels.json", "feats.json", "tospace.json", "udeprels.json", "upos.json"):
            (self.context / name).write_text("{}")
        self.base = {"working_tree_path": str(self.root), "ud_context_path": str(self.context), "options": {"language_code": "en"}}
        self.fake_report = {"passed": True, "incidents": [], "coverage": {"content": "completed"}}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def plan(self) -> dict:
        with patch("ud_agent.domain.validation.validation_report", return_value=self.fake_report):
            return release.release_plan({**self.base, "target_release": "2.99"})

    def build(self) -> dict:
        (self.root / "plan.json").write_text(json.dumps(self.plan()))
        observed = []
        def validate(args):
            package_path = Path(args["working_tree_path"]) / self.tree.name
            observed.append(package_path.read_bytes())
            return self.fake_report
        with patch("ud_agent.domain.validation.validation_report", side_effect=validate):
            result = release.release_candidate_build({**self.base, "release_plan_path": "plan.json", "output_dir_path": "/requested/output"})
        self.assertEqual(observed, [self.tree.read_bytes()])
        return result

    def test_release_plan_hashes_current_bytes(self) -> None:
        result = self.plan()
        self.assertTrue(result["ready"])
        entry = next(item for item in result["files"] if item["path"] == self.tree.name)
        self.assertEqual(entry["sha256"], sha256(self.tree.read_bytes()).hexdigest())

    def test_candidate_is_archive_readback_and_does_not_export_itself(self) -> None:
        result = self.build()
        self.assertTrue(result["ready"])
        self.assertEqual(result["output_dir_path"], "/requested/output")
        package = base64.b64decode(result["artifacts"][0]["content_base64"])
        entries = read_archive(package)
        self.assertEqual(entries[self.tree.name], self.tree.read_bytes())
        self.assertEqual(entries[release.MANIFEST_NAME], json.dumps(result["manifest"], ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
        self.assertFalse((self.root / "release-candidate.tar").exists())

    def test_stale_plan_is_conflict(self) -> None:
        (self.root / "plan.json").write_text(json.dumps(self.plan()))
        self.tree.write_text("modified")
        with self.assertRaises(WorkerError) as error:
            release.release_candidate_build({**self.base, "release_plan_path": "plan.json", "output_dir_path": "/out"})
        self.assertEqual(error.exception.code, "CONFLICT")

    def test_changed_archive_contents_cannot_pass_validation(self) -> None:
        (self.root / "plan.json").write_text(json.dumps(self.plan()))
        def corrupt(files):
            return archive({**files, self.tree.name: b"different packaged bytes"})
        with patch("ud_agent.domain.release.archive", side_effect=corrupt):
            with self.assertRaises(WorkerError) as error:
                release.release_candidate_build({**self.base, "release_plan_path": "plan.json", "output_dir_path": "/out"})
        self.assertEqual(error.exception.code, "PACKAGE_MISMATCH")

    def test_missing_validator_is_incomplete_not_pass(self) -> None:
        with patch("ud_agent.domain.validation._validator", side_effect=PrerequisiteMissing("official validator unavailable")):
            plan = release.release_plan({**self.base, "target_release": "2.99"})
        self.assertFalse(plan["ready"])
        self.assertIsNone(plan["validation"]["passed"])
        self.assertEqual(plan["status"], "incomplete")

    def test_deposit_validates_archive_and_only_returns_preparation(self) -> None:
        result = self.build()
        candidate = base64.b64decode(result["artifacts"][0]["content_base64"])
        (self.root / "candidate.tar").write_bytes(candidate)
        (self.root / "deposit.json").write_text(json.dumps({"title": "Example", "license": "CC-BY-SA-4.0"}))
        with patch("ud_agent.domain.validation.validation_report", return_value=self.fake_report):
            deposit = release.release_deposit_prepare({**self.base, "release_candidate_path": "candidate.tar", "deposit_metadata_path": "deposit.json", "output_dir_path": "/out"})
        self.assertTrue(deposit["ready"])
        item = json.loads(base64.b64decode(deposit["artifacts"][0]["content_base64"]))
        self.assertEqual(item["candidate_sha256"], sha256(candidate).hexdigest())
        self.assertIn("does not upload", item["external_action"])

    def test_hostile_archive_rejected(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            item = tarfile.TarInfo("../escape")
            item.size = 1
            tar.addfile(item, io.BytesIO(b"x"))
        with self.assertRaises(InvalidInput):
            read_archive(output.getvalue())

    def test_treebank_snapshot_returns_exact_bytes_without_writing(self) -> None:
        result = workspace.treebank_snapshot({**self.base, "file_paths": [self.tree.name], "output_dir_path": "/out"})
        self.assertEqual(base64.b64decode(result["artifacts"][0]["content_base64"]), self.tree.read_bytes())
        self.assertFalse((self.root / "snapshot-manifest.json").exists())

    def test_treebank_create_returns_candidates_and_conflicts(self) -> None:
        (self.root / "metadata.json").write_text(json.dumps({"treebank_name": "UD_Test-X", "language_code": "en"}))
        args = {**self.base, "metadata_path": "metadata.json"}
        self.assertEqual(workspace.treebank_create(args)["status"], "conflict")
        self.readme.unlink()
        result = workspace.treebank_create(args)
        self.assertEqual(result["status"], "candidate")
        self.assertFalse(self.readme.exists())
        text = base64.b64decode(next(x for x in result["changes"] if x["file_path"] == "README.md")["content_base64"])
        self.assertIn(b"UD_Test-X", text)

    def test_sync_plan_rejects_stale_or_missing_evidence(self) -> None:
        (self.root / "repo").mkdir()
        result = workspace.workspace_sync_plan({**self.base, "repository_specs": [{"path": "repo", "local_revision": "abc"}]})
        self.assertEqual(result["status"], "incomplete")
        timestamp = datetime.now(timezone.utc).isoformat()
        result = workspace.workspace_sync_plan({**self.base, "repository_specs": [{"path": "repo", "local_revision": "abc", "remote_snapshot": {"revision": "abc", "retrieved_at": timestamp}}]})
        self.assertEqual(result["repositories"][0]["status"], "matching_snapshots")

    def test_treebank_review_requires_attested_base(self) -> None:
        args = {**self.base, "base_revision": "abc", "peer_treebank_paths": []}
        self.assertEqual(workspace.treebank_review(args)["status"], "incomplete")
        base = self.root / "base"
        base.mkdir()
        old = b"old content"
        (base / self.tree.name).write_bytes(old)
        receipt = {"revision": "abc", "path": "base", "files": {self.tree.name: sha256(old).hexdigest()}}
        result = workspace.treebank_review({**args, "file_paths": [self.tree.name], "options": {"base_snapshot": receipt}})
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["revision_attestation"], "unverified")
        self.assertEqual(result["changes"][0]["kind"], "modified")
        self.assertEqual(result["changes"][0]["before_sha256"], sha256(old).hexdigest())

    def test_maintenance_policy_reports_missing_and_stale_data(self) -> None:
        (self.root / "policy.json").write_text(json.dumps({"required_files": ["README.md", "MISSING"], "require_remote_evidence": True}))
        result = maintenance.maintenance_report({**self.base, "maintenance_policy_path": "policy.json"})
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["passed"])
        self.assertEqual(next(c for c in result["checks"] if c.get("path") == "MISSING")["passed"], False)

    def test_handover_archive_includes_only_selected_files(self) -> None:
        (self.root / ".env").write_text("secret")
        result = maintenance.handover_package_build({**self.base, "output_dir_path": "/out"})
        package = read_archive(base64.b64decode(result["artifacts"][0]["content_base64"]))
        self.assertIn(self.tree.name, package)
        self.assertNotIn(".env", package)

    def test_rename_plan_is_reviewable_without_writes(self) -> None:
        (self.root / "identity.json").write_text(json.dumps({"old_name": "en_test", "new_name": "en_new"}))
        before = self.tree.read_bytes()
        result = maintenance.treebank_rename_plan({**self.base, "new_identity_path": "identity.json", "related_repository_paths": []})
        action = next(a for a in result["actions"] if a["type"] == "rename_file")
        self.assertEqual(action["destination"], "en_new-ud-train.conllu")
        self.assertEqual(self.tree.read_bytes(), before)
        self.assertFalse((self.root / action["destination"]).exists())

    def test_star_rating_does_not_assume_missing_validator(self) -> None:
        result = maintenance.star_rating_report(self.base)
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["stars"])
        with patch("ud_agent.domain.validation.validation_report", return_value=self.fake_report):
            complete = maintenance.star_rating_report(self.base)
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(complete["weights"]["size"], 10)
        self.assertEqual(complete["word_count"], 2)
        self.assertEqual(complete["validation"]["passed"], True)


if __name__ == "__main__":
    unittest.main()
