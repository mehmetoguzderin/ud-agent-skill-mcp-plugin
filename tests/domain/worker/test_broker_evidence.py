import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from ud_agent.domain import review, workspace
from ud_agent.errors import InvalidInput
from ud_agent.evidence import broker_evidence


def digest(data):
    return hashlib.sha256(data).hexdigest()


class BrokerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-broker-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.prior = b"# sent_id = a\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n\n"
        self.current = self.prior.replace(b"one", b"two")
        (self.root / "a.conllu").write_bytes(self.current)
        self.base_dir = self.root / ".ud-agent-inputs/base"
        self.base_dir.mkdir(parents=True)
        (self.base_dir / "a.conllu").write_bytes(self.prior)
        self.snapshot_name = ".ud-agent-inputs/base.json"
        (self.root / self.snapshot_name).write_text(json.dumps({"revision": "main~1", "files": {"a.conllu": {"content": self.prior.decode(), "sha256": digest(self.prior)}}}))
        self.snapshot_hash = "f" * 64
        self.metadata = {"schema_version": 1, "snapshot_sha256": self.snapshot_hash, "git_base": {
            "requested_revision": "main~1", "resolved_commit": "a" * 40, "tree_oid": "b" * 40,
            "files": {"a.conllu": {"sha256": digest(self.prior), "size_bytes": len(self.prior), "blob_oid": "c" * 40}},
            "base_directory_path": ".ud-agent-inputs/base", "base_snapshot_path": self.snapshot_name,
            "base_snapshot_sha256": digest((self.root / self.snapshot_name).read_bytes())}}
        self.args = {"working_tree_path": str(self.root), "base_revision": "main~1", "peer_treebank_paths": []}

    def test_attested_base_is_complete_and_default_current_scope_excludes_staged_inputs(self):
        with broker_evidence(self.metadata, self.snapshot_hash):
            report = workspace.treebank_review(self.args)
            changes = review.changes_review(self.args)
        self.assertEqual(report["status"], "complete")
        self.assertEqual([item["file_path"] for item in report["changes"]], ["a.conllu"])
        self.assertEqual(report["revision_attestation"]["resolved_commit"], "a" * 40)
        self.assertTrue(changes["coverage"]["base_identity_verified"])
        self.assertEqual(len(changes["changes"]), 1)
        # Evidence is scoped to a single worker request and does not leak.
        self.assertEqual(workspace.treebank_review(self.args)["status"], "incomplete")

    def test_caller_supplied_metadata_does_not_establish_trust(self):
        args = {**self.args, "options": {"base_snapshot": {"revision": "main~1", "path": ".ud-agent-inputs/base", "files": {"a.conllu": digest(self.prior)}}, "broker_evidence": self.metadata}}
        result = workspace.treebank_review(args)
        self.assertEqual(result["revision_attestation"], "unverified")
        self.assertEqual(result["status"], "incomplete")

    def test_wrong_snapshot_or_base_bytes_cannot_be_attested(self):
        with self.assertRaisesRegex(InvalidInput, "verified snapshot"):
            with broker_evidence(self.metadata, "0" * 64):
                pass
        (self.base_dir / "a.conllu").write_bytes(self.current)
        with broker_evidence(self.metadata, self.snapshot_hash), self.assertRaisesRegex(InvalidInput, "receipt"):
            workspace.treebank_review(self.args)

    def test_unlisted_base_file_is_not_accepted_as_complete_inventory(self):
        (self.base_dir / "extra.conllu").write_bytes(self.prior)
        with broker_evidence(self.metadata, self.snapshot_hash), self.assertRaisesRegex(InvalidInput, "inventory"):
            workspace.treebank_review(self.args)


if __name__ == "__main__":
    unittest.main()
