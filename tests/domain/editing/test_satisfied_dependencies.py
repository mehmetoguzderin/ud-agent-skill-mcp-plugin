"""Original plan-handler tests; synthetic trusted transport evidence is explicit."""
import copy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from ud_agent.domain.plans import plan_apply
from ud_agent.evidence import broker_evidence
from ud_agent.errors import InvalidInput


def digest(value):
    return sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def create(ident, file, content, dependencies=None):
    return {"id": ident, "type": "create_file", "file_path": file, "content": content,
            "before_sha256": None, "after_sha256": digest(content), "depends_on": dependencies or []}


class SatisfiedDependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ud-plan-proof-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipt_path = self.root / ".ud-agent-inputs/plan-state/manifest.json"
        self.receipt_path.parent.mkdir(parents=True)

    def prepare(self, actions, states, satisfied=None):
        raw = json.dumps({"schema_version": "ud-plan-v1", "actions": actions}).encode()
        (self.root / "plan.json").write_bytes(raw)
        receipt = {"schema_version": 1, "plan_path": "plan.json", "plan_sha256": digest(raw),
                   "selected_action_ids": ["selected"], "satisfied_action_ids": satisfied or ["dependency"],
                   "states": [{"path": key, "sha256": value} for key, value in states.items()]}
        encoded = json.dumps(receipt).encode()
        self.receipt_path.write_bytes(encoded)
        metadata = {"schema_version": 1, "snapshot_sha256": "a" * 64,
                    "plan_state": {"manifest_path": ".ud-agent-inputs/plan-state/manifest.json", "sha256": digest(encoded)}}
        return {"working_tree_path": str(self.root), "plan_path": "plan.json", "selected_action_ids": ["selected"]}, metadata

    def test_present_and_absent_complete_postconditions_skip_only_unselected_dependencies(self):
        (self.root / "ready.txt").write_bytes(b"already\r\n")
        dependencies = [create("present", "ready.txt", "already\r\n"),
                        {"id": "absent", "type": "delete_file", "file_path": "gone.txt", "before_sha256": digest("old"), "after_sha256": None, "depends_on": []}]
        selected = create("selected", "result.txt", "selected only", ["present", "absent"])
        args, evidence = self.prepare(dependencies + [selected], {"ready.txt": digest("already\r\n"), "gone.txt": None}, ["present", "absent"])
        with broker_evidence(evidence, "a" * 64):
            result = plan_apply(args)
        self.assertEqual(result["details"], {"selected_action_ids": ["selected"], "satisfied_action_ids": ["present", "absent"]})
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["file_operations"], [{"operation": "create", "file_path": "result.txt", "before_sha256": None, "after_sha256": digest("selected only"), "content": "selected only"}])
        self.assertEqual((self.root / "ready.txt").read_bytes(), b"already\r\n")
        self.assertFalse((self.root / "result.txt").exists())

    def test_user_arguments_and_snapshot_omission_cannot_authorize_absence(self):
        dependency = {"id": "dependency", "type": "delete_file", "file_path": "gone.txt", "before_sha256": digest("old"), "after_sha256": None, "depends_on": []}
        args, metadata = self.prepare([dependency, create("selected", "result.txt", "no", ["dependency"])], {})
        with self.assertRaisesRegex(InvalidInput, "verified broker"):
            plan_apply({**args, "broker_evidence": metadata})
        with broker_evidence(metadata, "a" * 64), self.assertRaisesRegex(InvalidInput, "not proven"):
            plan_apply(args)
        self.assertFalse((self.root / "result.txt").exists())

    def test_receipt_plan_selection_hash_and_staged_bytes_are_bound(self):
        (self.root / "ready.txt").write_text("ready")
        args, metadata = self.prepare([create("dependency", "ready.txt", "ready"), create("selected", "result.txt", "no", ["dependency"])], {"ready.txt": digest("ready")})
        original = self.receipt_path.read_bytes()
        for field, value in [("plan_sha256", "b" * 64), ("plan_path", "other.json"), ("selected_action_ids", []), ("satisfied_action_ids", [])]:
            with self.subTest(field=field):
                receipt = json.loads(original)
                receipt[field] = value
                raw = json.dumps(receipt).encode()
                self.receipt_path.write_bytes(raw)
                forged = copy.deepcopy(metadata)
                forged["plan_state"]["sha256"] = digest(raw)
                with broker_evidence(forged, "a" * 64), self.assertRaisesRegex(InvalidInput, "does not match"):
                    plan_apply(args)
        self.receipt_path.write_bytes(original)
        forged = copy.deepcopy(metadata)
        forged["plan_state"]["sha256"] = "c" * 64
        with broker_evidence(forged, "a" * 64), self.assertRaisesRegex(InvalidInput, "fingerprint"):
            plan_apply(args)
        (self.root / "ready.txt").write_text("changed")
        with broker_evidence(metadata, "a" * 64), self.assertRaisesRegex(InvalidInput, "staged bytes"):
            plan_apply(args)
        with self.assertRaisesRegex(InvalidInput, "verified snapshot"):
            with broker_evidence(metadata, "f" * 64):
                self.fail("mismatched snapshot context was installed")

    def test_supported_rename_and_replacement_effects_are_derived_from_action_bytes(self):
        (self.root / "new.txt").write_text("renamed bytes")
        (self.root / "rewritten.txt").write_text("renamed and rewritten")
        (self.root / "replaced.txt").write_text("final bytes")
        dependencies = [{"id": "rename", "type": "rename_file", "source": "old.txt", "destination": "new.txt", "before_sha256": digest("renamed bytes"), "target_before_sha256": None, "depends_on": []},
                        {"id": "rename-content", "type": "rename_file", "file_path": "previous.txt", "target_file_path": "rewritten.txt", "before_sha256": digest("original bytes"), "target_before_sha256": None, "after_sha256": digest("renamed and rewritten"), "content": "renamed and rewritten", "conflict": False, "depends_on": ["rename"]},
                        {"id": "replace", "type": "replace_file", "file_path": "replaced.txt", "before_sha256": digest("historical"), "after_sha256": digest("final bytes"), "content": "final bytes", "depends_on": ["rename-content"]}]
        args, metadata = self.prepare(dependencies + [create("selected", "result.txt", "only selected", ["replace"])], {"old.txt": None, "new.txt": digest("renamed bytes"), "previous.txt": None, "rewritten.txt": digest("renamed and rewritten"), "replaced.txt": digest("final bytes")}, ["rename", "rename-content", "replace"])
        with broker_evidence(metadata, "a" * 64):
            result = plan_apply(args)
        self.assertEqual([item["file_path"] for item in result["file_operations"]], ["result.txt"])
        self.assertEqual(result["details"]["satisfied_action_ids"], ["rename", "rename-content", "replace"])

    def test_unchanged_structural_text_or_context_claims_remain_unprovable(self):
        (self.root / "ready.txt").write_text("unchanged")
        for kind in ["token_split", "replace_text", "prepare_context"]:
            with self.subTest(kind=kind):
                dependency = {"id": "dependency", "type": kind, "file_path": "ready.txt", "after_sha256": digest("unchanged"), "postconditions": {"ready.txt": digest("unchanged")}, "depends_on": []}
                args, metadata = self.prepare([dependency, create("selected", "result.txt", "no", ["dependency"])], {"ready.txt": digest("unchanged")})
                with broker_evidence(metadata, "a" * 64), self.assertRaisesRegex(InvalidInput, "unsupported or unprovable"):
                    plan_apply(args)
        self.assertFalse((self.root / "result.txt").exists())

    def test_missing_dependency_cycles_and_maximum_depth_are_controlled(self):
        for dependencies in [["missing"], ["selected"]]:
            args, _ = self.prepare([create("selected", "result.txt", "no", dependencies)], {})
            with self.assertRaises(InvalidInput):
                plan_apply(args)
        actions = [create(str(index), f"out-{index}.txt", "", [str(index - 1)] if index else []) for index in range(1000)]
        (self.root / "plan.json").write_text(json.dumps({"schema_version": "ud-plan-v1", "actions": actions}))
        result = plan_apply({"working_tree_path": str(self.root), "plan_path": "plan.json", "selected_action_ids": [str(index) for index in range(1000)]})
        self.assertEqual(len(result["file_operations"]), 1000)
        self.assertEqual([item["file_path"] for item in result["file_operations"]], [f"out-{index}.txt" for index in range(1000)])
