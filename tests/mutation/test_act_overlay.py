from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("act_overlay", ROOT / "scripts/quality/act_overlay.py")
overlay_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay_module)


class ActOverlayTests(unittest.TestCase):
    def test_ci_caches_only_the_verified_sdk_outputs(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        workflow = overlay_module.yaml.load(source, Loader=overlay_module.WorkflowLoader)
        steps = workflow['jobs']['mutation-sdk']['steps']
        cache = next(step for step in steps if step.get('name') == 'Restore only the exact SDK cache')
        transfer = next(step for step in steps if step.get('name') == "Transfer the verified SDK to this run's ARM test job")
        expected = {
            '.artifacts/mutation-ci-sdk/sdk-image.tar',
            '.artifacts/mutation-ci-sdk/ci-sdk.json',
            '.artifacts/mutation-ci-sdk/input-receipt.json',
        }
        self.assertEqual(set(cache['with']['path'].splitlines()), expected)
        self.assertEqual(set(transfer['with']['path'].splitlines()), expected)

    def test_preserves_real_workflow_steps_and_uses_canonical_owned_cache(self):
        source = (ROOT / ".github/workflows/ci.yml").read_bytes()
        image = "ghcr.io/catthehacker/ubuntu@sha256:" + "a" * 64
        overlay, receipt = overlay_module.generate(source, "native", "amd64", "1" * 32, image)
        original = overlay_module.yaml.load(source.decode(), Loader=overlay_module.WorkflowLoader)
        self.assertIn("on", original)
        self.assertEqual(overlay["jobs"]["native"]["steps"], original["jobs"]["native"]["steps"])
        self.assertEqual(overlay["permissions"], original["permissions"])
        self.assertEqual(overlay["jobs"]["native"]["container"]["volumes"], [
            "act-toolcache:/ud-agent-unused-shared-toolcache",
            "ud-agent-act-" + "1" * 32 + "-amd64:/opt/hostedtoolcache",
        ])
        self.assertEqual(receipt["qualification"], "local_actions_emulation_only")
        self.assertTrue(receipt["init_process"])
        self.assertIn("--init", overlay["jobs"]["native"]["container"]["options"].split())
        self.assertEqual(receipt["overlay_jobs"], ["native"])
        self.assertNotIn("needs", overlay["jobs"]["native"])
        self.assertNotIn("container", overlay["jobs"]["mutation-sdk"])
        self.assertNotIn("container", overlay["jobs"]["native-arm"])
        changed = copy.deepcopy(overlay)
        changed["jobs"]["native"]["steps"].pop()
        with self.assertRaisesRegex(ValueError, "behavior"):
            overlay_module.verify(original, changed, "native", receipt["toolcache_volume"], image)

    def test_sdk_dependency_and_native_keep_exact_steps_and_share_only_owned_cache(self):
        source = (ROOT / ".github/workflows/ci.yml").read_bytes()
        image = "ghcr.io/catthehacker/ubuntu@sha256:" + "a" * 64
        overlay, receipt = overlay_module.generate(source, "native-arm", "arm64", "2" * 32, image, ("mutation-sdk",), 987)
        original = overlay_module.yaml.load(source.decode(), Loader=overlay_module.WorkflowLoader)
        self.assertEqual(receipt["overlay_jobs"], ["native-arm", "mutation-sdk"])
        self.assertEqual(overlay["jobs"]["native-arm"]["needs"], "mutation-sdk")
        self.assertNotIn("container", overlay["jobs"]["native"])
        self.assertEqual(original["jobs"]["native"]["steps"], original["jobs"]["native-arm"]["steps"])
        for name in receipt["overlay_jobs"]:
            self.assertEqual(overlay["jobs"][name]["steps"], original["jobs"][name]["steps"])
            self.assertEqual(overlay["jobs"][name]["container"]["volumes"][1], receipt["toolcache_volume"] + ":/opt/hostedtoolcache")
            self.assertIn("--group-add 987", overlay["jobs"][name]["container"]["options"])
            self.assertIn("--init", overlay["jobs"][name]["container"]["options"].split())
        changed = copy.deepcopy(overlay); changed["jobs"]["mutation-sdk"]["steps"].pop()
        with self.assertRaisesRegex(ValueError, "behavior"):
            overlay_module.verify(original, changed, "native-arm", receipt["toolcache_volume"], image, ("mutation-sdk",), 987)

    def test_rejects_ambiguous_or_unpinned_overlays(self):
        image = "ghcr.io/catthehacker/ubuntu@sha256:" + "a" * 64
        base = b"on: push\njobs:\n  native:\n    steps: [{run: 'true'}]\n"
        for arch, owner, selected in [("x64", "1" * 32, image), ("amd64", "../x", image), ("amd64", "1" * 32, "ubuntu:latest")]:
            with self.assertRaises(ValueError):
                overlay_module.generate(base, "native", arch, owner, selected)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            overlay_module.generate(b"jobs: {}\njobs: {}\n", "native", "amd64", "1" * 32, image)
        with self.assertRaisesRegex(ValueError, "nonempty"):
            overlay_module.generate(base, "absent", "amd64", "1" * 32, image)

    def test_local_sdk_removes_only_download_and_preserves_verification_and_tests(self):
        source = (ROOT / ".github/workflows/ci.yml").read_bytes()
        image = "ghcr.io/catthehacker/ubuntu@sha256:" + "a" * 64
        original = overlay_module.yaml.load(source.decode(), Loader=overlay_module.WorkflowLoader)
        overlay, receipt = overlay_module.generate(source, "native-arm", "arm64", "3" * 32, image, ("mutation-sdk",), local_sdk=True)
        expected_steps = [step for step in original["jobs"]["native-arm"]["steps"] if step.get("name") != "Receive the selected run's verified native ARM SDK"]
        self.assertEqual(len(expected_steps), len(original["jobs"]["native-arm"]["steps"]) - 1)
        self.assertEqual(overlay["jobs"]["native-arm"]["steps"], expected_steps)
        self.assertEqual(overlay["jobs"]["native"]["steps"], original["jobs"]["native"]["steps"])
        self.assertEqual(overlay["jobs"]["mutation-sdk"]["steps"], original["jobs"]["mutation-sdk"]["steps"])
        self.assertEqual(receipt["sdk_transport"], "verified-local-staging")
        with self.assertRaisesRegex(ValueError, "behavior"):
            overlay_module.verify(original, overlay, "native-arm", receipt["toolcache_volume"], image, ("mutation-sdk",))
        for step_name in ("Verify and import the exact native ARM SDK image", "Complete original tests and bounded mutations on native Linux ARM64"):
            changed = copy.deepcopy(overlay)
            changed["jobs"]["native-arm"]["steps"] = [step for step in changed["jobs"]["native-arm"]["steps"] if step.get("name") != step_name]
            with self.assertRaisesRegex(ValueError, "behavior"):
                overlay_module.verify(original, changed, "native-arm", receipt["toolcache_volume"], image, ("mutation-sdk",), local_sdk=True)

    def test_local_sdk_refuses_other_targets_or_ambiguous_downloads(self):
        source = (ROOT / ".github/workflows/ci.yml").read_bytes()
        image = "ghcr.io/catthehacker/ubuntu@sha256:" + "a" * 64
        for job, architecture in (("native", "arm64"), ("native-arm", "amd64")):
            with self.assertRaisesRegex(ValueError, "only permitted"):
                overlay_module.generate(source, job, architecture, "4" * 32, image, local_sdk=True)
        original = overlay_module.yaml.load(source.decode(), Loader=overlay_module.WorkflowLoader)
        download = next(step for step in original["jobs"]["native-arm"]["steps"] if step.get("name") == "Receive the selected run's verified native ARM SDK")
        for replacements in ([], [download, download], [{**download, "uses": "actions/upload-artifact@" + "a" * 40}]):
            changed = copy.deepcopy(original)
            changed["jobs"]["native-arm"]["steps"] = [step for step in changed["jobs"]["native-arm"]["steps"] if step.get("name") != download["name"]] + replacements
            with self.assertRaisesRegex(ValueError, "SDK"):
                overlay_module.generate(overlay_module.canonical(changed), "native-arm", "arm64", "4" * 32, image, local_sdk=True)


if __name__ == "__main__":
    unittest.main()
