import hashlib
import importlib.util
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ud_agent.domain.validation import _project_pipe_child, project_consistency_report
from ud_agent.errors import InvalidInput, WorkerError


class ProjectValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-project-validator-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "bank"
        self.root.mkdir()
        (self.root / "a.conllu").write_text("# sent_id = a\n1\ta\t_\tX\t_\t_\t0\troot\t_\t_\n\n", encoding="utf-8")
        self.rules = base / "rules"
        self.rules.mkdir()
        for name in ("upos", "feats", "udeprels", "deprels", "edeprels", "data", "tospace"):
            (self.rules / f"{name}.json").write_text("{}", encoding="utf-8")
        upstream = base / "upstream/udtools"
        upstream.mkdir(parents=True)
        (upstream / "__init__.py").write_text('''import json, os\nfrom pathlib import Path\nclass Incident:\n def json(self): return json.dumps({"testid":"official-only"})\nclass State:\n def __init__(self, passed): self.value=passed; self.error_tracker=[] if passed else [Incident()]\n def passed(self): return self.value\nclass Validator:\n def __init__(self, **kwargs): pass\n def validate_files(self, files):\n  Path(files[0]).with_name("official.pid").write_text(str(os.getpid()))\n  return State(False)\n''', encoding="utf-8")
        spec = importlib.util.spec_from_file_location("udtools", upstream / "__init__.py")
        self.assertIsNotNone(spec)
        fake = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fake)
        self.module_patch = patch.dict(sys.modules, {"udtools": fake})
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.source = b'''from udtools import Validator, State\nimport os\nfrom pathlib import Path\nclass Project(Validator):\n def validate_files(self, files):\n  Path(files[0]).with_name("project.pid").write_text(str(os.getpid()))\n  return State(True)\n'''
        (self.root / "project.py").write_bytes(self.source)
        self.args = {"working_tree_path": str(self.root), "validator_module_path": "project.py",
                     "validator_class_name": "Project", "ud_context_path": str(self.rules),
                     "options": {"language_code": "en", "level": 2}}

    def test_official_checks_run_independently_from_project_subclass(self):
        report = project_consistency_report(self.args)
        self.assertFalse(report["passed"])
        self.assertFalse(report["official"]["passed"])
        self.assertEqual(report["official"]["incidents"][0]["testid"], "official-only")
        self.assertTrue(report["project"]["passed"])
        self.assertEqual(report["project"]["coverage"]["content"], "project_checks_only")
        self.assertEqual(report["provenance"]["source_sha256"], hashlib.sha256(self.source).hexdigest())
        self.assertNotEqual((self.root / "official.pid").read_text(), (self.root / "project.pid").read_text())
        self.assertNotEqual((self.root / "official.pid").read_text(), str(os.getpid()))

    def test_rejects_paths_outside_the_snapshot_and_non_validator_classes(self):
        with self.assertRaises(InvalidInput):
            project_consistency_report({**self.args, "validator_module_path": "../project.py"})
        (self.root / "project.py").write_text("class Project: pass\n", encoding="utf-8")
        with self.assertRaises(WorkerError) as error:
            project_consistency_report(self.args)
        self.assertEqual(error.exception.code, "INVALID_INPUT")

    def test_project_failure_is_not_a_successful_official_report(self):
        (self.root / "project.py").write_text("raise RuntimeError('sensitive detail')\n", encoding="utf-8")
        with self.assertRaises(WorkerError) as error:
            project_consistency_report(self.args)
        self.assertEqual(error.exception.code, "PROJECT_VALIDATOR_FAILED")
        self.assertNotIn("sensitive detail", str(error.exception))

    def test_private_pipe_keeps_project_prints_out_of_separate_validation_results(self):
        (self.root / "project.py").write_bytes(b"import subprocess, sys\nprint('project stdout is not structured evidence')\nsubprocess.run([sys.executable, '-I', '-c', \"print('nested stdout is not evidence')\"], check=True)\n" + self.source)
        # Exercise the actual pipe transport on every host, including the
        # Windows selection path; this is not native Windows handle evidence.
        with patch("ud_agent.domain.validation.sys.platform", "win32"):
            report = project_consistency_report(self.args)
        self.assertFalse(report["official"]["passed"])
        self.assertTrue(report["project"]["passed"])
        self.assertNotEqual((self.root / "official.pid").read_text(), (self.root / "project.pid").read_text())

    def test_private_pipe_is_bounded_even_when_child_writes_directly(self):
        command = [sys.executable, "-I", "-c", "import os; os.write(1, b'x' * 65536)"]
        with self.assertRaises(WorkerError) as error:
            _project_pipe_child(command, b"{}", dict(os.environ), limit=1024)
        self.assertEqual(error.exception.code, "PROJECT_VALIDATOR_FAILED")
        self.assertIn("exceeded", str(error.exception))

    def test_private_pipe_deadline_stops_a_child_without_output(self):
        command = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
        with self.assertRaises(subprocess.TimeoutExpired):
            _project_pipe_child(command, b"{}", dict(os.environ), timeout=0.1)


if __name__ == "__main__":
    unittest.main()
