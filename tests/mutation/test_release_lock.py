from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release/lock_holder.py"
PYTHON = sys._base_executable if os.name == 'nt' else sys.executable


class ReleaseLockTests(unittest.TestCase):
    def start(self, filename):
        # Windows venv python.exe is a redirector with a different worker PID.
        # This stdlib-only lock fixture starts the selected base interpreter.
        child = subprocess.Popen([PYTHON, "-I", str(SCRIPT), str(filename), "--timeout", "1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            message = json.loads(child.stdout.readline())
            self.assertEqual(message, {"schema_version": 1, "locked": True, "pid": child.pid})
            return child
        except BaseException:
            child.kill(); child.communicate(timeout=3); raise

    def test_lock_excludes_a_second_holder_and_recovers_after_process_death(self):
        with tempfile.TemporaryDirectory(prefix="ud-release-lock-") as temporary:
            filename = Path(temporary) / ".lock"
            first = self.start(filename)
            try:
                blocked = subprocess.run([sys.executable, "-I", str(SCRIPT), str(filename), "--timeout", "0.1"], input="", capture_output=True, text=True, timeout=3)
                self.assertNotEqual(blocked.returncode, 0)
                self.assertIn("timed out", blocked.stderr)
            finally:
                first.kill()
                first.communicate(timeout=3)
            second = self.start(filename)
            second.communicate(input="", timeout=3)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(filename.read_bytes(), b"\0")

    def test_rejects_invalid_lock_files_and_unix_symlink_paths(self):
        with tempfile.TemporaryDirectory(prefix="ud-release-lock-") as temporary:
            filename = Path(temporary) / ".lock"
            filename.write_bytes(b"invalid oversized lock")
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), str(filename)], input="", capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private and owned", result.stderr)
            if os.name == "nt":
                return  # Windows reparse-point acceptance is a separate native row.
            filename.write_bytes(b"\0")
            filename.chmod(0o666)
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), str(filename)], input="", capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private and owned", result.stderr)
            filename.unlink()
            (Path(temporary) / "target").write_bytes(b"\0")
            filename.symlink_to("target")
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), str(filename)], input="", capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
