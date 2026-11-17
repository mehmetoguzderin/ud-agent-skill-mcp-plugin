"""Renderer ownership rules independent of Chromium and platform execution."""
import json
import subprocess
import sys
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ud_agent import render_process

BROWSER = str(Path("/verified/browser").absolute())


class RenderProcessTests(unittest.TestCase):
    def setUp(self):
        # These cases model Linux syscalls; retain real filesystem paths for
        # portable request fixtures and supply only absent Linux constants.
        for owner, name, value in [(render_process.os, "WNOHANG", 1), (render_process.signal, "SIGKILL", 9)]:
            mock = patch.object(owner, name, getattr(owner, name, value), create=True)
            mock.start(); self.addCleanup(mock.stop)

    def test_subreaper_requests_and_verifies_exact_linux_process_adoption(self):
        library = MagicMock()
        def prctl(command, *arguments):
            if command == 36:
                return 0 if arguments == (1, 0, 0, 0) else -1
            if command == 37 and len(arguments) == 4 and arguments[1:] == (0, 0, 0) and hasattr(arguments[0], "_obj"):
                arguments[0]._obj.value = 1
                return 0
            return -1
        library.prctl.side_effect = prctl
        child = MagicMock(); child.poll.return_value = 0; child.wait.return_value = 0
        with patch.object(render_process.ctypes, "CDLL", return_value=library) as load, patch.object(render_process.sys, "platform", "linux"), patch.object(render_process.sys, "argv", ["render_process", json.dumps([BROWSER])]), patch.object(render_process, "_affinity"), patch.object(render_process, "_cleanup"), patch.object(render_process.subprocess, "Popen", return_value=child):
            self.assertEqual(render_process.main(), 0)
        load.assert_called_once_with(None, use_errno=True)
        self.assertEqual(library.prctl.call_args_list[0].args, (36, 1, 0, 0, 0))
        self.assertEqual(library.prctl.call_args_list[1].args[0], 37)
        self.assertEqual(library.prctl.call_args_list[1].args[2:], (0, 0, 0))
        for results in [[0, -1], [0, 0]]:
            library = MagicMock(); library.prctl.side_effect = results
            with patch.object(render_process.ctypes, "CDLL", return_value=library):
                with self.assertRaisesRegex(RuntimeError, "^renderer child adoption was not verified$"): render_process._subreaper()
        library = MagicMock(); library.prctl.return_value = -1
        with patch.object(render_process.ctypes, "CDLL", return_value=library), patch.object(render_process.ctypes, "get_errno", return_value=13):
            with self.assertRaises(OSError) as raised: render_process._subreaper()
        self.assertEqual((raised.exception.errno, raised.exception.strerror), (13, "renderer child adoption failed"))

    def test_process_request_rejects_relative_programs_and_invalid_deadlines(self):
        for command, timeout in [([], 50), (["browser"], 50), (["/browser", "bad\x00argument"], 50), (["/browser"], 0), (["/browser"], 51)]:
            with patch.object(render_process.sys, "platform", "linux"):
                with self.assertRaises(ValueError):
                    render_process.run(command, timeout)

    def test_affinity_selects_a_subset_and_verifies_the_result(self):
        with patch.object(render_process.os, "sched_getaffinity", side_effect=[{3, 5, 9}, {3, 5}], create=True), patch.object(render_process.os, "sched_setaffinity", create=True) as select:
            render_process._affinity()
            select.assert_called_once_with(0, {3, 5})
        with patch.object(render_process.os, "sched_getaffinity", side_effect=[{3, 5, 9}, {3, 9}], create=True), patch.object(render_process.os, "sched_setaffinity", create=True):
            with self.assertRaisesRegex(RuntimeError, "not verified"):
                render_process._affinity()

    def test_cleanup_reaps_completed_owned_children_until_no_children_remain(self):
        with patch.object(render_process.os, "waitpid", side_effect=[(41, 0), (42, 0), ChildProcessError()]) as wait, patch.object(render_process, "_kill_children") as kill:
            render_process._cleanup()
            self.assertEqual(wait.call_count, 3)
            kill.assert_not_called()

    def test_cleanup_signals_only_its_pidfd_bound_children(self):
        def content(path, **_kwargs):
            return "41 42" if path.as_posix().endswith("/children") else "41 (owned child) S 123 0 0" if "/41/" in path.as_posix() else "42 (unrelated) S 999 0 0"
        with patch.object(render_process.os, "getpid", return_value=123), patch.object(render_process.Path, "read_text", content), patch.object(render_process.os, "pidfd_open", side_effect=[81, 82], create=True), patch.object(render_process.signal, "pidfd_send_signal", create=True) as send, patch.object(render_process.os, "close") as close:
            render_process._kill_children()
            send.assert_called_once_with(81, render_process.signal.SIGKILL)
            self.assertEqual([call.args for call in close.call_args_list], [(81,), (82,)])

    def test_unreaped_owned_children_fail_instead_of_claiming_cleanup(self):
        with patch.object(render_process.os, "waitpid", return_value=(0, 0)), patch.object(render_process, "_kill_children"), patch.object(render_process.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(RuntimeError, "cleanup was not verified"):
                render_process._cleanup()

    def test_browser_exit_preserves_code_and_always_verifies_its_own_cleanup(self):
        child = MagicMock()
        child.poll.return_value = 0
        child.wait.return_value = 0
        with patch.object(render_process.sys, "platform", "linux"), patch.object(render_process, "_subreaper"), patch.object(render_process, "_affinity"), patch.object(render_process.subprocess, "Popen", return_value=child), patch.object(render_process, "_cleanup") as cleanup:
            self.assertEqual(render_process.run([BROWSER]), 0)
            cleanup.assert_called_once()
            child.kill.assert_not_called()

    def test_cli_failure_is_bounded_and_structured_as_a_failed_execution(self):
        with patch.object(render_process.sys, "argv", ["render_process", "invalid"]), patch("builtins.print") as output:
            self.assertEqual(render_process.main(), 126)
            self.assertTrue(output.call_args.args[0].startswith("RENDER_PROCESS_FAILED:"))

    def test_private_libraries_apply_only_to_browser_child_and_ambient_loader_hooks_are_removed(self):
        child = MagicMock(); child.poll.return_value = 0; child.wait.return_value = 0
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"LD_PRELOAD":"/ambient/code.so", "LD_AUDIT":"/ambient/audit.so", "LD_LIBRARY_PATH":"/ambient/libs"}), patch.object(render_process.sys,"platform","linux"), patch.object(render_process,"_subreaper"), patch.object(render_process,"_affinity"), patch.object(render_process,"_cleanup"), patch.object(render_process.subprocess,"Popen",return_value=child) as spawn:
            self.assertEqual(render_process.run([BROWSER],library_dirs=[str(Path(directory).resolve())]),0)
            environment=spawn.call_args.kwargs["env"]
            self.assertEqual(environment["LD_LIBRARY_PATH"],str(Path(directory).resolve()))
            self.assertNotIn("LD_PRELOAD",environment);self.assertNotIn("LD_AUDIT",environment)
            self.assertEqual(os.environ["LD_LIBRARY_PATH"],"/ambient/libs")
        for libraries in [[],[{}],["relative"],["/missing"],["/bad:separator"]]:
            with patch.object(render_process.sys,"platform","linux"), self.assertRaises(ValueError):render_process.run([BROWSER],library_dirs=libraries)

    def test_cli_retains_legacy_list_and_accepts_only_complete_private_library_frames(self):
        for frame,expected in [([BROWSER],None),({"command":[BROWSER],"library_dirs":["/owned/libs"]},["/owned/libs"])]:
            with patch.object(render_process.sys,"argv",["render",json.dumps(frame)]),patch.object(render_process,"run",return_value=0) as run:
                self.assertEqual(render_process.main(),0)
                if expected is None:run.assert_called_once_with([BROWSER])
                else:run.assert_called_once_with([BROWSER],library_dirs=expected)
        for frame in [{"command":[BROWSER]},{"command":[BROWSER],"library_dirs":None},{"command":[BROWSER],"library_dirs":["/owned/libs"],"extra":True}]:
            with patch.object(render_process.sys,"argv",["render",json.dumps(frame)]),patch.object(render_process,"run") as run,patch("builtins.print"):
                self.assertEqual(render_process.main(),126);run.assert_not_called()
