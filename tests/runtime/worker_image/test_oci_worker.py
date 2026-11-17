import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ud_agent import oci_worker
from ud_agent.oci_worker import verify_confinement, verify_snapshot
model_spec = importlib.util.spec_from_file_location('oci_worker_posix_model', Path(__file__).resolve().parents[2] / 'mutation/posix_file_model.py')
model = importlib.util.module_from_spec(model_spec); model_spec.loader.exec_module(model)


def manifest(entries):
    files = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in entries]
    digest = hashlib.sha256(json.dumps(files, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return files, digest


class OciWorkerTests(unittest.TestCase):
    def test_snapshot_rechecks_exact_bytes_and_inventory(self):
        with tempfile.TemporaryDirectory(prefix="ud-oci-worker-") as tmp:
            root = Path(tmp)
            self.enterContext(model.posix_files(oci_worker, root))
            (root / "a.conllu").write_bytes(b"a\r\n")
            files, digest = manifest([("a.conllu", b"a\r\n")])
            verify_snapshot(tmp, files, digest)
            (root / "a.conllu").write_bytes(b"b\r\n")
            with self.assertRaisesRegex(ValueError, "DIGEST_MISMATCH"):
                verify_snapshot(tmp, files, digest)
            (root / "a.conllu").write_bytes(b"a\r\n")
            (root / "extra").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "INVENTORY_INVALID"):
                verify_snapshot(tmp, files, digest)
            (root / "extra").unlink()
            (root / "a.conllu").unlink()
            (root / "a.conllu").symlink_to("/etc/passwd")
            with self.assertRaises(OSError):
                verify_snapshot(tmp, files, digest)

    def test_confinement_requires_actual_uid_network_mounts_and_limits(self):
        contents = {
            "/proc/self/status": "NoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nSeccomp:\t2\n",
            "/proc/self/mountinfo": "10 1 0:1 / / ro,relatime - overlay overlay ro\n11 1 0:2 / /input ro,relatime - ext4 /dev/x ro\n",
            "/proc/net/route": "Iface Destination Gateway Flags\n",
            "/proc/net/ipv6_route": "000000 00 000000 00 000000 000000 000000 000000 000000 lo\n",
            "/sys/class/net/tunl0/flags": "0x80\n",
            "/sys/fs/cgroup/memory.max": "2147483648\n",
            "/sys/fs/cgroup/pids.max": "128\n",
            "/sys/fs/cgroup/cpu.max": "200000 100000\n",
        }
        def read_text(path, *args, **kwargs):
            return contents[path.as_posix()]
        with patch.object(oci_worker.os, "geteuid", return_value=10001, create=True), patch.object(oci_worker.os, "getegid", return_value=10001, create=True), \
                patch("socket.if_nameindex", return_value=[(1, "lo")]), patch.object(Path, "read_text", read_text):
            verify_confinement()
            with patch("socket.if_nameindex", return_value=[(1, "lo"), (2, "tunl0")]):
                verify_confinement()
                contents["/sys/class/net/tunl0/flags"] = "0x81\n"
                with self.assertRaisesRegex(RuntimeError, "NETWORK_UNVERIFIED"):
                    verify_confinement()
                contents["/sys/class/net/tunl0/flags"] = "0x80\n"
            contents["/proc/self/status"] = contents["/proc/self/status"].replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000001000")
            with self.assertRaisesRegex(RuntimeError, "PRIVILEGES_UNVERIFIED"):
                verify_confinement()
            contents["/proc/self/status"] = contents["/proc/self/status"].replace("CapPrm:\t0000000000001000", "CapPrm:\t0000000000000000")
            contents["/sys/fs/cgroup/memory.max"] = "max\n"
            with self.assertRaisesRegex(RuntimeError, "LIMITS_UNVERIFIED"):
                verify_confinement()
            contents["/sys/fs/cgroup/memory.max"] = "2147483648\n"
            contents["/proc/self/mountinfo"] = contents["/proc/self/mountinfo"].replace("/input ro,", "/input rw,")
            with self.assertRaisesRegex(RuntimeError, "MOUNTS_UNVERIFIED"):
                verify_confinement()
        with patch.object(oci_worker.os, "geteuid", return_value=0, create=True), self.assertRaisesRegex(RuntimeError, "IDENTITY_INVALID"):
            verify_confinement()


if __name__ == "__main__":
    unittest.main()
