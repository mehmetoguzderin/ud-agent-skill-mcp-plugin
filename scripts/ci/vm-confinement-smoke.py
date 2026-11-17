"""Execute inside a local Linux OCI fixture, never on the coordinator host."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys

sys.path.insert(0, "/")
from vm_confinement import install_seccomp, protect_runtime

assert os.geteuid() == 10001
protected = Path("/input/must-be-protected")
protected.write_text("before", encoding="utf-8")
protect_runtime()
install_seccomp()
Path("/tmp/allowed").write_text("scratch", encoding="utf-8")
for action in (lambda: protected.write_text("after", encoding="utf-8"), lambda: protected.unlink(), lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM), lambda: socket.socket(40, socket.SOCK_STREAM)):
    try:
        action()
        raise AssertionError("required protection did not reject the action")
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
assert protected.read_text(encoding="utf-8") == "before"
descendant = subprocess.run([sys.executable, "-I", "-B", "-c", "from pathlib import Path; Path('/input/must-be-protected').write_text('escape')"], capture_output=True, timeout=10)
assert descendant.returncode != 0 and b"PermissionError" in descendant.stderr
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
print(json.dumps({"schema_version": 1, "passed": True, "provider": "local-docker-fixture", "process_architecture": platform.machine(), "kernel_architecture": os.uname().machine, "module_sha256": hashlib.sha256(Path('/vm_confinement.py').read_bytes()).hexdigest(), "checks": ["landlock-write", "landlock-unlink", "scratch-write", "network-socket", "host-vsock", "descendant-inheritance", "no-new-privileges", "seccomp"]}, sort_keys=True))
