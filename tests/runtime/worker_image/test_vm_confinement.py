import ctypes
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

# These are Linux API policy models, not native kernel enforcement evidence.
# Load an isolated copy so a missing host resource module does not prevent
# Windows from exercising the same seccomp, Landlock and resource assertions.
try:
    import resource
except ModuleNotFoundError as error:
    if error.name != "resource":
        raise
    resource = ModuleType("resource")
    resource.RLIMIT_NPROC, resource.RLIMIT_NOFILE, resource.RLIMIT_CPU = 6, 7, 0
    resource.RLIM_INFINITY = -1
    resource.getrlimit = Mock(side_effect=AssertionError("resource fixture must be bound"))
    resource.setrlimit = Mock(side_effect=AssertionError("resource fixture must be bound"))
source = Path(__file__).resolve().parents[3] / "workers/ud/src/ud_agent/vm_confinement.py"
spec = importlib.util.spec_from_file_location("ud_vm_confinement_fixture", source)
vm = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"resource": resource}):
    spec.loader.exec_module(vm)
install_seccomp, protect_runtime, verify_vm_confinement = vm.install_seccomp, vm.protect_runtime, vm.verify_vm_confinement


def run_bpf(code, architecture, syscall, argument=0):
    words = {0: syscall, 4: architecture, 16: argument}
    index = 0
    accumulator = 0
    while index < len(code):
        instruction, yes, no, value = code[index]
        if instruction == 0x20:
            accumulator = words[value]
        elif instruction == 0x15:
            index += yes if accumulator == value else no
        elif instruction == 0x45:
            index += yes if accumulator & value else no
        elif instruction == 0x06:
            return value
        else:
            raise AssertionError("unexpected BPF instruction")
        index += 1
    raise AssertionError("BPF did not return")


class VmConfinementTests(unittest.TestCase):
    def test_installed_filter_blocks_kernel_and_host_socket_escape_for_both_architectures(self):
        class Filter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

        class Program(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

        for machine, architecture, sock, mount, ptrace, bpf in (("x86_64", 0xC000003E, 41, 165, 101, 321), ("aarch64", 0xC00000B7, 198, 40, 117, 280)):
            with self.subTest(machine=machine):
                captured = []

                def prctl(option, mode, program, *_args):
                    if option == 22:
                        self.assertEqual(mode, 2)
                        data = ctypes.cast(program, ctypes.POINTER(Program)).contents
                        captured.extend((entry.code, entry.jt, entry.jf, entry.k) for entry in data.filter[:data.len])
                    return 0

                libc = Mock()
                libc.prctl.side_effect = prctl
                with patch.object(vm, "_libc", return_value=libc), patch.object(vm.platform, "machine", return_value=machine):
                    install_seccomp()
                self.assertTrue(captured)
                self.assertEqual(run_bpf(captured, architecture, 0), 0x7FFF0000)
                self.assertEqual(run_bpf(captured, architecture, sock, 1), 0x7FFF0000)
                self.assertEqual(run_bpf(captured, architecture, sock, 16), 0x7FFF0000)
                for syscall, argument in ((mount, 0), (ptrace, 0), (bpf, 0), (sock, 2), (sock, 40), (425, 0), (426, 0), (427, 0)):
                    self.assertEqual(run_bpf(captured, architecture, syscall, argument), 0x50001)
                self.assertEqual(run_bpf(captured, 0, 0), 0x80000000)
                if machine == "x86_64":
                    self.assertEqual(run_bpf(captured, architecture, 0x40000000), 0x80000000)
        with patch.object(vm, "_libc", side_effect=AssertionError("unexpected native libc access")), patch.object(vm.platform, "machine", return_value="unsupported"), self.assertRaisesRegex(RuntimeError, "ARCHITECTURE_UNSUPPORTED"):
            install_seccomp()

    def test_landlock_handles_every_mutation_and_grants_only_the_open_scratch_directory(self):
        class Ruleset(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]

        class PathBeneath(ctypes.Structure):
            _layout_ = "ms"
            _pack_ = 1
            _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

        observed = []

        def syscall(number, *args):
            observed.append(number)
            if number == 444 and args[2] == 1:
                return 3
            if number == 444:
                self.assertEqual(ctypes.cast(args[0], ctypes.POINTER(Ruleset)).contents.handled_access_fs, 0x7FF2)
                return 200
            if number == 445:
                self.assertEqual(args[:2], (200, 1))
                rule = ctypes.cast(args[2], ctypes.POINTER(PathBeneath)).contents
                self.assertEqual((rule.allowed_access, rule.parent_fd), (0x7FF2, 42))
            if number == 446:
                self.assertEqual(args, (200, 0))
            return 0

        libc = Mock()
        libc.prctl.return_value = 0
        libc.syscall.side_effect = syscall
        with patch.object(vm, "_libc", return_value=libc), patch("os.open", return_value=42) as opened, patch("os.close") as closed, patch("os.O_PATH", 0x200000, create=True), patch("os.O_DIRECTORY", 0x10000, create=True), patch("os.O_NOFOLLOW", 0x20000, create=True), patch("os.O_CLOEXEC", 0x80000, create=True):
            protect_runtime()
            self.assertEqual(opened.call_args.args[0], "/tmp")
            self.assertEqual(opened.call_args.args[1], 0x200000 | 0x10000 | 0x20000 | 0x80000)
            self.assertEqual([call.args[0] for call in closed.call_args_list], [42, 200])
        self.assertEqual(observed, [444, 444, 445, 446])
        libc.syscall.side_effect = None
        libc.syscall.return_value = 2
        with patch.object(vm, "_libc", return_value=libc), self.assertRaisesRegex(RuntimeError, "TRUNCATE_CONTROL_REQUIRED"):
            protect_runtime()

    def test_vm_entrypoint_requires_effective_identity_network_mounts_resources_and_protections(self):
        contents = {
            "/proc/self/status": "NoNewPrivs:\t1\nSeccomp:\t2\n" + "".join(f"{key}:\t0000000000000000\n" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "/proc/net/route": "Iface Destination Gateway Flags\n",
            "/proc/net/ipv6_route": "0000 00 0000 00 0000 0000 lo\n",
            "/proc/self/mountinfo": "10 1 0:1 / /input ro - ext4 /dev/x ro\n11 1 0:2 / /tmp rw,noexec - tmpfs tmpfs rw\n",
            "/proc/meminfo": "MemTotal: 2000000 kB\n",
            "/proc/self/cgroup": "0::/\n",
            "/sys/fs/cgroup/memory.max": "2147483648\n",
            "/sys/fs/cgroup/cpu.max": "200000 100000\n",
        }
        with patch("os.geteuid", return_value=10001, create=True), patch("os.getegid", return_value=10001, create=True), patch("os.cpu_count", return_value=2), patch.object(vm.socket, "if_nameindex", return_value=[(1, "lo")]), patch.object(Path, "read_text", lambda path, *a, **k: contents[path.as_posix()]), patch.object(vm.resource, "getrlimit", return_value=(64, 64)), patch.object(vm.resource, "setrlimit") as limit, patch.object(vm, "protect_runtime") as protect, patch.object(vm, "install_seccomp") as seccomp:
            for provider in ("apple-container", "wslc"):
                verify_vm_confinement(provider)
            self.assertEqual(protect.call_count, 2)
            self.assertEqual(seccomp.call_count, 2)
            self.assertTrue(all(call.args[1] == (64, 64) for call in limit.call_args_list))
            with self.assertRaisesRegex(RuntimeError, "IDENTITY_INVALID"):
                verify_vm_confinement("anything")
            with patch("os.geteuid", return_value=0), self.assertRaisesRegex(RuntimeError, "IDENTITY_INVALID"):
                verify_vm_confinement("apple-container")
            contents["/proc/self/status"] = contents["/proc/self/status"].replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001")
            with self.assertRaisesRegex(RuntimeError, "CAPABILITIES_UNVERIFIED"):
                verify_vm_confinement("wslc")
            contents["/proc/self/status"] = contents["/proc/self/status"].replace("CapBnd:\t0000000000000001", "CapBnd:\t0000000000000000")
            contents["/proc/self/mountinfo"] = contents["/proc/self/mountinfo"].replace("/input ro", "/input rw")
            with self.assertRaisesRegex(RuntimeError, "MOUNTS_UNVERIFIED"):
                verify_vm_confinement("wslc")
            contents["/proc/self/mountinfo"] = contents["/proc/self/mountinfo"].replace("/input rw", "/input ro")
            # WSL's encompassing VM can expose more CPUs; the worker's actual
            # two-CPU cgroup is the relevant effective limit.
            with patch("os.cpu_count", return_value=8):
                verify_vm_confinement("wslc")
            with patch("os.cpu_count", return_value=4), self.assertRaisesRegex(RuntimeError, "RESOURCE_BOUNDARY_UNVERIFIED"):
                verify_vm_confinement("apple-container")
            contents["/proc/meminfo"] = "MemTotal: 2152800 kB\n"
            with patch("os.cpu_count", return_value=3):
                verify_vm_confinement("apple-container")
            for filename, invalid in (("/proc/self/cgroup", ["0::/unbound\n", "1:memory:/\n"]), ("/sys/fs/cgroup/memory.max", ["max", "0", "-1", "2147483649", "２"]), ("/sys/fs/cgroup/cpu.max", ["max 100000", "0 100000", "200001 100000", "1 0", "2 1000001", "200000", "200000 100000 1", "２ 100000"])):
                original = contents[filename]
                for value in invalid:
                    contents[filename] = value
                    with self.subTest(filename=filename, value=value), self.assertRaisesRegex(RuntimeError, "RESOURCE_BOUNDARY_UNVERIFIED"):
                        verify_vm_confinement("apple-container")
                contents[filename] = original
            contents["/proc/meminfo"] = "MemTotal: 4000000 kB\n"
            with self.assertRaisesRegex(RuntimeError, "RESOURCE_BOUNDARY_UNVERIFIED"):
                verify_vm_confinement("apple-container")


if __name__ == "__main__":
    unittest.main()
