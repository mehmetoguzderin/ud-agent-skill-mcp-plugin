import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]

def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

core = module("ud_agent_core_build_tests", "scripts/runtime/prepare-core-build.py")
verify_core = module("ud_agent_core_verifier_tests", "scripts/runtime/verify-core-build.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CoreBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.cache = self.root / ".artifacts/wheels"
        self.cache.mkdir(parents=True)
        sources = self.root / ".artifacts/sources"
        sources.mkdir()
        worker = self.root / "workers/ud/src/ud_agent"
        worker.mkdir(parents=True)
        (worker / "__init__.py").write_text("", encoding="utf-8")
        (worker / "worker.py").write_text("print('worker')\n", encoding="utf-8")
        (worker / "unicode_casefold.json").write_text('{"unicode_version":"16.0.0","mapping":{}}\n', encoding="utf-8")
        (worker / "userspace_operations.json").write_text('{"schema_version":1,"operations":[]}\n', encoding="utf-8")
        (worker / "perl").mkdir()
        (worker / "perl/graph_bridge.pl").write_text("# bridge\n", encoding="utf-8")
        (worker / "perl/unapproved.pl").write_text("# omitted\n", encoding="utf-8")
        (self.root / "LICENSE").write_text("project license\n", encoding="utf-8")
        (self.root / "NOTICE").write_text("Unicode notice\n", encoding="utf-8")
        (self.root / "licenses").mkdir()
        (self.root / "licenses/Unicode-3.0.txt").write_text("Unicode license\n", encoding="utf-8")
        # The provenance verifier is tested separately with its own signed
        # fixtures; these tests exercise deterministic core-context assembly.
        def stage_perl(root, destination):
            destination.mkdir()
            (destination / "fixture").write_text("verified Perl fixture\n", encoding="utf-8")
            return {"lock_sha256": "0" * 64, "interset_commit": "a" * 40, "packages": {"amd64": 1, "arm64": 1}}
        for builder in (core.perl_build, verify_core.core.perl_build):
            patcher = mock.patch.object(builder, "stage", side_effect=stage_perl)
            patcher.start()
            self.addCleanup(patcher.stop)
        commit = "a" * 40
        entries = {"udtools/src/udtools/__init__.py": b"__version__ = '0.0.1'\n",
                   "LICENSE.txt": b"upstream license\n", "udtools/LICENSE.txt": b"subpackage license\n"}
        rules = {}
        for name in core.RULES:
            content = (name + "\n").encode()
            entries["data/" + name] = content
            rules[name] = digest(content)
        archive = sources / f"tools-{commit}.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name, content in sorted(entries.items()):
                info = tarfile.TarInfo(f"tools-{commit}/{name}")
                info.size = len(content)
                stream.addfile(info, io.BytesIO(content))
        tool = {"repository": "UniversalDependencies/tools", "commit": commit, "archive_sha256": digest(archive.read_bytes())}
        repository_sources = []
        for name, items in {
            "docs-automation": {"codes_and_flags.yaml": b"languages: {}\n", "valdan/releases.json": b"{}\n", "LICENSE": b"automation license\n"},
            "docs": {"_en/index.md": b"English documentation\n", "LICENSE.txt": b"docs license\n", "_en/irrelevant.md": b"not required\n"},
        }.items():
            filename = sources / f"{name}-{commit}.tar.gz"
            with tarfile.open(filename, "w:gz") as stream:
                for relative, content in sorted(items.items()):
                    info = tarfile.TarInfo(f"{name}-{commit}/{relative}"); info.size = len(content)
                    stream.addfile(info, io.BytesIO(content))
            repository_sources.append({"repository": "UniversalDependencies/" + name, "commit": commit, "archive_sha256": digest(filename.read_bytes())})
        (self.runtime / "ud-sources.lock.json").write_text(json.dumps({"schema_version": 1, "sources": [tool] + repository_sources, "tools_rule_sha256": rules}), encoding="utf-8")
        image = {"schema_version": 1, "image": "docker.io/library/python:3.15.2-slim", "python_version": "3.15.2",
                 "index_digest": "sha256:" + "1" * 64,
                 "platforms": {"linux/amd64": "sha256:" + "2" * 64, "linux/arm64": "sha256:" + "3" * 64},
                 "qualification": "unbuilt"}
        (self.runtime / "core-image.lock.json").write_text(json.dumps(image), encoding="utf-8")
        (self.runtime / "Containerfile.core").write_text(f'FROM {image["image"]}@{image["index_digest"]}\nUSER 10001:10001\n', encoding="utf-8")
        wheels = []
        for architecture in ("x86_64", "aarch64"):
            name = f"regex-1.0-cp315-cp315-manylinux_2_28_{architecture}.whl"
            content = architecture.encode()
            (self.cache / name).write_bytes(content)
            wheels.append(f'{{ url = "https://files.pythonhosted.org/packages/{name}", hash = "sha256:{digest(content)}", size = {len(content)} }}')
        lock = f'''version = 1
[[package]]
name = "udtools"
version = "0.0.1"
source = {{ git = "https://github.com/UniversalDependencies/tools.git?rev={commit}#{commit}" }}
dependencies = [{{ name = "regex" }}]
[[package]]
name = "regex"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{", ".join(wheels)}]
'''
        (self.root / "uv.lock").write_text(lock, encoding="utf-8")
        self.tool = tool
        self.archive = archive

    def test_locked_wheels_cover_both_worker_architectures(self):
        _, _, lock = core.read_locks(self.root)
        selected = core.dependency_wheels(lock, self.tool["commit"])
        self.assertEqual([p["name"] for p in selected], ["regex"])
        self.assertIn("x86_64", selected[0]["platforms"]["linux/amd64"]["filename"])
        self.assertIn("aarch64", selected[0]["platforms"]["linux/arm64"]["filename"])

    def test_context_is_reproducible_and_verified(self):
        first = self.root / "build-one"
        second = self.root / "build-two"
        one = core.prepare(self.root, self.cache, first)
        two = core.prepare(self.root, self.cache, second)
        self.assertEqual(one, two)
        self.assertFalse(one["release_qualified"])
        self.assertTrue(verify_core.verify(self.root, self.cache, first)["verified"])
        self.assertIn("--hash=sha256:", (first / "requirements.txt").read_text())
        self.assertEqual((first / "context/rules/upos.json").read_bytes(), b"upos.json\n")
        self.assertEqual((first / "worker/ud_agent/perl/graph_bridge.pl").read_text(), "# bridge\n")
        self.assertEqual((first / "worker/ud_agent/unicode_casefold.json").read_text(), '{"unicode_version":"16.0.0","mapping":{}}\n')
        self.assertEqual((first / "worker/ud_agent/userspace_operations.json").read_text(), '{"schema_version":1,"operations":[]}\n')
        self.assertEqual((first / "licenses/Unicode-3.0.txt").read_text(), "Unicode license\n")
        self.assertEqual((first / "licenses/project-NOTICE").read_text(), "Unicode notice\n")
        self.assertFalse((first / "worker/ud_agent/perl/unapproved.pl").exists())
        self.assertTrue(all(path.stat().st_mtime == 0 for path in first.rglob("*") if path.is_file()))
        with self.assertRaises(ValueError):
            core.prepare(self.root, self.cache, first)

    def test_tampered_context_and_unexpected_file_fail(self):
        output = self.root / "build"
        core.prepare(self.root, self.cache, output)
        (output / "worker/ud_agent/worker.py").write_text("tampered", encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_core.verify(self.root, self.cache, output)
        (output / "worker/ud_agent/worker.py").write_text("print('worker')\n", encoding="utf-8")
        (output / "unexpected").write_text("extra", encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_core.verify(self.root, self.cache, output)

    def test_equal_size_epoch_zero_receipts_have_distinct_copy_paths_and_exact_bytes(self):
        first = self.root / 'first-receipt'
        second = self.root / 'second-receipt'
        core.prepare(self.root, self.cache, first)
        source = self.root / 'workers/ud/src/ud_agent/worker.py'
        original = source.read_bytes()
        source.write_bytes(original.replace(b'worker', b'change'))
        core.prepare(self.root, self.cache, second)
        one, two = core.content_addressed_manifest(first), core.content_addressed_manifest(second)
        self.assertNotEqual(one, two)
        self.assertEqual((first / 'input-manifest.json').stat().st_size, (second / 'input-manifest.json').stat().st_size)
        self.assertEqual((first / one).stat().st_mtime, 0)
        self.assertEqual((second / two).stat().st_mtime, 0)
        self.assertEqual((first / one).read_bytes(), (first / 'input-manifest.json').read_bytes())
        self.assertEqual((second / two).read_bytes(), (second / 'input-manifest.json').read_bytes())
        (second / two).write_bytes((first / one).read_bytes())
        with self.assertRaisesRegex(ValueError, 'exact bytes'):
            core.content_addressed_manifest(second)

    def test_corrupt_wheel_and_missing_offline_wheel_fail(self):
        _, _, lock = core.read_locks(self.root)
        wheel = core.dependency_wheels(lock, self.tool["commit"])[0]["platforms"]["linux/amd64"]
        path = self.cache / wheel["filename"]
        path.write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            core.ensure_wheel(self.cache, wheel, False)
        path.unlink()
        with self.assertRaises(ValueError):
            core.ensure_wheel(self.cache, wheel, False)

    def test_archive_path_escape_rejected_even_with_matching_archive_hash(self):
        bad = self.root / "bad.tar.gz"
        with tarfile.open(bad, "w:gz") as stream:
            data = b"escape"
            info = tarfile.TarInfo("tools-" + self.tool["commit"] + "/../escape")
            info.size = len(data)
            stream.addfile(info, io.BytesIO(data))
        tool = {**self.tool, "archive_sha256": digest(bad.read_bytes())}
        with self.assertRaises(ValueError):
            core.extract_verified_tools(bad, tool, self.root / "out")

    def test_rejects_redirect_to_untrusted_host(self):
        with self.assertRaises(ValueError):
            core.SafeRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com/file.whl")

if __name__ == "__main__":
    unittest.main()
