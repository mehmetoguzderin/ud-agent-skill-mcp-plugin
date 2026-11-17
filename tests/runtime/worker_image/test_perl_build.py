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
spec = importlib.util.spec_from_file_location("ud_agent_perl_inputs_test", ROOT / "scripts/runtime/perl_build.py")
perl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perl)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def receipt(name, content):
    return {"file": name, "size": len(content), "sha256": digest(content)}


class PerlBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "runtime").mkdir()
        self.image = {"image": "python:fixture", "index_digest": "sha256:" + "1" * 64}
        (self.root / "runtime/core-image.lock.json").write_text(json.dumps(self.image))
        records = {}
        for arch in ("amd64", "arm64"):
            base = self.root / ".artifacts/perl-debs" / arch
            evidence = base / "evidence"
            debs = base / "debs"
            indexes = self.root / ".artifacts/perl-index" / arch
            evidence.mkdir(parents=True)
            debs.mkdir()
            indexes.mkdir(parents=True)
            data = ("deb-" + arch).encode()
            filename = f"fixture_1_{arch}.deb"
            (debs / filename).write_bytes(data)
            package = {"file": filename, "name": "fixture", "version": "1", "architecture": arch,
                       "sha256": digest(data), "size": len(data), "source": "main", "repository_path": "pool/" + filename}
            main = (f"Package: fixture\nVersion: 1\nArchitecture: {arch}\n"
                    f"SHA256: {digest(data)}\nSize: {len(data)}\nFilename: pool/{filename}\n\n").encode()
            security = b""
            keyring = b"fixture-keyring"
            (evidence / "debian-archive-keyring.gpg").write_bytes(keyring)
            evidence_records = [receipt("debian-archive-keyring.gpg", keyring)]
            index_records = []
            for source, content in (("main", main), ("security", security)):
                name = source + "-Packages"
                (indexes / name).write_bytes(content)
                index_records.append({**receipt(name, content), "source": source, "release_path": f"main/binary-{arch}/Packages"})
                signed = (f"SHA256:\n {digest(content)} {len(content)} main/binary-{arch}/Packages\n"
                          "-----BEGIN PGP SIGNATURE-----\n").encode()
                release_name = f"snapshot_debian{'-security' if source == 'security' else ''}_fixture_InRelease"
                (evidence / release_name).write_bytes(signed)
                evidence_records.append(receipt(release_name, signed))
            records[arch] = {"packages": [package], "evidence": evidence_records, "indexes": index_records}
        commit = "a" * 40
        sources = self.root / ".artifacts/perl-sources"
        sources.mkdir()
        archive = sources / "interset.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name, content in (("LICENSE.txt", b"license"), ("lib/Lingua/Interset/Converter.pm", b"fixture module")):
                info = tarfile.TarInfo(f"interset-{commit}/{name}")
                info.size = len(content)
                stream.addfile(info, io.BytesIO(content))
        content = archive.read_bytes()
        self.lock = {"schema_version": 1, "state": "frozen-inputs",
                     "base_image": self.image["image"] + "@" + self.image["index_digest"],
                     "debian": {"architectures": records, "signed_by": {"main": ["A" * 40], "security": ["B" * 40]}},
                     "interset": {"repository": "https://github.com/dan-zeman/interset", "commit": commit,
                                  "archive": archive.name, "archive_size": len(content), "archive_sha256": digest(content)}}
        self.write_lock()
        # Cryptographic gpgv behavior has separate checks; these synthetic
        # fixtures exercise all signed-index reconciliation paths locally.
        self.signature = mock.patch.object(perl, "_verify_release", return_value=None)
        self.verifier = self.signature.start()
        self.addCleanup(self.signature.stop)

    def write_lock(self):
        (self.root / "runtime/perl-deps.lock.json").write_text(json.dumps(self.lock))

    def test_stages_both_architectures_and_pinned_source(self):
        output = self.root / "out"
        result = perl.stage(self.root, output)
        self.assertEqual(result["packages"], {"amd64": 1, "arm64": 1})
        self.assertEqual((output / "interset/lib/Lingua/Interset/Converter.pm").read_bytes(), b"fixture module")
        self.assertIn(digest(b"deb-arm64"), (output / "debs/arm64/SHA256SUMS").read_text())
        self.assertEqual(self.verifier.call_count, 4)
        with self.assertRaises(ValueError):
            perl.stage(self.root, output)

    def test_tampered_deb_and_index_are_rejected(self):
        deb = self.root / ".artifacts/perl-debs/arm64/debs/fixture_1_arm64.deb"
        deb.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "does not match"):
            perl.stage(self.root, self.root / "bad-deb")
        deb.write_bytes(b"deb-arm64")
        index = self.root / ".artifacts/perl-index/amd64/main-Packages"
        index.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "does not match"):
            perl.stage(self.root, self.root / "bad-index")

    def test_signed_index_mismatch_and_duplicate_package_fail(self):
        self.lock["debian"]["architectures"]["arm64"]["packages"][0]["repository_path"] = "pool/other"
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "signed index"):
            perl.stage(self.root, self.root / "bad-origin")
        records = self.lock["debian"]["architectures"]["arm64"]["packages"]
        records.append(dict(records[0]))
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            perl.stage(self.root, self.root / "duplicate")

    def test_identical_signed_mirrors_are_allowed_but_conflicting_bytes_are_not(self):
        arch = "arm64"
        config = self.lock["debian"]["architectures"][arch]
        package = config["packages"][0]
        index = next(item for item in config["indexes"] if item["source"] == "security")
        release = next(item for item in config["evidence"] if "_debian-security_" in item["file"])

        def replace_security(value):
            data = (f"Package: fixture\nVersion: 1\nArchitecture: {arch}\n"
                    f"SHA256: {value}\nSize: {package['size']}\nFilename: pool/updates/fixture.deb\n\n").encode()
            (self.root / ".artifacts/perl-index" / arch / index["file"]).write_bytes(data)
            index.update(receipt(index["file"], data))
            signed = (f"SHA256:\n {digest(data)} {len(data)} main/binary-{arch}/Packages\n"
                      "-----BEGIN PGP SIGNATURE-----\n").encode()
            (self.root / ".artifacts/perl-debs" / arch / "evidence" / release["file"]).write_bytes(signed)
            release.update(receipt(release["file"], signed))
            self.write_lock()

        replace_security(package["sha256"])
        perl.stage(self.root, self.root / "matching-mirrors")
        replace_security("0" * 64)
        with self.assertRaisesRegex(ValueError, "conflicting origins"):
            perl.stage(self.root, self.root / "conflicting-mirrors")

    def test_base_image_and_unsafe_archive_are_rejected(self):
        self.lock["base_image"] = "different"
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "different base image"):
            perl.stage(self.root, self.root / "wrong-base")
        self.lock["base_image"] = self.image["image"] + "@" + self.image["index_digest"]
        archive = self.root / ".artifacts/perl-sources/interset.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            info = tarfile.TarInfo("interset-" + "a" * 40 + "/lib/../../escape")
            info.size = 1
            stream.addfile(info, io.BytesIO(b"x"))
        data = archive.read_bytes()
        self.lock["interset"]["archive_size"] = len(data)
        self.lock["interset"]["archive_sha256"] = digest(data)
        self.write_lock()
        output = self.root / "unsafe"
        with self.assertRaisesRegex(ValueError, "unsafe Interset"):
            perl.stage(self.root, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
