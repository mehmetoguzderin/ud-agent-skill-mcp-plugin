import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/runtime"))
try:
    spec = importlib.util.spec_from_file_location("ud_agent_perl_fetch_test", ROOT / "scripts/runtime/fetch_perl_inputs.py")
    fetch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fetch)
finally:
    sys.path.pop(0)


class PerlFetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_only_pinned_https_origins_and_relative_debian_pool_paths_are_allowed(self):
        self.assertEqual(fetch.safe_url("https://snapshot.debian.org/archive/example"), "https://snapshot.debian.org/archive/example")
        for url in ("http://snapshot.debian.org/a", "https://example.com/a", "https://u@snapshot.debian.org/a",
                    "https://snapshot.debian.org/a?token=1", "https://snapshot.debian.org:443/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch.safe_url(url)
        self.assertEqual(fetch.safe_package_path("pool/main/p/perl/perl_1_arm64.deb"), "pool/main/p/perl/perl_1_arm64.deb")
        for path in ("../other", "pool/../secret", "pool/a\\b", "/pool/a", "pool//a"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                fetch.safe_package_path(path)

    def test_offline_missing_and_corrupt_cache_fail_without_network(self):
        filename = self.root / "input"
        expected = hashlib.sha256(b"good").hexdigest()
        with mock.patch.object(fetch, "build_opener", side_effect=AssertionError("network used")):
            with self.assertRaisesRegex(ValueError, "offline Perl input missing"):
                fetch.acquire("https://snapshot.debian.org/file", filename, 4, expected, False)
            filename.write_bytes(b"evil")
            with self.assertRaisesRegex(ValueError, "does not match"):
                fetch.acquire("https://snapshot.debian.org/file", filename, 4, expected, True)
            self.assertEqual(filename.read_bytes(), b"evil")

    def test_valid_cache_avoids_network_and_checks_length(self):
        data = b"valid"
        filename = self.root / "input"
        filename.write_bytes(data)
        with mock.patch.object(fetch, "build_opener", side_effect=AssertionError("network used")):
            fetch.acquire("https://snapshot.debian.org/file", filename, len(data), hashlib.sha256(data).hexdigest(), False)
            with self.assertRaises(ValueError):
                fetch.acquire("https://snapshot.debian.org/file", filename, len(data) + 1, hashlib.sha256(data).hexdigest(), False)

    def test_signature_verification_requires_a_pinned_valid_signer(self):
        signer = "A" * 40
        valid = mock.Mock(returncode=0, stdout=f"[GNUPG:] VALIDSIG {signer} 2026-01-01\n")
        with mock.patch.object(fetch.perl_build.subprocess, "run", return_value=valid):
            fetch.perl_build._verify_release(self.root / "release", self.root / "keyring", [signer])
            with self.assertRaisesRegex(ValueError, "not trusted"):
                fetch.perl_build._verify_release(self.root / "release", self.root / "keyring", ["B" * 40])
        invalid = mock.Mock(returncode=1, stdout=f"[GNUPG:] VALIDSIG {signer} 2026-01-01\n")
        with mock.patch.object(fetch.perl_build.subprocess, "run", return_value=invalid):
            with self.assertRaisesRegex(ValueError, "not trusted"):
                fetch.perl_build._verify_release(self.root / "release", self.root / "keyring", [signer])


if __name__ == "__main__":
    unittest.main()
