import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("sbom_tests", ROOT / "scripts/release/sbom.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


class SbomTests(unittest.TestCase):
    def test_all_locked_ecosystems_and_exact_source_files_are_represented(self):
        content = (ROOT / "LICENSE").read_bytes()
        source = {"sha256": "a" * 64, "files": [{"path": "LICENSE", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content), "executable": False}]}
        result = sbom.generate(ROOT, source, "2026-11-09T00:00:00Z")
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        self.assertEqual(result["creationInfo"]["created"], "2026-11-09T00:00:00Z")
        names = {item["name"] for item in result["packages"]}
        self.assertIn("@mehmetoguzderin/ud-agent-skill-mcp-plugin", names)
        self.assertIn("udtools", names)
        self.assertIn("cap-std", names)
        self.assertIn("@modelcontextprotocol/server", names)
        self.assertIn("runtime/render-deps.lock.json", names)
        self.assertIn("runtime/lima-inputs.lock.json", names)
        self.assertIn("Ubuntu Lima guest amd64", names)
        self.assertIn("apparmor", names)
        self.assertGreater(len([item for item in result["packages"] if item.get("externalRefs") and item["externalRefs"][0]["referenceLocator"].startswith("pkg:deb/ubuntu/")]), 1000)
        self.assertIn("lima-2.3.0-Darwin-x86_64.tar.gz", names)
        self.assertTrue(any(item["name"] == "nerdctl-full-2.4.2-linux-arm64.tar.gz" and item["checksums"][0]["checksumValue"] == "fe0ef0e9840ee8932640e6058f84b7fa98050f9726e44af44883a5b804ae830e" for item in result["packages"]))
        self.assertTrue(all(item['licenseDeclared'] == 'NOASSERTION' for item in result['packages'] if item['name'].startswith('nerdctl-full-')))
        for item in result['packages']:
            for reference in item.get('externalRefs', []):
                if reference['referenceLocator'].startswith('pkg:deb/'):
                    version = reference['referenceLocator'].split('@', 1)[1].split('?', 1)[0]
                    self.assertNotIn(':', version)
                    self.assertNotIn('+', version)
        extracted = {item["licenseId"] for item in result["hasExtractedLicensingInfos"]}
        self.assertIn("LicenseRef-Public-Domain", extracted)
        self.assertIn('LicenseRef-Microsoft-VisualStudio-2026-CRT', extracted)
        proprietary = [item for item in result['packages'] if item['name'].startswith('microsoft-crt-')]
        self.assertEqual(len(proprietary), 6)
        self.assertTrue(all(item['licenseDeclared'] == 'LicenseRef-Microsoft-VisualStudio-2026-CRT' and item['licenseConcluded'] == 'NOASSERTION' and 'source unavailable' in item['sourceInfo'] and 'unverified-external' in item['annotations'][0]['comment'] for item in proprietary))
        stl = [item for item in result['packages'] if item['name'].startswith('microsoft-stl-')]
        self.assertEqual(len(stl), 2)
        self.assertTrue(all(item['licenseDeclared'] == 'Apache-2.0 WITH LLVM-exception' and item['licenseConcluded'] == 'NOASSERTION' and 'pending-exact-per-object' in item['sourceInfo'] for item in stl))
        self.assertEqual(result["files"][0]["checksums"], [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(content).hexdigest()}])
        ids = [item["SPDXID"] for item in result["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(result, sbom.generate(ROOT, source, "2026-11-09T00:00:00Z"))
        with self.assertRaisesRegex(ValueError, "explicit UTC"):
            sbom.generate(ROOT, source, "today")


if __name__ == "__main__":
    unittest.main()
