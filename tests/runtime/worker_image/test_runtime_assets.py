import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch

from ud_agent.runtime_assets import extract


class RuntimeAssets(unittest.TestCase):
    def test_google_deferred_base_has_no_vendor_bytes_or_edge_decoder_fields(self):
        for failure in (None, 'missing_recipe', 'browser_bytes', 'outside_executable', 'edge_decoder'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                root=Path(name)
                files={'vendor-browser-recipe.json':b'{}','fonts/font.ttf':b'private font','elf/lib/libc.so.6':b'OS library'}
                if failure=='browser_bytes':files['browser/chrome-headless-shell']=b'vendor'
                def mutate(manifest):
                    manifest['executable']='browser/chrome-headless-shell'
                    manifest['deferred_browser']={'provider':'google-chrome-for-testing','recipe':'vendor-browser-recipe.json','directory':'browser'}
                    if failure=='missing_recipe':manifest['deferred_browser']['recipe']='missing.json'
                    if failure=='outside_executable':manifest['executable']='outside/browser'
                    if failure=='edge_decoder':manifest['deferred_browser']['decoder']='decoder.exe'
                archive,digest,size=self.bundle(root,files=files,mutate=mutate);destination=root/'out';destination.mkdir()
                if failure:
                    with self.assertRaises(ValueError):extract(str(archive),digest,size,str(destination),'manifest.json')
                    self.assertEqual(list(destination.iterdir()),[])
                else:
                    extract(str(archive),digest,size,str(destination),'manifest.json')
                    self.assertFalse((destination/'browser').exists())
                    self.assertEqual((destination/'fonts/font.ttf').read_bytes(),b'private font')

    def bundle(self, root, extra=None, mutate=None, files=None):
        files = files or {"browser/chromium": b"verified-browser", "fonts/font.ttf": b"verified-font"}
        manifest = {"schema_version": 1, "executable": "browser/chromium", "files": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)} for name, data in files.items()]}
        if mutate:
            mutate(manifest)
        files["manifest.json"] = json.dumps(manifest).encode()
        archive = root / "pack.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            if extra:
                output.addfile(extra)
        payload = archive.read_bytes()
        return archive, "sha256:" + hashlib.sha256(payload).hexdigest(), len(payload)

    def test_exact_inventory_and_executable(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, digest, size = self.bundle(root)
            destination = root / "out"
            destination.mkdir()
            chmod = Path.chmod; modes = []
            def record_mode(path, mode, **options):
                modes.append((path, mode)); return chmod(path, mode, **options)
            with patch.object(Path, 'chmod', record_mode):
                extract(str(archive), digest, size, str(destination), "manifest.json")
            self.assertIn((destination / 'browser/chromium', 0o700), modes)
            self.assertIn((destination / 'fonts/font.ttf', 0o600), modes)
            self.assertEqual((destination / "browser/chromium").read_bytes(), b"verified-browser")
            self.assertEqual((destination / "browser/chromium").stat().st_mode & 0o777, 0o666 if os.name == 'nt' else 0o700)
            self.assertEqual((destination / "fonts/font.ttf").stat().st_mode & 0o777, 0o666 if os.name == 'nt' else 0o600)

    def test_integrity_inventory_and_hostile_members_fail_before_writes(self):
        for kind in ("escape", "link", "duplicate", "unlisted", "hash", "archive", "reserved", "control", "trailing", "file_directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                extra = None
                if kind in ("escape", "link", "duplicate", "unlisted", "reserved", "control", "trailing", "file_directory"):
                    extra = tarfile.TarInfo({"escape": "../escaped", "link": "linked", "duplicate": "BROWSER/CHROMIUM", "unlisted": "extra", "reserved": "fonts/CON.ttf", "control": "fonts/bad\x01.ttf", "trailing": "fonts/bad. ", "file_directory": "browser"}[kind])
                    if kind == "link":
                        extra.type, extra.linkname = tarfile.SYMTYPE, "/etc/passwd"
                mutate = (lambda manifest: manifest["files"][0].update(sha256="0" * 64)) if kind == "hash" else None
                archive, digest, size = self.bundle(root, extra, mutate)
                destination = root / "out"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    extract(str(archive), "sha256:" + "0" * 64 if kind == "archive" else digest, size, str(destination), "manifest.json")
                self.assertEqual(list(destination.iterdir()), [])

    def test_private_setup_runs_the_verified_decoder_directly_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive, digest, size = self.bundle(root)
            destination = root / "out"
            destination.mkdir()
            import ud_agent.runtime_assets
            result = subprocess.run([sys.executable, "-I", "-B", str(Path(ud_agent.runtime_assets.__file__).resolve()),
                                     str(archive), digest, str(size), str(destination), "manifest.json"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual((destination / "browser/chromium").read_bytes(), b"verified-browser")

    def test_deferred_vendor_recipe_contains_only_redistributable_base_assets(self):
        for failure in (None, 'foreign_provider', 'missing_decoder', 'browser_bytes', 'wrong_executable', 'path_escape'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                files = {'windows-browser-recipe.json': b'{}', 'decoder/7zdec.exe': b'PD-decoder', 'fonts/font.ttf': b'font'}
                if failure == 'browser_bytes':
                    files['browser/msedge.exe'] = b'vendor-binary'
                def mutate(receipt):
                    receipt['executable'] = 'browser/msedge.exe'
                    receipt['deferred_browser'] = {'provider': 'microsoft-edge', 'recipe': 'windows-browser-recipe.json', 'decoder': 'decoder/7zdec.exe', 'directory': 'browser'}
                    if failure == 'foreign_provider':
                        receipt['deferred_browser']['provider'] = 'other'
                    elif failure == 'missing_decoder':
                        receipt['deferred_browser']['decoder'] = 'absent.exe'
                    elif failure == 'wrong_executable':
                        receipt['executable'] = 'browser/other.exe'
                    elif failure == 'path_escape':
                        receipt['deferred_browser']['directory'] = '../browser'
                archive, digest, size = self.bundle(root, mutate=mutate, files=files)
                destination = root / 'out'; destination.mkdir()
                if failure:
                    with self.assertRaises(ValueError):
                        extract(str(archive), digest, size, str(destination), 'manifest.json')
                    self.assertEqual(list(destination.iterdir()), [])
                else:
                    extract(str(archive), digest, size, str(destination), 'manifest.json')
                    self.assertEqual((destination / 'decoder/7zdec.exe').read_bytes(), b'PD-decoder')
                    self.assertFalse((destination / 'browser').exists())
