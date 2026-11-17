import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('render_source_joins', ROOT / 'scripts/release/bind-render-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


def content(body): return {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}


class RenderSourceJoinTests(unittest.TestCase):
    def metadata(self):
        rows = {}
        def add(name, body=b'font source fixture'):
            rows[name] = {'path': name, **content(body)}; return body
        for name in binding.fonts.FONT_NAMES: add('fonts/noto/' + name)
        add('fonts/noto/NotoSansCJK-Regular.ttc'); add('fonts/generated/NotoSansCJK-Regular.otf')
        add('elf/lib/loader'); add('fontconfig/fonts.conf', binding.FONTCONFIG)
        closure = {'schema_version': 1, 'source': {'image_index': 'sha256:' + 'b' * 64}, 'libraries': {'elf/lib/loader': {'image_path': 'lib/loader', 'sha256': rows['elf/lib/loader']['sha256']}}, 'transformations': []}
        browser = {'version': '1', 'url': 'https://example.test/exact-vendor.zip', 'sha256': 'a' * 64, 'size_bytes': 99}
        vendor = {'schema_version': 1, 'provider': 'google-chrome-for-testing', 'platform': 'linux/arm64', 'version': '1', 'archive': {key: browser[key] for key in ('url', 'sha256', 'size_bytes')}, 'source_root': 'chrome-headless-shell-linux-arm64', 'files': [{'path': 'chrome-headless-shell', **content(b'unshipped vendor binary')}], 'linux_loader': {'executable': 'elf/lib/loader', 'library_dirs': ['elf/lib'], 'materialization': 'elf-interpreter-v1'}}
        bodies = {'dependency-lock.json': binding.encoded({'browser': browser, 'fonts': []}), 'vendor-browser-recipe.json': binding.encoded(vendor), 'elf-closure.json': binding.encoded(closure), 'fontconfig/fonts.conf': binding.FONTCONFIG}
        for name, body in bodies.items(): add(name, body)
        # Path-component order is the real producer's Path.rglob/sorted order:
        # elf/lib precedes elf-closure, unlike flat string sorting.
        manifest = {'schema_version': 1, 'executable': 'browser/chrome-headless-shell', 'files': [rows[name] for name in sorted(rows, key=lambda name: Path(name).parts)], 'fonts': ['fonts/noto/' + name for name in binding.fonts.FONT_NAMES] + ['fonts/generated/NotoSansCJK-Regular.otf'], 'fontconfig': 'fontconfig/fonts.conf', 'deferred_browser': {'provider': 'google-chrome-for-testing', 'recipe': 'vendor-browser-recipe.json', 'directory': 'browser'}}
        bodies['manifest.json'] = binding.encoded(manifest); add('manifest.json', bodies['manifest.json'])
        return rows, bodies, browser

    def test_exact_generated_metadata_keeps_the_full_inventory_and_private_vendor_recipe(self):
        rows, bodies, browser = self.metadata()
        self.assertEqual(binding.validate_metadata(rows, bodies, browser, [], 'linux/arm64'), ['dependency-lock.json', 'elf-closure.json', 'fontconfig/fonts.conf', 'manifest.json', 'vendor-browser-recipe.json'])
        self.assertNotIn('browser/chrome-headless-shell', rows)

    def test_changed_inputs_missing_files_fonts_loader_or_noncanonical_metadata_are_not_source_joins(self):
        for mode in ('browser', 'omitted-file', 'font', 'loader', 'format', 'fontconfig'):
            with self.subTest(mode=mode):
                rows, bodies, browser = self.metadata()
                if mode == 'browser': browser['sha256'] = 'c' * 64
                elif mode == 'omitted-file': rows['unknown-binary'] = {'path': 'unknown-binary', **content(b'extra actual member')}
                elif mode == 'font': rows.pop('fonts/noto/NotoSansArabic-Regular.ttf')
                elif mode == 'loader': value = json.loads(bodies['vendor-browser-recipe.json']); value['linux_loader']['executable'] = 'foreign/loader'; bodies['vendor-browser-recipe.json'] = binding.encoded(value)
                elif mode == 'format': bodies['manifest.json'] = json.dumps(json.loads(bodies['manifest.json'])).encode()
                else: bodies['fontconfig/fonts.conf'] = b'<fontconfig><dir>/outside</dir></fontconfig>'
                with self.assertRaises(ValueError): binding.validate_metadata(rows, bodies, browser, [], 'linux/arm64')

    def test_archive_inventory_hashes_actual_bounded_members_and_rejects_changed_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'render.tar.gz'
            with tarfile.open(file, 'w:gz') as archive:
                for name, body in [('manifest.json', b'{}\n'), ('decoder/7zdec.exe', b'MZ actual retained data')]:
                    row = tarfile.TarInfo(name); row.size = len(body); archive.addfile(row, io.BytesIO(body))
            expected = content(file.read_bytes()); rows, bodies = binding.archive_inventory(file, expected)
            self.assertEqual(rows['decoder/7zdec.exe'], {'path': 'decoder/7zdec.exe', **content(b'MZ actual retained data')})
            self.assertEqual(bodies, {'manifest.json': b'{}\n'})
            file.write_bytes(b'changed')
            with self.assertRaises(ValueError): binding.archive_inventory(file, expected)

    def decoder(self, root, machine=0xaa64):
        def put(name, body):
            file = root / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body); return file
        def archive(name, member, body):
            file = root / name; file.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(file, 'w:xz') as tar:
                row = tarfile.TarInfo(member); row.size = len(body); tar.addfile(row, io.BytesIO(body))
            return file
        seven_terms, zig_terms = b'Exact original decoder terms', b'Exact original compiler terms'
        seven = archive('runtime/sources/7z.tar.xz', 'DOC/License.txt', seven_terms)
        base = '.artifacts/source-materials-data/derived-lima-go/'
        zig = archive(base + 'zig.tar.xz', 'zig-0.17.1/LICENSE', zig_terms)
        binary = bytearray(128); binary[:2] = b'MZ'; struct.pack_into('<I', binary, 60, 64); binary[64:68] = b'PE\0\0'; struct.pack_into('<H', binary, 68, machine)
        put('.artifacts/native-decoder/windows-arm64/7zdec.exe', binary)
        source = {'path': 'runtime/sources/7z.tar.xz', **binding.record(seven)}
        lock = {'source': source, 'compiler': {'version': '0.17.1', 'target': 'aarch64-windows-gnu'}, 'program': {'path': 'decoder/7zdec.exe', **content(binary)}, 'license_receipts': {'licenses/7zip-License.txt': content(seven_terms)['sha256'], 'licenses/Zig-MIT.txt': content(zig_terms)['sha256']}}
        put('licenses/7zip-License.txt', seven_terms); put('licenses/Zig-MIT.txt', zig_terms)
        put('runtime/native-decoder.lock.json', json.dumps(lock).encode())
        put('scripts/runtime/build-native-decoder.py', b'# original fixture build recipe; never executed\n')
        receipt = {'schema_version': 1, 'source': source, 'compiler': {'version': '0.17.1'}, 'target': 'aarch64-windows-gnu', 'build_profile': 'Alone7z/ST_MODE/Unicode/long-path/no-RAR', **content(binary)}
        put('.artifacts/native-decoder/windows-arm64/7zdec.exe.receipt.json', json.dumps(receipt).encode())
        zig_source = {'role': 'zig-source', 'url': 'https://ziglang.org/download/0.17.1/zig-0.17.1.tar.xz', **binding.record(zig)}
        put('runtime/materials/lima-runtime-sources.lock.json', json.dumps({'runtime_sources': [zig_source]}).encode())
        put(base + 'receipt.json', json.dumps({'derived_runtime_sources': [{**zig_source, 'path': 'zig.tar.xz'}]}).encode())
        return lock

    def test_locked_decoder_join_requires_actual_arm_subject_and_all_original_archive_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock = self.decoder(root)
            program, source = binding.decoder_binding(root, root)
            self.assertEqual(program['content'], {key: lock['program'][key] for key in ('sha256', 'size_bytes')})
            self.assertEqual(source['content'], {key: lock['source'][key] for key in ('sha256', 'size_bytes')})
            self.assertEqual({row['source_member'] for row in program['notices']}, {'DOC/License.txt', 'zig-0.17.1/LICENSE'})
            self.assertEqual(len(program['required_materials']), 2)
            (root / 'licenses/Zig-MIT.txt').write_bytes(b'Changed original terms')
            with self.assertRaises(ValueError): binding.decoder_binding(root, root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.decoder(root, machine=0x8664)
            with self.assertRaisesRegex(ValueError, 'ARM64 PE'): binding.decoder_binding(root, root)

    def supplier_deb(self, root):
        body = b'Exact original supplier copyright and original terms'
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:xz') as tar:
            for name, payload in [('usr/share/doc/perl-fixture/copyright', body), ('usr/lib/unshipped-program', b'Never admitted as a render source component')]:
                row = tarfile.TarInfo('./' + name); row.size = len(payload); tar.addfile(row, io.BytesIO(payload))
        control = io.BytesIO()
        with tarfile.open(fileobj=control, mode='w:gz') as tar:
            payload = b'Package: perl-fixture\nVersion: 1.0-1\nArchitecture: all\nSource: exact-original-source (1.0-1)\n'
            row = tarfile.TarInfo('./control'); row.size = len(payload); tar.addfile(row, io.BytesIO(payload))
        raw = bytearray(b'!<arch>\n')
        for name, payload in [('control.tar.gz', control.getvalue()), ('data.tar.xz', data.getvalue())]:
            header = (name + '/').encode().ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'100644'.ljust(8) + str(len(payload)).encode().ljust(10) + b'`\n'
            raw.extend(header + payload + (b'\n' if len(payload) & 1 else b''))
        archive = root / '.artifacts/perl-debs/arm64/debs/fixture.deb'; archive.parent.mkdir(parents=True); archive.write_bytes(raw)
        package = {'name': 'perl-fixture', 'version': '1.0-1', 'architecture': 'all', 'file': 'fixture.deb', 'sha256': binding.digest(archive), 'size': archive.stat().st_size}
        (root / 'runtime').mkdir(); (root / 'runtime/perl-deps.lock.json').write_text(json.dumps({'debian': {'architectures': {'arm64': {'packages': [package]}}}}))
        source = root / 'runtime/decoder-source.fixture'; source.write_bytes(b'Original decoder source archive fixture')
        (root / 'runtime/native-decoder.lock.json').write_text(json.dumps({'source': {'path': 'runtime/decoder-source.fixture', **binding.record(source)}}))
        subjects = [{'id': 'render-assets-linux-arm64', 'members': [{'path': 'licenses/oci/usr/share/doc/perl-fixture/copyright', **content(body)}, {'path': 'usr/lib/unshipped-program', **content(b'Never admitted as a render source component')}]}]
        return archive, subjects, body

    def test_historical_notice_receipt_is_required_only_for_matching_actual_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, subjects, _ = self.supplier_deb(root)

            unrelated = copy.deepcopy(subjects)
            unrelated[0]['members'][0]['path'] = 'licenses/oci/usr/share/doc/current-publisher/copyright'
            self.assertEqual(binding.locked_notice_bindings(root, root, unrelated), [])
            self.assertEqual(binding.locked_notice_bindings(root, root, subjects, {('1' * 64, 10)}), [])
            with self.assertRaises(FileNotFoundError):
                binding.locked_notice_bindings(root, root, subjects)

    def test_reviewed_notice_sources_retain_plaintext_without_unshipped_container_programs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive, subjects, body = self.supplier_deb(root)
            output = root / '.artifacts/original-notices'
            collection = binding.capture_notice_sources(root, root, subjects, output)
            lock = {'schema_version': 1, 'qualification': 'frozen-original-render-notice-source-extractions', 'collection': {'path': '.artifacts/original-notices/receipt.json', **binding.record(output / 'receipt.json')}, 'extractions_sha256': hashlib.sha256(json.dumps(collection['original_extractions'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
            lock_file = root / 'runtime/materials/native-render-notice-sources.lock.json'; lock_file.parent.mkdir(); lock_file.write_text(json.dumps(lock))
            review_file = root / 'quality/reviews/native-render-notice-sources-root-review.json'; review_file.parent.mkdir(parents=True)
            review = {'schema_version': 1, 'qualification': 'independent-exact-render-notice-source-extraction-review-not-publisher-authority', 'decision': 'original-readable-notice-source-only', 'author': 'native_transactions', 'reviewed_by': 'root', 'implementation_coverage': False, 'publisher_authority': False, 'lock': {'path': 'runtime/materials/native-render-notice-sources.lock.json', **binding.record(lock_file)}, 'extractions_sha256': lock['extractions_sha256']}
            with self.assertRaises(FileNotFoundError): binding.locked_notice_bindings(root, root, subjects)
            review_file.write_text(json.dumps(review))
            # The source replay consumes original plain text. The original .deb
            # remains historical extraction evidence and is never distributed.
            archive.unlink()
            rows = binding.locked_notice_bindings(root, root, subjects)
            self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['content'], content(body))
            self.assertEqual(rows[0]['sources'][0]['form'], 'original-readable-copyright-notice-provided-as-preferred-source')
            self.assertEqual(rows[0]['required_materials'], [{'path': '.artifacts/original-notices/blobs/' + content(body)['sha256'], **content(body)}])
            self.assertEqual(len(collection['files']), 2)
            self.assertTrue(all((output / row['path']).read_bytes() != b'Never admitted as a render source component' for row in collection['files']))
            changed = copy.deepcopy(subjects); changed[0]['members'][0]['sha256'] = 'e' * 64
            with self.assertRaisesRegex(ValueError, 'copied notice differs'): binding.locked_notice_bindings(root, root, changed)
            review_file.write_text(json.dumps({**review, 'implementation_coverage': True}))
            with self.assertRaises(ValueError): binding.locked_notice_bindings(root, root, subjects)
            review_file.write_text(json.dumps(review)); (output / 'blobs' / content(body)['sha256']).write_bytes(b'changed original notice')
            with self.assertRaises(ValueError): binding.locked_notice_bindings(root, root, subjects)


if __name__ == '__main__': unittest.main()
