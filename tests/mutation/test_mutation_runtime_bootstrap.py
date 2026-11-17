"""Original data tests for the locked CI SDK bootstrap, without tool execution."""
from __future__ import annotations

import hashlib
import gzip
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ud_test_ci_bootstrap', ROOT / 'scripts/quality/mutation-runtime-bootstrap.py')
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class MutationRuntimeBootstrapTests(unittest.TestCase):
    def test_exact_container_absence_accepts_docker_capitalization_only(self):
        for diagnostic in (b'Error: No such object: owned-id\n', b'error: no such object: owned-id\n', b'Error response from daemon: No such container: owned-id\n'):
            with patch.object(BOOTSTRAP.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr=diagnostic)):
                self.assertIsNone(BOOTSTRAP.inspect_sdk_container('owned-id'))
        for diagnostic in (b'error: no such object: foreign-id\n', b'permission denied\n', b'no such object: owned-id\npermission denied\n'):
            with patch.object(BOOTSTRAP.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr=diagnostic)):
                with self.assertRaisesRegex(ValueError, 'cannot inspect'):
                    BOOTSTRAP.inspect_sdk_container('owned-id')

    def test_upstream_cargo_build_is_outside_product_workspace_without_manifest_edits(self):
        original = b'[package]\nname = "cargo-mutants"\nversion = "27.1.0"\n'
        lock = b'version = 4\n'
        def unpack(_archive, target, prefix):
            self.assertEqual(prefix, 'cargo-mutants-27.1.0')
            target.mkdir(); (target / 'Cargo.toml').write_bytes(original); (target / 'Cargo.lock').write_bytes(lock)
        with patch.object(BOOTSTRAP, 'extract', side_effect=unpack):
            with BOOTSTRAP.isolated_cargo_source(self.root / 'original.crate', hashlib.sha256(lock).hexdigest()) as source:
                self.assertFalse(source.is_relative_to(ROOT)); self.assertEqual((source / 'Cargo.toml').read_bytes(), original)
                captured = source
            self.assertFalse(captured.exists())
            with self.assertRaisesRegex(ValueError, 'original lock changed'):
                with BOOTSTRAP.isolated_cargo_source(self.root / 'original.crate', 'a' * 64): pass

    def test_rust_installers_do_not_overlap_and_failed_installers_remain_recoverable(self):
        downloads = self.assets / 'mutation-rust-assets/downloads'; downloads.mkdir(parents=True)
        export = self.assets / 'mutation-rust-assets/export'
        archives = []
        for name in ('compiler', 'standard-library'):
            archive = downloads / (name + '.tar.xz')
            with tarfile.open(archive, 'w:xz') as stream:
                body = ('original ' + name).encode()
                info = tarfile.TarInfo(name + '/payload'); info.size = len(body)
                stream.addfile(info, io.BytesIO(body))
            archives.append({'url': 'https://example.invalid/' + archive.name, 'sha256': BOOTSTRAP.sha(archive)})
        installed = []
        def install(command, **_options):
            component = Path(command[1]).parent
            self.assertEqual(sorted(path.name for path in component.parent.iterdir()), [component.name])
            export.mkdir(exist_ok=True)
            (export / component.name).write_bytes((component / 'payload').read_bytes())
            installed.append(component.name)
        lock = {'rust': {'toolchain_archives': archives}}
        with patch.object(BOOTSTRAP, 'checked', side_effect=install):
            BOOTSTRAP.install_rust_components(lock, self.assets, export, {})
        self.assertEqual(installed, ['compiler', 'standard-library'])
        self.assertFalse((export.parent / 'staging').exists())
        self.assertEqual((export / 'compiler').read_bytes(), b'original compiler')
        self.assertEqual((export / 'standard-library').read_bytes(), b'original standard-library')
        self.assertEqual(len(list(downloads.iterdir())), 2)
        with patch.object(BOOTSTRAP, 'checked', side_effect=ValueError('installer failed')):
            with self.assertRaisesRegex(ValueError, 'installer failed'):
                BOOTSTRAP.install_rust_components(lock, self.assets, export, {})
        self.assertEqual((export.parent / 'staging/compiler/payload').read_bytes(), b'original compiler')

    def test_vendor_sources_are_built_in_the_retained_export_without_a_second_tree(self):
        downloads = self.assets / 'mutation-rust-assets/downloads'; downloads.mkdir(parents=True)
        archive = self.archive('dependency.crate', [self.member('dependency-1.0/src/lib.rs', b'original dependency')])
        retained = downloads / archive.name; archive.rename(retained)
        digest = BOOTSTRAP.sha(retained)
        lock = {'rust': {'crates': [{'name': 'dependency', 'version': '1.0', 'url': 'https://example.invalid/dependency.crate', 'sha256': digest}]}}
        vendor = BOOTSTRAP.vendor_crates(lock, self.assets)
        self.assertEqual(vendor, self.assets / 'mutation-rust-assets/export/vendor')
        self.assertEqual((vendor / 'dependency-1.0/src/lib.rs').read_bytes(), b'original dependency')
        self.assertEqual(json.loads((vendor / 'dependency-1.0/.cargo-checksum.json').read_text())['package'], digest)
        self.assertFalse((vendor.parent.parent / 'vendor-complete').exists())

    def consumed_fixture(self):
        node = self.assets / 'node-runtime'
        entries = {'bin/node': b'original node', 'LICENSE': b'Node license',
                   'lib/node_modules/npm/bin/npm-cli.js': b'original npm', 'lib/node_modules/npm/LICENSE': b'npm license',
                   'lib/node_modules/npm/package.json': b'{"name":"npm","version":"1.0.0"}'}
        archive = self.assets / 'node/node-v26.0.0-linux-arm64.tar.xz'; archive.parent.mkdir()
        with tarfile.open(archive, 'w:xz') as output:
            for name, data in entries.items():
                member = tarfile.TarInfo('node-v26.0.0-linux-arm64/' + name); member.size = len(data)
                output.addfile(member, io.BytesIO(data))
                target = node / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        (node / 'bin/npm').symlink_to('../lib/node_modules/npm/bin/npm-cli.js')
        rust = self.assets / 'mutation-rust-assets'; (rust / 'downloads').mkdir(parents=True)
        inputs = []
        for name in ('rustc.tar.xz', 'cargo-mutants.crate'):
            file = rust / 'downloads' / name; file.write_bytes(('original ' + name).encode())
            inputs.append({'url': 'https://example.invalid/' + name, 'sha256': BOOTSTRAP.sha(file), 'size_bytes': file.stat().st_size})
        lock = {'provider': self.provider, 'node': {'filename': archive.name, 'version': '26.0.0', 'sha256': BOOTSTRAP.sha(archive)},
                'rust': {'toolchain_archives': inputs[:1], 'cargo_mutants': inputs[1], 'crates': []}}
        (self.root / BOOTSTRAP.LOCK).write_text(json.dumps(lock))
        (rust / 'export/bin').mkdir(parents=True); (rust / 'export/bin/tool').write_bytes(b'verified tool')
        receipt = {'platform': 'linux/arm64', 'files': [{'path': 'bin/tool', 'size': 13, 'sha256': BOOTSTRAP.sha(rust / 'export/bin/tool')}]}
        (rust / 'rust-input-receipt.json').write_text(json.dumps(receipt))
        (self.assets / 'native-inputs.json').write_text(json.dumps({'qualification': 'original-locked-native-SDK-input-build-no-generated-variants',
            'dependency_key': BOOTSTRAP.cache_key(self.root, False), 'provider': self.provider, 'rust_receipt_sha256': BOOTSTRAP.sha(rust / 'rust-input-receipt.json')}))
        profile = self.assets / 'mutation-node-linux-arm64-v4'; profile.mkdir(); (profile / 'installation-receipt.json').write_text('{}')
        context = self.output / ('context-' + 'a' * 32); prepared = context / 'context'; prepared.mkdir(parents=True)
        info = context.stat()
        (context / '.sdk-context-owner.json').write_text(json.dumps({'root': str(self.root), 'assets': str(self.assets), 'context': str(context),
            'creator_pid': os.getpid(), 'device': info.st_dev, 'inode': info.st_ino}))
        (prepared / 'input-receipt.json').write_text(json.dumps({'qualification': 'development-mutation-runner', 'platform': 'linux/arm64',
            'base': self.provider, 'package_lock_sha256': BOOTSTRAP.sha(self.root / 'package-lock.json')}))
        payload = prepared / 'sdk-inputs.tar.xz'; payload.write_bytes(lzma.compress(b'verified compact inputs', preset=6))
        (prepared / 'Containerfile').write_text('RUN --mount=type=bind,source=sdk-inputs.tar.xz,target=/sdk-inputs.tar.xz,readonly python3 -c \'assert hashlib.file_digest(open(p,"rb"),"sha256").hexdigest()=="' + BOOTSTRAP.sha(payload) + '"\'\n')
        return context, lock, entries

    def test_consumed_inputs_retire_only_after_compaction_and_allow_offline_recreation(self):
        context, lock, entries = self.consumed_fixture()
        keep = [context / 'context' / name for name in ('sdk-inputs.tar.xz', 'input-receipt.json', 'Containerfile')]
        keep += [self.assets / name for name in ('native-inputs.json', 'mutation-rust-assets/rust-input-receipt.json', 'mutation-rust-assets/export/bin/tool',
                 'mutation-node-linux-arm64-v4/installation-receipt.json', 'node/' + lock['node']['filename'])]
        unknown = self.assets / 'mutation-rust-assets/downloads/unrelated'; unknown.write_bytes(b'keep'); keep.append(unknown)
        before = {file: file.read_bytes() for file in keep}
        BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        self.assertFalse((self.assets / 'node-runtime').exists()); self.assertFalse((self.assets / 'node-runtime.retired').exists())
        self.assertEqual(sorted(file.name for file in unknown.parent.iterdir()), ['unrelated'])
        self.assertEqual({file: file.read_bytes() for file in keep}, before)
        with patch.object(BOOTSTRAP, 'acquire', side_effect=AssertionError('offline retry reacquired consumed Rust archives')):
            BOOTSTRAP.acquire_rust_inputs(self.root, self.assets, False, lock)
        modules = {}
        for name in ('scripts/quality/prepare-mutation-runtime.py', 'scripts/release/extract-node.py'):
            spec = importlib.util.spec_from_file_location('retry_' + name.replace('/', '_'), ROOT / name)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); modules[name] = module
        with patch.object(BOOTSTRAP, 'ROOT', self.root), patch.object(BOOTSTRAP, 'module', side_effect=modules.__getitem__), \
                patch.object(BOOTSTRAP, 'checked', side_effect=AssertionError('completed Node profile reinstalled')):
            BOOTSTRAP.node_inputs(self.assets)
        for name, data in entries.items(): self.assertEqual((self.assets / 'node-runtime' / name).read_bytes(), data)
        self.assertTrue((self.assets / 'node-runtime/bin/npm').is_symlink())
        (self.assets / 'mutation-rust-assets/export/bin/tool').write_bytes(b'changed bytes')
        with self.assertRaisesRegex(ValueError, 'differs from its receipt'):
            BOOTSTRAP.acquire_rust_inputs(self.root, self.assets, False, lock)

    def test_interrupted_staging_retirement_recovers_only_the_journaled_inode(self):
        context, lock, _ = self.consumed_fixture()
        with patch.object(BOOTSTRAP.shutil, 'rmtree', side_effect=InterruptedError('retirement interrupted')):
            with self.assertRaises(InterruptedError): BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        retired = self.assets / 'node-runtime.retired'
        self.assertFalse((self.assets / 'node-runtime').exists()); self.assertTrue(retired.is_dir())
        original = self.assets / 'original-retired'; retired.rename(original)
        retired.mkdir(); (retired / 'unrelated').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'ownership differs'): BOOTSTRAP.recover_consumed_inputs(self.root, self.assets)
        self.assertEqual((retired / 'unrelated').read_bytes(), b'keep')
        (retired / 'unrelated').unlink(); retired.rmdir(); original.rename(retired)
        BOOTSTRAP.recover_consumed_inputs(self.root, self.assets)
        self.assertFalse(retired.exists())

    def test_consumed_input_retirement_rejects_changed_or_foreign_bytes_before_deletion(self):
        context, _, _ = self.consumed_fixture()
        payload = context / 'context/sdk-inputs.tar.xz'; original = payload.read_bytes(); payload.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'context or retained'): BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        payload.write_bytes(original)
        foreign = self.assets / 'node-runtime/foreign'; foreign.write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'differs from its locked archive'): BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        self.assertEqual(foreign.read_bytes(), b'keep'); foreign.unlink()
        rust = self.assets / 'mutation-rust-assets'; outside = self.root / 'outside-rust'; rust.rename(outside); rust.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'parent is aliased'): BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        self.assertTrue((outside / 'downloads/rustc.tar.xz').is_file()); self.assertTrue((self.assets / 'node-runtime/bin/node').is_file())

    def test_rust_retirement_preserves_an_archive_replaced_after_validation(self):
        context, _, _ = self.consumed_fixture()
        archive = self.assets / 'mutation-rust-assets/downloads/rustc.tar.xz'
        original_recover = BOOTSTRAP.recover_consumed_inputs
        def recover(root, assets):
            original_recover(root, assets)
            if (assets / 'consumed-inputs.json').exists():
                archive.rename(archive.with_suffix('.retained-original'))
                archive.write_bytes(b'unrelated replacement')
        with patch.object(BOOTSTRAP, 'recover_consumed_inputs', side_effect=recover):
            with self.assertRaisesRegex(ValueError, 'changed before retirement'):
                BOOTSTRAP.retire_consumed_inputs(self.root, self.assets, context)
        self.assertEqual(archive.read_bytes(), b'unrelated replacement')
        self.assertTrue((archive.parent / 'cargo-mutants.crate').exists())

    def test_rust_acquisition_requires_valid_completion_before_skipping_consumed_inputs(self):
        _, lock, _ = self.consumed_fixture()
        marker = self.assets / 'native-inputs.json'; completed = json.loads(marker.read_bytes())
        for field in ('qualification', 'dependency_key', 'provider', 'rust_receipt_sha256'):
            with self.subTest(field=field), patch.object(BOOTSTRAP, 'acquire', side_effect=AssertionError('invalid completion reached acquisition')):
                marker.write_text(json.dumps({**completed, field: 'changed'}))
                with self.assertRaisesRegex(ValueError, 'completion binding differs'):
                    BOOTSTRAP.acquire_rust_inputs(self.root, self.assets, False, lock)
        marker.unlink()
        with patch.object(BOOTSTRAP, 'acquire') as acquire:
            BOOTSTRAP.acquire_rust_inputs(self.root, self.assets, False, lock)
        self.assertEqual(len(acquire.call_args_list), 2)
        self.assertTrue(all(call.args[2] is False for call in acquire.call_args_list))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'source'
        self.root.mkdir()
        self.assets = self.root / '.artifacts/sdk'
        self.assets.mkdir(parents=True)
        self.output = self.root / '.artifacts/context'
        self.provider = 'ghcr.io/example/native@sha256:' + 'a' * 64
        self.image = 'sha256:' + 'b' * 64
        self.binding = {'endpoint': 'unix:///tmp/sdk.sock', 'daemon_id': 'daemon-a'}
        self.harness = ['worker.py', 'pytest_evidence.py']
        for name, content in {
            BOOTSTRAP.LOCK: json.dumps({'provider': self.provider}),
            'package-lock.json': '{"lockfileVersion":3}\n',
            'scripts/quality/recipe.py': '# original build recipe\n',
            'scripts/quality/worker.py': '# protected executable harness\n',
            'tests/mutation/pytest_evidence.py': '# original assertion observer\n',
            'packages/launcher/src/guard.rs': '// original native guard\n',
            'scripts/quality/rust-assertion-parser/src/main.rs': '// original parser\n',
            'README.md': 'Host installation guidance\n',
        }.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        for mocked in (
            patch.object(BOOTSTRAP, 'RECIPES', ['scripts/quality/recipe.py']),
            patch.object(BOOTSTRAP, 'LOCKS', [BOOTSTRAP.LOCK, 'package-lock.json']),
            patch.object(BOOTSTRAP, 'module', return_value=SimpleNamespace(HARNESS_NAMES=self.harness)),
            patch.object(BOOTSTRAP, 'assert_docker_binding', return_value=self.binding),
            patch.dict(os.environ, {'UD_SDK_EXPORT_OWNER': '01234567-89ab-cdef-0123-456789abcdef'}),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def provider_result(self, **changed):
        image = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux', 'RepoDigests': [self.provider], **changed}
        return SimpleNamespace(returncode=0, stdout=json.dumps([image]).encode(), stderr=b'')

    def test_image_export_holds_the_journaled_inode_and_saves_the_immutable_image(self):
        target = self.assets / ('sdk-image.' + 'a' * 32 + '.tar')
        def checked(command, **options):
            self.assertEqual(command, ['docker', 'save', self.image])
            record = json.loads((self.assets / 'image-export.json').read_bytes())
            info = os.fstat(options['stdout'].fileno())
            self.assertEqual((record['device'], record['inode']), (info.st_dev, info.st_ino))
            self.assertEqual(record['path'], target.name)
            self.assertEqual(record['creator_pid'], os.getpid())
            self.assertEqual(record['owner'], os.environ['UD_SDK_EXPORT_OWNER'])
            self.assertEqual(record['docker'], self.binding)
            self.assertIs(options['gzip_stdout'], True)
            options['stdout'].write(gzip.compress(b'original image archive', mtime=0))
        chmod = Path.chmod
        with patch.object(BOOTSTRAP, 'checked', side_effect=checked), patch.object(Path, 'chmod', autospec=True, side_effect=chmod) as requested_mode:
            BOOTSTRAP.export_image(self.root, self.assets, target, self.image)
        requested_mode.assert_any_call(target, 0o600)
        self.assertEqual(gzip.decompress(target.read_bytes()), b'original image archive')
        # Windows chmod exposes the read-only flag, not POSIX owner/group bits.
        if os.name == 'nt': self.assertTrue(target.stat().st_mode & 0o200)
        else: self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_redirected_original_stdout_keeps_only_stderr_in_the_bounded_capture(self):
        target = self.assets / 'stdout'
        with target.open('xb') as output, patch.object(BOOTSTRAP, 'SDK_LOG_LIMIT', 64):
            result = BOOTSTRAP.checked([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*1024);sys.stderr.write("diagnostic")'], stdout=output)
        self.assertEqual(target.read_bytes(), b'x' * 1024)
        self.assertEqual(result, b'diagnostic')

    def test_compressed_original_stdout_streams_binary_bytes_into_the_held_inode(self):
        target = self.assets / 'sdk-image.tar'
        with target.open('xb') as output, patch.object(BOOTSTRAP, 'SDK_LOG_LIMIT', 64):
            before = os.fstat(output.fileno())
            result = BOOTSTRAP.checked([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(bytes(range(256))*4096);sys.stderr.write("diagnostic")'], stdout=output, gzip_stdout=True)
            after = os.fstat(output.fileno())
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(result, b'diagnostic')
        self.assertEqual(gzip.decompress(target.read_bytes()), bytes(range(256)) * 4096)
        self.assertLess(target.stat().st_size, 16384)
        self.assertEqual(list(self.assets.iterdir()), [target])

    def test_compressed_export_failure_timeout_and_stderr_limit_stop_the_producer(self):
        cases = [
            ('import sys;sys.stdout.buffer.write(b"partial");sys.exit(4)', ValueError, 'original command failed', 10),
            ('import sys,time;sys.stderr.write("x"*65);sys.stderr.flush();time.sleep(30)', ValueError, 'bounded log', 10),
            ('import time;time.sleep(30)', subprocess.TimeoutExpired, 'timed out', 0.1),
        ]
        popen = subprocess.Popen
        for index, (program, error, message, timeout) in enumerate(cases):
            processes = []
            def started(*args, **kwargs):
                process = popen(*args, **kwargs); processes.append(process); return process
            with self.subTest(index=index), (self.assets / f'failed-{index}.gz').open('xb') as output, \
                    patch.object(BOOTSTRAP, 'SDK_LOG_LIMIT', 64), patch.object(BOOTSTRAP.subprocess, 'Popen', side_effect=started):
                with self.assertRaisesRegex(error, message):
                    BOOTSTRAP.checked([sys.executable, '-c', program], stdout=output, gzip_stdout=True, timeout=timeout)
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll())

    def missing_provider(self):
        return SimpleNamespace(returncode=1, stdout=b'', stderr=('Error response from daemon: No such image: ' + self.provider).encode())

    def image_record(self):
        runtime = {
            'platform': 'linux/arm64',
            'package_lock_sha256': BOOTSTRAP.sha(self.root / 'package-lock.json'),
            'harness': [
                {'path': name, 'sha256': BOOTSTRAP.sha(self.root / ('tests/mutation' if name == 'pytest_evidence.py' else 'scripts/quality') / name)}
                for name in self.harness
            ],
        }
        (self.assets / 'input-receipt.json').write_bytes(BOOTSTRAP.canonical(runtime) + b'\n')
        (self.assets / 'sdk-image.tar').write_bytes(b'original locked archive fixture\n')
        record = {
            'schema_version': 1,
            'qualification': 'private-native-arm-CI-SDK-not-product-release',
            'cache_key': BOOTSTRAP.cache_key(self.root),
            'image_id': self.image,
            'runtime_input_sha256': BOOTSTRAP.sha(self.assets / 'input-receipt.json'),
            'archive': {'path': 'sdk-image.tar', 'sha256': BOOTSTRAP.sha(self.assets / 'sdk-image.tar'), 'size_bytes': (self.assets / 'sdk-image.tar').stat().st_size},
        }
        self.save_record(record)
        return record

    def save_record(self, record):
        (self.assets / 'ci-sdk.json').write_bytes(BOOTSTRAP.canonical(record) + b'\n')

    def test_original_subprocess_output_and_accumulated_logs_are_bounded(self):
        log = self.assets / 'bounded.log'
        with patch.object(BOOTSTRAP, 'SDK_LOG_LIMIT', 64):
            result = BOOTSTRAP.checked([sys.executable, '-c', 'print("verified")'], log=log)
            self.assertEqual(result, b'verified' + os.linesep.encode())
            self.assertEqual(log.read_bytes(), b'verified' + os.linesep.encode())
            with self.assertRaisesRegex(ValueError, 'exceeds its bounded log'):
                BOOTSTRAP.checked([sys.executable, '-c', 'print("x" * 70)'], log=log)
            self.assertLessEqual(log.stat().st_size, 64)
            with self.assertRaisesRegex(ValueError, 'exceeds its bounded log'):
                BOOTSTRAP.checked([sys.executable, '-c', 'print("y" * 70)'])
            log.write_bytes(b'a' * 60)
            with self.assertRaisesRegex(ValueError, 'exceeds its bounded log'):
                BOOTSTRAP.checked([sys.executable, '-c', 'print("five!")'], log=log)
            self.assertEqual(log.read_bytes(), b'a' * 60)

    def test_original_subprocess_failure_and_timeout_remain_failures(self):
        with self.assertRaisesRegex(ValueError, 'SDK original command failed.*'):
            BOOTSTRAP.checked([sys.executable, '-c', 'import sys; print("bad input"); sys.exit(4)'])
        with self.assertRaises(subprocess.TimeoutExpired):
            BOOTSTRAP.checked([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)

    def test_interrupted_job_recovers_only_journal_owned_container_and_new_outputs(self):
        owner, identifier = 'd' * 32, 'e' * 64
        name = 'ud-sdk-bootstrap-' + owner
        argv = ['docker', 'create', '--pull=never', '--name', name, '--label',
                'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap=' + owner,
                'type=bind,src=' + str(self.root) + ',dst=/src,readonly',
                'type=bind,src=' + str(self.assets) + ',dst=/src/.artifacts', '--native-inputs']
        record = {'schema_version': 1, 'qualification': 'original-SDK-bootstrap-not-mutant-execution',
                  'owner': owner, 'status': 'started', 'creator_pid': 91234, 'root': str(self.root),
                  'assets': str(self.assets), 'mode': '--native-inputs', 'argv': argv, 'docker': self.binding,
                  'cleanup_candidates': ['mutation-rust-assets/staging']}
        evidence = self.assets / ('bootstrap-' + owner + '.json')
        evidence.write_bytes(BOOTSTRAP.canonical(record))
        staging = self.assets / 'mutation-rust-assets/staging'
        staging.mkdir(parents=True); (staging / 'partial').write_text('interrupted')
        retained = self.assets / 'mutation-rust-assets/downloads'
        retained.mkdir(); (retained / 'original').write_text('keep')
        self.output.mkdir()
        context = self.output / ('context-' + 'f' * 32); context.mkdir()
        info = context.stat()
        (context / '.sdk-context-owner.json').write_bytes(BOOTSTRAP.canonical({
            'root': str(self.root), 'assets': str(self.assets), 'context': str(context), 'creator_pid': 91234,
            'device': info.st_dev, 'inode': info.st_ino}))
        container = {'Id': identifier, 'Name': '/' + name,
                     'Config': {'Image': self.provider, 'Labels': {'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap': owner}},
                     'Mounts': [{'Destination': '/src', 'Source': str(self.root)},
                                {'Destination': '/src/.artifacts', 'Source': str(self.assets)}]}
        with patch.object(BOOTSTRAP, 'process_alive', return_value=False), \
                patch.object(BOOTSTRAP, 'inspect_sdk_container', side_effect=[container, None]), \
                patch.object(BOOTSTRAP, 'checked') as checked:
            with self.assertRaisesRegex(ValueError, 'ambiguous ownership'):
                BOOTSTRAP.recover_sdk_jobs(self.root, self.assets, self.output)
        checked.assert_called_once_with(['docker', 'rm', '--force', identifier])
        self.assertTrue(staging.exists()); self.assertTrue(context.exists())
        self.assertEqual((retained / 'original').read_text(), 'keep')
        self.assertFalse(json.loads(evidence.read_bytes())['recovered'])
        (staging / 'partial').unlink(); staging.rmdir()
        with patch.object(BOOTSTRAP, 'process_alive', return_value=False), \
                patch.object(BOOTSTRAP, 'inspect_sdk_container', side_effect=AssertionError('removed container was inspected')):
            BOOTSTRAP.recover_sdk_jobs(self.root, self.assets, self.output)
        self.assertFalse(context.exists())
        self.assertTrue(json.loads(evidence.read_bytes())['recovered'])

    def test_interrupted_job_refuses_active_or_foreign_owner(self):
        owner = 'd' * 32
        name = 'ud-sdk-bootstrap-' + owner
        record = {'schema_version': 1, 'qualification': 'original-SDK-bootstrap-not-mutant-execution',
                  'owner': owner, 'status': 'started', 'creator_pid': 91234, 'root': str(self.root),
                  'assets': str(self.assets), 'mode': '--node-inputs', 'cleanup_candidates': [], 'docker': self.binding,
                  'argv': ['docker', 'create', '--pull=never', '--name', name, '--label',
                           'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap=' + owner,
                           'type=bind,src=' + str(self.root) + ',dst=/src,readonly',
                           'type=bind,src=' + str(self.assets) + ',dst=/src/.artifacts', '--node-inputs']}
        (self.assets / ('bootstrap-' + owner + '.json')).write_bytes(BOOTSTRAP.canonical(record))
        with patch.object(BOOTSTRAP, 'process_alive', return_value=True), patch.object(BOOTSTRAP, 'checked') as checked:
            with self.assertRaisesRegex(ValueError, 'still active'): BOOTSTRAP.recover_sdk_jobs(self.root, self.assets)
            checked.assert_not_called()
        foreign = {'Id': 'e' * 64, 'Name': '/' + name, 'Config': {'Image': self.provider, 'Labels': {}}, 'Mounts': []}
        with patch.object(BOOTSTRAP, 'process_alive', return_value=False), \
                patch.object(BOOTSTRAP, 'inspect_sdk_container', return_value=foreign), patch.object(BOOTSTRAP, 'checked') as checked:
            with self.assertRaisesRegex(ValueError, 'does not match'): BOOTSTRAP.recover_sdk_jobs(self.root, self.assets)
            checked.assert_not_called()
        with patch.object(BOOTSTRAP, 'assert_docker_binding', return_value={'endpoint': self.binding['endpoint'], 'daemon_id': 'other'}), \
                patch.object(BOOTSTRAP, 'inspect_sdk_container', side_effect=AssertionError('wrong daemon reached')):
            with self.assertRaisesRegex(ValueError, 'exact owned recovery record'): BOOTSTRAP.recover_sdk_jobs(self.root, self.assets)

    def test_recovery_preserves_context_replaced_at_same_path(self):
        self.output.mkdir()
        context = self.output / ('context-' + 'f' * 32); context.mkdir()
        info = context.stat()
        marker = BOOTSTRAP.canonical({'root': str(self.root), 'assets': str(self.assets), 'context': str(context),
                                      'creator_pid': 91234, 'device': info.st_dev, 'inode': info.st_ino})
        (context / '.sdk-context-owner.json').write_bytes(marker)
        context.rename(self.output / 'old-owned-context')
        context.mkdir(); (context / '.sdk-context-owner.json').write_bytes(marker)
        (context / 'foreign').write_text('keep')
        with patch.object(BOOTSTRAP, 'process_alive', return_value=False):
            with self.assertRaisesRegex(ValueError, 'inode differs'): BOOTSTRAP.recover_sdk_jobs(self.root, self.assets, self.output)
        self.assertEqual((context / 'foreign').read_text(), 'keep')

    def test_key_binds_executable_and_lock_inputs_but_excludes_host_guidance(self):
        initial = BOOTSTRAP.cache_key(self.root)
        self.assertEqual(initial, BOOTSTRAP.cache_key(self.root))
        self.assertRegex(initial, r'^[a-f0-9]{64}$')
        (self.root / 'README.md').write_text('Changed host guidance only\n')
        self.assertEqual(BOOTSTRAP.cache_key(self.root), initial)
        for name in ('scripts/quality/recipe.py', BOOTSTRAP.LOCK, 'package-lock.json', 'packages/launcher/src/guard.rs', 'scripts/quality/rust-assertion-parser/src/main.rs'):
            with self.subTest(name=name):
                target = self.root / name
                original = target.read_bytes()
                target.write_bytes(original + b'\n')
                self.assertNotEqual(BOOTSTRAP.cache_key(self.root), initial)
                target.write_bytes(original)
        dependencies = BOOTSTRAP.cache_key(self.root, False)
        (self.root / 'scripts/quality/worker.py').write_text('# changed protected harness\n')
        self.assertNotEqual(BOOTSTRAP.cache_key(self.root), initial)
        self.assertEqual(BOOTSTRAP.cache_key(self.root, False), dependencies)

    def test_exact_acquisition_reuses_offline_bytes_and_never_repairs_corruption(self):
        content = b'locked original input'
        record = {'url': 'https://example.invalid/input.tar', 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)}
        target = self.assets / 'input.tar'
        target.write_bytes(content)
        with patch.object(BOOTSTRAP, 'urlopen', side_effect=AssertionError('unexpected download')):
            self.assertEqual(BOOTSTRAP.acquire(record, target, False), target)
            target.write_bytes(b'corrupt original input')
            with self.assertRaisesRegex(ValueError, 'differs from its locked original'):
                BOOTSTRAP.acquire(record, target, True)
            self.assertEqual(target.read_bytes(), b'corrupt original input')
            with self.assertRaisesRegex(ValueError, 'offline SDK input is absent'):
                BOOTSTRAP.acquire(record, self.assets / 'absent', False)

    def test_node_profile_does_not_hide_interrupted_or_foreign_setup(self):
        profile = self.assets / 'mutation-node-linux-arm64-v4'
        self.assertFalse(BOOTSTRAP.node_profile_ready(profile))
        profile.mkdir()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            BOOTSTRAP.node_profile_ready(profile)
        (profile / 'installation-receipt.json').write_text('{}')
        (profile / 'INCOMPLETE').write_text('interrupted')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            BOOTSTRAP.node_profile_ready(profile)
        (profile / 'INCOMPLETE').unlink()
        self.assertTrue(BOOTSTRAP.node_profile_ready(profile))

    def test_acquisition_checks_https_hash_and_declared_download_bound(self):
        content = b'verified download fixture'
        record = {'url': 'https://example.invalid/input.tar', 'hash': 'sha256:' + hashlib.sha256(content).hexdigest(), 'size': len(content)}
        with patch.object(BOOTSTRAP, 'urlopen', return_value=io.BytesIO(content)) as download:
            target = BOOTSTRAP.acquire(record, self.assets / 'acquired', True)
            self.assertEqual(target.read_bytes(), content)
            download.assert_called_once_with(record['url'], timeout=60)
        for changes in ({'url': 'http://example.invalid/input.tar'}, {'hash': 'not-a-hash'}, {'size': True}, {'size': -1}):
            with self.subTest(changes=changes), patch.object(BOOTSTRAP, 'urlopen', side_effect=AssertionError('invalid lock reached network')):
                with self.assertRaisesRegex(ValueError, 'bounded exact HTTPS'):
                    BOOTSTRAP.acquire({**record, **changes}, self.assets / 'invalid', True)
        with patch.object(BOOTSTRAP, 'urlopen', return_value=io.BytesIO(content + b'excess')):
            with self.assertRaisesRegex(ValueError, 'exceeds its bound'):
                BOOTSTRAP.acquire(record, self.assets / 'oversized', True)
        self.assertFalse((self.assets / 'oversized').exists())
        self.assertEqual(list(self.assets.glob('.oversized.*.tmp')), [])

    def test_interrupted_download_does_not_poison_retry(self):
        content = b'original locked download'
        record = {'url': 'https://example.invalid/input.tar', 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)}
        target = self.assets / 'download'

        class BrokenDownload(io.BytesIO):
            def read(self, amount=-1):
                if self.tell(): raise OSError('connection interrupted')
                return super().read(4)

        with patch.object(BOOTSTRAP, 'urlopen', return_value=BrokenDownload(content)):
            with self.assertRaisesRegex(OSError, 'connection interrupted'):
                BOOTSTRAP.acquire(record, target, True)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.assets.glob('.download.*.tmp')), [])
        with patch.object(BOOTSTRAP, 'urlopen', return_value=io.BytesIO(content)):
            self.assertEqual(BOOTSTRAP.acquire(record, target, True).read_bytes(), content)

    def archive(self, name, entries):
        target = self.assets / name
        with tarfile.open(target, 'w') as stream:
            for member, content in entries:
                stream.addfile(member, io.BytesIO(content) if content is not None else None)
        return target

    def member(self, name, content=b'original source', kind=tarfile.REGTYPE):
        member = tarfile.TarInfo(name)
        member.type = kind
        member.mode = 0o777
        member.size = len(content) if kind == tarfile.REGTYPE else 0
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            member.linkname = '../outside'
        return member, content if kind == tarfile.REGTYPE else None

    def test_source_extraction_preserves_bytes_and_rejects_hostile_members(self):
        archive = self.archive('valid.tar', [self.member('crate/lib.rs'), self.member('crate/bin/tool', b'original tool')])
        output = self.assets / 'valid'
        chmod = Path.chmod
        with patch.object(Path, 'chmod', autospec=True, side_effect=chmod) as requested_mode:
            BOOTSTRAP.extract(archive, output, 'crate')
        requested_mode.assert_any_call(output / 'bin/tool', 0o755)
        self.assertEqual((output / 'lib.rs').read_bytes(), b'original source')
        if os.name == 'nt': self.assertTrue((output / 'bin/tool').stat().st_mode & 0o200)
        else: self.assertEqual((output / 'bin/tool').stat().st_mode & 0o777, 0o755)
        cases = [
            [self.member('crate/../escape')],
            [self.member('crate/a\\b')],
            [self.member('other/source')],
            [self.member('crate/link', kind=tarfile.SYMTYPE)],
            [self.member('crate/link', kind=tarfile.LNKTYPE)],
            [self.member('crate/repeated'), self.member('crate/repeated')],
        ]
        for index, members in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    BOOTSTRAP.extract(self.archive(f'bad-{index}.tar', members), self.assets / f'bad-{index}', 'crate')
        self.assertFalse((self.assets / 'escape').exists())

    def test_cache_corruption_and_stale_executable_bindings_fail_before_docker(self):
        for problem in ('archive-bytes', 'archive-size', 'archive-compression', 'archive-compression-header', 'runtime-bytes', 'source-key', 'mutable-image', 'harness', 'duplicate-harness', 'platform', 'package-lock'):
            with self.subTest(problem=problem):
                record = self.image_record()
                if problem == 'archive-bytes':
                    (self.assets / 'sdk-image.tar').write_bytes(b'changed image')
                elif problem == 'archive-size':
                    record['archive']['size_bytes'] += 1
                elif problem == 'archive-compression':
                    record['archive']['compression'] = 'unknown'
                elif problem == 'archive-compression-header':
                    record['archive']['compression'] = 'gzip'
                elif problem == 'runtime-bytes':
                    (self.assets / 'input-receipt.json').write_bytes(b'changed receipt')
                elif problem == 'source-key':
                    record['cache_key'] = '0' * 64
                elif problem == 'mutable-image':
                    record['image_id'] = 'localhost/sdk:latest'
                else:
                    runtime = BOOTSTRAP.read(self.assets / 'input-receipt.json')
                    if problem == 'harness': runtime['harness'][0]['sha256'] = '0' * 64
                    elif problem == 'duplicate-harness': runtime['harness'].append(runtime['harness'][0])
                    elif problem == 'platform': runtime['platform'] = 'linux/amd64'
                    elif problem == 'package-lock': runtime['package_lock_sha256'] = '0' * 64
                    (self.assets / 'input-receipt.json').write_bytes(BOOTSTRAP.canonical(runtime))
                    record['runtime_input_sha256'] = BOOTSTRAP.sha(self.assets / 'input-receipt.json')
                self.save_record(record)
                with patch.object(BOOTSTRAP, 'checked', side_effect=AssertionError('invalid cache reached Docker')):
                    with self.assertRaises(ValueError): BOOTSTRAP.load_image(self.root, self.assets)

    def test_warm_setup_loads_exact_image_without_download_or_build(self):
        record = self.image_record()
        commands = []

        def checked(command, **options):
            commands.append(command)
            if command[:2] == ['docker', 'load']:
                return b'loaded original fixture\n'
            self.assertEqual(command, ['docker', 'image', 'inspect', self.image])
            return json.dumps([{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()

        with patch.object(BOOTSTRAP, 'checked', side_effect=checked), \
                patch.object(BOOTSTRAP, 'acquire_inputs', side_effect=AssertionError('warm download')), \
                patch.object(BOOTSTRAP, 'container', side_effect=AssertionError('warm build')), \
                patch.object(BOOTSTRAP.subprocess, 'run', side_effect=AssertionError('unverified subprocess')):
            result = BOOTSTRAP.ensure(self.root, self.assets, self.output, False)
        self.assertEqual(result, {key: record[key] for key in ('image_id', 'runtime_input_sha256', 'cache_key')})
        self.assertEqual(commands, [['docker', 'load', '--input', str(self.assets / 'sdk-image.tar')], ['docker', 'image', 'inspect', self.image]])

    def test_gzip_cache_load_preserves_the_three_file_warm_cache_contract(self):
        record = self.image_record()
        archive = self.assets / 'sdk-image.tar'
        archive.write_bytes(gzip.compress(archive.read_bytes(), mtime=0))
        record['archive'].update(compression='gzip', sha256=BOOTSTRAP.sha(archive), size_bytes=archive.stat().st_size)
        self.save_record(record)
        actual = json.dumps([{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()
        with patch.object(BOOTSTRAP, 'checked', side_effect=[b'loaded gzip image', actual]) as commands, \
                patch.object(BOOTSTRAP, 'provider_input', side_effect=AssertionError('warm provider acquisition')), \
                patch.object(BOOTSTRAP, 'acquire_inputs', side_effect=AssertionError('warm download')):
            result = BOOTSTRAP.ensure(self.root, self.assets, self.output, False)
        self.assertEqual(result['image_id'], self.image)
        self.assertEqual(commands.call_args_list[0].args[0], ['docker', 'load', '--input', str(archive)])
        self.assertEqual(sorted(file.name for file in self.assets.iterdir()), ['ci-sdk.json', 'input-receipt.json', 'sdk-image.tar'])

    def test_provider_phase_acquires_only_the_locked_digest_and_records_its_verified_identity(self):
        commands = []
        def checked(command, **_options):
            commands.append(command)
            if command == ['docker', 'info', '--format', '{{.Architecture}}']: return b'arm64\n'
            self.assertEqual(command, ['docker', 'pull', '--platform', 'linux/arm64', self.provider])
            return b'pulled original provider\n'
        with patch.object(BOOTSTRAP, 'checked', side_effect=checked), \
                patch.object(BOOTSTRAP.subprocess, 'run', side_effect=[self.missing_provider(), self.provider_result()]):
            result = BOOTSTRAP.prepare_provider(self.root, self.assets, True)
        self.assertEqual(len(commands), 2)
        self.assertEqual(result['provider'], self.provider)
        self.assertEqual(result['image_id'], self.image)
        self.assertEqual(result['docker'], self.binding)
        self.assertEqual(result['lock_sha256'], BOOTSTRAP.sha(self.root / BOOTSTRAP.LOCK))
        self.assertEqual(json.loads((self.assets / 'provider-input.json').read_bytes()), result)

    def test_missing_provider_cannot_trigger_an_offline_or_native_build_phase_pull(self):
        with patch.object(BOOTSTRAP, 'checked', return_value=b'arm64\n') as command, \
                patch.object(BOOTSTRAP.subprocess, 'run', return_value=self.missing_provider()), \
                patch.object(BOOTSTRAP, 'acquire_inputs', side_effect=AssertionError('unadmitted provider reached builds')):
            for operation in (lambda: BOOTSTRAP.prepare_provider(self.root, self.assets, False),
                              lambda: BOOTSTRAP.ensure(self.root, self.assets, self.output, True)):
                with self.assertRaisesRegex(ValueError, 'supervised provider phase'): operation()
        self.assertTrue(all(call.args[0] == ['docker', 'info', '--format', '{{.Architecture}}'] for call in command.call_args_list))
        self.assertFalse((self.assets / 'provider-input.json').exists())

    def test_provider_phase_rejects_failed_queries_wrong_digest_and_foreign_platforms(self):
        cases = [self.provider_result(RepoDigests=[]), self.provider_result(RepoDigests=self.provider), self.provider_result(Architecture='amd64'), self.provider_result(Os='windows'),
                 SimpleNamespace(returncode=1, stdout=b'', stderr=b'Cannot connect to the Docker daemon')]
        for result in cases:
            with self.subTest(result=result), patch.object(BOOTSTRAP, 'checked', return_value=b'arm64\n') as command, \
                    patch.object(BOOTSTRAP.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'provider (differs|inspection failed)'):
                    BOOTSTRAP.prepare_provider(self.root, self.assets, True)
                command.assert_called_once_with(['docker', 'info', '--format', '{{.Architecture}}'])
        self.assertFalse((self.assets / 'provider-input.json').exists())

    def test_verified_warm_sdk_needs_no_provider_acquisition(self):
        self.image_record()
        with patch.object(BOOTSTRAP, 'provider_input', side_effect=AssertionError('warm provider acquisition')):
            result = BOOTSTRAP.prepare_provider(self.root, self.assets, False)
        self.assertEqual(result['qualification'], 'verified-cached-SDK-provider-not-required')
        self.assertFalse((self.assets / 'provider-input.json').exists())

    def test_replaced_sdk_keeps_only_its_compact_receipt(self):
        record = self.image_record()
        BOOTSTRAP.retire_stale_image(self.assets)
        self.assertFalse((self.assets / 'sdk-image.tar').exists())
        self.assertEqual(json.loads((self.assets / 'ci-sdk.previous.json').read_bytes()), record)
        self.assertFalse(list(self.assets.glob('superseded-*')))
        BOOTSTRAP.retire_stale_image(self.assets)

    def test_unowned_or_changed_sdk_is_not_deleted(self):
        self.image_record()
        archive = self.assets / 'sdk-image.tar'
        archive.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs from its retained receipt'):
            BOOTSTRAP.retire_stale_image(self.assets)
        self.assertEqual(archive.read_bytes(), b'changed')
        (self.assets / 'ci-sdk.json').unlink()
        with self.assertRaisesRegex(ValueError, 'not a receipt-owned ordinary file'):
            BOOTSTRAP.retire_stale_image(self.assets)
        self.assertEqual(archive.read_bytes(), b'changed')

    def test_interrupted_sdk_export_removes_partial_and_build_context(self):
        previous = self.image_record()
        runtime = (self.assets / 'input-receipt.json').read_bytes()
        (self.root / 'scripts/quality/recipe.py').write_text('# newer build recipe\n')

        def container(_root, _assets, mode, **options):
            if mode == '--prepare-context':
                context = options['output'] / 'context'
                context.mkdir()
                (context / 'Containerfile').write_text('FROM ' + self.provider + '\n')
                (context / 'input-receipt.json').write_bytes(runtime)

        def checked(command, **_options):
            if command[:2] == ['docker', 'info']: return b'arm64\n'
            if command[:3] == ['docker', 'buildx', 'build']: return b'built'
            if command[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()
            self.assertEqual(command[:2], ['docker', 'save'])
            _options['stdout'].write(b'incomplete export')
            raise ValueError('export interrupted')

        with patch.object(BOOTSTRAP, 'checked', side_effect=checked), \
                patch.object(BOOTSTRAP, 'container', side_effect=container), \
                patch.object(BOOTSTRAP, 'retire_consumed_inputs'), \
                patch.object(BOOTSTRAP, 'acquire_inputs'), \
                patch.object(BOOTSTRAP.subprocess, 'run', return_value=self.provider_result()):
            with self.assertRaisesRegex(ValueError, 'export interrupted'):
                BOOTSTRAP.ensure(self.root, self.assets, self.output, True)
        self.assertEqual(json.loads((self.assets / 'ci-sdk.previous.json').read_bytes()), previous)
        self.assertEqual(list(self.assets.glob('sdk-image*.tar')), [])
        self.assertEqual(list(self.output.glob('context-*')), [])
        # If the old sources return, the previous receipt explains the absent
        # archive and setup starts a rebuild instead of trying to load it.
        (self.root / 'scripts/quality/recipe.py').write_text('# original build recipe\n')
        with patch.object(BOOTSTRAP, 'checked', side_effect=AssertionError('cold rebuild reached')):
            with self.assertRaisesRegex(AssertionError, 'cold rebuild reached'):
                BOOTSTRAP.ensure(self.root, self.assets, self.output, False)

    def test_cold_setup_builds_the_generated_containerfile_with_offline_native_limits(self):
        self.image_record()
        runtime_bytes = (self.assets / 'input-receipt.json').read_bytes()
        for filename in ('ci-sdk.json', 'input-receipt.json', 'sdk-image.tar'):
            (self.assets / filename).unlink()
        containers, commands = [], []

        def container(root, assets, mode, **options):
            self.assertEqual((root, assets), (self.root, self.assets))
            containers.append((mode, options))
            if mode == '--prepare-context':
                context = options['output'] / 'context'
                context.mkdir()
                (context / 'Containerfile').write_text('FROM ' + self.provider + '\n')
                (context / 'input-receipt.json').write_bytes(runtime_bytes)

        def checked(command, **options):
            commands.append(command)
            if command == ['docker', 'info', '--format', '{{.Architecture}}']:
                return b'aarch64\n'
            if command[:3] == ['docker', 'buildx', 'build']:
                self.assertTrue(retire.called)
                context = containers[-1][1]['output'] / 'context'
                self.assertEqual(command[command.index('--file') + 1], str(context / 'Containerfile'))
                self.assertTrue((context / 'Containerfile').is_file())
                self.assertFalse((context / 'Dockerfile').exists())
                self.assertEqual(command[command.index('--platform') + 1], 'linux/arm64')
                self.assertIn('--network=none', command)
                self.assertIn('--pull=false', command)
                self.assertIn('--load', command)
                self.assertEqual(command[-1], str(context))
                return b'original build fixture\n'
            if command[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()
            self.assertEqual(command[:2], ['docker', 'save'])
            self.assertIs(options['gzip_stdout'], True)
            options['stdout'].write(gzip.compress(b'original image archive fixture\n', mtime=0))
            return b'saved\n'

        with patch.object(BOOTSTRAP, 'checked', side_effect=checked), \
                patch.object(BOOTSTRAP, 'container', side_effect=container), \
                patch.object(BOOTSTRAP, 'retire_consumed_inputs') as retire, \
                patch.object(BOOTSTRAP, 'acquire_inputs') as acquire, \
                patch.object(BOOTSTRAP.subprocess, 'run', return_value=self.provider_result()) as provider:
            result = BOOTSTRAP.ensure(self.root, self.assets, self.output, True)
        acquire.assert_called_once_with(self.root, self.assets, True)
        retire.assert_called_once_with(self.root, self.assets, containers[-1][1]['output'])
        self.assertEqual(provider.call_args.args[0], ['docker', 'image', 'inspect', self.provider])
        self.assertEqual([mode for mode, _ in containers], ['--node-inputs', '--native-inputs', '--prepare-context'])
        self.assertEqual(containers[0][1], {'network': 'bridge'})
        self.assertEqual(containers[1][1], {})
        self.assertEqual(len(commands), 4)
        self.assertEqual(result['image_id'], self.image)
        self.assertEqual(BOOTSTRAP.verify_image_record(self.root, self.assets)['image_id'], self.image)
        self.assertEqual(BOOTSTRAP.read(self.assets / 'ci-sdk.json')['archive']['compression'], 'gzip')
        self.assertEqual(gzip.decompress((self.assets / 'sdk-image.tar').read_bytes()), b'original image archive fixture\n')
        self.assertEqual(list(self.output.glob('context-*')), [])

    def test_loaded_identity_and_owned_setup_paths_are_required(self):
        self.image_record()
        for changed in ({'Id': 'sha256:' + 'c' * 64}, {'Architecture': 'amd64'}, {'Os': 'windows'}):
            with self.subTest(changed=changed):
                actual = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux', **changed}
                with patch.object(BOOTSTRAP, 'checked', side_effect=[b'loaded', json.dumps([actual]).encode()]):
                    with self.assertRaisesRegex(ValueError, 'different immutable native identity'):
                        BOOTSTRAP.load_image(self.root, self.assets)
        with patch.object(BOOTSTRAP, 'checked', side_effect=AssertionError('invalid setup reached Docker')):
            for assets, output in ((self.root, self.output), (self.root / '.artifacts', self.output), (self.assets, self.root / 'outside')):
                with self.subTest(assets=assets, output=output), self.assertRaisesRegex(ValueError, 'owned artifact subdirectories'):
                    BOOTSTRAP.ensure(self.root, assets, output, False)
            with self.assertRaisesRegex(ValueError, 'differs from locked native provider'):
                BOOTSTRAP.ensure(self.root, self.assets, self.output, False, 'mutable:latest')


if __name__ == '__main__':
    unittest.main()
