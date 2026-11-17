"""Portable byte/policy tests; native UID, RO-mount and Landlock proof is separate."""
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import io
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_oci_exec_policy', ROOT / 'scripts/quality/oci-exec.py')
boundary = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'resource': types.SimpleNamespace(), 'fcntl': types.SimpleNamespace()} if os.name == 'nt' else {}):
    spec.loader.exec_module(boundary)


def entry(name, payload, mode=0o644):
    return {'path': name, 'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload), 'mode': mode}


@contextmanager
def modeled_coordinator_owner(*, readonly=True):
    # Windows/macOS run these same byte and shape tests. This projects ONLY the
    # unavailable container-root ownership/RO metadata; native proof covers it.
    fstat, ordinary_stat = os.fstat, os.stat
    def project(info):
        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        values['st_uid'] = 0
        return types.SimpleNamespace(**values)
    with ExitStack() as stack:
        stack.enter_context(patch.object(boundary.os, 'fstat', side_effect=lambda fd: project(fstat(fd))))
        stack.enter_context(patch.object(boundary.os, 'stat', side_effect=lambda *args, **kwargs: project(ordinary_stat(*args, **kwargs))))
        stack.enter_context(patch.object(boundary.os, 'chown'))
        if readonly:
            stack.enter_context(patch.object(boundary.os, 'fstatvfs', return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)))
        yield


class HandoffPolicyTests(unittest.TestCase):
    def test_mutant_fingerprints_keep_the_original_source_closure_distinct(self):
        workspace = {'root': '/state/original', 'files': [entry('source.js', b'original')], 'readonly_links': [], 'readonly_tree': True}
        original = boundary.handoff_fingerprints(workspace)
        self.assertEqual(original['inventory_sha256'], original['source_inventory_sha256'])
        mutated = {**workspace, 'materializations': [{'path': 'source.js', 'before_sha256': 'a' * 64, 'after_sha256': 'b' * 64, 'size': 7, 'bytes': b'mutated'}]}
        receipt = boundary.handoff_fingerprints(mutated)
        self.assertEqual(receipt['source_inventory_sha256'], original['inventory_sha256'])
        self.assertNotEqual(receipt['inventory_sha256'], original['inventory_sha256'])
        other = {**mutated, 'files': [entry('source.js', b'another original')]}
        self.assertNotEqual(boundary.handoff_fingerprints(other)['source_inventory_sha256'], receipt['source_inventory_sha256'])
        changed = {**mutated, 'materializations': [{**mutated['materializations'][0], 'after_sha256': 'c' * 64}]}
        self.assertNotEqual(boundary.handoff_fingerprints(changed)['inventory_sha256'], receipt['inventory_sha256'])
        self.assertEqual(mutated['materializations'][0]['bytes'], b'mutated')

    def test_result_reads_remain_bounded_independently_of_child_file_writes(self):
        for value in [True, False, 0, -1, 32 * 1024**2 + 1, 3.5, '1234', {}, []]:
            with self.subTest(value=value), patch.object(boundary.os, 'geteuid', return_value=0, create=True), self.assertRaisesRegex(ValueError, 'result bound'):
                boundary.execute([sys.executable], state='/unused', environment={}, result={'basename': 'result.json', 'max_bytes': value})

    def test_materialization_binds_one_closed_source_and_never_tests_or_unsealed_trees(self):
        before, after = b'answer = true;\r\n', b'answer = false;\r\n'
        name = 'packages/coordinator/src/answer.ts'
        files = {name: entry(name, before)}
        patch_bytes = {'path': name, 'before_sha256': hashlib.sha256(before).hexdigest(), 'after_sha256': hashlib.sha256(after).hexdigest(), 'size': len(after), 'bytes': after}
        workspace = {'readonly_tree': True, 'materializations': [patch_bytes]}
        self.assertEqual(boundary.materializations(workspace, files), {name: patch_bytes})
        cli_name = 'packages/npm-distribution/cli.cjs'
        self.assertEqual(boundary.materializations({**workspace, 'materializations': [{**patch_bytes, 'path': cli_name}]}, {cli_name: entry(cli_name, before)}), {cli_name: {**patch_bytes, 'path': cli_name}})
        grader_name = 'evals/graders/workflow.mjs'
        self.assertEqual(boundary.materializations({**workspace, 'materializations': [{**patch_bytes, 'path': grader_name}]}, {grader_name: entry(grader_name, before)}), {grader_name: {**patch_bytes, 'path': grader_name}})
        self.assertEqual(boundary.handoff_definition(workspace), {'readonly_tree': True, 'materializations': [{key: value for key, value in patch_bytes.items() if key != 'bytes'}]})
        for changed in [{'before_sha256': 'a' * 64}, {'after_sha256': 'a' * 64}, {'size': True}, {'size': len(after) + 1}, {'bytes': after.decode()}, {'extra': True}, {'path': 'packages/coordinator/tests/answer.ts'}, {'path': 'scripts/tests/answer.py'}, {'path': 'README.md'}, {'path': '../outside'}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):boundary.materializations({**workspace, 'materializations': [{**patch_bytes, **changed}]}, files)
        for changed in [{'readonly_tree': False}, {'materializations': [patch_bytes, patch_bytes]}, {'materializations': None}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):boundary.materializations({**workspace, **changed}, files)
        self.assertEqual(boundary.materializations({}, files), {})

    def test_materialized_copy_checks_original_then_seals_only_private_replacement(self):
        if os.name == 'nt':
            return self.test_materialization_binds_one_closed_source_and_never_tests_or_unsealed_trees()
        with tempfile.TemporaryDirectory() as temporary, modeled_coordinator_owner():
            root=Path(temporary).resolve();source=root/'source';job=root/'job';source.mkdir();job.mkdir();name='scripts/example.py'
            (source/'scripts').mkdir();original=b'original()\r\n';replacement=b'mutated()\r\n';(source/name).write_bytes(original);(source/name).chmod(0o644)
            contract={'root':str(source),'files':[entry(name,original)],'readonly_links':[],'readonly_tree':True,'materializations':[{'path':name,'before_sha256':hashlib.sha256(original).hexdigest(),'after_sha256':hashlib.sha256(replacement).hexdigest(),'size':len(replacement),'bytes':replacement}]}
            tree=boundary._handoff(contract,job,100001)
            self.assertEqual((tree/name).read_bytes(),replacement);self.assertEqual((source/name).read_bytes(),original);self.assertEqual(stat.S_IMODE((tree/name).stat().st_mode),0o444)
            (tree/'scripts').chmod(0o755);tree.chmod(0o755)
            rejected=root/'rejected';rejected.mkdir();(source/name).write_bytes(b'substitute!\n')
            with self.assertRaises(ValueError):boundary._handoff(contract,rejected,100001)

    def test_exact_closed_copy_and_immutable_link_preserve_input_bytes(self):
        if os.name == 'nt':
            return self.posix_model('copy')
        with tempfile.TemporaryDirectory() as temporary, modeled_coordinator_owner():
            root = Path(temporary).resolve()
            source, job, dependencies = root / 'source', root / 'job', root / 'dependencies'
            for directory in (source, job, dependencies):
                directory.mkdir(mode=0o700)
            (source / 'nested').mkdir()
            original = b'export const answer = 42;\r\n'
            (source / 'nested/main.ts').write_bytes(original)
            (source / 'nested/main.ts').chmod(0o644)
            module = b'export default 7;\n'
            (dependencies / 'module.mjs').write_bytes(module)
            (dependencies / 'module.mjs').chmod(0o444)
            (dependencies / 'alias.mjs').symlink_to('module.mjs')
            manifest = {'schema_version': 1, 'files': [entry('module.mjs', module, 0o444)], 'links': [{'path': 'alias.mjs', 'target': 'module.mjs'}]}
            receipt = root / 'dependencies.json'
            payload = json.dumps(manifest).encode()
            receipt.write_bytes(payload)
            receipt.chmod(0o444)
            contract = {'root': str(source), 'files': [entry('nested/main.ts', original)], 'readonly_links': [{'path': 'node_modules', 'target': str(dependencies), 'closure_receipt': {'path': str(receipt), 'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)}}]}
            copied = boundary._handoff(contract, job, os.getuid())
            self.assertEqual(copied, job / 'tree')
            self.assertEqual((copied / 'nested/main.ts').read_bytes(), original)
            self.assertEqual(os.readlink(copied / 'node_modules'), str(dependencies))
            (copied / 'nested/main.ts').write_bytes(b'changed inside job')
            self.assertEqual((source / 'nested/main.ts').read_bytes(), original)
            scoped_job = root / 'scoped-job'
            scoped_job.mkdir(mode=0o700)
            scoped = boundary._handoff({**contract, 'cwd': 'nested'}, scoped_job, os.getuid())
            self.assertEqual(scoped, scoped_job / 'tree')
            self.assertEqual((scoped / 'nested/main.ts').read_bytes(), original)
            for name in ('../outside', 'node_modules', 'nested/main.ts', 'missing'):
                rejected = root / ('rejected-' + hashlib.sha256(name.encode()).hexdigest())
                rejected.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    boundary._handoff({**contract, 'cwd': name}, rejected, os.getuid())
            # Cache admission is per-controller and still reads/hash-checks the
            # immutable receipt on every call.
            receipt.chmod(0o644)
            receipt.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                boundary._dependency(str(dependencies), contract['readonly_links'][0]['closure_receipt'])

    def test_inventory_rejects_unlisted_links_special_files_and_incorrect_bytes(self):
        if os.name == 'nt':
            return self.posix_model('inventory')
        for case in ('extra', 'symlink', 'fifo', 'wrong-hash', 'wrong-size', 'hardlink', 'mode', 'directory-alias'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary, modeled_coordinator_owner():
                root = Path(temporary).resolve()
                source, job = root / 'source', root / 'job'
                source.mkdir(mode=0o700)
                job.mkdir(mode=0o700)
                payload = b'expected bytes'
                (source / 'input').write_bytes(payload)
                (source / 'input').chmod(0o644)
                contract = {'root': str(source), 'files': [entry('input', payload)], 'readonly_links': []}
                if case == 'extra':
                    (source / 'unlisted').write_bytes(b'foreign')
                elif case == 'symlink':
                    (source / 'input').unlink()
                    (source / 'input').symlink_to(job / 'outside')
                elif case == 'fifo':
                    (source / 'input').unlink()
                    os.mkfifo(source / 'input')
                elif case == 'wrong-hash':
                    (source / 'input').write_bytes(b'x' * len(payload))
                elif case == 'wrong-size':
                    contract['files'][0]['size'] += 1
                elif case == 'hardlink':
                    os.link(source / 'input', root / 'other')
                elif case == 'mode':
                    (source / 'input').chmod(0o600)
                else:
                    (source / 'nested').symlink_to(job)
                    contract['files'].append(entry('nested/file', b'not reachable'))
                with self.assertRaises((ValueError, OSError)):
                    boundary._handoff(contract, job, os.getuid())
                self.assertFalse((job / 'tree/input').is_symlink())

    def posix_model(self, kind):
        """Execute POSIX policy on Windows without claiming native FD support."""
        def metadata(mode=stat.S_IFREG | 0o644, size=7, links=1, inode=11):
            return types.SimpleNamespace(st_dev=3, st_ino=inode, st_uid=0, st_gid=0, st_mode=mode, st_nlink=links, st_size=size, st_mtime_ns=1234, st_ctime_ns=5678)
        if kind == 'copy':
            content = b'exact\r\n'
            info = metadata(size=len(content))
            for changed in (False, True):
                output = io.BytesIO()
                after = metadata(size=len(content), inode=12) if changed else info
                with patch.object(boundary, '_open_at', return_value=7), patch.object(boundary.os, 'fstat', side_effect=[info, after]), patch.object(boundary.os, 'read', side_effect=[content, b'']), patch.object(boundary.os, 'close'):
                    if changed:
                        with self.assertRaises(ValueError):
                            boundary._read_at(5, entry('input', content), output=output)
                    else:
                        boundary._read_at(5, entry('input', content), output=output)
                        self.assertEqual(output.getvalue(), content)
        elif kind == 'inventory':
            declared = {'input': entry('input', b'example')}
            for mode, names in [(stat.S_IFREG | 0o644, ['input']), (stat.S_IFIFO | 0o600, ['input']), (stat.S_IFLNK | 0o777, ['input']), (stat.S_IFREG | 0o644, ['foreign'])]:
                with patch.object(boundary.os, 'listdir', return_value=names), patch.object(boundary.os, 'stat', return_value=metadata(mode=mode)):
                    if mode == stat.S_IFREG | 0o644 and names == ['input']:
                        boundary._inventory(5, declared, {})
                    else:
                        with self.assertRaises(ValueError):
                            boundary._inventory(5, declared, {})
        elif kind == 'result':
            for mode, links, size in [(stat.S_IFREG | 0o600, 1, 7), (stat.S_IFREG | 0o600, 2, 7), (stat.S_IFIFO | 0o600, 1, 7), (stat.S_IFREG | 0o600, 1, 9)]:
                info = metadata(mode=mode, links=links, size=size)
                with patch.object(boundary.os, 'O_NOFOLLOW', 0x20000, create=True), patch.object(boundary.os, 'O_NONBLOCK', 0x800, create=True), patch.object(boundary.os, 'open', return_value=7) as opened, patch.object(boundary.os, 'fstat', return_value=info), patch.object(boundary.os, 'read', side_effect=[b'example', b'']), patch.object(boundary.os, 'close'):
                    if stat.S_ISREG(mode) and links == 1 and size == 7:
                        self.assertEqual(boundary._result('/job/result', 0, 8), b'example')
                    else:
                        with self.assertRaises(ValueError):
                            boundary._result('/job/result', 0, 8)
                    self.assertTrue(opened.call_args.args[1] & 0x20000)
        elif kind == 'dependencies':
            class PolicyPath(PurePosixPath):
                def resolve(self, strict=True):
                    return PolicyPath('/outside')
                def is_file(self):
                    return True
                def is_dir(self):
                    return False
            cases = [
                {'schema_version': 2, 'files': [], 'links': []},
                {'schema_version': 1, 'files': [entry('file', b'example', 0o644)], 'links': []},
                {'schema_version': 1, 'files': [], 'links': [{'path': 'alias', 'target': '../outside'}]},
            ]
            for data in cases:
                payload = json.dumps(data).encode()
                with patch.object(boundary, '_directory', return_value=5), patch.object(boundary.os, 'fstatvfs', return_value=types.SimpleNamespace(f_flag=1), create=True), patch.object(boundary.os, 'ST_RDONLY', 1, create=True), patch.object(boundary, '_read_at', return_value=payload), patch.object(boundary.os, 'fstat', return_value=metadata(mode=stat.S_IFDIR | 0o555)), patch.object(boundary.os, 'close'), patch.object(boundary, '_inventory'), patch.object(boundary, 'Path', PolicyPath):
                    with self.assertRaises(ValueError):
                        boundary._dependency('/deps', {'path': '/receipt.json', 'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)})
        else:
            self.fail('unknown modeled POSIX policy')

    def test_windows_posix_models_are_executed_on_every_host(self):
        for kind in ('copy', 'inventory', 'result', 'dependencies'):
            with self.subTest(kind=kind):
                self.posix_model(kind)

    def test_paths_schema_and_collisions_are_bounded(self):
        for value in (None, 0, 1, 'true', [], {}):
            with self.subTest(readonly_tree=value), self.assertRaises(ValueError):
                boundary._handoff({'root': '/not-opened', 'files': [], 'readonly_links': [], 'readonly_tree': value}, Path('/not-created'), 100001)
        for path in ('', '/abs', '../outside', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'C:drive', 'e\u0301', 'nul\0byte'):
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                boundary.relative(path)
        for definitions in ([entry('x', b'a'), entry('X', b'b')], [entry('x', b'a'), entry('x', b'a')], [{**entry('x', b'a'), 'size': True}], [{**entry('x', b'a'), 'mode': 0o4755}], [{**entry('x', b'a'), 'sha256': 'f' * 63}], [{**entry('x', b'a'), 'extra': 1}]):
            with self.subTest(definitions=definitions), self.assertRaises(ValueError):
                boundary._file_entries(definitions)
        self.assertEqual(boundary._file_entries([entry('nested/é.ts', b'')]), {'nested/é.ts': entry('nested/é.ts', b'')})

    def test_readonly_tree_seals_file_modes_and_retains_root_namespace_ownership(self):
        if os.name == 'nt':
            with patch.object(boundary, '_file_entries', side_effect=ValueError('modeled subsequent validation')) as checked:
                with self.assertRaisesRegex(ValueError, 'subsequent'):
                    boundary._handoff({'root': '/input', 'files': [], 'readonly_links': [], 'readonly_tree': True}, Path('/job'), 100001)
                checked.assert_called_once_with([])
            return
        with tempfile.TemporaryDirectory() as temporary, modeled_coordinator_owner(), patch.object(boundary.os, 'chown') as chown:
            root = Path(temporary).resolve(); source = root / 'source'; source.mkdir(); job = root / 'job'; job.mkdir()
            (source / 'nested').mkdir();(source / 'nested/test').write_bytes(b'trusted test');(source / 'nested/test').chmod(0o755)
            tree = boundary._handoff({'root': str(source), 'files': [entry('nested/test', b'trusted test', 0o755)], 'readonly_links': [], 'readonly_tree': True}, job, 100001)
            self.assertEqual(stat.S_IMODE((tree / 'nested/test').stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(tree.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((tree / 'nested').stat().st_mode), 0o555)
            chown.assert_not_called()
            # Restore local owner permissions solely for portable fixture cleanup.
            (tree / 'nested').chmod(0o755);tree.chmod(0o755)
            private_job = root / 'private-job';private_job.mkdir()
            (source / 'nested/test').chmod(0o600)
            private_tree = boundary._handoff({'root': str(source), 'files': [entry('nested/test', b'trusted test', 0o600)], 'readonly_links': [], 'readonly_tree': True}, private_job, 100001)
            self.assertEqual(stat.S_IMODE((private_tree / 'nested/test').stat().st_mode), 0o444)
            self.assertEqual((private_tree / 'nested/test').read_bytes(), b'trusted test')
            (private_tree / 'nested').chmod(0o755);private_tree.chmod(0o755)

    def test_result_collection_is_bounded_identity_checked_and_rejects_aliases(self):
        if os.name == 'nt':
            return self.posix_model('result')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = root / 'result.json'
            content = b'{"status":"detected","assertions":["exact"]}'
            result.write_bytes(content)
            self.assertEqual(boundary._result(result, os.getuid(), len(content)), content)
            for owner, limit in ((os.getuid() + 1, len(content)), (os.getuid(), len(content) - 1)):
                with self.assertRaises(ValueError):
                    boundary._result(result, owner, limit)
            os.link(result, root / 'second-link')
            with self.assertRaises(ValueError):
                boundary._result(result, os.getuid(), len(content))
            (root / 'second-link').unlink()
            result.unlink()
            result.symlink_to(root / 'foreign')
            with self.assertRaises(OSError):
                boundary._result(result, os.getuid(), 1024)
            result.unlink()
            os.mkfifo(result)
            with self.assertRaises(ValueError):
                boundary._result(result, os.getuid(), 1024)

    def test_dependency_receipt_cannot_admit_foreign_links_or_writable_assets(self):
        if os.name == 'nt':
            return self.posix_model('dependencies')
        for case in ('foreign', 'cycle', 'writable', 'unlisted', 'malformed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary, modeled_coordinator_owner():
                root = Path(temporary).resolve()
                deps = root / 'node_modules'
                deps.mkdir(mode=0o700)
                content = b'immutable'
                (deps / 'file').write_bytes(content)
                (deps / 'file').chmod(0o444)
                manifest = {'schema_version': 1, 'files': [entry('file', content, 0o444)], 'links': []}
                if case == 'foreign':
                    (root / 'outside').write_bytes(b'outside')
                    (deps / 'alias').symlink_to('../outside')
                    manifest['links'] = [{'path': 'alias', 'target': '../outside'}]
                elif case == 'cycle':
                    (deps / 'alias').symlink_to('alias')
                    manifest['links'] = [{'path': 'alias', 'target': 'alias'}]
                elif case == 'writable':
                    (deps / 'file').chmod(0o644)
                    manifest['files'][0]['mode'] = 0o644
                elif case == 'unlisted':
                    (deps / 'extra').write_bytes(b'extra')
                else:
                    manifest['schema_version'] = 2
                payload = json.dumps(manifest).encode()
                receipt = root / 'receipt.json'
                receipt.write_bytes(payload)
                receipt.chmod(0o444)
                with self.assertRaises((ValueError, OSError, RuntimeError)):
                    boundary._dependency(str(deps), {'path': str(receipt), 'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)})


if __name__ == '__main__':
    unittest.main()
