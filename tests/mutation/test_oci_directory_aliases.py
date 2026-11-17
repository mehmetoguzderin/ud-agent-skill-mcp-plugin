"""Portable closed-inventory policy models; real Linux handoff is separate."""
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('oci_alias_original_fixture', Path(__file__).with_name('test_oci_exec.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
boundary = fixture.boundary


def inspect(nodes, files, links=None):
    """Model a case-sensitive filesystem even on case-insensitive hosts.
    Only kernel directory operations/metadata are modeled, not the policy."""
    directories = {'': 10}
    for name, value in nodes.items():
        if value[0] == 'dir': directories[name] = 10 + len(directories)
    names = {descriptor: name for name, descriptor in directories.items()}
    def info(name):
        kind, changes = nodes[name]
        values = dict(st_dev=1, st_ino=100 + list(nodes).index(name), st_mode={'dir': stat.S_IFDIR | 0o755, 'file': stat.S_IFREG | 0o644, 'link': stat.S_IFLNK | 0o777}[kind], st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=123, st_ctime_ns=456)
        return types.SimpleNamespace(**{**values, **changes})
    def listing(descriptor):
        prefix = names[descriptor]
        return sorted(name.rsplit('/', 1)[-1] for name in nodes if name.rpartition('/')[0] == prefix)
    def relative(name, descriptor): return '/'.join(filter(None, (names[descriptor], name)))
    def metadata(name, *, dir_fd, follow_symlinks):
        if follow_symlinks is not False: raise AssertionError('inventory followed a link')
        return info(relative(name, dir_fd))
    def opened(name, flags, *, dir_fd):
        if flags & boundary.os.O_NOFOLLOW != boundary.os.O_NOFOLLOW: raise AssertionError('directory open lost O_NOFOLLOW')
        return directories[relative(name, dir_fd)]
    with ExitStack() as stack:
        stack.enter_context(patch.object(boundary.os, 'O_DIRECTORY', getattr(os, 'O_DIRECTORY', 0x10000), create=True))
        stack.enter_context(patch.object(boundary.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0x20000), create=True))
        stack.enter_context(patch.object(boundary.os, 'listdir', side_effect=listing))
        stack.enter_context(patch.object(boundary.os, 'stat', side_effect=metadata))
        stack.enter_context(patch.object(boundary.os, 'open', side_effect=opened))
        stack.enter_context(patch.object(boundary.os, 'fstat', side_effect=lambda descriptor: info(names[descriptor])))
        stack.enter_context(patch.object(boundary.os, 'close'))
        stack.enter_context(patch.object(boundary.os, 'readlink', return_value='/outside'))
        boundary._inventory(10, files, links or {})


def original_perl_directories():
    return {'Pod': ('dir', {}), 'Pod/Html.pm': ('file', {}), 'pod': ('dir', {}), 'pod/perlpod.pod': ('file', {})}


class DirectoryAliasInventoryTests(unittest.TestCase):
    def test_original_Pod_and_pod_spellings_with_distinct_exact_files_are_admitted(self):
        nodes = original_perl_directories()
        files = boundary._file_entries([fixture.entry('Pod/Html.pm', b'original module'), fixture.entry('pod/perlpod.pod', b'original documentation')])
        inspect(nodes, files)
        self.assertEqual(set(files), {'Pod/Html.pm', 'pod/perlpod.pod'})

    def test_full_file_case_collisions_stay_rejected(self):
        entries = [fixture.entry('Pod/README', b'one'), fixture.entry('pod/readme', b'two')]
        with self.assertRaisesRegex(ValueError, 'colliding path'): boundary._file_entries(entries)
        nodes = {'Pod': ('dir', {}), 'pod': ('dir', {}), 'Pod/README': ('file', {}), 'pod/readme': ('file', {})}
        with self.assertRaisesRegex(ValueError, 'colliding paths'): inspect(nodes, {row['path']: row for row in entries})

    def test_file_directory_and_link_directory_aliases_cannot_borrow_directory_permission(self):
        for kind in ('file', 'link'):
            with self.subTest(kind=kind):
                nodes = {'Pod': ('dir', {}), 'Pod/Html.pm': ('file', {}), 'pod': (kind, {})}
                files = {'Pod/Html.pm': fixture.entry('Pod/Html.pm', b'one')}
                if kind == 'file': files['pod'] = fixture.entry('pod', b'two')
                with self.assertRaisesRegex(ValueError, 'colliding paths'): inspect(nodes, files, {'pod': '/outside'} if kind == 'link' else {})

    def test_unlisted_files_and_directory_symlink_escape_stay_rejected(self):
        for extra in ('unlisted-file', 'directory-link'):
            with self.subTest(extra=extra):
                nodes = original_perl_directories()
                files = {name: fixture.entry(name, b'original') for name in ('Pod/Html.pm', 'pod/perlpod.pod')}
                if extra == 'unlisted-file': nodes['pod/unlisted'] = ('file', {})
                else: nodes['pod'] = ('link', {})
                with self.assertRaises(ValueError): inspect(nodes, files)

    def test_directory_aliases_do_not_relax_owner_or_write_permissions(self):
        for change in ({'st_uid': 501}, {'st_mode': stat.S_IFDIR | 0o777}):
            with self.subTest(change=change):
                nodes = original_perl_directories(); nodes['pod'] = ('dir', change)
                files = {name: fixture.entry(name, b'original') for name in ('Pod/Html.pm', 'pod/perlpod.pod')}
                with self.assertRaises(ValueError): inspect(nodes, files)


if __name__ == '__main__': unittest.main()
