"""POSIX metadata/syscall model over real fixture bytes and file identities.

Foreign hosts exercise policy only; native Linux supplies confinement evidence.
The adapter is confined to explicitly registered temporary fixture roots.
"""
import contextlib
import errno
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch


@contextlib.contextmanager
def posix_files(module, root, *, enabled=None):
    if enabled is None:
        enabled = os.name == 'nt'
    if not enabled:
        yield
        return
    root = Path(root).absolute()
    original_stat, original_lstat, original_chmod = Path.stat, Path.lstat, Path.chmod
    modes, descriptors = {}, {}
    nofollow, nonblock = 0x10000000, 0x20000000

    def inside(path):
        return Path(path).absolute().is_relative_to(root)

    def metadata(value, mode=None):
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        identity = value.st_dev, value.st_ino
        default = (0o700 if stat.S_ISDIR(value.st_mode) else 0o555 if not value.st_mode & 0o222 else 0o644)
        fields.update(st_uid=1000, st_mode=stat.S_IFMT(value.st_mode) | modes.get(identity, default if mode is None else mode))
        return SimpleNamespace(**fields)

    def named(path, *, follow_symlinks=True):
        value = original_stat(path, follow_symlinks=follow_symlinks)
        return metadata(value) if inside(path) else value

    def chmod(path, mode, **options):
        if inside(path):
            info = original_lstat(path)
            modes[info.st_dev, info.st_ino] = mode
        return original_chmod(path, mode, **options)

    def opened(path, flags, mode=0o777):
        if not inside(path):
            raise AssertionError('POSIX file model escaped its fixture root')
        if flags & nofollow:
            try:
                if stat.S_ISLNK(original_lstat(path).st_mode):
                    raise OSError(errno.ELOOP, 'modeled O_NOFOLLOW refusal')
            except FileNotFoundError:
                pass
        native_flags = flags & ~(nofollow | nonblock)
        if flags & nofollow:
            native_flags |= getattr(os, 'O_NOFOLLOW', 0)
        if flags & nonblock:
            native_flags |= getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(path, native_flags, mode)
        descriptors[descriptor] = Path(path)
        if flags & os.O_CREAT:
            value = os.fstat(descriptor)
            modes[value.st_dev, value.st_ino] = mode
        return descriptor

    def fstat(descriptor):
        if descriptor not in descriptors:
            raise AssertionError('POSIX file model received an unowned descriptor')
        return metadata(os.fstat(descriptor))

    def fchmod(descriptor, mode):
        chmod(descriptors[descriptor], mode)

    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    proxy.O_NOFOLLOW, proxy.O_NONBLOCK = nofollow, nonblock
    proxy.getuid = proxy.geteuid = lambda: 1000
    proxy.open, proxy.fstat, proxy.fchmod = opened, fstat, fchmod
    with patch.object(module, 'os', proxy), patch.object(Path, 'stat', named), \
            patch.object(Path, 'lstat', lambda path: named(path, follow_symlinks=False)), \
            patch.object(Path, 'chmod', chmod):
        yield
