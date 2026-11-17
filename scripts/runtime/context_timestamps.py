"""Normalize timestamps only on ordinary, caller-owned build context entries."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import stat


def set_epoch(path):
    path = Path(path)
    info = path.lstat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('build context timestamp target is not ordinary')
    if os.name == 'nt':
        spec = importlib.util.spec_from_file_location('ud_context_windows_storage', Path(__file__).resolve().parents[1] / 'quality/windows-storage-acl.py')
        storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
        storage.WindowsStorage().set_epoch(str(path.absolute()), 'directory' if stat.S_ISDIR(info.st_mode) else 'file', (info.st_dev, info.st_ino))
    else:
        os.utime(path, (0, 0), follow_symlinks=False)
