"""Inventory bounded mutation evidence without retaining disposable work trees."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_FILE = 16 * 1024 ** 2
MAX_TOTAL = 64 * 1024 ** 2
MAX_FILES = 50000
DISPOSABLE = {'node_modules', 'target', '__pycache__', '.cache', '.venv', 'coordinator-home', 'rust-cargo-home', 'rust-candidates'}


def inventory(root: Path, *, max_file=MAX_FILE, max_total=MAX_TOTAL, max_files=MAX_FILES):
    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode) or root.is_symlink():
        raise ValueError('mutation evidence root must be an ordinary directory')
    rows = []; total = 0
    def walk(directory, generated=False, work_root=False):
        nonlocal total
        for item in sorted(os.scandir(directory), key=lambda entry: entry.name):
            name = Path(item.path).relative_to(root).as_posix()
            # DirEntry.stat() caches zero inode/link fields on Windows.
            # A fresh lstat retains the actual single-link evidence policy.
            info = os.lstat(item.path)
            if stat.S_ISLNK(info.st_mode):
                # Work contains the deliberate immutable node_modules link.
                if generated: continue
                raise ValueError('mutation evidence contains a link')
            if stat.S_ISDIR(info.st_mode):
                if item.name in DISPOSABLE: continue
                if work_root and item.name not in {'mutants', 'mutants.out', '.ud-generator-repairs'}: continue
                walk(Path(item.path), generated or item.name in {'work', 'mutants', 'mutants.out', 'src'}, item.name == 'work')
                continue
            # Python generation proof reads the latest runtime projection as
            # data, alongside its exact CONTROL copy and span metadata.
            indexed_program = Path(item.name).suffix == '.py' and Path(item.path + '.spans').is_file()
            selected = not generated or Path(item.name).suffix in {'.meta', '.spans', '.json', '.jsonl', '.log'} or item.name == 'CONTROL' or indexed_program
            if not selected: continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('mutation evidence contains a linked or special file')
            if info.st_size > max_file or total + info.st_size > max_total or len(rows) >= max_files:
                raise ValueError('mutation evidence exceeds its retention budget')
            fingerprint = hashlib.sha256()
            with open(item.path, 'rb') as stream:
                before = os.fstat(stream.fileno())
                while block := stream.read(1024 ** 2): fingerprint.update(block)
                after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('mutation evidence changed during inventory')
            total += info.st_size
            rows.append({'path': name, 'size_bytes': info.st_size, 'sha256': fingerprint.hexdigest()})
    walk(root)
    return {'schema_version': 1, 'qualification': 'bounded-required-mutation-evidence', 'size_bytes': total, 'files': rows}


def usage(root: Path, maximum: int):
    """Read-only conservative accounting; disposable files still consume budget."""
    root = Path(root); total = 0; count = 0; pending = [root]
    if root.is_symlink() or not root.is_dir(): raise ValueError('mutation usage root is invalid')
    while pending:
        directory = pending.pop()
        try: entries = list(os.scandir(directory))
        except FileNotFoundError: continue
        for item in entries:
            try: info = item.stat(follow_symlinks=False)
            except FileNotFoundError: continue
            count += 1
            total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
            if count > 200000 or total > maximum: raise ValueError('mutation state exceeds its scratch budget')
            if stat.S_ISDIR(info.st_mode): pending.append(Path(item.path))
    filesystem = os.statvfs(root)
    free = filesystem.f_bavail * filesystem.f_frsize
    if free < 10_000_000_000: raise ValueError('mutation state would consume its 10 GB free reserve')
    return {'size_bytes': total, 'entries': count, 'free_bytes': free}


if __name__ == '__main__':
    import sys
    print(json.dumps(usage(Path(sys.argv[1]), int(sys.argv[3])) if len(sys.argv) == 4 and sys.argv[2] == '--usage' else inventory(Path(sys.argv[1])), separators=(',', ':')))
