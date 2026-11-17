"""Stream the verified source inventory to an OCI input volume. MIT."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile


class VerifiedReader:
    def __init__(self, stream):
        self.stream = stream
        self.sha = hashlib.sha256()
        self.size = 0

    def read(self, amount):
        result = self.stream.read(amount)
        self.sha.update(result)
        self.size += len(result)
        return result


def stream_source(root, receipt, output):
    root = Path(root).resolve(strict=True)
    files = receipt.get('files')
    if not isinstance(files, list) or not files:
        raise ValueError('source inventory is empty')
    seen = set()
    with tarfile.open(fileobj=output, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        for row in files:
            name = row.get('path'); size = row.get('size'); digest = row.get('sha256')
            if not isinstance(name, str) or not name or '\\' in name or ':' in name or '\0' in name or name.startswith('/') or any(part in ('', '.', '..') for part in name.split('/')) or name in seen:
                raise ValueError('source inventory path is unsafe or duplicated')
            if type(size) is not int or size < 0 or not isinstance(digest, str) or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest) or type(row.get('executable')) is not bool:
                raise ValueError('source inventory receipt is invalid')
            seen.add(name); current = root
            for component in name.split('/'):
                current = current / component
                if stat.S_ISLNK(current.lstat().st_mode): raise ValueError('source inventory contains a symlink')
            fd = os.open(current, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                    raise ValueError('source size or type differs from receipt')
                info = tarfile.TarInfo('source/' + name)
                info.size = size; info.mode = 0o755 if row['executable'] else 0o644; info.mtime = 0
                reader = VerifiedReader(source)
                archive.addfile(info, reader)
                after = os.fstat(source.fileno())
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                if identity(before) != identity(after) or reader.size != size or reader.sha.hexdigest() != digest:
                    raise ValueError('source bytes changed or differ from receipt')


if __name__ == '__main__':
    if len(sys.argv) != 3: raise SystemExit('usage: stream-mutation-source.py ROOT RECEIPT')
    with open(sys.argv[2], 'rb') as receipt_file:
        stream_source(sys.argv[1], json.load(receipt_file), sys.stdout.buffer)
