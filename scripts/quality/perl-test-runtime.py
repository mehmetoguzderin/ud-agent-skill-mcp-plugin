#!/opt/mutation/python/bin/python3
"""Expose the exact image-private Perl to isolated bridge fixture processes."""
import json
import os
from pathlib import Path
import sys

root = Path('/opt/ud-agent/perl')
receipt = json.loads((root / 'runtime.json').read_text())
loader = receipt['loader']
command = [str(root / loader['executable']), '--inhibit-cache', '--library-path', ':'.join(str(root / item) for item in loader['library_dirs']), str(root / receipt['executable']), '-f']
for directory in receipt['library_dirs']:
    command += ['-I', str(root / directory)]
# Tests supply their own explicitly authored Graph/Node fixtures with -I or
# PERL5LIB. These sit inside the child's Landlock-confined temporary directory.
os.execv(command[0], [*command, *sys.argv[1:]])
