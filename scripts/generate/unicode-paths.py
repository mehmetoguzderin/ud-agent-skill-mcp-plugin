#!/usr/bin/env python3
"""Derive frozen path data from independently pinned official Unicode16 inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUTS = {
    'UnicodeData.txt': ('ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f', 2175362),
    'CaseFolding.txt': ('6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb', 86092),
    'ReadMe.txt': ('14cafa23788d3a20dd21d6b0cdcb8d6dab520781fcd9ad9392f3b88ea607e633', 693),
}


def generate(root: Path) -> str:
    data, receipts = {}, []
    for name, (sha, size) in INPUTS.items():
        path = root / 'runtime/unicode-16' / name
        raw = path.read_bytes()
        if path.is_symlink() or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('official Unicode16 source differs from its pinned receipt: ' + name)
        data[name] = raw.decode('utf-8')
        receipts.append({'path': 'runtime/unicode-16/' + name, 'url': 'https://www.unicode.org/Public/16.0.0/ucd/' + name, 'sha256': sha, 'size_bytes': size})
    assigned, first = [], None
    for line in data['UnicodeData.txt'].splitlines():
        fields = line.split(';')
        codepoint = int(fields[0], 16)
        if fields[1].endswith(', First>'):
            if first is not None:
                raise ValueError('overlapping Unicode range')
            first = codepoint
        elif fields[1].endswith(', Last>'):
            if first is None or codepoint < first:
                raise ValueError('unpaired Unicode range')
            assigned.append([first, codepoint]); first = None
        elif fields[2] != 'Cn':
            assigned.append([codepoint, codepoint])
    if first is not None:
        raise ValueError('unterminated Unicode range')
    ranges = []
    for start, end in assigned:
        if ranges and start == ranges[-1][1] + 1:
            ranges[-1][1] = end
        else:
            ranges.append([start, end])
    mapping = {}
    for line in data['CaseFolding.txt'].splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        source, status, target, _ = [part.strip() for part in line.split(';')]
        if status in ('C', 'F'):
            mapping[chr(int(source, 16))] = ''.join(chr(int(part, 16)) for part in target.split())
    value = {'unicode_version': '16.0.0', 'normalization_form': 'NFC',
             'normalization_algorithm': 'normalize maximal assigned16 chunks; preserve every unassigned16 scalar as a CCC0 boundary',
             'normalization_assigned_ranges': ranges, 'mapping': mapping,
             'provenance': {'license': 'Unicode-3.0', 'license_path': 'licenses/Unicode-3.0.txt', 'sources': receipts}}
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    output = ROOT / 'workers/ud/src/ud_agent/unicode_casefold.json'
    generated = generate(ROOT)
    if args.check:
        if output.read_text() != generated:
            raise SystemExit('frozen Unicode path data is stale')
    else:
        output.write_text(generated, encoding='utf-8')


if __name__ == '__main__':
    main()
