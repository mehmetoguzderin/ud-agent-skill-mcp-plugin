"""Frozen portable path keys shared by workers and standalone runtime setup."""
from __future__ import annotations
import json
from pathlib import Path
import unicodedata

_DATA = json.loads(Path(__file__).with_name('unicode_casefold.json').read_text(encoding='utf-8'))
_FOLDS = _DATA['mapping']
_ASSIGNED = _DATA['normalization_assigned_ranges']


def validate_path(value: object) -> str:
    """The same bounded portable path domain as the TypeScript broker."""
    if (not isinstance(value, str) or not value
            or any(ord(ch) < 32 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
            or len(value.encode('utf-8')) > 4096 or '\\' in value or ':' in value):
        raise ValueError('invalid portable path')
    parts = value.split('/')
    if len(parts) > 64:
        raise ValueError('portable path depth limit')
    for part in parts:
        stem = part.split('.')[0].lower()
        if (not part or part in ('.', '..') or part.lower() == '.git' or len(part.encode('utf-8')) > 255
                or part.endswith(('.', ' ')) or stem in {'con', 'prn', 'aux', 'nul'}
                or (len(stem) == 4 and stem[:3] in ('com', 'lpt') and stem[3] in '123456789')):
            raise ValueError('unsafe portable path component')
    return value


def assigned16(codepoint: int) -> bool:
    left, right = 0, len(_ASSIGNED)
    while left < right:
        middle = (left + right) // 2
        first, last = _ASSIGNED[middle]
        if codepoint < first:
            right = middle
        elif codepoint > last:
            left = middle + 1
        else:
            return True
    return False


def frozen_nfc(value: str) -> str:
    chunks, current = [], []
    for character in value:
        if assigned16(ord(character)):
            current.append(character)
        else:
            chunks.extend((unicodedata.normalize('NFC', ''.join(current)), character))
            current.clear()
    chunks.append(unicodedata.normalize('NFC', ''.join(current)))
    return ''.join(chunks)


def path_key(value: str) -> str:
    return ''.join(_FOLDS.get(character, character) for character in frozen_nfc(value))
