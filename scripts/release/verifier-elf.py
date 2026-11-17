"""Bounded data-only ELF64 inspection for publisher verifier inventories."""
import struct

LIMIT = 1 << 64


def virtual_bytes(data, loads, address, size):
    """Read file-backed virtual bytes, including adjacent PT_LOAD segments.

    A boundary may change the file displacement. Overlapping mappings must
    agree on that displacement; holes and zero-fill are never file bytes.
    """
    if not 0 <= address < LIMIT or not 0 <= size <= 16 * 1024**2 or address + size > LIMIT:
        raise ValueError('invalid ELF virtual read bounds')
    end = address + size
    boundaries = sorted({address, end} | {value for start, _, length in loads for value in (start, start + length) if address < value < end})
    result = bytearray()
    for start, stop in zip(boundaries, boundaries[1:]):
        offsets = {offset + start - origin for origin, offset, length in loads if origin <= start and stop <= origin + length}
        if len(offsets) != 1:
            raise ValueError('ELF virtual bytes are missing or ambiguously mapped')
        offset = offsets.pop()
        if offset < 0 or offset + stop - start > len(data):
            raise ValueError('ELF virtual bytes exceed the file')
        result.extend(data[offset:offset + stop - start])
    return bytes(result)


def inspect(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected little-endian ELF64')
    machine = struct.unpack_from('<H', data, 18)[0]
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not 1 <= count <= 256 or offset + size * count > len(data):
        raise ValueError('invalid ELF program headers')
    loads = []; dynamic = None; interpreter = None
    for index in range(count):
        kind, _, file_offset, address, _, file_size, memory_size, _ = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        if file_offset + file_size > len(data) or address + memory_size > LIMIT or (kind == 1 and file_size > memory_size):
            raise ValueError('invalid ELF segment bounds')
        if kind == 1:
            loads.append((address, file_offset, file_size))
        elif kind == 2:
            if dynamic is not None or file_size % 16 or file_size > 1024 * 1024:
                raise ValueError('invalid ELF dynamic segment')
            dynamic = (file_offset, file_size)
        elif kind == 3:
            if interpreter is not None or not 1 <= file_size <= 4096:
                raise ValueError('invalid ELF interpreter')
            raw = data[file_offset:file_offset + file_size]
            if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
                raise ValueError('invalid ELF interpreter string')
            interpreter = raw[:-1].decode('ascii')
    needed = []; paths = []; tags = {}; entries = []
    if dynamic:
        terminated = False
        for cursor in range(dynamic[0], dynamic[0] + dynamic[1], 16):
            kind, value = struct.unpack_from('<qQ', data, cursor)
            if kind == 0:
                terminated = True; break
            entries.append((kind, value))
            if kind in (5, 10):
                if kind in tags:
                    raise ValueError('duplicate ELF string-table declaration')
                tags[kind] = value
        if not terminated or 5 not in tags or 10 not in tags:
            raise ValueError('ELF dynamic strings are unavailable')
        table = virtual_bytes(data, loads, tags[5], tags[10])
        for kind, value in entries:
            if kind not in (1, 15, 29):
                continue
            if value >= len(table) or (end := table.find(b'\0', value)) < 0:
                raise ValueError('ELF dynamic string exceeds bounds or is unterminated')
            text = table[value:end].decode('ascii')
            (needed if kind == 1 else paths).append(text)
    return {'machine': machine, 'interpreter': interpreter, 'needed': needed, 'search_paths': paths}
