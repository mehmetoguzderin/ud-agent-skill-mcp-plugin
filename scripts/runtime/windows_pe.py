"""Bounded PE identities/import closure for private Windows runtime artifacts."""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import shutil
import struct

MACHINES = {"x64": 0x8664, "arm64": 0xAA64}
# Windows 10+ system components, always resolved by the OS. VC redistributables
# deliberately are not in this set: they must be present in the owned closure.
SYSTEM_DLLS = frozenset("advapi32 bcrypt bcryptprimitives cabinet cfgmgr32 comctl32 comdlg32 crypt32 cryptbase cryptsp dbghelp dnsapi gdi32 imm32 iphlpapi kernel32 kernelbase mpr mswsock ncrypt netapi32 normaliz ntdll ole32 oleaut32 powrprof propsys psapi rpcrt4 secur32 setupapi shell32 shlwapi sspicli user32 userenv ucrtbase version winhttp wininet winmm winspool winscard wintrust wldap32 ws2_32 wtsapi32".split())

def _name(value: bytes) -> str:
    try: text = value.decode("ascii").lower()
    except UnicodeDecodeError as error: raise ValueError("non-ASCII PE import name") from error
    if not re.fullmatch(r"[a-z0-9_][a-z0-9_.-]{0,254}\.(?:dll|drv)", text) or ".." in text:
        raise ValueError("PE import must be a DLL basename: "+repr(text))
    return text

def inspect_pe(data: bytes, architecture: str) -> dict:
    """Inspect normal and delay imports without loading or executing a binary."""
    if architecture not in MACHINES or not isinstance(data, bytes) or len(data) > 256 * 1024 * 1024 or len(data) < 64 or data[:2] != b"MZ": raise ValueError("invalid bounded PE image")
    def u16(offset):
        if offset < 0 or offset + 2 > len(data): raise ValueError("truncated PE header")
        return struct.unpack_from("<H", data, offset)[0]
    def u32(offset):
        if offset < 0 or offset + 4 > len(data): raise ValueError("truncated PE header")
        return struct.unpack_from("<I", data, offset)[0]
    pe = u32(60)
    if pe < 64 or pe + 24 > len(data) or data[pe:pe+4] != b"PE\0\0" or u16(pe+4) != MACHINES[architecture]: raise ValueError("PE architecture or signature mismatch")
    sections, optional_size = u16(pe+6), u16(pe+20)
    optional = pe + 24
    if not 1 <= sections <= 96 or optional_size < 240 or optional + optional_size + 40 * sections > len(data) or u16(optional) != 0x20B: raise ValueError("invalid PE32+ sections or optional header")
    directory_count = u32(optional+108)
    if directory_count < 14 or directory_count > 16 or optional_size < 112 + 8 * directory_count: raise ValueError("invalid PE data directory count")
    image_base = struct.unpack_from("<Q", data, optional+24)[0]
    headers_size = u32(optional+60)
    if headers_size < optional + optional_size + sections * 40 or headers_size > len(data): raise ValueError("invalid PE header extent")
    regions = []
    for index in range(sections):
        at = optional + optional_size + index * 40
        virtual_size, rva, raw_size, raw = (u32(at+x) for x in (8, 12, 16, 20))
        if raw_size and (raw < headers_size or raw + raw_size > len(data)) or rva + max(virtual_size, raw_size) > 0x100000000: raise ValueError("invalid PE section extent")
        if any(rva < end and start < rva + max(virtual_size, raw_size) for start, end, _, _ in regions): raise ValueError("overlapping PE virtual sections")
        regions.append((rva, rva + max(virtual_size, raw_size), raw, raw_size))
    def offset(rva, size):
        if not isinstance(rva, int) or not isinstance(size, int) or rva < 0 or size < 0 or rva + size > 0x100000000: raise ValueError("invalid PE RVA")
        if rva < headers_size and rva + size <= headers_size: return rva
        for start, end, raw, raw_size in regions:
            if start <= rva and rva + size <= end and rva - start + size <= raw_size: return raw + rva - start
        raise ValueError("PE RVA does not refer to complete file bytes")
    def cstring(rva):
        value = bytearray()
        for index in range(257):
            byte = data[offset(rva+index, 1)]
            if byte == 0: return _name(bytes(value))
            value.append(byte)
        raise ValueError("oversized PE import name")
    imports = set()
    for directory, stride in ((1, 20), (13, 32)):
        address, length = u32(optional+112+8*directory), u32(optional+116+8*directory)
        if not address and not length: continue
        if not address or length < stride or length > stride * 4097: raise ValueError("invalid PE import directory")
        offset(address, length)
        terminated = False
        for index in range(min(length // stride, 4097)):
            at = offset(address+index*stride, stride); entry = data[at:at+stride]
            if not any(entry): terminated = True; break
            name = u32(at+12 if directory == 1 else at+4)
            if directory == 13:
                flags = u32(at)
                if flags not in (0, 1): raise ValueError("unknown PE delay import attributes")
                if flags == 0: name -= image_base
            imports.add(cstring(name))
        if not terminated: raise ValueError("unterminated PE import directory")
    return {"architecture": architecture, "sha256": "sha256:"+hashlib.sha256(data).hexdigest(), "size": len(data), "imports": sorted(imports)}

def system_dll(name: str) -> bool:
    return name == "winspool.drv" or name.endswith(".dll") and (name[:-4] in SYSTEM_DLLS or re.fullmatch(r"(?:api|ext)-ms-win-[a-z0-9-]+\.dll", name) is not None)

def close_runtime_imports(root: Path, architecture: str, providers: list[Path]) -> list[dict]:
    """Copy only verified-provider DLL bytes needed by all packaged PE roots."""
    root = root.resolve(strict=True)
    candidates = {}
    for provider in providers:
        provider = provider.resolve(strict=True)
        for item in sorted(provider.rglob("*")):
            if item.is_symlink(): raise ValueError("Windows runtime provider contains links")
            if item.is_file() and item.suffix.lower() == ".dll":
                name = _name(item.name.encode("ascii")); body = item.read_bytes(); fingerprint = "sha256:"+hashlib.sha256(body).hexdigest()
                if name in candidates and candidates[name][1] != fingerprint: raise ValueError("ambiguous runtime provider DLL")
                candidates[name] = (item, fingerprint)
    binary_directory = root / "bin"
    if not binary_directory.is_dir() or binary_directory.is_symlink(): raise ValueError("private Perl bin directory is absent")
    roots = sorted(item for item in root.rglob("*") if item.suffix.lower() in (".exe", ".dll"))
    if not roots or len(roots) > 10000: raise ValueError("invalid Windows runtime PE inventory")
    receipt = []; visited = set(); local = {}
    for item in roots:
        if item.is_symlink() or not item.is_file(): raise ValueError("Windows runtime binary is not a regular file")
        if item.parent == binary_directory:
            name = item.name.lower(); body = item.read_bytes(); identity = inspect_pe(body, architecture)
            if name in local and local[name][1] != identity["sha256"]: raise ValueError("ambiguous product DLL search identity")
            local[name] = (item, identity["sha256"])
    while roots:
        item = roots.pop(0)
        if item in visited: continue
        visited.add(item); identity = inspect_pe(item.read_bytes(), architecture)
        receipt.append({"path": item.relative_to(root).as_posix(), **identity})
        for name in identity["imports"]:
            if system_dll(name): continue
            beside = [candidate for candidate in item.parent.iterdir() if candidate.name.lower() == name]
            if len(beside) > 1: raise ValueError("ambiguous DLL beside packaged binary")
            if beside:
                dependency = beside[0]
                if dependency.is_symlink() or not dependency.is_file(): raise ValueError("runtime DLL is not a regular file")
                inspect_pe(dependency.read_bytes(), architecture); roots.append(dependency); continue
            if name in local: roots.append(local[name][0]); continue
            if name not in candidates: raise ValueError("missing private runtime DLL: "+name)
            source, expected = candidates[name]; target = binary_directory / name
            body = source.read_bytes()
            if "sha256:"+hashlib.sha256(body).hexdigest() != expected: raise ValueError("runtime provider changed during closure copy")
            inspect_pe(body, architecture)
            with target.open("xb") as output: output.write(body)
            target.chmod(0o644); local[name] = (target, expected); roots.append(target)
    return sorted(receipt, key=lambda item:item["path"])
