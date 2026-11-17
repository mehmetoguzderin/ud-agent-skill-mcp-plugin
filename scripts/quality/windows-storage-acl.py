#!/usr/bin/env python3
"""Handle-bound Windows ACLs for original quality storage. Authored MIT."""
from __future__ import annotations
import base64
import ctypes
from ctypes import wintypes
import json
import ntpath
import os
from pathlib import Path
import struct
import sys


def sid(authority, *parts):
    return bytes([1, len(parts)]) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', part) for part in parts)


SYSTEM = sid(5, 18)
ADMINS = sid(5, 32, 544)
FULL = 0x1F01FF
READ_ONLY = 0x80000000 | 0x20000000 | 0x100000 | 0x20000 | 1 | 8 | 32 | 128


def verify_final_path(requested, expanded, actual):
    def ordinary(value):
        if value.startswith('\\\\?\\UNC\\'): value = '\\\\' + value[8:]
        elif value.startswith('\\\\?\\'): value = value[4:]
        return ntpath.normcase(value)
    if ordinary(expanded) != ordinary(actual):
        details = {name: value[:160] for name, value in [('requested', requested), ('expanded', expanded), ('actual', actual)]}
        raise ValueError('Windows storage path contains an alias: ' + json.dumps(details, ensure_ascii=True))


def verify_owner(owner, caller):
    if owner != caller:
        raise ValueError('Windows storage must be owned by the current user')


def verify_acl(owner, caller, aces, private):
    """Match the native guardian's caller/SYSTEM/Administrators policy."""
    verify_owner(owner, caller)
    if aces is None:
        raise ValueError('Windows storage has no verified DACL')
    caller_full = False
    for kind, mask, principal, *flags in aces:
        if kind == 0:
            if principal not in (caller, SYSTEM, ADMINS) and (private or mask & ~READ_ONLY):
                raise ValueError('Windows storage permits another principal')
            if principal == caller and not (flags and flags[0] & 8) and (mask & 0x10000000 or mask & FULL == FULL):
                caller_full = True
        elif kind != 1:
            raise ValueError('Windows storage has an unsupported ACE')
    if not caller_full:
        raise ValueError('Windows storage lacks current-user full control')


class FileInformation(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME),
                ('accessed', wintypes.FILETIME), ('written', wintypes.FILETIME),
                ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]


class SecurityAttributes(ctypes.Structure):
    _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', wintypes.BOOL)]


class FileIdInformation(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_uint64), ('identifier', ctypes.c_ubyte * 16)]


class WindowsStorage:
    def __init__(self):
        if os.name != 'nt':
            raise ValueError('Windows storage ACLs require native Windows')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.security = ctypes.WinDLL('advapi32', use_last_error=True)
        pointer = ctypes.c_void_p
        signatures = [
            (self.kernel, 'GetCurrentProcess', [], wintypes.HANDLE),
            (self.kernel, 'CloseHandle', [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel, 'LocalFree', [pointer], pointer),
            (self.kernel, 'CreateFileW', [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, pointer, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
            (self.kernel, 'CreateDirectoryW', [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)], wintypes.BOOL),
            (self.kernel, 'GetFileInformationByHandle', [wintypes.HANDLE, ctypes.POINTER(FileInformation)], wintypes.BOOL),
            (self.kernel, 'GetFileInformationByHandleEx', [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD], wintypes.BOOL),
            (self.kernel, 'GetFinalPathNameByHandleW', [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD], wintypes.DWORD),
            (self.kernel, 'GetLongPathNameW', [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD], wintypes.DWORD),
            (self.kernel, 'WriteFile', [wintypes.HANDLE, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), pointer], wintypes.BOOL),
            (self.kernel, 'FlushFileBuffers', [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel, 'SetFileInformationByHandle', [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD], wintypes.BOOL),
            (self.kernel, 'SetFileTime', [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)], wintypes.BOOL),
            (self.security, 'OpenProcessToken', [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
            (self.security, 'GetTokenInformation', [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.security, 'IsValidSid', [pointer], wintypes.BOOL),
            (self.security, 'GetLengthSid', [pointer], wintypes.DWORD),
            (self.security, 'IsValidAcl', [pointer], wintypes.BOOL),
            (self.security, 'GetAce', [pointer, wintypes.DWORD, ctypes.POINTER(pointer)], wintypes.BOOL),
            (self.security, 'GetSecurityInfo', [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)], wintypes.DWORD),
            (self.security, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), pointer], wintypes.BOOL),
        ]
        for library, name, args, result in signatures:
            function = getattr(library, name); function.argtypes = args; function.restype = result
        token = wintypes.HANDLE()
        self.require(self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
        try:
            size = wintypes.DWORD()
            self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 4096: raise ValueError('Windows token is not bounded')
            buffer = ctypes.create_string_buffer(size.value)
            self.require(self.security.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)))
            self.caller = self.sid_bytes(ctypes.cast(buffer, ctypes.POINTER(pointer))[0])
        finally:
            self.kernel.CloseHandle(token)

    @staticmethod
    def require(result):
        if not result: raise ctypes.WinError(ctypes.get_last_error())
        return result

    def sid_bytes(self, address):
        self.require(address and self.security.IsValidSid(address))
        size = self.security.GetLengthSid(address)
        if not 8 <= size <= 68: raise ValueError('Windows SID is not bounded')
        return ctypes.string_at(address, size)

    def inspect_handle(self, handle, filename, kind, private, *, mutation=False):
        info = FileInformation()
        self.require(self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)))
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != (kind == 'directory') or kind == 'file' and info.links != 1:
            raise ValueError('Windows storage is linked, special or has a different kind')
        final = ctypes.create_unicode_buffer(32768)
        length = self.kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < length < len(final): raise ValueError('Windows storage final path is unavailable')
        # Node's non-native realpath walks symlinks but can retain an 8.3 TEMP
        # spelling. Expand that spelling without accepting a different target.
        expanded = ctypes.create_unicode_buffer(32768)
        length = self.kernel.GetLongPathNameW(os.path.abspath(filename), expanded, len(expanded))
        if not 0 < length < len(expanded): raise ValueError('Windows storage long path is unavailable')
        verify_final_path(filename, expanded.value, final.value)
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        result = self.security.GetSecurityInfo(handle, 1, 1 if mutation else 1 | 4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if result: raise ctypes.WinError(result)
        try:
            aces = None
            if dacl:
                self.require(self.security.IsValidAcl(dacl))
                header = ctypes.string_at(dacl, 8)
                size, count = struct.unpack_from('<HH', header, 2)
                if not 8 <= size <= 65535 or count > 4096: raise ValueError('Windows DACL is not bounded')
                aces = []
                for index in range(count):
                    address = ctypes.c_void_p()
                    self.require(self.security.GetAce(dacl, index, ctypes.byref(address)))
                    kind_value, flags, ace_size, mask = struct.unpack('<BBHI', ctypes.string_at(address, 8))
                    if kind_value not in (0, 1) or ace_size < 16: raise ValueError('Windows DACL has an unsupported ACE')
                    principal = self.sid_bytes(address.value + 8)
                    if len(principal) + 8 > ace_size: raise ValueError('Windows ACE is truncated')
                    aces.append((kind_value, mask, principal, flags))
            if mutation:
                verify_owner(self.sid_bytes(owner), self.caller)
            else:
                verify_acl(self.sid_bytes(owner), self.caller, aces, private)
        finally:
            if descriptor: self.kernel.LocalFree(descriptor)
        return {'device': str(info.volume), 'inode': str((info.index_high << 32) | info.index_low)}

    def inspect(self, filename, kind, private=True):
        handle = self.kernel.CreateFileW(filename, 0x20000 | 0x80, 1 | 2, None, 3, 0x02000000 | 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        try: return self.inspect_handle(handle, filename, kind, private)
        finally: self.kernel.CloseHandle(handle)

    def mutation_handle(self, filename, kind, access, expected=None):
        before = os.lstat(filename)
        identity = (before.st_dev, before.st_ino)
        if expected is not None and identity != expected: raise ValueError('Windows mutation file identity changed')
        handle = self.kernel.CreateFileW(filename, access | 0x20000 | 0x80, 1, None, 3, 0x02000000 | 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        try:
            # Ordinary context/replay data need not have private ACLs. The
            # kernel admitted this exact operation, and this held handle denies
            # concurrent writers/deleters while owner/path/identity are checked.
            self.inspect_handle(handle, filename, kind, False, mutation=True)
            full = FileIdInformation()
            self.require(self.kernel.GetFileInformationByHandleEx(handle, 18, ctypes.byref(full), ctypes.sizeof(full)))
            if (full.volume, int.from_bytes(bytes(full.identifier), 'little')) != identity:
                raise ValueError('Windows mutation file identity changed')
            return handle
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise

    def unlink_readonly(self, filename, expected=None):
        """Delete one exact owned ordinary inode without changing its ACL/mode."""
        handle = self.mutation_handle(filename, 'file', 0x10000, expected)
        try:
            # FileDispositionInfoEx: DELETE | IGNORE_READONLY_ATTRIBUTE.
            # No POSIX replacement flag or pathname deletion fallback.
            flags = wintypes.DWORD(1 | 0x10)
            self.require(self.kernel.SetFileInformationByHandle(handle, 21, ctypes.byref(flags), ctypes.sizeof(flags)))
        finally: self.kernel.CloseHandle(handle)

    def set_epoch(self, filename, kind, expected=None):
        """Set access/write timestamps on the held ordinary owned context entry."""
        handle = self.mutation_handle(filename, kind, 0x100, expected)
        try:
            before = self.inspect_handle(handle, filename, kind, False, mutation=True)
            ticks = 116444736000000000  # 1970-01-01 in 100ns units since 1601.
            epoch = wintypes.FILETIME(ticks & 0xffffffff, ticks >> 32)
            self.require(self.kernel.SetFileTime(handle, None, ctypes.byref(epoch), ctypes.byref(epoch)))
            if self.inspect_handle(handle, filename, kind, False, mutation=True) != before:
                raise ValueError('Windows context timestamp identity changed')
            observed = FileInformation()
            self.require(self.kernel.GetFileInformationByHandle(handle, ctypes.byref(observed)))
            for value in (observed.accessed, observed.written):
                if (value.dwHighDateTime << 32) | value.dwLowDateTime != ticks:
                    raise ValueError('Windows context epoch timestamp did not persist')
        finally: self.kernel.CloseHandle(handle)

    def create(self, filename, kind, data=None):
        # An explicit owner also works with an elevated token whose default
        # owner is the Administrators group. Never rewrite an existing object.
        authority = int.from_bytes(self.caller[2:8], 'big')
        principal = 'S-1-' + str(authority) + ''.join('-' + str(part[0]) for part in struct.iter_unpack('<I', self.caller[8:]))
        descriptor = ctypes.c_void_p()
        self.require(self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f'O:{principal}D:P(A;OICI;FA;;;{principal})(A;OICI;FA;;;SY)', 1, ctypes.byref(descriptor), None))
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        try:
            if kind == 'directory':
                self.require(self.kernel.CreateDirectoryW(filename, ctypes.byref(attributes)))
                return self.inspect(filename, kind)
            handle = self.kernel.CreateFileW(filename, 0x40000000 | 0x20000 | 0x80, 1, ctypes.byref(attributes), 1, 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
            try:
                offset = 0
                while offset < len(data):
                    written = wintypes.DWORD(); chunk = data[offset:]; buffer = ctypes.create_string_buffer(chunk)
                    self.require(self.kernel.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None))
                    if not written.value: raise ValueError('Windows storage write made no progress')
                    offset += written.value
                self.require(self.kernel.FlushFileBuffers(handle))
                return self.inspect_handle(handle, filename, kind, True)
            finally: self.kernel.CloseHandle(handle)
        finally: self.kernel.LocalFree(descriptor)


def main():
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024: raise ValueError('Windows storage request is oversized')
    requests = json.loads(raw)
    if not isinstance(requests, list) or not 1 <= len(requests) <= 128: raise ValueError('Windows storage request is not bounded')
    native = WindowsStorage(); result = []
    for row in requests:
        filename, kind, operation = row.get('path'), row.get('kind'), row.get('operation')
        if not isinstance(filename, str) or not Path(filename).is_absolute() or '\0' in filename or kind not in ('file', 'directory'):
            raise ValueError('Windows storage target is invalid')
        if operation == 'check' and type(row.get('private')) is bool:
            result.append(native.inspect(filename, kind, row['private']))
        elif operation == 'create':
            body = base64.b64decode(row.get('body', ''), validate=True) if kind == 'file' else None
            if body is not None and len(body) > 1024 * 1024: raise ValueError('Windows storage record is oversized')
            result.append(native.create(filename, kind, body))
        else: raise ValueError('Windows storage operation is invalid')
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Windows storage ACL admission failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1) from None
