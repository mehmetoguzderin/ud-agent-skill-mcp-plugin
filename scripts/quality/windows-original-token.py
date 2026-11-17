#!/usr/bin/env python3
"""Run trusted original tests with caller-owned Windows objects. Authored MIT.

Hosted elevated tokens can default new objects to Administrators ownership.
Change only a restricted copy's default owner, never the runner/account token.
This is original-test environment provisioning, not a mutant security boundary.
"""
from __future__ import annotations
import argparse
import contextlib
import ctypes as C
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

DWORD, LONG, HANDLE, SIZE_T = C.c_uint32, C.c_int32, C.c_void_p, C.c_size_t
ADMIN_SID = bytes.fromhex('01020000000000052000000020020000')
WAIT_TIMEOUT = 258
INFINITE = 0xffffffff


class Luid(C.Structure):
    _fields_ = [('low', DWORD), ('high', LONG)]


class Privilege(C.Structure):
    _fields_ = [('luid', Luid), ('attributes', DWORD)]


class SidEntry(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('attributes', DWORD)]


class GroupPrefix(C.Structure):
    _fields_ = [('count', DWORD), ('entries', SidEntry * 1)]


class Startup(C.Structure):
    _fields_ = [('cb', DWORD), ('reserved', C.c_wchar_p), ('desktop', C.c_wchar_p), ('title', C.c_wchar_p),
                ('x', DWORD), ('y', DWORD), ('x_size', DWORD), ('y_size', DWORD), ('x_chars', DWORD),
                ('y_chars', DWORD), ('fill', DWORD), ('flags', DWORD), ('show', C.c_uint16),
                ('reserved_size', C.c_uint16), ('reserved_bytes', C.c_void_p),
                ('stdin', HANDLE), ('stdout', HANDLE), ('stderr', HANDLE)]


class StartupEx(C.Structure):
    _fields_ = [('startup', Startup), ('attributes', C.c_void_p)]


class ProcessInfo(C.Structure):
    _fields_ = [('process', HANDLE), ('thread', HANDLE), ('pid', DWORD), ('tid', DWORD)]


class JobBasic(C.Structure):
    _fields_ = [('process_time', C.c_int64), ('job_time', C.c_int64), ('flags', DWORD),
                ('minimum_working_set', SIZE_T), ('maximum_working_set', SIZE_T), ('active_limit', DWORD),
                ('affinity', SIZE_T), ('priority', DWORD), ('scheduling', DWORD)]


class IoCounters(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ['read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes']]


class JobLimits(C.Structure):
    _fields_ = [('basic', JobBasic), ('io', IoCounters), ('process_memory', SIZE_T), ('job_memory', SIZE_T),
                ('peak_process_memory', SIZE_T), ('peak_job_memory', SIZE_T)]


class JobAccounting(C.Structure):
    _fields_ = [('user_time', C.c_int64), ('kernel_time', C.c_int64), ('period_user_time', C.c_int64),
                ('period_kernel_time', C.c_int64), ('page_faults', DWORD), ('total', DWORD),
                ('active', DWORD), ('terminated', DWORD)]


def verify_token(parent, child, removed):
    """The child retains the exact caller and capabilities except named removal."""
    expected = {**parent, 'owner': parent['user'], 'privileges': tuple(row for row in parent['privileges'] if row[0] not in removed)}
    if child != expected:
        raise ValueError('Original-test child token differs beyond its caller owner and removed debug privilege')


def validate_command(command, cwd, timeout):
    if not command or len(command) > 128 or not all(isinstance(value, str) and '\0' not in value for value in command):
        raise ValueError('Original-test command is invalid')
    if not Path(command[0]).is_absolute() or not Path(command[0]).is_file() or not Path(cwd).is_absolute() or not Path(cwd).is_dir():
        raise ValueError('Original-test executable and working directory must be explicit existing absolute paths')
    quoted = subprocess.list2cmdline(command)
    if len(quoted.encode('utf-16-le')) // 2 >= 32767 or timeout is not None and (type(timeout) is not int or not 1 <= timeout <= (INFINITE - 1) // 1000):
        raise ValueError('Original-test command or deadline exceeds its bound')
    return quoted


class Native:
    def __init__(self):
        if os.name != 'nt': raise ValueError('Original-test token provisioning requires Windows')
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.a = C.WinDLL('advapi32', use_last_error=True)
        P = C.c_void_p
        signatures = [
            (self.k, 'GetCurrentProcess', [], HANDLE), (self.k, 'CloseHandle', [HANDLE], LONG),
            (self.k, 'GetStdHandle', [DWORD], HANDLE),
            (self.k, 'DuplicateHandle', [HANDLE, HANDLE, HANDLE, C.POINTER(HANDLE), DWORD, LONG, DWORD], LONG),
            (self.k, 'CreateFileW', [C.c_wchar_p, DWORD, DWORD, P, DWORD, DWORD, HANDLE], HANDLE),
            (self.k, 'CreateJobObjectW', [P, C.c_wchar_p], HANDLE),
            (self.k, 'SetInformationJobObject', [HANDLE, LONG, P, DWORD], LONG),
            (self.k, 'QueryInformationJobObject', [HANDLE, LONG, P, DWORD, P], LONG),
            (self.k, 'TerminateJobObject', [HANDLE, DWORD], LONG),
            (self.k, 'IsProcessInJob', [HANDLE, HANDLE, C.POINTER(LONG)], LONG),
            (self.k, 'InitializeProcThreadAttributeList', [P, DWORD, DWORD, C.POINTER(SIZE_T)], LONG),
            (self.k, 'UpdateProcThreadAttribute', [P, DWORD, SIZE_T, P, SIZE_T, P, P], LONG),
            (self.k, 'DeleteProcThreadAttributeList', [P], None),
            (self.k, 'CreateProcessW', [C.c_wchar_p, C.c_wchar_p, P, P, LONG, DWORD, P, C.c_wchar_p, P, C.POINTER(ProcessInfo)], LONG),
            (self.k, 'ResumeThread', [HANDLE], DWORD), (self.k, 'WaitForSingleObject', [HANDLE, DWORD], DWORD),
            (self.k, 'GetExitCodeProcess', [HANDLE, C.POINTER(DWORD)], LONG),
            (self.k, 'TerminateProcess', [HANDLE, DWORD], LONG),
            (self.a, 'OpenProcessToken', [HANDLE, DWORD, C.POINTER(HANDLE)], LONG),
            (self.a, 'GetTokenInformation', [HANDLE, LONG, P, DWORD, C.POINTER(DWORD)], LONG),
            (self.a, 'SetTokenInformation', [HANDLE, LONG, P, DWORD], LONG),
            (self.a, 'IsValidSid', [P], LONG), (self.a, 'GetLengthSid', [P], DWORD),
            (self.a, 'LookupPrivilegeValueW', [C.c_wchar_p, C.c_wchar_p, C.POINTER(Luid)], LONG),
            (self.a, 'CreateRestrictedToken', [HANDLE, DWORD, DWORD, P, DWORD, P, DWORD, P, C.POINTER(HANDLE)], LONG),
            (self.a, 'CreateProcessAsUserW', [HANDLE, C.c_wchar_p, C.c_wchar_p, P, P, LONG, DWORD, P, C.c_wchar_p, P, C.POINTER(ProcessInfo)], LONG),
        ]
        for library, name, arguments, result in signatures:
            function = getattr(library, name); function.argtypes = arguments; function.restype = result

    @staticmethod
    def require(value):
        if not value: raise C.WinError(C.get_last_error())
        return value

    def token(self, process, access=8):
        handle = HANDLE(); self.require(self.a.OpenProcessToken(process, access, C.byref(handle)))
        return handle.value

    def token_buffer(self, token, kind):
        size = DWORD(); self.a.GetTokenInformation(token, kind, None, 0, C.byref(size))
        if not 0 < size.value <= 65536: raise ValueError('Original-test token information is not bounded')
        data = C.create_string_buffer(size.value)
        self.require(self.a.GetTokenInformation(token, kind, data, size, C.byref(size)))
        return data

    def sid(self, address):
        self.require(address and self.a.IsValidSid(address))
        length = self.a.GetLengthSid(address)
        if not 8 <= length <= 68: raise ValueError('Original-test token SID is not bounded')
        return C.string_at(address, length)

    def snapshot(self, token):
        def principal(kind):
            data = self.token_buffer(token, kind)
            return self.sid(C.cast(data, C.POINTER(C.c_void_p))[0])
        data = self.token_buffer(token, 3); count = DWORD.from_buffer(data).value
        if count > 1024 or 4 + count * C.sizeof(Privilege) > len(data): raise ValueError('Original-test token privileges are not bounded')
        privileges = (Privilege * count).from_buffer(data, 4)
        rows = tuple(sorted((row.luid.low | ((row.luid.high & 0xffffffff) << 32), row.attributes) for row in privileges))
        data = self.token_buffer(token, 2); count = DWORD.from_buffer(data).value; offset = GroupPrefix.entries.offset
        if count > 1024 or offset + count * C.sizeof(SidEntry) > len(data): raise ValueError('Original-test token groups are not bounded')
        groups = tuple(sorted((self.sid(row.sid), row.attributes) for row in (SidEntry * count).from_buffer(data, offset)))
        data = self.token_buffer(token, 6); address = C.cast(data, C.POINTER(C.c_void_p))[0]
        dacl = None
        if address:
            length = C.c_uint16.from_address(address + 2).value
            if not 8 <= length <= 65535: raise ValueError('Original-test token default DACL is not bounded')
            dacl = C.string_at(address, length)
        return {'user': principal(1), 'owner': principal(4), 'primary_group': principal(5),
                'groups': groups, 'privileges': rows, 'dacl': dacl}

    def child_token(self, parent, before, resources):
        if before['owner'] == before['user']: return None, set()
        if before['owner'] != ADMIN_SID: raise ValueError('Original-test default owner is neither caller nor Administrators')
        debug = Luid(); self.require(self.a.LookupPrivilegeValueW(None, 'SeDebugPrivilege', C.byref(debug)))
        key = debug.low | ((debug.high & 0xffffffff) << 32)
        if key not in dict(before['privileges']): raise ValueError('Elevated original-test token has no removable debug privilege')
        # Keep SeCreateSymbolicLinkPrivilege, traversal and every other existing
        # capability. No AdjustTokenPrivileges call touches the parent token.
        removed = Privilege(debug, 0); token = HANDLE()
        self.require(self.a.CreateRestrictedToken(parent, 0, 0, None, 1, C.byref(removed), 0, None, C.byref(token)))
        resources.callback(self.k.CloseHandle, token.value)
        caller = C.create_string_buffer(before['user']); owner = C.c_void_p(C.addressof(caller))
        self.require(self.a.SetTokenInformation(token, 4, C.byref(owner), C.sizeof(owner)))
        verify_token(before, self.snapshot(token), {key})
        if self.snapshot(parent) != before: raise ValueError('Original-test parent token changed')
        return token.value, {key}

    def stdio(self, resources):
        current = self.k.GetCurrentProcess(); handles = []
        for number in [-10, -11, -12]:
            original = self.k.GetStdHandle(number & 0xffffffff)
            if original in (None, C.c_void_p(-1).value):
                original = self.k.CreateFileW('NUL', 0x80000000 if number == -10 else 0x40000000, 3, None, 3, 0, None)
                if original == C.c_void_p(-1).value: raise C.WinError(C.get_last_error())
                resources.callback(self.k.CloseHandle, original)
            duplicate = HANDLE()
            self.require(self.k.DuplicateHandle(current, original, current, C.byref(duplicate), 0, True, 2))
            resources.callback(self.k.CloseHandle, duplicate.value); handles.append(duplicate.value)
        return (HANDLE * 3)(*handles)

    def active(self, job):
        value = JobAccounting(); self.require(self.k.QueryInformationJobObject(job, 1, C.byref(value), C.sizeof(value), None))
        return value.active

    def reap(self, job):
        self.require(self.k.TerminateJobObject(job, 137))
        deadline = time.monotonic() + 30
        while self.active(job):
            if time.monotonic() >= deadline: raise ValueError('Original-test job cleanup was not verified')
            time.sleep(0.01)

    def supervise(self, parent, before, removed, job, process, resources, timeout, restricted):
        failure = None
        try:
            assigned = LONG(); self.require(self.k.IsProcessInJob(process.process, job, C.byref(assigned)))
            if not assigned.value:
                # The creation attribute requires assignment. If verification
                # contradicts that, retain the exact held child for cleanup.
                self.require(self.k.TerminateProcess(process.process, 137))
                if self.k.WaitForSingleObject(process.process, 30000) != 0:
                    raise ValueError('Unassigned original-test child cleanup was not verified')
                raise ValueError('Original-test child job assignment was not verified')
            child = self.token(process.process); resources.callback(self.k.CloseHandle, child)
            verify_token(before, self.snapshot(child), removed)
            if self.snapshot(parent) != before: raise ValueError('Original-test parent token changed during launch')
            print(json.dumps({'original_windows_token': 'caller-owned', 'restricted_copy': restricted,
                              'removed_privileges': ['SeDebugPrivilege'] if removed else [], 'parent_unchanged': True}), file=sys.stderr, flush=True)
            if self.k.ResumeThread(process.thread) == 0xffffffff: raise C.WinError(C.get_last_error())
            wait = self.k.WaitForSingleObject(process.process, INFINITE if timeout is None else timeout * 1000)
            if wait == WAIT_TIMEOUT: raise TimeoutError('Original-test Windows process exceeded its deadline')
            if wait != 0: raise C.WinError(C.get_last_error())
            code = DWORD(); self.require(self.k.GetExitCodeProcess(process.process, C.byref(code)))
            return code.value
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                self.reap(job)
                if self.snapshot(parent) != before: raise ValueError('Original-test parent token changed')
                print(json.dumps({'original_windows_cleanup': 'verified', 'parent_unchanged': True}), file=sys.stderr, flush=True)
            except Exception as cleanup:
                if failure is not None:
                    raise RuntimeError(str(failure) + '; cleanup: ' + str(cleanup)) from failure
                raise

    def run(self, command, cwd, timeout):
        quoted = validate_command(command, cwd, timeout)
        with contextlib.ExitStack() as resources:
            # CreateRestrictedToken preserves the input handle's access rights;
            # the new handle needs ADJUST_DEFAULT and ASSIGN_PRIMARY. Opening
            # these rights does not modify the original token.
            parent = self.token(self.k.GetCurrentProcess(), 8 | 2 | 0x80 | 1); resources.callback(self.k.CloseHandle, parent)
            before = self.snapshot(parent); token, removed = self.child_token(parent, before, resources)
            job = self.require(self.k.CreateJobObjectW(None, None)); resources.callback(self.k.CloseHandle, job)
            limits = JobLimits(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway.
            self.require(self.k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
            handles = self.stdio(resources); jobs = (HANDLE * 1)(job)
            size = SIZE_T(); self.k.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
            if not 0 < size.value <= 65536: raise ValueError('Original-test process attributes are not bounded')
            attributes = C.create_string_buffer(size.value)
            self.require(self.k.InitializeProcThreadAttributeList(attributes, 2, 0, C.byref(size)))
            resources.callback(self.k.DeleteProcThreadAttributeList, attributes)
            self.require(self.k.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, C.sizeof(handles), None, None))
            # Creation-time assignment closes the suspended-child cancellation gap.
            self.require(self.k.UpdateProcThreadAttribute(attributes, 0, 0x2000d, jobs, C.sizeof(jobs), None, None))
            startup = StartupEx(); startup.startup.cb = C.sizeof(startup); startup.startup.flags = 0x100
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = handles
            startup.attributes = C.addressof(attributes); process = ProcessInfo(); line = C.create_unicode_buffer(quoted)
            common = (command[0], line, None, None, True, 0x4 | 0x80000, None, cwd, C.byref(startup), C.byref(process))
            self.require(self.a.CreateProcessAsUserW(token, *common) if token else self.k.CreateProcessW(*common))
            resources.callback(self.k.CloseHandle, process.process); resources.callback(self.k.CloseHandle, process.thread)
            return self.supervise(parent, before, removed, job, process, resources, timeout, token is not None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cwd', required=True)
    parser.add_argument('--timeout-seconds', type=int, help='Optional explicit command deadline; ownership and cleanup apply without an aggregate timer by default.')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    validate_command(command, args.cwd, args.timeout_seconds)
    return Native().run(command, args.cwd, args.timeout_seconds)


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print('Original-test Windows token launch failed: ' + str(error)[:2048], file=sys.stderr)
        raise SystemExit(1) from None
