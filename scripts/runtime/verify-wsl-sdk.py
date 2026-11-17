#!/usr/bin/env python3
"""Verify the frozen WSL SDK ABI and exports without executing Windows code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from windows_pe import inspect_pe

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ['WslcInitSessionSettings', 'WslcSetSessionSettingsCpuCount',
            'WslcSetSessionSettingsMemory', 'WslcSetSessionSettingsTimeout',
            'WslcGetMissingComponents', 'WslcCreateSession', 'WslcTerminateSession',
            'WslcReleaseSession', 'WslcGetSessionTerminationEvent']


def verify(root, reader):
    rows = []
    source_bytes = (ROOT / 'packages/launcher/src/wsl_session.rs').read_bytes()
    source = source_bytes.decode('utf-8', 'strict')
    native = re.search(r'struct Settings\(\[u8; (\d+)\]\)', source)
    alignment = re.search(r'#\[repr\(C, align\((\d+)\)\)\]\s*(?://[^\n]*\n)*struct Settings', source)
    if native is None or alignment is None:
        raise ValueError('native session ABI declaration is absent')
    for architecture in ['arm64', 'x64']:
        directory = root / f'runtime/providers/wslc/win32-{architecture}'
        header = (directory / 'include/wslcsdk.h').read_bytes()
        size = re.search(rb'#define WSLC_SESSION_OPTIONS_SIZE (\d+)', header)
        align = re.search(rb'#define WSLC_SESSION_OPTIONS_ALIGNMENT (\d+)', header)
        if size is None or align is None or int(size[1]) != int(native[1]) or int(align[1]) != int(alignment[1]):
            raise ValueError('native session ABI differs from the frozen SDK header')
        binary = directory / 'bin/wslcsdk.dll'
        image = inspect_pe(binary.read_bytes(), architecture)
        result = subprocess.run([str(reader), '--coff-exports', str(binary)], check=True, capture_output=True, text=True, timeout=30)
        exported = re.findall(r'^  Name: (\S+)$', result.stdout, re.MULTILINE)
        if len(exported) != len(set(exported)) or not set(REQUIRED).issubset(exported):
            raise ValueError('native session SDK exports are missing or ambiguous')
        rows.append({'architecture': architecture, 'sdk_sha256': image['sha256'],
                     'header_sha256': 'sha256:' + hashlib.sha256(header).hexdigest(),
                     'session_settings_size': int(size[1]), 'session_settings_alignment': int(align[1]),
                     'required_exports': REQUIRED, 'status': 'passed_static', 'native_execution': 'pending_native'})
    return {'schema_version': 1, 'reader_sha256': 'sha256:' + hashlib.sha256(reader.read_bytes()).hexdigest(),
            'native_source_sha256': 'sha256:' + hashlib.sha256(source_bytes).hexdigest(), 'rows': rows}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--llvm-readobj', type=Path, default=Path('/opt/homebrew/opt/llvm/bin/llvm-readobj'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.assets.resolve(strict=True), args.llvm_readobj.resolve(strict=True))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'architectures': [row['architecture'] for row in report['rows']], 'status': 'passed_static'}))
