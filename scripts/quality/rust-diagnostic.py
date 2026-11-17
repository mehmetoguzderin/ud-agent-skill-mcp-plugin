#!/usr/bin/env python3
"""Compatibility entrypoint for source-bound Rust diagnostics inside protected OCI."""
import argparse
import importlib.util
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--cargo-mutants', type=Path, required=True)
    parser.add_argument('--file', action='append', default=[], help='Explicit diagnostic subset; never complete acceptance')
    args = parser.parse_args()
    if not hasattr(os, 'geteuid') or os.geteuid() != 0 or os.environ.get('UD_MUTATION_OCI_GUARD') != '1' or not Path('/opt/mutation/input-receipt.json').is_file():
        raise ValueError('Rust mutation execution requires the protected native ARM OCI backend; host execution is forbidden')
    spec = importlib.util.spec_from_file_location('ud_owned_literal_diagnostic', '/opt/mutation/harness/rust-literal.py')
    backend = importlib.util.module_from_spec(spec);spec.loader.exec_module(backend)
    original = sys.argv
    try:
        sys.argv = ['rust-literal.py', '--snapshot', str(args.snapshot), '--cargo-mutants', str(args.cargo_mutants), '--output', str(args.snapshot.resolve().parent / 'rust-protected'), '--jobs', '1', *[part for name in args.file for part in ('--file', name)]]
        return backend.main()
    finally:
        sys.argv = original


if __name__ == '__main__':
    raise SystemExit(main())
