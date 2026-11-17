#!/usr/bin/env python3
"""Assemble physical source parts selected by actual shipped-component replay.

The caller supplies original collections and fixed recipe inputs, never coverage
or a source-material allowlist. Production independently replays both the model
and the exact physical tar membership before admitting these artifacts.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file)); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
closure = module('ud_source_assembly_replay', 'component-closure.py')
materials = module('ud_source_assembly_parts', 'source-bundle.py')


def assemble(root, candidate, recipe, collections, output, *, assets_root=None, runtime_root=None, candidate_root=None, available_targets=False, diagnostic=False, part_bytes=256 * 1024 ** 2):
    """Reconstruct coverage first, then archive exactly its original materials."""
    root = root.resolve(); output = output.resolve()
    if output.exists(): raise ValueError('component-source assembly output must be new')
    result = closure.derive(root, candidate, recipe, assets_root=assets_root, runtime_root=runtime_root, candidate_root=candidate_root, available_targets=available_targets, diagnostic=diagnostic)
    if not result['complete_available_shipped_component_coverage']:
        raise ValueError('available shipped components still have unresolved original source/license relationships')
    if not result['required_materials']:
        raise ValueError('no external original source materials are required by the actual available subjects')
    index = materials.bundle(collections, output, part_bytes, result['required_materials'], result)
    # Reconsume the real closed tar through the same independently implemented
    # streaming verifier that promotion uses; a correct compressed hash alone
    # does not prove safe or complete corresponding-source membership.
    runtime = output / 'runtime'; runtime.mkdir()
    index_file = output / 'ud-agent-corresponding-source-index.json'
    receipt = lambda file: {'path': file.relative_to(output).as_posix(), 'sha256': closure.digest(file), 'size': file.stat().st_size}
    lock = {'schema_version': 1, 'index': receipt(index_file), 'parts': [{**row, **receipt(output / row['path'])} for row in index['parts']]}
    (runtime / 'source-materials.lock.json').write_bytes(materials.canonical(lock))
    report = output / 'component-source-coverage.json'; report.write_bytes(closure.report_bytes(result))
    code = "import{readFileSync}from'node:fs';import{verifyRequiredSourceMaterials}from" + json.dumps((ROOT / 'scripts/release/source-artifacts.mjs').as_uri()) + ";let report=JSON.parse(readFileSync(process.argv[2]));console.log(JSON.stringify(verifyRequiredSourceMaterials(process.argv[1],report.required_materials)))"
    checked = subprocess.run(['node', '--input-type=module', '-e', code, str(output), str(report)], capture_output=True, timeout=1800)
    if checked.returncode or len(checked.stdout) > 1024 * 1024: raise ValueError('actual physical source parts failed independent stream/membership verification: ' + checked.stderr.decode('utf-8', 'replace')[-2000:])
    verification = json.loads(checked.stdout)
    if verification != {'verified': True, 'original_source_materials': len(result['required_materials'])}: raise ValueError('physical source requirement verification is incomplete')
    if closure.source_inventory(root)['sha256'] != result['source_inventory_sha256']: raise ValueError('original source snapshot changed during source assembly')
    assembled = {'schema_version': 1, 'qualification': 'actual-shipped-component-selected-original-source-assembly', 'source_tree_sha256': result['source_inventory_sha256'], 'runtime_lock_sha256': result['runtime_lock_sha256'], 'complete_available_shipped_component_coverage': result['complete_available_shipped_component_coverage'], 'complete_product_coverage': result['complete_product_coverage'], 'missing_distribution_subjects': result['missing_distribution_subjects'], 'component_source_coverage': receipt(report), 'source_materials_lock': receipt(runtime / 'source-materials.lock.json'), 'index': lock['index'], 'parts': lock['parts'], 'physical_source_verification': verification, 'generator_sha256': closure.digest(Path(__file__))}
    (output / 'ASSEMBLY.json').write_bytes(materials.canonical(assembled))
    return assembled


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--assets-root', type=Path); parser.add_argument('--runtime-root', type=Path); parser.add_argument('--candidate-root', type=Path); parser.add_argument('--candidate', type=Path, required=True); parser.add_argument('--recipe', type=Path, required=True); parser.add_argument('--collection', action='append', required=True); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--diagnostic', action='store_true'); parser.add_argument('--available-targets', action='store_true'); parser.add_argument('--part-bytes', type=int, default=256 * 1024 ** 2); args = parser.parse_args(); collections = []
    for item in args.collection:
        identifier, separator, name = item.partition('=')
        if not separator: parser.error('collection must be ID=RECEIPT')
        collections.append((identifier, Path(name)))
    result = assemble(args.root, json.loads(args.candidate.read_bytes()), json.loads(args.recipe.read_bytes()), collections, args.output, assets_root=args.assets_root.resolve() if args.assets_root else None, runtime_root=args.runtime_root.resolve() if args.runtime_root else None, candidate_root=args.candidate_root.resolve() if args.candidate_root else None, available_targets=args.available_targets, diagnostic=args.diagnostic, part_bytes=args.part_bytes)
    print(json.dumps({key: result[key] for key in ('qualification', 'complete_available_shipped_component_coverage', 'complete_product_coverage', 'physical_source_verification')}))
