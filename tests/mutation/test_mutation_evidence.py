import importlib.util
from pathlib import Path
import pytest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mutation_evidence', Path(__file__).parents[2] / 'scripts/quality/mutation-evidence.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def test_exports_assertions_controls_and_raw_metadata_without_work_payloads(tmp_path):
    files = {'fault-outcomes.json': b'outcome', 'control/jobs/one.exec.json': b'control', 'rust-named-faults/case.log': b'assertion', 'work/mutants/one.meta': b'meta', 'work/mutants/CONTROL': b'control metadata', 'work/mutants/one.py': b'generated variant', 'control/python-projection/files/module.py': b'full CONTROL', 'work/mutants/projected.py': b'latest projected program', 'work/mutants/projected.py.spans': b'spans', 'work/package/original.py': b'original', 'work/contracts/schema.json': b'authored schema is not evidence', 'work/mutants/.ud-generator-repairs/repair.jsonl': b'repair evidence', 'rust-candidates/binary': b'compiled', 'rust-named-faults/work/source.rs': b'copied source'}
    for name, data in files.items():
        target = tmp_path / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    report = module.inventory(tmp_path)
    expected = {'fault-outcomes.json', 'control/jobs/one.exec.json', 'rust-named-faults/case.log', 'work/mutants/one.meta', 'work/mutants/CONTROL', 'control/python-projection/files/module.py', 'work/mutants/projected.py', 'work/mutants/projected.py.spans', 'work/mutants/.ud-generator-repairs/repair.jsonl'}
    assert {row['path'] for row in report['files']} == expected
    assert report['size_bytes'] == sum(len(files[name]) for name in expected)


def test_export_budget_rejects_without_mutating_evidence(tmp_path):
    data = tmp_path / 'fault.result'; data.write_bytes(b'12345')
    with pytest.raises(ValueError, match='budget'): module.inventory(tmp_path, max_file=4)
    with pytest.raises(ValueError, match='budget'): module.inventory(tmp_path, max_total=4)
    assert data.read_bytes() == b'12345'


def test_inventory_uses_current_named_metadata_not_incomplete_directory_cache(tmp_path):
    file = tmp_path / 'report.json'; file.write_bytes(b'exact evidence')
    entry = SimpleNamespace(name=file.name, path=str(file))
    with patch.object(module.os, 'scandir', return_value=[entry]):
        assert module.inventory(tmp_path)['files'][0]['size_bytes'] == len(b'exact evidence')
    alias = tmp_path / 'linked.json'; module.os.link(file, alias)
    with pytest.raises(ValueError, match='linked'): module.inventory(tmp_path)


def test_evidence_links_are_rejected_and_generated_dependency_links_ignored(tmp_path):
    (tmp_path / 'work').mkdir(); (tmp_path / 'work/node_modules').symlink_to('/missing')
    assert module.inventory(tmp_path)['files'] == []
    (tmp_path / 'control.json').symlink_to('/missing')
    with pytest.raises(ValueError, match='link'): module.inventory(tmp_path)


def test_usage_counts_disposable_work_even_when_export_omits_it(tmp_path):
    (tmp_path / 'work').mkdir(); (tmp_path / 'work/generated.py').write_bytes(b'payload')
    assert module.inventory(tmp_path)['files'] == []
    with pytest.raises(ValueError, match='scratch budget'): module.usage(tmp_path, 1)


def test_retention_defaults_are_compact_even_for_optional_exhaustive_data():
    assert module.MAX_FILE == 16 * 1024 ** 2
    assert module.MAX_TOTAL == 64 * 1024 ** 2


# The acceptance collector uses the standard unittest loader; expose the same
# functions there with a fresh temporary directory. Pytest ignores this class.
import inspect as _inspect, tempfile as _tempfile, unittest as _unittest


class UnittestCollection(_unittest.TestCase):
    __test__ = False


def _collected(function):
    def case(self):
        if 'tmp_path' not in _inspect.signature(function).parameters: return function()
        with _tempfile.TemporaryDirectory() as directory: function(Path(directory))
    return case


for _name, _function in list(globals().items()):
    if _name.startswith('test_') and _inspect.isfunction(_function): setattr(UnittestCollection, _name, _collected(_function))
