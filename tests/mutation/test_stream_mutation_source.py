import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest


spec = importlib.util.spec_from_file_location('mutation_stream', Path(__file__).parents[2] / 'scripts/quality/stream-mutation-source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(name, data, executable=False):
    return {'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'executable': executable}


def test_streams_only_exact_received_source_bytes(tmp_path):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/kept.py').write_bytes(b'print(1)\n')
    (tmp_path / 'src/not-in-receipt').write_bytes(b'private')
    output = io.BytesIO()
    module.stream_source(tmp_path, {'files': [row('src/kept.py', b'print(1)\n', True)]}, output)
    output.seek(0)
    with tarfile.open(fileobj=output, mode='r|') as archive:
        entries = list(archive)
    assert [(item.name, item.size, item.mode) for item in entries] == [('source/src/kept.py', 9, 0o755)]
    output.seek(0)
    with tarfile.open(fileobj=output, mode='r|') as archive:
        assert archive.extractfile(next(iter(archive))).read() == b'print(1)\n'


def test_rejects_stale_unsafe_duplicate_and_linked_inputs(tmp_path):
    (tmp_path / 'input').write_bytes(b'actual')
    (tmp_path / 'linked').symlink_to(tmp_path / 'input')
    for files in ([row('input', b'wrong!')], [row('../escape', b'')], [row('linked', b'actual')], [row('input', b'actual')] * 2):
        with pytest.raises(ValueError):
            module.stream_source(tmp_path, {'files': files}, io.BytesIO())


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
