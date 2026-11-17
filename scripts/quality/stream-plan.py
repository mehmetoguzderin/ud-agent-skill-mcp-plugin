"""Read large trusted generation plans without V8's single-string size limit."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


def stream(file, output):
    file = Path(file)
    descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 1024**3:
            raise ValueError('bounded ordinary generation plan required')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate generation object key')
                result[key] = value
            return result
        plan = json.load(source, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite generation value')))
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('generation plan changed during read')
    if not isinstance(plan, dict):
        raise ValueError('generation plan object required')
    field = 'inventory' if 'inventory' in plan else 'mutants'
    items = plan.get(field)
    if not isinstance(items, list) or not items or len(items) > 2_000_000 or any(not isinstance(item, dict) or not isinstance(item.get('id'), str) for item in items):
        raise ValueError('complete bounded generation inventory required')
    items.sort(key=lambda item: item['id'].encode('utf-16-be', errors='surrogatepass'))
    resolver = None
    if 'definition_representation' in plan:
        helper = Path(__file__).with_name('python-runtime-projection.py')
        spec = importlib.util.spec_from_file_location('ud_streamed_control_definitions', helper)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        resolver = module.ControlDefinitionReader(file.parent, plan)
    elif any('definition_ref' in item for item in items):
        raise ValueError('compact Python rows require their versioned representation')
    def emit(value, maximum=4*1024**2):
        encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode()) > maximum:
            raise ValueError('generation frame exceeds its bound')
        output.write(encoded + '\n')
        output.flush()
    header = {key: value for key, value in plan.items() if key != field}
    emit({'type': 'header', 'count': len(items), 'field': field, 'plan': header}, 64*1024**2)
    digest = hashlib.sha256()
    for item in items:
        if resolver is not None:
            item = resolver.resolve(item)
        encoded = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        digest.update(encoded + b'\n')
        emit({'type': 'mutant', 'value': item})
    emit({'type': 'end', 'count': len(items), 'definition_stream_sha256': digest.hexdigest()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    stream(parser.parse_args().plan, sys.stdout)
