"""SDK source derivation checks; the derived adapter is never executed here."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_original_sdk_producer', ROOT/'scripts/quality/prepare-mutation-runtime.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class PythonProjectionSdkTests(unittest.TestCase):
    def test_fixed_adapter_retains_original_wheel_and_notice_bytes_with_exact_before_after_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root/'mutmut-3.8.1-py3-none-any.whl'
            upstream = b'# Original upstream notice remains unchanged\ndef wrap_in_trampoline(value):\n    return value\n'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('mutmut/mutation/trampoline.py', upstream)
            helper = root/'python-runtime-projection.py'; helper.write_text("VERSION='ud-python-inert-projection-1'\n")
            output = root/'output'; output.mkdir()
            before = wheel.read_bytes()
            receipt = producer.prepare_python_projection_sdk(wheel, helper, output)
            actual = (output/'python-trampoline-derived.py').read_bytes()
            self.assertEqual(wheel.read_bytes(), before)
            self.assertEqual((output/'python-trampoline-upstream.py').read_bytes(), upstream)
            self.assertEqual(actual, upstream+(output/'python-trampoline-adapter.py').read_bytes())
            self.assertEqual(receipt['upstream_source']['sha256'], hashlib.sha256(upstream).hexdigest())
            self.assertEqual(receipt['derived_source']['sha256'], hashlib.sha256(actual).hexdigest())
            self.assertEqual(receipt['original_wheel']['sha256'], hashlib.sha256(before).hexdigest())
            self.assertEqual(receipt['installed_path'], 'python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py')
            self.assertIn(b"/opt/mutation/harness/python-runtime-projection.py", actual)
            self.assertIn(b"context_required=True", actual)
            ast.parse(actual)  # Pure data; no adapter/application code executes.

    def test_unknown_release_and_omitted_original_trampoline_cannot_issue_sdk_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); helper=root/'helper.py'; helper.write_bytes(b'# original helper\n')
            wheel = root/'mutmut-3.8.1-py3-none-any.whl'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('mutmut/other.py', b'# not the required original\n')
            with self.assertRaises(ValueError):
                producer.prepare_python_projection_sdk(wheel, helper, root)
            other=root/'mutmut-0-py3-none-any.whl'; other.write_bytes(wheel.read_bytes())
            with self.assertRaises(ValueError):
                producer.prepare_python_projection_sdk(other, helper, root)
            self.assertFalse((root/'python-trampoline-derived.py').exists())


if __name__ == '__main__':
    unittest.main()
