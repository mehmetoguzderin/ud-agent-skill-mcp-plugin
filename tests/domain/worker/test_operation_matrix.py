import json
from pathlib import Path
import unittest
import tempfile

from operation_cases import make_cases, execute_case


class OperationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ud-operation-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve(strict=True)
        cls.cases = make_cases(cls.root)
        cls.by_name = {case["operation"]: case for case in cls.cases}

    def test_each_domain_operation_has_an_independent_successful_behavior_case(self):
        names = [case["operation"] for case in self.cases]
        self.assertEqual(len(names), 102)
        self.assertEqual(len(set(names)), 102)
        self.assertEqual(set(names), {item["name"] for item in CATALOG})


CATALOG = json.loads((Path(__file__).resolve().parents[3] / "contracts/ud-interfaces.json").read_text())
for entry in CATALOG:
    def behavior(self, name=entry["name"]):
        self.assertIn(name, self.by_name, "operation has no independently authored behavior fixture")
        execute_case(self.root, self.by_name[name])
    setattr(OperationMatrixTests, "test_" + entry["id"] + "_" + entry["name"], behavior)


if __name__ == "__main__":
    unittest.main()
