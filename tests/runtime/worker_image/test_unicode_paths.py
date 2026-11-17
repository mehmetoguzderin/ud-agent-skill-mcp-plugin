"""Frozen path keys stay independent of the interpreter's Unicode revision."""
import json
from pathlib import Path
import unittest
from ud_agent.snapshot_receiver import _assigned16, _frozen_nfc, _path_key


class FrozenUnicodePathsTests(unittest.TestCase):
    def test_new_unicode17_marks_retain_unicode16_starter_boundaries(self):
        for point in [0x1acf, 0x1ad0, 0x1ae0, 0x1aeb, 0x10efa]:
            mark = chr(point)
            self.assertEqual(_path_key('A\u0315' + mark + '.conllu'), 'a\u0315' + mark + '.conllu')
            self.assertNotEqual(_path_key('A\u0315' + mark), _path_key('A' + mark + '\u0315'))
        self.assertEqual(_path_key('A\u0315\u0300.conllu'), '\u00e0\u0315.conllu')
        self.assertEqual(_path_key('e\u0301.conllu'), '\u00e9.conllu')
        self.assertEqual(_path_key('\u1100\u1161.conllu'), '\uac00.conllu')
        self.assertEqual(_frozen_nfc(''), '')

    def test_frozen_ranges_include_their_endpoints_and_leave_gaps_unassigned(self):
        data = json.loads((Path(__file__).resolve().parents[3] / 'workers/ud/src/ud_agent/unicode_casefold.json').read_text())
        ranges = data['normalization_assigned_ranges']
        self.assertEqual(data['unicode_version'], '16.0.0')
        for index, (first, last) in enumerate(ranges):
            self.assertTrue(_assigned16(first)); self.assertTrue(_assigned16(last))
            if index and ranges[index - 1][1] + 1 < first:
                self.assertFalse(_assigned16(first - 1))
            if last < 0x10ffff and (index + 1 == len(ranges) or last + 1 < ranges[index + 1][0]):
                self.assertFalse(_assigned16(last + 1))


if __name__ == '__main__':
    unittest.main()
