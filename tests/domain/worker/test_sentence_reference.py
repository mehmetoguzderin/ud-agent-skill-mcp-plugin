"""A missing sent_id names the identifiers that exist; other reference errors keep their wording. MIT."""
import tempfile
import unittest
from pathlib import Path
from ud_agent.conllu import core


class SentenceReference(unittest.TestCase):
    def test_unknown_sent_id_lists_existing_ids(self):
        directory = tempfile.TemporaryDirectory(prefix='ud-sentence-ref-'); self.addCleanup(directory.cleanup)
        (Path(directory.name) / 'edit.conllu').write_text('# sent_id = edit-1\n# text = Birds fly\n1\tBirds\tbird\tNOUN\t_\t_\t2\tnsubj\t_\t_\n2\tfly\tfly\tVERB\t_\t_\t0\troot\t_\t_\n\n')
        document = core.Document(str(Path(directory.name).resolve()), 'edit.conllu')
        with self.assertRaises(ValueError) as caught:
            document.find({'sent_id': 'sentence-1'})
        self.assertEqual(str(caught.exception), "sentence reference is missing: no sentence has sent_id 'sentence-1'; sent_id values in this file: edit-1")
        self.assertEqual(document.find({'sent_id': 'edit-1'})[0], 0)


if __name__ == '__main__':
    unittest.main()
