import json
import hashlib
import os
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch

from ud_agent.domain.validation import validation_report, sentence_validation_report
from ud_agent.errors import InvalidInput, PrerequisiteMissing


class RepositoryValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-repository-validation-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(strict=True)
        self.root = self.base / "bank"
        self.root.mkdir()
        (self.root / "en_test-ud-train.conllu").write_text("# sent_id = a\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n\n")
        self.tools = self.base / "tools"
        self.tools.mkdir()
        # Real Perl process, controlled module API fixture. Upstream modules
        # are tested separately in the pinned worker image.
        (self.tools / "udlib.pm").write_text('''package udlib;
sub get_language_hash { return {English => {lcode => 'en'}}; }
sub decompose_repo_name { return ('English', 'Test'); }
sub get_ltcode_from_repo_name { return 'en_test'; }
sub check_files { my ($root,$name,$key,$errors,$count)=@_; die 'bad snapshot' unless -f "$root/$name/en_test-ud-train.conllu"; push @$errors, 'missing license', 'extra file'; $$count += 2; print "upstream warning\\n"; }
sub read_readme { return {}; }
sub check_metadata { my ($root,$name,$data,$errors,$count)=@_; push @$errors, 'missing contact'; $$count++; }
sub check_documentation { my ($root,$name,$lang,$errors,$count)=@_; push @$errors, 'documentation incomplete'; $$count++; }
1;
''')
        rules = self.base / "rules"
        rules.mkdir()
        for name in ["upos", "feats", "udeprels", "deprels", "edeprels", "data", "tospace"]:
            (rules / (name + ".json")).write_text("{}")
        docs = self.base / "docs"
        docs.mkdir()
        languages = self.base / "languages.yaml"
        languages.write_text("English: {lcode: en}\n")
        self.context = self.base / "context.json"
        self.context.write_text(json.dumps({"rule_dir": str(rules), "repository_checks": {"languages_path": "languages.yaml", "docs_path": "docs",
                                             "assets": {"languages.yaml": {"sha256": hashlib.sha256(languages.read_bytes()).hexdigest(), "size_bytes": languages.stat().st_size}}}}))
        self.args = {"working_tree_path": str(self.root), "file_paths": ["en_test-ud-train.conllu"], "ud_context_path": str(self.context),
                     "options": {"language_code": "en", "repository_name": "UD_English-Test", "check_families": ["repository", "documentation"]}}
        perl = shutil.which("perl")
        self.assertIsNotNone(perl, "the required Perl test runtime is unavailable")
        self.env = patch.dict(os.environ, {"UD_AGENT_UDTOOLS": str(self.tools), "UD_AGENT_PERL": perl})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_repository_and_documentation_collect_all_incidents_without_content_pass_claim(self):
        with patch("ud_agent.domain.validation._validator") as validator:
            result = validation_report(self.args)
            validator.assert_not_called()
        self.assertFalse(result["passed"])
        self.assertEqual([incident["message"] for incident in result["incidents"]], ["missing license", "extra file", "missing contact", "documentation incomplete"])
        self.assertEqual(result["coverage"]["content"], "not_requested")
        self.assertEqual(result["coverage"]["repository"], "completed")
        self.assertEqual(result["coverage"]["documentation"], "completed")
        self.assertEqual(result["provenance"]["repository_name"], "UD_English-Test")

    def test_missing_pinned_repository_data_is_a_prerequisite_failure(self):
        self.context.write_text(json.dumps({"rule_dir": str(self.base / "rules")}))
        with self.assertRaises(PrerequisiteMissing):
            validation_report(self.args)

    def test_sentence_and_malformed_family_requests_are_rejected(self):
        with self.assertRaisesRegex(InvalidInput, "sentence-only"):
            sentence_validation_report({**self.args, "sentence_conllu": "1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n\n"})
        with self.assertRaisesRegex(InvalidInput, "check_families"):
            validation_report({**self.args, "options": {**self.args["options"], "check_families": [{}]}})

    def test_context_data_traversal_and_changed_assets_are_rejected_before_perl(self):
        context = json.loads(self.context.read_text())
        context["repository_checks"]["languages_path"] = "../outside.yaml"
        self.context.write_text(json.dumps(context))
        with self.assertRaisesRegex(InvalidInput, "leaves its snapshot"):
            validation_report(self.args)
        context["repository_checks"]["languages_path"] = "languages.yaml"
        self.context.write_text(json.dumps(context))
        (self.base / "languages.yaml").write_text("changed")
        with self.assertRaisesRegex(InvalidInput, "receipt"):
            validation_report(self.args)


if __name__ == "__main__":
    unittest.main()
