import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from graph_fixture import graph_fixture

from ud_agent import dispatch, wire
from ud_agent.conllu.core import StaleInputError
from ud_agent.errors import InvalidInput, PrerequisiteMissing
from ud_agent.domain import analysis, comparison, conversion, enhanced, evaluation, metadata, parallel, plans, review, rules, validation, workspace

FIRST = """# sent_id = s1
# text = Big cats run
1\tBig\tbig\tADJ\t_\tNumber=Plur\t2\tamod\t2:amod\t_
2\tcats\tcat\tNOUN\t_\tNumber=Plur\t3\tnsubj\t3:nsubj\t_
3\trun\trun\tVERB\t_\tNumber=Sing\t0\troot\t0:root\t_

"""
SECOND = """# sent_id = s2
# text = Ada Lovelace runs
1\tAda\tAda\tPROPN\t_\t_\t3\tnsubj\t3:nsubj\t_
2\tLovelace\tLovelace\tPROPN\t_\t_\t1\tflat\t1:flat\t_
3\truns\trun\tVERB\t_\tNumber=Sing\t0\troot\t0:root\t_

"""

class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "a.conllu").write_bytes(FIRST.encode())
        (self.root / "b.conllu").write_bytes(SECOND.encode())
        self.args = {"working_tree_path": str(self.root)}
        self.enterContext(graph_fixture())

    def test_profile_counts_and_denominator(self):
        result = analysis.treebank_profile(self.args)
        self.assertEqual((result["sentence_count"], result["word_count"]), (2, 6))
        noun = next(item for item in result["upos"] if item["value"] == "NOUN")
        self.assertEqual((noun["count"], noun["denominator"]), (1, 6))

    def test_falsey_invalid_options_are_rejected(self):
        with self.assertRaises(InvalidInput):
            analysis.treebank_profile({**self.args, "options": []})
        with self.assertRaises(InvalidInput):
            validation.validation_report({**self.args, "options": []})
        with self.assertRaises(InvalidInput):
            comparison.duplicate_report({**self.args, "matching_options": []})
        with self.assertRaises(InvalidInput):
            conversion.token_alignment_report({**self.args, "source_file_paths": ["a.conllu"], "target_file_paths": ["b.conllu"], "options": []})

    def test_whitespace_separators_and_zero_based_locations(self):
        content = FIRST.rstrip("\n") + "\n  \n" + SECOND
        (self.root / "a.conllu").write_text(content, encoding="utf-8", newline="")
        result = analysis.lexeme_pos_report({**self.args, "file_paths": ["a.conllu"], "lexeme_filter": {"lemma": "run"}})
        self.assertEqual([item["ordinal"] for item in result["entries"][0]["occurrences"]], [0, 1])

    def test_analysis_rejects_invalid_or_duplicate_row_ids(self):
        invalid = FIRST.replace("1\tBig", "0\tBig")
        (self.root / "a.conllu").write_text(invalid, encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            analysis.treebank_profile({**self.args, "file_paths": ["a.conllu"]})
        duplicate = FIRST.replace("2\tcats", "1\tcats")
        (self.root / "a.conllu").write_text(duplicate, encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            analysis.treebank_profile({**self.args, "file_paths": ["a.conllu"]})

    def test_lexeme_occurrences_and_filter(self):
        result = analysis.lexeme_pos_report({**self.args, "lexeme_filter": {"lemma": "run"}})
        self.assertEqual(result["entries"][0]["count"], 2)
        self.assertEqual([i["sent_id"] for i in result["entries"][0]["occurrences"]], ["s1", "s2"])
        with self.assertRaises(InvalidInput):
            analysis.lexeme_pos_report({**self.args, "lexeme_filter": {"unknown": "x"}})

    def test_agreement_includes_negative_evidence(self):
        result = analysis.feature_agreement_report({**self.args, "feature_name": "Number"})
        self.assertEqual((result["agreeing"], result["disagreeing"]), (1, 1))
        self.assertEqual(result["skipped"]["missing_feature"], 2)

    def test_names_are_runs_not_entities(self):
        report = analysis.proper_name_sequences(self.args)
        self.assertEqual(report["sequences"][0]["forms"], ["Ada", "Lovelace"])
        self.assertIn("not named-entity", report["limitations"][0])

    def test_enhanced_graph_reaches_all_words(self):
        report = enhanced.enhanced_graph_report(self.args)
        self.assertEqual(report["sentences"][0]["unreachable_from_root"], [])
        self.assertEqual(len(report["sentences"][0]["edges"]), 3)

    def test_enhanced_connectivity_follows_edge_direction(self):
        content = "# sent_id = graph\n1\tA\ta\tNOUN\t_\t_\t0\troot\t0:root|2:dep\t_\n2\tB\tb\tNOUN\t_\t_\t1\tdep\t_\t_\n\n"
        (self.root / "graph.conllu").write_text(content, encoding="utf-8", newline="")
        report = enhanced.enhanced_graph_report({**self.args, "file_paths": ["graph.conllu"]})
        self.assertEqual(report["sentences"][0]["unreachable_from_root"], ["2"])

    def test_invalid_enhanced_head_rejected(self):
        (self.root / "a.conllu").write_text(FIRST.replace("2:amod", "99:amod"), encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            enhanced.enhanced_graph_report(self.args)

    def test_exact_duplicates_and_missing_text(self):
        (self.root / "c.conllu").write_text(FIRST.replace("s1", "s3") + SECOND.replace("# text = Ada Lovelace runs\n", ""), encoding="utf-8", newline="")
        report = comparison.duplicate_report(self.args)
        self.assertEqual(len(report["groups"]), 1)
        self.assertEqual(len(report["groups"][0]["occurrences"]), 2)
        self.assertEqual(len(report["missing_text"]), 1)

    def test_comparison_and_peer_are_scoped(self):
        peer = self.root / "peer"
        peer.mkdir()
        (peer / "p.conllu").write_text(FIRST.replace("s1", "p1"), encoding="utf-8", newline="")
        result = comparison.overlap_report({**self.args, "file_paths": ["a.conllu"], "peer_treebank_paths": ["peer"]})
        self.assertEqual(result["matches"][0]["peer_treebank"], "peer")
        with self.assertRaises(InvalidInput):
            comparison.overlap_report({**self.args, "peer_treebank_paths": ["../outside"]})

    def test_text_compare_incomplete_is_not_equal(self):
        (self.root / "missing.conllu").write_text(FIRST.replace("# text = Big cats run\n", ""), encoding="utf-8", newline="")
        result = conversion.text_content_compare({**self.args, "left_path": "missing.conllu", "right_path": "a.conllu", "left_format": "conllu", "right_format": "conllu"})
        self.assertIsNone(result["equal"])
        self.assertFalse(result["complete"])

    def test_token_alignment_keeps_tails(self):
        result = conversion.token_alignment_report({**self.args, "source_file_paths": ["a.conllu"], "target_file_paths": ["b.conllu"]})
        self.assertEqual(sum(len(s["source"]) for s in result["segments"]), 3)
        self.assertEqual(sum(len(s["target"]) for s in result["segments"]), 3)

    def test_document_split_is_deterministic_and_does_not_write(self):
        spec = self.root / "split.json"
        spec.write_text(json.dumps({"splits": {"train": 8, "test": 2}}), encoding="utf-8", newline="")
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        args = {**self.args, "split_spec_path": "split.json", "seed": 42}
        first = conversion.dataset_split_plan(args)
        second = conversion.dataset_split_plan(args)
        self.assertEqual(first, second)
        self.assertEqual(sum(first["counts"].values()), 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        with self.assertRaises(InvalidInput):
            conversion.dataset_split_plan({**args, "seed": True})

    def test_fix_plan_and_apply_check_preconditions_without_writing(self):
        file = self.root / "a.conllu"
        before = FIRST.rstrip("\n").encode()
        file.write_bytes(before)
        plan = plans.fix_plan({**self.args, "file_paths": ["a.conllu"], "fix_ids": ["final_blank_line"]})
        self.assertEqual(len(plan["actions"]), 1)
        (self.root / "plan.json").write_text(json.dumps(plan), encoding="utf-8", newline="")
        request = {**self.args, "plan_path": "plan.json", "selected_action_ids": [plan["actions"][0]["id"]]}
        candidate = plans.plan_apply(request)
        self.assertEqual(file.read_bytes(), before)
        self.assertEqual(candidate["changes"][0]["content"], FIRST)
        file.write_text("changed", encoding="utf-8", newline="")
        with self.assertRaises(StaleInputError):
            plans.plan_apply(request)

    def test_parallel_alignment_reports_missing_references(self):
        peer = self.root / "peer"
        peer.mkdir()
        (peer / "p.conllu").write_text(SECOND, encoding="utf-8", newline="")
        source = {"treebank": ".", "file_path": "a.conllu", "sent_id": "s1"}
        target = {"treebank": "peer", "file_path": "p.conllu", "sent_id": "s2"}
        missing = {**target, "sent_id": "missing"}
        (self.root / "alignment.json").write_text(json.dumps({"alignments": [{"source": source, "targets": [target, missing]}]}), encoding="utf-8", newline="")
        report = parallel.parallel_corpus_report({**self.args, "peer_treebank_paths": ["peer"], "alignment_spec_path": "alignment.json"})
        self.assertEqual(report["coverage"], {"requested": 1, "complete": 0})
        self.assertEqual(report["missing_references"][0]["reference"]["sent_id"], "missing")

    def test_bible_concordance_keeps_missing_correspondence(self):
        (self.root / "a.conllu").write_text(FIRST.replace("s1", "b.GEN.1.1"), encoding="utf-8", newline="")
        (self.root / "b.conllu").write_text(SECOND.replace("s2", "b.GEN.1.2"), encoding="utf-8", newline="")
        report = parallel.bible_passage_concordance({**self.args, "file_paths": ["a.conllu"], "peer_file_paths": ["b.conllu"]})
        self.assertEqual([(p["verse"], p["correspondence_complete"]) for p in report["passages"]], [(1, False), (2, False)])

    def test_annotation_import_plan_is_complete_and_applicable(self):
        (self.root / "source.conllu").write_text(FIRST.replace("\tcat\tNOUN", "\tCAT\tNOUN"), encoding="utf-8", newline="")
        args = {**self.args, "source_annotation_paths": ["source.conllu"], "target_file_paths": ["a.conllu"], "columns": ["LEMMA"]}
        plan = conversion.annotation_import_plan(args)
        self.assertEqual(plan["pairs"][0]["aligned_words"], 3)
        self.assertEqual(len(plan["actions"]), 1)
        self.assertIn("\tCAT\tNOUN", plan["actions"][0]["content"])
        (self.root / "plan.json").write_text(json.dumps(plan), encoding="utf-8", newline="")
        candidate = plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [plan["actions"][0]["id"]]})
        self.assertIn("\tCAT\tNOUN", candidate["changes"][0]["content"])
        (self.root / "source.conllu").write_text(FIRST, encoding="utf-8", newline="")
        with self.assertRaises(StaleInputError):
            plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [plan["actions"][0]["id"]]})
        with self.assertRaises(InvalidInput):
            conversion.annotation_import_plan({**args, "target_file_paths": ["b.conllu"]})

    def test_tagset_conversion_never_guesses_unknown_tags(self):
        doc = FIRST.replace("\tADJ\t_\t", "\tADJ\tA\t").replace("\tNOUN\t_\t", "\tNOUN\tN\t").replace("\tVERB\t_\t", "\tVERB\tV\t")
        (self.root / "a.conllu").write_text(doc, encoding="utf-8", newline="")
        args = {**self.args, "file_paths": ["a.conllu"], "source_tagset": "local", "target_tagset": "UD", "options": {"mapping": {"A": "ADJ", "N": "PROPN"}}}
        incomplete = conversion.tagset_conversion_plan(args)
        self.assertEqual(incomplete["status"], "needs_annotation")
        self.assertEqual(incomplete["unmapped"][0]["tag"], "V")
        self.assertEqual(incomplete["actions"], [])
        args["options"]["mapping"]["V"] = "VERB"
        complete = conversion.tagset_conversion_plan(args)
        self.assertEqual(complete["status"], "ready")
        self.assertIn("\tcat\tPROPN\tN\t", complete["actions"][0]["content"])

    def test_tokenization_plan_requires_maps_for_changes(self):
        source = FIRST.replace("3\trun\trun\tVERB", "3\truns\trun\tVERB")
        (self.root / "source.conllu").write_text(source, encoding="utf-8", newline="")
        report = conversion.tokenization_change_plan({**self.args, "source_tokenization_paths": ["source.conllu"], "target_file_paths": ["a.conllu"]})
        self.assertEqual(report["status"], "needs_annotation")
        self.assertTrue(report["actions"][0]["requires_annotation_map"])
        self.assertEqual(report["actions"][0]["target_tokens"][0]["form"], "run")
        self.assertEqual(len(report["source_fingerprints"]["source.conllu"]), 64)
        self.assertEqual(len(report["target_fingerprints"]["a.conllu"]), 64)

    def test_segmentation_plan_refuses_different_text(self):
        report = conversion.sentence_segmentation_change_plan({**self.args, "source_segmentation_paths": ["a.conllu"], "target_file_paths": ["b.conllu"]})
        self.assertEqual(report["status"], "conflict")
        self.assertEqual(report["actions"], [])
        self.assertEqual(len(report["source_fingerprints"]["a.conllu"]), 64)
        report = conversion.sentence_segmentation_change_plan({**self.args, "source_segmentation_paths": ["a.conllu"], "target_file_paths": ["a.conllu"]})
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["actions"], [])

    def test_conversion_prepares_loss_explicit_export(self):
        request = {**self.args, "input_paths": ["a.conllu"], "target_format": "conllx", "output_dir_path": "/authorized/output"}
        result = conversion.format_convert(request)
        self.assertTrue(result["requires_host_export"])
        self.assertEqual(result["artifacts"][0]["filename"], "a.conllx")
        self.assertIn("enhanced dependencies", result["losses"])
        self.assertIn("1\tBig\tbig\tADJ\t_\tNumber=Plur\t2\tamod\t_\t_", result["artifacts"][0]["content"])
        self.assertFalse(Path("/authorized/output").exists())

    def test_extract_prepares_only_requested_sentence(self):
        selection = {"sentences": [{"file_path": "a.conllu", "sent_id": "s1"}]}
        (self.root / "selection.json").write_text(json.dumps(selection), encoding="utf-8", newline="")
        result = conversion.sentence_batch_extract({**self.args, "selection_path": "selection.json", "output_dir_path": "/authorized/output"})
        self.assertEqual(result["artifacts"][0]["content"], FIRST)
        self.assertTrue(result["requires_host_export"])
        for unsafe in ("CON.txt", "file?.conllu", "name.", "name "):
            with self.assertRaises(InvalidInput):
                conversion.sentence_batch_extract({**self.args, "selection_path": "selection.json", "output_dir_path": "/authorized/output", "options": {"output_filename": unsafe}})

    def test_empty_node_drop_plan_reports_lost_edges(self):
        content = "# sent_id = e1\n# text = A B\n1\tA\ta\tNOUN\t_\t_\t0\troot\t0:root\t_\n1.1\tx\tx\tVERB\t_\t_\t_\t_\t1:dep\t_\n2\tB\tb\tNOUN\t_\t_\t1\tdep\t1.1:dep\t_\n\n"
        (self.root / "empty.conllu").write_text(content, encoding="utf-8", newline="")
        (self.root / "transform.json").write_text(json.dumps({"mode": "drop", "allow_information_loss": True}), encoding="utf-8", newline="")
        args = {**self.args, "file_paths": ["empty.conllu"], "transformation_spec_path": "transform.json"}
        report = enhanced.enhanced_empty_node_collapse_plan(args)
        self.assertEqual(len(report["actions"]), 1)
        self.assertEqual(len(report["losses"]), 2)
        self.assertNotIn("1.1:dep", report["actions"][0]["content"])
        self.assertNotIn("1.1\tx", report["actions"][0]["content"])
        (self.root / "transform.json").write_text(json.dumps({"mode": "drop", "allow_information_loss": 1}), encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            enhanced.enhanced_empty_node_collapse_plan(args)

    def test_enhanced_explanation_is_evidence_not_guess(self):
        report = enhanced.enhanced_edge_explanations({**self.args, "file_paths": ["a.conllu"], "output_dir_path": "/authorized/output"})
        artifact = json.loads(report["artifacts"][0]["content"])
        self.assertTrue(artifact["explanations"][0]["matches_basic"])
        self.assertEqual(artifact["explanations"][0]["evidence"], "explicit DEPS annotation")

    def test_relative_clause_classifier_uses_explicit_markers(self):
        content = "# sent_id = r1\n# text = book which I read fell\n1\tbook\tbook\tNOUN\t_\t_\t5\tnsubj\t_\t_\n2\twhich\twhich\tPRON\t_\tPronType=Rel\t4\tobj\t_\t_\n3\tI\tI\tPRON\t_\t_\t4\tnsubj\t_\t_\n4\tread\tread\tVERB\t_\t_\t1\tacl:relcl\t_\t_\n5\tfell\tfall\tVERB\t_\t_\t0\troot\t_\t_\n\n"
        (self.root / "relative.conllu").write_text(content, encoding="utf-8", newline="")
        result = analysis.english_relative_clause_classify({**self.args, "file_paths": ["relative.conllu"], "output_dir_path": "/output"})
        clause = json.loads(result["artifacts"][0]["content"])["clauses"][0]
        self.assertEqual(clause["category"], "adnominal")
        self.assertEqual(clause["relative_markers"][0]["form"], "which")
        self.assertTrue(result["requires_host_export"])

    def test_changes_review_uses_verified_snapshot_bytes(self):
        from hashlib import sha256
        prior = FIRST.replace("Big", "Large")
        snapshot = {"revision": "base", "files": {"a.conllu": {"content": prior, "sha256": sha256(prior.encode()).hexdigest()}}}
        (self.root / "base.json").write_text(json.dumps(snapshot), encoding="utf-8", newline="")
        result = review.changes_review({**self.args, "base_revision": "base", "options": {"base_snapshot_path": "base.json"}})
        self.assertEqual([item["change"] for item in result["changes"]], ["modified", "added"])
        self.assertFalse(result["coverage"]["base_identity_verified"])
        snapshot["files"]["a.conllu"]["sha256"] = "bad"
        (self.root / "base.json").write_text(json.dumps(snapshot), encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            review.changes_review({**self.args, "base_revision": "base", "options": {"base_snapshot_path": "base.json"}})

    def test_contribution_patch_requires_exact_context_and_is_candidate_only(self):
        patch = "--- a/a.conllu\n+++ b/a.conllu\n@@ -1,3 +1,3 @@\n # sent_id = s1\n # text = Big cats run\n-1\tBig\tbig\tADJ\t_\tNumber=Plur\t2\tamod\t2:amod\t_\n+1\tLarge\tbig\tADJ\t_\tNumber=Plur\t2\tamod\t2:amod\t_\n"
        (self.root / "input.patch").write_text(patch, encoding="utf-8", newline="")
        plan = review.contribution_plan({**self.args, "patch_path": "input.patch"})
        self.assertEqual(len(plan["actions"]), 1)
        self.assertIn("1\tLarge", plan["actions"][0]["content"])
        self.assertEqual((self.root / "a.conllu").read_text(), FIRST)
        (self.root / "a.conllu").write_text("different\n", encoding="utf-8", newline="")
        with self.assertRaises(InvalidInput):
            review.contribution_plan({**self.args, "patch_path": "input.patch"})

    def test_rule_change_plan_creates_verified_context_candidate(self):
        base = self.root / "base_rules"
        proposed = self.root / "new_rules"
        base.mkdir()
        proposed.mkdir()
        for file, key, value in (("upos", "upos", ["NOUN"]), ("feats", "features", {"en": {"Number": {}}}),
                                 ("udeprels", "udeprels", ["root"]), ("deprels", "deprels", {"en": {"root": {}}}),
                                 ("edeprels", "edeprels", {}), ("data", "auxiliaries", {}), ("tospace", "expressions", {})):
            (base / f"{file}.json").write_text(json.dumps({key: value}), encoding="utf-8", newline="")
            (proposed / f"{file}.json").write_text(json.dumps({key: value}), encoding="utf-8", newline="")
        (proposed / "upos.json").write_text(json.dumps({"upos": ["NOUN", "VERB"]}), encoding="utf-8", newline="")
        report = rules.language_rule_change_plan({**self.args, "language_code": "en", "ud_context_path": str(base), "proposed_rules_path": "new_rules"})
        self.assertEqual(report["changed_files"], ["upos.json"])
        (self.root / "plan.json").write_text(json.dumps(report), encoding="utf-8", newline="")
        applied = plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [report["actions"][0]["id"]]})
        self.assertTrue(applied["requires_host_commit"])
        self.assertEqual(len(applied["context_changes"]), 1)
        (proposed / "upos.json").write_text('{}', encoding="utf-8", newline="")
        with self.assertRaises(StaleInputError):
            plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [report["actions"][0]["id"]]})

    def test_metadata_plan_preserves_readme_prose_and_uses_preconditions(self):
        readme = "Intro\r\n\r\n=== Machine-readable metadata (DO NOT REMOVE!) =====\r\nLicense: old\r\nGenre: web\r\n=======================\r\nTail\r\n"
        (self.root / "README.md").write_bytes(readme.encode())
        (self.root / "metadata.json").write_text(json.dumps({"License": "new", "Genre": None, "Contact": "a@example.org"}), encoding="utf-8", newline="")
        report = metadata.metadata_change_plan({**self.args, "proposed_metadata_path": "metadata.json"})
        content = report["actions"][0]["content"]
        self.assertEqual(content, "Intro\r\n\r\n=== Machine-readable metadata (DO NOT REMOVE!) =====\r\nLicense: new\r\nContact: a@example.org\r\n=======================\r\nTail\r\n")
        (self.root / "plan.json").write_text(json.dumps(report), encoding="utf-8", newline="")
        candidate = plans.plan_apply({**self.args, "plan_path": "plan.json", "selected_action_ids": [report["actions"][0]["id"]]})
        self.assertEqual(candidate["changes"][0]["content"], content)

    def test_symlink_paths_are_rejected(self):
        (self.root / "link.conllu").symlink_to(self.root / "a.conllu")
        with self.assertRaises(InvalidInput):
            analysis.treebank_profile({**self.args, "file_paths": ["link.conllu"]})
        self.assertEqual(analysis.treebank_profile(self.args)["word_count"], 6)

    def test_workspace_inventory_contains_hashes(self):
        found = workspace.workspace_inspect(self.args)["files"]
        self.assertEqual([item["path"] for item in found], ["a.conllu", "b.conllu"])
        self.assertEqual(len(found[0]["sha256"]), 64)

    def test_rejects_empty_input_and_missing_prerequisites(self):
        with self.assertRaises(InvalidInput):
            validation.validation_report({**self.args, "file_paths": []})
        with self.assertRaises(InvalidInput):
            validation.validation_report(self.args)

    def test_official_validator_one_call_over_all_files(self):
        rules = self.root / "rules"
        rules.mkdir()
        for name in ["upos", "feats", "udeprels", "deprels", "edeprels", "data", "tospace"]:
            (rules / f"{name}.json").write_text("{}", encoding="utf-8", newline="")
        class Incident:
            def json(self):
                return json.dumps({"message": "bad", "code": "E"})
        class State:
            error_tracker = [Incident()]
            def passed(self):
                return False
        class Validator:
            calls = []
            configured = []
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.configured.append(kwargs)
            def validate_files(self, files):
                self.calls.append(files)
                return State()
        with patch.dict(sys.modules, {"udtools": types.SimpleNamespace(Validator=Validator)}):
            result = validation.validation_report({**self.args, "ud_context_path": str(rules), "options": {"language_code": "en", "coref": True, "test_filters": ["example"]}})
        self.assertFalse(result["passed"])
        self.assertEqual(result["incidents"][0]["code"], "E")
        self.assertEqual(len(Validator.calls), 1)
        self.assertEqual(len(Validator.calls[0]), 2)
        self.assertTrue(Validator.configured[0]["check_coref"])
        self.assertEqual(Validator.configured[0]["args"].include_only, ["example"])
        self.assertTrue(result["scope"]["filtered"])

    def test_rules_report_separates_global_and_language_data(self):
        directory = self.root / "rules"
        directory.mkdir()
        for file, key, value in (("upos", "upos", ["NOUN"]), ("feats", "features", {"en": {"Number": {}}}),
                                 ("udeprels", "udeprels", ["root"]), ("deprels", "deprels", {"en": {"root": {}}}),
                                 ("edeprels", "edeprels", {}), ("data", "auxiliaries", {}), ("tospace", "expressions", {})):
            (directory / f"{file}.json").write_text(json.dumps({key: value}), encoding="utf-8", newline="")
        report = rules.language_rules_report({**self.args, "language_code": "en", "ud_context_path": str(directory)})
        self.assertEqual(report["rules"]["upos"], ["NOUN"])
        self.assertEqual(report["rules"]["features"], {"Number": {}})
        self.assertIsNone(report["rules"]["expressions"])
        self.assertEqual(len(report["source_hashes"]), 7)

    def test_scoring_aggregates_counts_and_preserves_gold_roles(self):
        class Score:
            def __init__(self, correct, total):
                self.correct = correct
                self.gold_total = total
                self.system_total = total
                self.aligned_total = total
        class Scorer:
            @staticmethod
            def load_conllu(stream, path, _settings):
                self.assertFalse(stream.closed)
                return Path(path).name
            @staticmethod
            def evaluate(gold, system):
                self.assertEqual(gold, system)
                return {"LAS": Score(1, 1) if gold == "a.conllu" else Score(0, 9), "ELAS": Score(1, 1)}
        with patch.dict(sys.modules, {"udtools": types.SimpleNamespace(udeval=Scorer)}):
            result = evaluation.predictions_evaluate({**self.args, "gold_file_paths": ["a.conllu", "b.conllu"],
                                                       "prediction_file_paths": ["a.conllu", "b.conllu"]})
        self.assertAlmostEqual(result["scores"]["LAS"]["f1"], 0.1)
        self.assertNotIn("ELAS", result["scores"])
        self.assertEqual(result["roles"]["gold"], ["a.conllu", "b.conllu"])

class WireTests(unittest.TestCase):
    def test_invalid_requests_are_failures(self):
        self.assertEqual(wire.process({})["error"]["code"], "INVALID_INPUT")
        self.assertEqual(wire.process({"operation": "made_up", "arguments": {}})["error"]["code"], "INVALID_INPUT")
        with patch("ud_agent.dispatch.import_module", side_effect=ModuleNotFoundError("missing", name="ud_agent.domain.rendering")):
            result = wire.process({"operation": "documentation_preview", "arguments": {}})
        self.assertEqual(result["error"]["code"], "HANDLER_UNAVAILABLE")

    def test_invalid_results_rejected(self):
        with self.assertRaises(Exception):
            wire.encode({"value": float("nan")})

    def test_stale_input_is_conflict(self):
        with patch("ud_agent.domain.edit_batch.token_edit", side_effect=StaleInputError("stale fingerprint")):
            result = wire.process({"operation": "token_edit", "arguments": {}})
        self.assertEqual(result["error"]["code"], "CONFLICT")

    def test_stdio_stays_protocol_json(self):
        env = dict(os.environ)
        result = subprocess.run([sys.executable, "-m", "ud_agent.worker"], input=b'bad json\n{"operation":"made_up","arguments":{}}\n', env=env, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["error"]["code"], "INVALID_JSON")
        self.assertEqual(json.loads(lines[1])["error"]["code"], "INVALID_INPUT")
        self.assertEqual(result.stderr, b"")

if __name__ == "__main__":
    unittest.main()
