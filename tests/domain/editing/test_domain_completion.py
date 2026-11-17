import hashlib
import base64
import json
from pathlib import Path
import tempfile
import unittest

from ud_agent.domain import conversion, maintenance, plans, sentences, structural, edit_batch
from ud_agent.conllu.core import StaleInputError


def sentence(ident, form, boundary=""):
    return boundary + f"# sent_id = {ident}\n1\t{form}\t_\tX\t_\t_\t0\troot\t_\t_\n\n"


class DomainCompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ud-domain-completion-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = {"working_tree_path": str(self.root)}

    def apply_plan(self, plan):
        (self.root / "plan.json").write_text(json.dumps(plan), encoding="utf-8", newline="")
        return plans.plan_apply({**self.base, "plan_path": "plan.json",
                                 "selected_action_ids": [action["id"] for action in plan["actions"]]})

    def test_split_plan_produces_executable_absence_checked_creates(self):
        original = sentence("a", "one", "# newdoc id = first\n") + sentence("b", "two", "# newdoc id = second\n")
        (self.root / "a.conllu").write_text(original, encoding="utf-8", newline="")
        (self.root / "spec.json").write_text(json.dumps({"splits": {"train": 1, "test": 1}}), encoding="utf-8", newline="")
        plan = conversion.dataset_split_plan({**self.base, "file_paths": ["a.conllu"], "split_spec_path": "spec.json", "seed": 1})
        result = self.apply_plan(plan)
        self.assertEqual([op["operation"] for op in result["file_operations"]], ["create", "create"])
        outputs = {op["file_path"]: op["content"] for op in result["file_operations"]}
        self.assertEqual(set(outputs), {"splits/test.conllu", "splits/train.conllu"})
        self.assertEqual(set(outputs.values()), {sentence("a", "one", "# newdoc id = first\n"), sentence("b", "two", "# newdoc id = second\n")})
        self.assertEqual((self.root / "a.conllu").read_text(), original)
        (self.root / "splits").mkdir()
        (self.root / "splits/test.conllu").write_text("existing", newline="")
        with self.assertRaisesRegex(StaleInputError, "absent"):
            self.apply_plan(plan)

    def test_rename_plan_is_executable_and_binds_identity_input(self):
        content = sentence("a", "one")
        (self.root / "old-ud-train.conllu").write_text(content, newline="")
        (self.root / "README.md").write_text("Treebank old\n", newline="")
        (self.root / "identity.json").write_text(json.dumps({"old_name": "old", "new_name": "new"}), newline="")
        plan = maintenance.treebank_rename_plan({**self.base, "new_identity_path": "identity.json", "related_repository_paths": []})
        result = self.apply_plan(plan)
        self.assertEqual(result["file_operations"], [{"operation": "rename", "file_path": "old-ud-train.conllu", "target_file_path": "new-ud-train.conllu", "before_sha256": hashlib.sha256(content.encode()).hexdigest(), "target_before_sha256": None,
                                                   "after_sha256": hashlib.sha256(content.encode()).hexdigest(), "content_base64": base64.b64encode(content.encode()).decode()}])
        self.assertEqual(result["changes"][0]["content"], "Treebank new\n")
        (self.root / "identity.json").write_text("{}", newline="")
        with self.assertRaisesRegex(StaleInputError, "input fingerprint"):
            self.apply_plan(plan)

    def test_boundary_removal_transfers_only_explicit_markers(self):
        first = sentence("a", "one", "# newdoc id = doc\n# newpar id = paragraph\n")
        second = sentence("b", "two")
        (self.root / "a.conllu").write_text(first + second, newline="")
        args = {**self.base, "tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "edit_options": {"boundary_policy": "transfer_to_next"}}
        result = sentences.tree_remove(args)
        self.assertEqual(result["changes"][0]["content"], "# newdoc id = doc\n# newpar id = paragraph\n" + second)
        self.assertEqual((self.root / "a.conllu").read_text(), first + second)
        with self.assertRaisesRegex(ValueError, "supported explicit"):
            sentences.tree_remove({**args, "edit_options": {"boundary_policy": "anything"}})

    def test_copy_can_drop_boundary_without_changing_source(self):
        source = sentence("a", "one", "# newdoc id = doc\n")
        (self.root / "a.conllu").write_text(source, newline="")
        (self.root / "b.conllu").write_text(sentence("b", "two"), newline="")
        result = sentences.tree_copy({**self.base, "tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "target_file_path": "b.conllu", "new_sent_id": "c", "insertion_point": "end", "edit_options": {"boundary_policy": "drop"}})
        self.assertEqual(len(result["changes"]), 1)
        self.assertEqual(result["changes"][0]["content"], sentence("b", "two") + sentence("c", "one"))

    def test_boundary_transfer_rejects_conflicting_next_document(self):
        (self.root / "a.conllu").write_text(sentence("a", "one", "# newdoc id = one\n") + sentence("b", "two", "# newdoc id = two\n"), newline="")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            sentences.tree_remove({**self.base, "tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "edit_options": {"boundary_policy": "preserve"}})

    def test_structural_map_compiles_temporary_rows_with_explicit_annotations(self):
        (self.root / "a.conllu").write_text(sentence("a", "cannot"), newline="")
        def word(ident, form, head, rel):
            return {"id": ident, "kind": "word", "form": form, "lemma": "_", "upos": "X", "xpos": "_",
                    "feats": {}, "head": head, "deprel": rel, "deps": [{"head_id": head, "deprel": rel}], "misc": {}}
        annotation = {"id_mapping": {"a#1": ["a#$can", "a#$not"]}, "sentences": [{"sent_id": "a", "text": "can not", "comments": [],
                      "rows": [word("$can", "can", "0", "root"), word("$not", "not", "$can", "advmod")]}]}
        result = structural.token_split({**self.base, "token_ref": {"tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "token_id": "1"},
                                         "replacement_words": ["can", "not"], "annotation_map": annotation})
        self.assertEqual(result["details"]["id_mapping"], {"a#1": ["a#1", "a#2"]})
        self.assertEqual(result["changes"][0]["content"], "# sent_id = a\n# text = can not\n1\tcan\t_\tX\t_\t_\t0\troot\t0:root\t_\n2\tnot\t_\tX\t_\t_\t1\tadvmod\t1:advmod\t_\n\n")
        del annotation["sentences"][0]["rows"][0]["misc"]
        with self.assertRaisesRegex(ValueError, "every annotation field"):
            structural.token_split({**self.base, "token_ref": {"tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "token_id": "1"},
                                     "replacement_words": ["can", "not"], "annotation_map": annotation})

    def test_structural_identity_collisions_include_other_workspace_files(self):
        (self.root / "a.conllu").write_text(sentence("a", "one") + sentence("b", "two"), newline="")
        (self.root / "other.conllu").write_text(sentence("merged", "elsewhere"), newline="")
        target = "# sent_id = merged\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\ttwo\t_\tX\t_\t_\t1\tdep\t_\t_\n\n"
        annotation = {"id_mapping": {"a#1": ["merged#1"], "b#1": ["merged#2"]}, "sentences": [{"sent_id": "merged", "conllu": target}],
                      "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}
        with self.assertRaisesRegex(ValueError, "workspace"):
            structural.trees_merge({**self.base, "tree_refs": [{"file_path": "a.conllu", "sent_id": "a"}, {"file_path": "a.conllu", "sent_id": "b"}],
                                    "new_sent_id": "merged", "annotation_map": annotation})

    def test_batch_insert_preserves_snapshot_ids_and_resolves_temporary_row(self):
        original = "# sent_id = a\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\ttwo\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        (self.root / "a.conllu").write_text(original, newline="")
        ref = {"file_path": "a.conllu", "sent_id": "a"}
        result = edit_batch.tree_edit({**self.base, "tree_ref": ref, "edit_operations": [
            {"operation": "token_add", "temporary_id": "$new", "arguments": {"token_data": {"form": "new", "upos": "X"}, "insertion_point": {"before_word_id": "1"}, "attachment_spec": {"head_id": "1", "deprel": "dep"}}},
            {"operation": "token_form_set", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "2"}, "form": "TWO"}},
            {"operation": "token_lemma_set", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "$new"}, "lemma": "new-lemma"}},
        ]})
        self.assertEqual(result["changes"][0]["content"], "# sent_id = a\n1\tnew\tnew-lemma\tX\t_\t_\t2\tdep\t_\t_\n2\tone\t_\tX\t_\t_\t0\troot\t_\t_\n3\tTWO\t_\tX\t_\t_\t2\tobj\t_\t_\n\n")
        self.assertEqual((self.root / "a.conllu").read_text(), original)

    def test_batch_remove_then_edit_uses_the_original_word_identity(self):
        original = "# sent_id = a\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\ttwo\t_\tX\t_\t_\t1\tobj\t_\t_\n3\tthree\t_\tX\t_\t_\t1\tobl\t_\t_\n\n"
        (self.root / "a.conllu").write_text(original, newline="")
        ref = {"file_path": "a.conllu", "sent_id": "a"}
        result = edit_batch.tree_edit({**self.base, "tree_ref": ref, "edit_operations": [
            {"operation": "token_remove", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "2"}, "removal_spec": {"dependent_heads": {}, "enhanced_edges": "remove", "multiword_tokens": "remove"}}},
            {"operation": "token_form_set", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "3"}, "form": "THREE"}},
        ]})
        self.assertEqual(result["changes"][0]["content"], "# sent_id = a\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\tTHREE\t_\tX\t_\t_\t1\tobl\t_\t_\n\n")

    def test_batch_structural_split_can_name_and_edit_new_words(self):
        (self.root / "a.conllu").write_text(sentence("a", "cannot"), newline="")
        ref = {"file_path": "a.conllu", "sent_id": "a"}
        target = "# sent_id = a\n1\tcan\t_\tX\t_\t_\t0\troot\t_\t_\n2\tnot\t_\tX\t_\t_\t1\tadvmod\t_\t_\n\n"
        annotation = {"id_mapping": {"a#1": ["a#1", "a#2"]}, "sentences": [{"sent_id": "a", "conllu": target}],
                      "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}
        result = edit_batch.tree_edit({**self.base, "tree_ref": ref, "edit_operations": [
            {"operation": "token_split", "temporary_ids": {"$negative": "2"}, "arguments": {"token_ref": {"tree_ref": ref, "token_id": "1"}, "replacement_words": ["can", "not"], "annotation_map": annotation}},
            {"operation": "token_lemma_set", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "$negative"}, "lemma": "not"}},
        ]})
        self.assertEqual(result["changes"][0]["content"], target.replace("2\tnot\t_", "2\tnot\tnot"))

    def test_structural_plan_requires_annotations_then_executes_the_completed_action(self):
        (self.root / "a.conllu").write_text(sentence("a", "cannot"), newline="")
        action = {"id": "split", "type": "token_split", "depends_on": [], "requires_annotation_map": True}
        plan = {"schema_version": "ud-plan-v1", "actions": [action]}
        incomplete = self.apply_plan(plan)
        self.assertEqual(incomplete["status"], "needs_annotation")
        self.assertFalse(incomplete["requires_host_commit"])
        target = "# sent_id = a\n1\tcan\t_\tX\t_\t_\t0\troot\t_\t_\n2\tnot\t_\tX\t_\t_\t1\tadvmod\t_\t_\n\n"
        action["arguments"] = {"token_ref": {"tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "token_id": "1"}, "replacement_words": ["can", "not"],
                               "annotation_map": {"id_mapping": {"a#1": ["a#1", "a#2"]}, "sentences": [{"sent_id": "a", "conllu": target}],
                                                  "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}}
        result = self.apply_plan(plan)
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["changes"][0]["content"], target)

    def test_batch_move_keeps_original_sentence_reference_bound_after_relocation(self):
        original_a = sentence("a", "one") + sentence("tail", "tail")
        original_b = sentence("b", "two")
        (self.root / "a.conllu").write_text(original_a, newline="")
        (self.root / "b.conllu").write_text(original_b, newline="")
        ref = {"file_path": "a.conllu", "sent_id": "a"}
        result = edit_batch.treebank_edit({**self.base, "edit_batch": [
            {"operation": "tree_move", "arguments": {"tree_ref": ref, "target_file_path": "b.conllu", "insertion_point": "end"}},
            {"operation": "token_form_set", "arguments": {"token_ref": {"tree_ref": ref, "token_id": "1"}, "form": "ONE"}},
        ]})
        outputs = {item["file_path"]: item["content"] for item in result["changes"]}
        self.assertEqual(outputs, {"a.conllu": sentence("tail", "tail"), "b.conllu": original_b + sentence("a", "ONE")})
        self.assertEqual((self.root / "a.conllu").read_text(), original_a)

    def test_batch_copy_can_name_and_edit_new_sentence_before_original(self):
        original = sentence("a", "one")
        (self.root / "a.conllu").write_text(original, newline="")
        result = edit_batch.treebank_edit({**self.base, "edit_batch": [
            {"operation": "tree_copy", "temporary_id": "$copy", "arguments": {"tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "target_file_path": "a.conllu", "new_sent_id": "copy", "insertion_point": 0}},
            {"operation": "token_lemma_set", "arguments": {"token_ref": {"tree_ref": {"temporary_id": "$copy"}, "token_id": "1"}, "lemma": "copied"}},
        ]})
        self.assertEqual(result["changes"][0]["content"], sentence("copy", "one").replace("one\t_", "one\tcopied") + original)

    def test_batch_sentence_split_can_name_and_edit_a_result_sentence(self):
        original = "# sent_id = source\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\ttwo\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        (self.root / "a.conllu").write_text(original, newline="")
        annotation = {"id_mapping": {"source#1": ["first#1"], "source#2": ["second#1"]}, "sentences": [{"sent_id": "first", "conllu": sentence("first", "one")}, {"sent_id": "second", "conllu": sentence("second", "two")}],
                      "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}
        result = edit_batch.treebank_edit({**self.base, "edit_batch": [
            {"operation": "tree_split", "temporary_tree_ids": {"$second": "second"}, "arguments": {"tree_ref": {"file_path": "a.conllu", "sent_id": "source"}, "split_boundaries": ["1"], "new_sent_ids": ["first", "second"], "annotation_map": annotation}},
            {"operation": "token_form_set", "arguments": {"token_ref": {"tree_ref": {"temporary_id": "$second"}, "token_id": "1"}, "form": "TWO"}},
        ]})
        self.assertEqual(result["changes"][0]["content"], sentence("first", "one") + sentence("second", "TWO"))

    def test_batch_merge_preserves_original_word_reference_from_second_file(self):
        (self.root / "a.conllu").write_text(sentence("a", "one"), newline="")
        (self.root / "b.conllu").write_text(sentence("b", "two"), newline="")
        merged = "# sent_id = merged\n1\tone\t_\tX\t_\t_\t0\troot\t_\t_\n2\ttwo\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        annotation = {"id_mapping": {"a#1": ["merged#1"], "b#1": ["merged#2"]}, "sentences": [{"sent_id": "merged", "conllu": merged}],
                      "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}
        result = edit_batch.treebank_edit({**self.base, "edit_batch": [
            {"operation": "trees_merge", "arguments": {"tree_refs": [{"file_path": "a.conllu", "sent_id": "a"}, {"file_path": "b.conllu", "sent_id": "b"}], "new_sent_id": "merged", "annotation_map": annotation}},
            {"operation": "token_lemma_set", "arguments": {"token_ref": {"tree_ref": {"file_path": "b.conllu", "sent_id": "b"}, "token_id": "1"}, "lemma": "second"}},
        ]})
        self.assertEqual({item["file_path"]: item["content"] for item in result["changes"]}, {"a.conllu": merged.replace("two\t_", "two\tsecond"), "b.conllu": ""})

    def test_completed_many_to_many_tokenization_plan_executes_full_annotation_map(self):
        original = "# sent_id = a\n1\tab\t_\tX\t_\t_\t0\troot\t_\t_\n2\tc\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        target = "# sent_id = a\n1\ta\t_\tX\t_\t_\t0\troot\t_\t_\n2\tbc\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        (self.root / "a.conllu").write_text(original, newline="")
        plan = {"schema_version": "ud-plan-v1", "actions": [{"id": "reconcile", "type": "tokenization_reconcile", "depends_on": [],
                "arguments": {"tree_ref": {"file_path": "a.conllu", "sent_id": "a"}, "replacement_words": ["a", "bc"],
                              "annotation_map": {"id_mapping": {"a#1": ["a#1", "a#2"], "a#2": ["a#2"]}, "sentences": [{"sent_id": "a", "conllu": target}],
                                                 "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}}}]}
        result = self.apply_plan(plan)
        self.assertEqual(result["changes"][0]["content"], target)
        self.assertEqual((self.root / "a.conllu").read_text(), original)
        plan["actions"][0]["arguments"]["operation"] = "tokenization_reconcile"
        self.assertEqual(self.apply_plan(plan)["changes"][0]["content"], target)

    def test_multiple_completed_segmentation_actions_compose_in_one_file(self):
        def source(ident, first, second):
            return f"# sent_id = {ident}\n1\t{first}\t_\tX\t_\t_\t0\troot\t_\t_\n2\t{second}\t_\tX\t_\t_\t1\tobj\t_\t_\n\n"
        (self.root / "a.conllu").write_text(source("a", "one", "two") + source("b", "three", "four"), newline="")
        actions = []
        for ident, first, second in [("a", "one", "two"), ("b", "three", "four")]:
            targets = [ident + "1", ident + "2"]
            actions.append({"id": ident, "type": "tree_split", "depends_on": [], "arguments": {
                "tree_ref": {"file_path": "a.conllu", "sent_id": ident}, "split_boundaries": ["1"], "new_sent_ids": targets,
                "annotation_map": {"id_mapping": {ident + "#1": [targets[0] + "#1"], ident + "#2": [targets[1] + "#1"]},
                                   "sentences": [{"sent_id": targets[0], "conllu": sentence(targets[0], first)}, {"sent_id": targets[1], "conllu": sentence(targets[1], second)}],
                                   "decisions": {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}}}})
        result = self.apply_plan({"schema_version": "ud-plan-v1", "actions": actions})
        self.assertEqual(result["changes"][0]["content"], sentence("a1", "one") + sentence("a2", "two") + sentence("b1", "three") + sentence("b2", "four"))


class FlatReferenceCompatibilityTests(unittest.TestCase):
    def test_flat_token_identity_aliases_preserve_real_standalone_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = sentence('a', 'one')
            (root / 'a.conllu').write_text(original, newline="")
            for field in ['token_id', 'word_id', 'id']:
                result = edit_batch.token_edit({'working_tree_path': str(root), 'token_ref': {'file_path': 'a.conllu', 'sent_id': 'a', field: '1'}, 'token_patch': {'lemma': 'changed'}})
                self.assertEqual(result['changes'][0]['content'], original.replace('one\t_', 'one\tchanged'))
                self.assertEqual((root / 'a.conllu').read_text(), original)

    def test_explicit_flat_batch_sentence_precedes_the_inherited_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = sentence('a', 'one'), sentence('b', 'two')
            (root / 'a.conllu').write_text(first + second, newline="")
            result = edit_batch.tree_edit({'working_tree_path': str(root), 'tree_ref': {'file_path': 'a.conllu', 'sent_id': 'a'}, 'edit_operations': [{'operation': 'token_lemma_set', 'arguments': {'token_ref': {'file_path': 'a.conllu', 'sent_id': 'b', 'token_id': '1'}, 'lemma': 'changed'}}]})
            self.assertEqual(result['changes'][0]['content'], first + second.replace('two\t_', 'two\tchanged'))
            self.assertEqual((root / 'a.conllu').read_text(), first + second)


if __name__ == "__main__":
    unittest.main()
