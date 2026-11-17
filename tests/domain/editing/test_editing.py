from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from ud_agent.domain import dependencies, edit_batch, sentences, special_rows, structural, tokens


def row(ident: str, form: str, head: str, relation: str, feats: str = "_", deps: str = "_", misc: str = "_") -> str:
    return f"{ident}\t{form}\t_\tX\t_\t{feats}\t{head}\t{relation}\t{deps}\t{misc}\n"


def sent(ident: str, rows: str) -> str:
    return f"# sent_id = {ident}\n{rows}\n"


class EditingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.file = self.root / "train.conllu"
        self.file.write_text(sent("s1", row("1", "one", "0", "root", "Number=Sing", "0:root", "SpaceAfter=No") + row("2", "two", "1", "obj", deps="1:obj")) + sent("s2", row("1", "tail", "0", "root")), encoding="utf-8", newline="")
        self.args = {"working_tree_path": str(self.root), "tree_ref": {"file_path": "train.conllu", "sent_id": "s1"},
                     "token_ref": {"tree_ref": {"file_path": "train.conllu", "sent_id": "s1"}, "token_id": "1"}}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def changed(self, result: dict) -> str:
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(len(result["changes"]), 1)
        return result["changes"][0]["content"]

    def annotation(self, mapping: dict, target: list[tuple[str, str]]) -> dict:
        return {"id_mapping": mapping, "created": [], "sentences": [{"sent_id": ident, "conllu": text} for ident, text in target],
                "decisions": {key: "explicit" for key in ("basic", "enhanced", "surface", "metadata")}, "unresolved": []}

    def test_focused_patch_is_same_as_broad_and_does_not_write(self) -> None:
        before = self.file.read_bytes()
        focused = tokens.token_form_set({**self.args, "form": "ONE", "edit_options": {"mode": "apply"}})
        broad = edit_batch.token_edit({**self.args, "token_patch": {"form": "ONE"}, "edit_options": {"mode": "apply"}})
        self.assertEqual(self.changed(focused), self.changed(broad))
        self.assertEqual(self.file.read_bytes(), before)
        self.assertTrue(focused["requires_host_commit"])
        self.assertEqual(focused["changes"][0]["before_sha256"], hashlib.sha256(before).hexdigest())
        self.assertIn(sent("s2", row("1", "tail", "0", "root")), self.changed(focused))

    def test_empty_features_and_misc_are_cleared(self) -> None:
        feats = self.changed(tokens.token_features_replace({**self.args, "features": {}}))
        self.assertIn("1\tone\t_\tX\t_\t_\t0\troot", feats)
        misc = self.changed(tokens.token_misc_replace({**self.args, "misc_entries": {}}))
        self.assertIn("0:root\t_\n", misc)

    def test_attribute_update_preserves_other_attributes(self) -> None:
        result = self.changed(tokens.token_misc_set({**self.args, "attribute_name": "Foo", "attribute_values": ["a", "b"]}))
        self.assertIn("SpaceAfter=No|Foo=a,b", result)

    def test_stale_fingerprint_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "stale"):
            tokens.token_form_set({**self.args, "form": "bad", "edit_options": {"expected_file_sha256": "0" * 64}})

    def test_sentence_reference_duplicate_requires_ordinal_and_hash(self) -> None:
        self.file.write_text(sent("same", row("1", "x", "0", "root")) + sent("same", row("1", "y", "0", "root")), newline="")
        ref = {"file_path": "train.conllu", "sent_id": "same"}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            sentences.tree_get({"working_tree_path": str(self.root), "tree_ref": ref})
        listing = sentences.tree_list({"working_tree_path": str(self.root), "file_paths": ["train.conllu"]})["trees"]
        result = sentences.tree_get({"working_tree_path": str(self.root), "tree_ref": {**ref, "ordinal": 1, "fingerprint": listing[1]["fingerprint"]}})
        self.assertIn("\ty\t", result["conllu"])

    def test_basic_cycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "cycle"):
            dependencies.basic_dependency_set({**self.args, "head_id": "2", "deprel": "dep"})

    def test_enhanced_replacement_replaces_incoming_edges(self) -> None:
        result = self.changed(dependencies.enhanced_dependencies_replace({**self.args, "dependent_id": "2", "incoming_edges": [{"head_id": "0", "deprel": "root"}]}))
        self.assertIn("2\ttwo\t_\tX\t_\t_\t1\tobj\t0:root\t_", result)
        self.assertNotIn("1:obj", result)

    def test_multiword_remove_preserves_components(self) -> None:
        self.file.write_text(sent("s1", "1-2\tcan't\t_\t_\t_\t_\t_\t_\t_\t_\n" + row("1", "ca", "0", "root") + row("2", "n't", "1", "advmod")), newline="")
        result = self.changed(special_rows.multiword_token_remove({**self.args, "range_id": "1-2"}))
        self.assertNotIn("1-2\t", result)
        self.assertIn("1\tca\t", result)
        self.assertIn("2\tn't\t", result)

    def test_reindex_updates_empty_node_decimal_and_edges(self) -> None:
        self.file.write_text(sent("s1", row("2", "a", "0", "root", deps="0:root") + row("5", "b", "2", "dep", deps="5.10:dep") + "5.10\tx\t_\tX\t_\t_\t_\t_\t2:dep\t_\n"), newline="")
        result = self.changed(special_rows.tree_reindex(self.args))
        self.assertIn("2.10\tx\t", result)
        self.assertIn("2.10:dep", result)
        self.assertIn("2\tb\t_\tX\t_\t_\t1\tdep", result)

    def test_missing_structural_map_needs_annotation(self) -> None:
        result = structural.token_split({**self.args, "replacement_words": ["o", "ne"]})
        self.assertEqual(result["status"], "needs_annotation")
        self.assertEqual(result["changes"], [])

    def test_token_split_executes_complete_map(self) -> None:
        original = sent("s1", row("1", "abc", "0", "root"))
        self.file.write_text(original, newline="")
        target = sent("s1", row("1", "a", "2", "dep") + row("2", "bc", "0", "root"))
        amap = self.annotation({"s1#1": ["s1#1", "s1#2"]}, [("s1", target)])
        result = structural.token_split({**self.args, "replacement_words": ["a", "bc"], "annotation_map": amap})
        self.assertEqual(self.changed(result), target)

    def test_tokens_merge_executes_complete_map(self) -> None:
        self.file.write_text(sent("s1", row("1", "a", "2", "dep") + row("2", "bc", "0", "root")), newline="")
        target = sent("s1", row("1", "abc", "0", "root"))
        amap = self.annotation({"s1#1": ["s1#1"], "s1#2": ["s1#1"]}, [("s1", target)])
        result = structural.tokens_merge({**self.args, "token_ids": ["1", "2"], "merged_word": "abc", "annotation_map": amap})
        self.assertEqual(self.changed(result), target)

    def test_tree_split_executes_complete_map(self) -> None:
        self.file.write_text(sent("s1", row("1", "a", "0", "root") + row("2", "b", "1", "dep")), newline="")
        first, second = sent("a", row("1", "a", "0", "root")), sent("b", row("1", "b", "0", "root"))
        amap = self.annotation({"s1#1": ["a#1"], "s1#2": ["b#1"]}, [("a", first), ("b", second)])
        result = structural.tree_split({**self.args, "split_boundaries": [1], "new_sent_ids": ["a", "b"], "annotation_map": amap})
        self.assertEqual(self.changed(result), first + second)

    def test_trees_merge_executes_complete_map(self) -> None:
        self.file.write_text(sent("s1", row("1", "a", "0", "root")) + sent("s2", row("1", "b", "0", "root")), newline="")
        target = sent("merged", row("1", "a", "2", "dep") + row("2", "b", "0", "root"))
        amap = self.annotation({"s1#1": ["merged#1"], "s2#1": ["merged#2"]}, [("merged", target)])
        result = structural.trees_merge({"working_tree_path": str(self.root), "tree_refs": [{"file_path": "train.conllu", "sent_id": "s1"}, {"file_path": "train.conllu", "sent_id": "s2"}], "new_sent_id": "merged", "annotation_map": amap})
        self.assertEqual(self.changed(result), target)

    def test_structural_mapping_cannot_point_to_nonexistent_node(self) -> None:
        self.file.write_text(sent("s1", row("1", "abc", "0", "root")), newline="")
        target = sent("s1", row("1", "a", "2", "dep") + row("2", "bc", "0", "root"))
        amap = self.annotation({"s1#1": ["s1#1", "s1#99"]}, [("s1", target)])
        with self.assertRaisesRegex(ValueError, "account"):
            structural.token_split({**self.args, "replacement_words": ["a", "bc"], "annotation_map": amap})

    def test_batch_edits_are_composed_against_snapshot(self) -> None:
        batch = [{"operation": "token_edit", "arguments": {"token_ref": self.args["token_ref"], "token_patch": {"form": "ONE"}}},
                 {"operation": "tree_metadata_edit", "arguments": {"tree_ref": self.args["tree_ref"], "metadata_patch": {"text": "ONE two"}}}]
        result = self.changed(edit_batch.treebank_edit({"working_tree_path": str(self.root), "edit_batch": batch}))
        self.assertIn("\tONE\t", result)
        self.assertIn("# text = ONE two", result)

    def test_symlink_input_is_rejected(self) -> None:
        (self.root / "link.conllu").symlink_to(self.file)
        with self.assertRaisesRegex(ValueError, "symlink"):
            sentences.tree_list({"working_tree_path": str(self.root), "file_paths": ["link.conllu"]})

    def test_crlf_untouched_sentence_is_byte_preserved(self) -> None:
        first = sent("s1", row("1", "one", "0", "root")).replace("\n", "\r\n")
        second = sent("s2", row("1", "tail", "0", "root")).replace("\n", "\r\n")
        self.file.write_bytes((first + second).encode())
        result = self.changed(tokens.token_form_set({**self.args, "form": "ONE"}))
        self.assertTrue(result.endswith(second))
        self.assertIn("\r\n", result)


    def test_sentence_edits_preserve_unselected_blocks(self) -> None:
        base = self.file.read_text()
        added = sent("new", row("1", "new", "0", "root"))
        result = self.changed(sentences.tree_add({**self.args, "file_path": "train.conllu", "insertion_point": "end", "sentence_conllu": added}))
        self.assertEqual(result, base + added)
        replaced = self.changed(sentences.tree_replace({**self.args, "sentence_conllu": sent("s1", row("1", "replacement", "0", "root"))}))
        self.assertIn("replacement", replaced)
        self.assertIn("tail", replaced)
        removed = self.changed(sentences.tree_remove(self.args))
        self.assertEqual(removed, sent("s2", row("1", "tail", "0", "root")))

    def test_copy_and_move_target_specific_documents(self) -> None:
        target = self.root / "target.conllu"
        target.write_text(sent("existing", row("1", "existing", "0", "root")), newline="")
        copied = sentences.tree_copy({**self.args, "target_file_path": "target.conllu", "new_sent_id": "copy", "insertion_point": "end"})
        self.assertEqual([c["file_path"] for c in copied["changes"]], ["target.conllu"])
        self.assertIn("# sent_id = copy", copied["changes"][0]["content"])
        moved = sentences.tree_move({**self.args, "target_file_path": "target.conllu", "insertion_point": "end"})
        self.assertEqual(len(moved["changes"]), 2)
        self.assertNotIn("# sent_id = s1", moved["changes"][0]["content"])
        self.assertIn("# sent_id = s1", moved["changes"][1]["content"])
        self.assertEqual(target.read_text(), sent("existing", row("1", "existing", "0", "root")))

    def test_identity_text_and_comment_edits(self) -> None:
        changed_id = self.changed(sentences.tree_id_set({**self.args, "new_sent_id": "new-id"}))
        self.assertIn("# sent_id = new-id", changed_id)
        text = self.changed(sentences.tree_text_set({**self.args, "text": "One two"}))
        self.assertIn("# text = One two", text)
        note = self.changed(sentences.tree_comment_set({**self.args, "comment_key": "note", "comment_value": "value"}))
        self.assertIn("# note = value", note)
        self.file.write_text(self.file.read_text().replace("# sent_id = s1\n", "# sent_id = s1\n# note = value\n"), newline="")
        removed = self.changed(sentences.tree_comment_remove({**self.args, "comment_key": "note"}))
        self.assertNotIn("# note =", removed)
        with self.assertRaisesRegex(ValueError, "already exists"):
            sentences.tree_id_set({**self.args, "new_sent_id": "s2"})

    def test_token_reads_and_field_setters(self) -> None:
        self.assertEqual(len(tokens.token_list(self.args)["tokens"]), 2)
        self.assertEqual(tokens.token_get(self.args)["token"]["form"], "one")
        for func, key, value, fragment in [
            (tokens.token_lemma_set, "lemma", "lemma", "\tone\tlemma\t"),
            (tokens.token_upos_set, "upos", "NOUN", "\tNOUN\t"),
            (tokens.token_xpos_set, "xpos", "NN", "\tNN\t"),
        ]:
            with self.subTest(key=key):
                self.assertIn(fragment, self.changed(func({**self.args, key: value})))
        feature = self.changed(tokens.token_feature_set({**self.args, "feature_name": "Case", "feature_values": ["Nom"]}))
        self.assertIn("Number=Sing|Case=Nom", feature)
        self.assertNotIn("Number=Sing", self.changed(tokens.token_feature_remove({**self.args, "feature_name": "Number"})))
        self.assertNotIn("SpaceAfter=No", self.changed(tokens.token_misc_remove({**self.args, "attribute_name": "SpaceAfter"})))

    def test_token_insertion_and_removal_remap_dependents(self) -> None:
        add = self.changed(tokens.token_add({**self.args, "insertion_point": {"after_word_id": "1"}, "token_data": {"form": "new"}, "attachment_spec": {"head_id": "1", "deprel": "dep"}}))
        self.assertIn("2\tnew\t_\t_\t_\t_\t1\tdep", add)
        self.assertIn("3\ttwo\t_\tX\t_\t_\t1\tobj", add)
        ref2 = {"tree_ref": self.args["tree_ref"], "token_id": "2"}
        removed = self.changed(tokens.token_remove({**self.args, "token_ref": ref2, "removal_spec": {}}))
        self.assertNotIn("two", removed)
        self.assertIn("one", removed)
        with self.assertRaisesRegex(ValueError, "dependent"):
            tokens.token_remove({**self.args, "removal_spec": {}})

    def test_broad_metadata_graph_and_tree_edit(self) -> None:
        self.assertIn("# note = x", self.changed(edit_batch.tree_metadata_edit({**self.args, "metadata_patch": {"note": "x"}})))
        graph = self.changed(edit_batch.enhanced_graph_edit({**self.args, "edge_operations": [{"action": "add", "dependent_id": "2", "head_id": "0", "deprel": "root"}]}))
        self.assertIn("1:obj|0:root", graph)
        edit = self.changed(edit_batch.tree_edit({**self.args, "edit_operations": [{"operation": "tree_metadata_edit", "metadata_patch": {"note": "x"}}]}))
        self.assertIn("# note = x", edit)

    def test_dependency_label_and_focused_edge_changes(self) -> None:
        ref2 = {"tree_ref": self.args["tree_ref"], "token_id": "2"}
        relabeled = self.changed(dependencies.basic_dependency_label_set({**self.args, "token_ref": ref2, "deprel": "nsubj"}))
        self.assertIn("\t1\tnsubj\t", relabeled)
        changed = self.changed(dependencies.basic_dependency_set({**self.args, "token_ref": ref2, "head_id": "1", "deprel": "obl"}))
        self.assertIn("\t1\tobl\t", changed)
        add = self.changed(dependencies.enhanced_edge_add({**self.args, "dependent_id": "2", "head_id": "0", "deprel": "root"}))
        self.assertIn("1:obj|0:root", add)
        remove = self.changed(dependencies.enhanced_edge_remove({**self.args, "dependent_id": "2", "head_id": "1", "deprel": "obj"}))
        self.assertNotIn("1:obj", remove)

    def test_multiword_and_empty_node_edits(self) -> None:
        added = self.changed(special_rows.multiword_token_add({**self.args, "first_word_id": "1", "last_word_id": "2", "form": "onetwo", "misc_entries": {}}))
        self.assertIn("1-2\tonetwo", added)
        self.file.write_text(added, newline="")
        edited = self.changed(special_rows.multiword_token_edit({**self.args, "range_id": "1-2", "multiword_token_patch": {"form": "one-two"}}))
        self.assertIn("1-2\tone-two", edited)
        empty = self.changed(special_rows.empty_node_add({**self.args, "after_word_id": "1", "empty_node_data": {"form": "elided"}, "enhanced_edges": [{"head_id": "1", "deprel": "dep"}]}))
        self.assertIn("1.1\telided", empty)
        self.file.write_text(empty, newline="")
        changed = self.changed(special_rows.empty_node_edit({**self.args, "empty_node_id": "1.1", "empty_node_patch": {"lemma": "hidden"}}))
        self.assertIn("1.1\telided\thidden", changed)
        removed = self.changed(special_rows.empty_node_remove({**self.args, "empty_node_id": "1.1", "incident_edge_policy": "remove"}))
        self.assertNotIn("1.1\telided", removed)

    def test_misc_opaque_entries_survive_focused_update(self) -> None:
        self.file.write_text(self.file.read_text().replace("SpaceAfter=No", "SpaceAfter=No|OpaqueFlag"), newline="")
        changed = self.changed(tokens.token_misc_set({**self.args, "attribute_name": "Note", "attribute_values": ["x"]}))
        self.assertIn("SpaceAfter=No|OpaqueFlag|Note=x", changed)

    def test_explicit_empty_node_decimal_order_is_numeric(self) -> None:
        self.file.write_text(sent("s1", row("1", "one", "0", "root") + "1.10\tx\t_\tX\t_\t_\t_\t_\t1:dep\t_\n"), newline="")
        changed = self.changed(special_rows.empty_node_add({**self.args, "after_word_id": "1", "empty_node_data": {"id": "1.2", "form": "new"}, "enhanced_edges": [{"head_id": "1", "deprel": "dep"}]}))
        self.assertLess(changed.index("1.2\t"), changed.index("1.10\t"))

    def test_reference_mismatch_cannot_edit_another_tree(self) -> None:
        other = {"tree_ref": {"file_path": "train.conllu", "sent_id": "s2"}, "token_id": "1"}
        with self.assertRaisesRegex(ValueError, "different sentences"):
            tokens.token_form_set({**self.args, "token_ref": other, "form": "oops"})

    def test_candidate_generation_is_repeatable_and_apply_never_writes(self) -> None:
        before = self.file.read_bytes()
        request = {**self.args, "form": "changed", "edit_options": {"mode": "apply", "expected_file_sha256": hashlib.sha256(before).hexdigest()}}
        first = tokens.token_form_set(request)
        self.assertEqual(first, tokens.token_form_set(request))
        self.assertEqual(before, self.file.read_bytes())

    def test_structural_unresolved_and_unrelated_rewrite_are_rejected(self) -> None:
        self.file.write_text(sent("s1", row("1", "a", "0", "root") + row("2", "b", "1", "dep")), newline="")
        target = sent("a", row("1", "altered", "0", "root")) + sent("b", row("1", "b", "0", "root"))
        a, b = target.split("\n\n", 1)
        amap = self.annotation({"s1#1": ["a#1"], "s1#2": ["b#1"]}, [("a", a + "\n\n"), ("b", b)])
        amap["unresolved"] = ["choose syntax"]
        unresolved = structural.tree_split({**self.args, "split_boundaries": [1], "new_sent_ids": ["a", "b"], "annotation_map": amap})
        self.assertEqual(unresolved["status"], "needs_annotation")
        amap["unresolved"] = []
        with self.assertRaisesRegex(ValueError, "same form"):
            structural.tree_split({**self.args, "split_boundaries": [1], "new_sent_ids": ["a", "b"], "annotation_map": amap})


if __name__ == "__main__":
    unittest.main()
