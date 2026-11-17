"""Independent valid-input and expected-behavior cases for the 102-tool API.

These are deterministic domain tests. Runtime/provider, project-code isolation,
and final-browser acceptance remain separate end-to-end suites.
"""
from __future__ import annotations

import base64
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch

from graph_fixture import graph_fixture

from ud_agent import wire
from ud_agent.domain import release
from ud_agent.evidence import broker_evidence


SAMPLE = "# sent_id = a\n# text = Birds fly\n1\tBirds\tbird\tNOUN\tNN\t_\t2\tnsubj\t2:nsubj\t_\n2\tfly\tfly\tVERB\tVB\t_\t0\troot\t0:root\t_\n\n"


def hashed(data):
    return hashlib.sha256(data).hexdigest()


def make_cases(root: Path, *, prepare_context=None):
    def put(name, content):
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return name
    def js(name, value):
        return put(name, json.dumps(value, ensure_ascii=False))
    put("main.conllu", SAMPLE)
    put("annotation.conllu", SAMPLE.replace("Birds\tbird", "Birds\tavian"))
    put("special.conllu", SAMPLE.replace("1\tBirds", "1-2\tBirdsfly\t_\t_\t_\t_\t_\t_\t_\t_\n1\tBirds").replace("\n\n", "\n2.1\tghost\tghost\tX\t_\t_\t_\t_\t2:dep\t_\n\n"))
    put("noncontiguous.conllu", SAMPLE.replace("2\tnsubj", "4\tnsubj").replace("2:nsubj", "4:nsubj").replace("\n2\tfly", "\n4\tfly"))
    put("missing-blank.conllu", SAMPLE.rstrip("\n") + "\n")
    put("peer/peer.conllu", SAMPLE.replace("sent_id = a", "sent_id = peer"))
    put("bible.conllu", SAMPLE.replace("sent_id = a", "sent_id = MAT_1_1"))
    put("bible-peer.conllu", SAMPLE.replace("sent_id = a", "sent_id = MAT_1_1_peer"))
    put("proper.conllu", SAMPLE.replace("\tNOUN\t", "\tPROPN\t"))
    put("relative.conllu", SAMPLE.replace("\tnsubj\t", "\tacl:relcl\t"))
    put("words.conllu", SAMPLE.replace("1\tBirds\tbird", "1\tBird\tbird").replace("2\tfly\tfly", "2\ts\ts"))
    put("two-sentences.conllu", SAMPLE + SAMPLE.replace("sent_id = a", "sent_id = b"))
    put("text.txt", "Birds fly")
    put("template/seed.txt", "{{treebank_name}} {{language_code}}\n")
    js("create-metadata.json", {"treebank_name": "Example", "language_code": "en"})
    put("LICENSE", "MIT\n")
    put("README.md", "# Example\n\n```conllu\n" + SAMPLE + "```\n\n=== Machine-readable metadata ===\nLemmas: manual native\nUPOS: manual native\nFeatures: manual native\nRelations: manual native\nGenre: news\nIncludes text: yes\nContact: old@example.org\n===\n")
    put("example.md", "```conllu\n" + SAMPLE + "```\n")
    js("metadata.json", {"Contact": "new@example.org"})
    js("identity.json", {"old_name": "main", "new_name": "renamed"})
    js("split.json", {"splits": {"train": 1}})
    js("selection.json", {"sentences": [{"file_path": "main.conllu", "sent_id": "a"}]})
    js("collapse.json", {"mode": "drop", "allow_information_loss": True})
    js("maintenance.json", {"required_files": ["LICENSE"]})
    js("alignment.json", {"alignments": [{"source": {"treebank": ".", "file_path": "main.conllu", "sent_id": "a"}, "targets": [{"treebank": "peer", "file_path": "peer.conllu", "sent_id": "peer"}]}]})
    put("change.patch", "--- a/main.conllu\n+++ b/main.conllu\n@@ -1,3 +1,3 @@\n # sent_id = a\n # text = Birds fly\n-1\tBirds\tbird\tNOUN\tNN\t_\t2\tnsubj\t2:nsubj\t_\n+1\tBirds\tavian\tNOUN\tNN\t_\t2\tnsubj\t2:nsubj\t_\n")
    rules = {"upos": {"upos": ["NOUN", "VERB", "X", "PROPN"]}, "feats": {"features": {}},
             "udeprels": {"udeprels": ["root", "nsubj", "obj", "dep", "advmod"]}, "deprels": {"deprels": {}},
             "edeprels": {"edeprels": {}}, "data": {"auxiliaries": {}}, "tospace": {"expressions": {}}}
    for name, value in rules.items():
        js("rules/" + name + ".json", value)
        js("proposed/" + name + ".json", value if name != "upos" else {"upos": ["NOUN", "VERB", "X", "PROPN", "ADJ"]})
    if prepare_context is None:
        js("context.json", {"rule_dir": "rules"})
    else:
        prepare_context(root)
    context = str(root / "context.json")
    base = {"working_tree_path": str(root), "file_paths": ["main.conllu"], "ud_context_path": context}
    ref = {"file_path": "main.conllu", "sent_id": "a"}
    token = {"tree_ref": ref, "token_id": "1"}
    edit = {**base, "tree_ref": ref, "token_ref": token}
    cases = []
    def add(name, extra, checks, negative, **metadata):
        cases.append({"operation": name, "arguments": {**base, **extra}, "checks": checks, "negative_field": negative, **metadata})
    def candidate(name, extra, check=None):
        checks = {"status": "candidate", "requested_mode": "preview"}
        if check:
            checks.update(check)
        add(name, {**edit, **extra}, checks, "status")
    add("treebank_create", {"template_path": "template", "metadata_path": "create-metadata.json"}, {"status": "candidate", "changes.0.file_path": "seed.txt"}, "status")
    add("workspace_inspect", {"related_repository_paths": ["peer"]}, {"related_repository_paths": ["peer"]}, "files")
    add("workspace_sync_plan", {"repository_specs": [{"path": "peer", "local_revision": "abc", "remote_snapshot": {"revision": "abc", "retrieved_at": datetime.now(timezone.utc).isoformat()}}]}, {"status": "complete", "repositories.0.status": "matching_snapshots"}, "repositories")
    add("treebank_snapshot", {"output_dir_path": "/out"}, {"status": "complete", "manifest.0.sha256": hashed(SAMPLE.encode())}, "manifest")
    prior = SAMPLE.replace("Birds", "Swallows")
    js(".ud-agent-inputs/base.json", {"revision": "base", "files": {"main.conllu": {"content": prior, "sha256": hashed(prior.encode())}}})
    put(".ud-agent-inputs/base/main.conllu", prior)
    evidence = {"schema_version": 1, "snapshot_sha256": "f" * 64, "git_base": {"requested_revision": "base", "resolved_commit": "a" * 40, "tree_oid": "b" * 40,
                "files": {"main.conllu": {"sha256": hashed(prior.encode()), "size_bytes": len(prior.encode()), "blob_oid": "c" * 40}},
                "base_directory_path": ".ud-agent-inputs/base", "base_snapshot_path": ".ud-agent-inputs/base.json", "base_snapshot_sha256": hashed((root / ".ud-agent-inputs/base.json").read_bytes())}}
    add("treebank_review", {"base_revision": "base", "peer_treebank_paths": []}, {"status": "complete", "changes.0.kind": "modified"}, "status", evidence=evidence)
    candidate("treebank_edit", {"edit_batch": [{"operation": "token_form_set", "arguments": {"token_ref": token, "form": "Swallows"}}]}, {"details.operations.0.operation": "token_form_set"})
    candidate("tree_edit", {"edit_operations": [{"operation": "token_lemma_set", "arguments": {"token_ref": token, "lemma": "avian"}}]}, {"details.operations.0.operation": "token_lemma_set"})
    candidate("token_edit", {"token_patch": {"lemma": "avian"}}, {"details.token.lemma": "avian"})
    candidate("tree_metadata_edit", {"metadata_patch": {"text": "Swallows fly"}}, {"details.metadata_fields": ["text"]})
    candidate("enhanced_graph_edit", {"edge_operations": [{"action": "add", "dependent_id": "1", "head_id": "0", "deprel": "dep"}]}, {"details.edges.0.dependent_id": "1"})
    add("tree_list", {}, {"trees.0.sent_id": "a", "trees.0.text": "Birds fly"}, "trees")
    add("tree_get", {"tree_ref": ref}, {"conllu": SAMPLE, "ordinal": 0}, "conllu")
    candidate("tree_add", {"file_path": "main.conllu", "sentence_conllu": SAMPLE.replace("sent_id = a", "sent_id = new"), "insertion_point": "end"}, {"details.inserted_ordinal": 1})
    candidate("tree_replace", {"sentence_conllu": SAMPLE.replace("Birds", "Swallows")}, {"details.replaced_ordinal": 0})
    candidate("tree_remove", {}, {"details.removed_ordinal": 0})
    candidate("tree_copy", {"target_file_path": "main.conllu", "new_sent_id": "copy", "insertion_point": "end"}, {"details.target_ordinal": 1})
    candidate("tree_move", {"target_file_path": "peer/peer.conllu", "insertion_point": "end"}, {"details.target_ordinal": 1})
    candidate("tree_id_set", {"new_sent_id": "new"}, {"details.sent_id": "new"})
    candidate("tree_text_set", {"text": "Swallows fly"}, {"details.text": "Swallows fly"})
    candidate("tree_comment_set", {"comment_key": "source", "comment_value": "fixture"})
    candidate("tree_comment_remove", {"comment_key": "text"})
    add("token_list", {"tree_ref": ref}, {"tokens.0.form": "Birds", "tokens.1.form": "fly"}, "tokens")
    add("token_get", {"token_ref": token}, {"token.id": "1", "token.lemma": "bird"}, "token")
    candidate("token_add", {"token_data": {"form": "today", "upos": "NOUN"}, "attachment_spec": {"head_id": "2", "deprel": "obl"}, "insertion_point": 3}, {"details.token_id": "3"})
    candidate("token_remove", {"removal_spec": {"dependent_heads": {}, "enhanced_edges": "remove", "multiword_tokens": "remove"}}, {"details.removed_token_id": "1"})
    setters = [("token_form_set", "form", "Swallows", "form"), ("token_lemma_set", "lemma", "avian", "lemma"),
               ("token_upos_set", "upos", "PROPN", "upos"), ("token_xpos_set", "xpos", "NNP", "xpos"),
               ("token_features_replace", "features", {"Number": "Plur"}, "feats"), ("token_misc_replace", "misc_entries", {"SpaceAfter": "No"}, "misc")]
    for name, parameter, value, column in setters:
        expected = "Number=Plur" if column == "feats" else "SpaceAfter=No" if column == "misc" else value
        candidate(name, {parameter: value}, {"details.token." + column: expected})
    candidate("token_feature_set", {"feature_name": "Number", "feature_values": ["Plur"]}, {"details.token.feats": "Number=Plur"})
    candidate("token_feature_remove", {"feature_name": "Number"}, {"details.token.feats": "_"})
    candidate("token_misc_set", {"attribute_name": "SpaceAfter", "attribute_values": ["No"]}, {"details.token.misc": "SpaceAfter=No"})
    candidate("token_misc_remove", {"attribute_name": "SpaceAfter"}, {"details.token.misc": "_"})
    candidate("basic_dependency_set", {"head_id": "2", "deprel": "obj"}, {"details.head_id": "2", "details.deprel": "obj"})
    candidate("basic_dependency_label_set", {"deprel": "obj"}, {"details.deprel": "obj"})
    candidate("enhanced_edge_add", {"dependent_id": "1", "head_id": "0", "deprel": "dep"}, {"details.edges.1.head_id": "0"})
    candidate("enhanced_edge_remove", {"dependent_id": "1", "head_id": "2", "deprel": "nsubj"}, {"details.edges": []})
    candidate("enhanced_dependencies_replace", {"dependent_id": "1", "incoming_edges": [{"head_id": "0", "deprel": "dep"}]}, {"details.edges.0.head_id": "0"})
    candidate("multiword_token_add", {"first_word_id": "1", "last_word_id": "2", "form": "Birdsfly", "misc_entries": {}}, {"details.range_id": "1-2"})
    special = {"tree_ref": {"file_path": "special.conllu", "sent_id": "a"}}
    candidate("multiword_token_edit", {**special, "token_ref": {"tree_ref": special["tree_ref"], "token_id": "1"}, "range_id": "1-2", "multiword_token_patch": {"form": "Birds fly"}}, {"details.range_id": "1-2"})
    candidate("multiword_token_remove", {**special, "token_ref": {"tree_ref": special["tree_ref"], "token_id": "1"}, "range_id": "1-2"}, {"details.removed_range_id": "1-2"})
    candidate("empty_node_add", {"after_word_id": "2", "empty_node_data": {"form": "ghost", "upos": "X"}, "enhanced_edges": [{"head_id": "2", "deprel": "dep"}]}, {"details.empty_node_id": "2.1"})
    candidate("empty_node_edit", {**special, "token_ref": {"tree_ref": special["tree_ref"], "token_id": "1"}, "empty_node_id": "2.1", "empty_node_patch": {"form": "silent"}}, {"details.empty_node_id": "2.1"})
    candidate("empty_node_remove", {**special, "token_ref": {"tree_ref": special["tree_ref"], "token_id": "1"}, "empty_node_id": "2.1", "incident_edge_policy": "remove"}, {"details.removed_empty_node_id": "2.1"})
    candidate("tree_reindex", {"tree_ref": {"file_path": "noncontiguous.conllu", "sent_id": "a"}, "token_ref": {"tree_ref": {"file_path": "noncontiguous.conllu", "sent_id": "a"}, "token_id": "1"}}, {"details.id_mapping.4": "2"})
    validation_options = {"language_code": "ud", "level": 2}
    add("validation_report", {"options": validation_options}, {"passed": True, "coverage.content": "completed"}, "passed")
    add("sentence_validation_report", {"sentence_conllu": SAMPLE, "language_code": "ud", "options": validation_options}, {"passed": True, "scope.sentence_only": True}, "passed")
    official = {"passed": False, "incidents": [{"testid": "official-fixture"}], "scope": {"file_paths": ["main.conllu"], "sentence_only": False}, "coverage": {"content": "completed"}, "limitations": []}
    custom = {**official, "passed": True, "incidents": [], "provenance": {"validator_module_path": "project.py", "validator_class_name": "Project", "source_sha256": hashed(b"from udtools import Validator\nclass Project(Validator): pass\n")}}
    put("project.py", "from udtools import Validator\nclass Project(Validator): pass\n")
    add("project_consistency_report", {"validator_module_path": "project.py", "validator_class_name": "Project", "options": validation_options}, {"passed": False, "official.passed": False, "project.passed": True}, "official", child_reports=[official, custom])
    add("fix_plan", {"file_paths": ["missing-blank.conllu"], "fix_ids": ["final_blank_line"]}, {"plan_type": "mechanical_fix", "actions.0.type": "replace_file"}, "actions")
    fixed = SAMPLE.replace("Birds", "Swallows")
    js("apply.json", {"schema_version": "ud-plan-v1", "actions": [{"id": "replace", "type": "replace_file", "file_path": "main.conllu", "before_sha256": hashed(SAMPLE.encode()), "after_sha256": hashed(fixed.encode()), "content": fixed, "depends_on": []}]})
    add("plan_apply", {"plan_path": "apply.json", "selected_action_ids": ["replace"]}, {"status": "candidate", "changes.0.content": fixed}, "status")
    add("annotation_import_plan", {"source_annotation_paths": ["annotation.conllu"], "target_file_paths": ["main.conllu"], "columns": ["LEMMA"]}, {"plan_type": "annotation_import", "actions.0.type": "replace_file"}, "actions")
    add("token_alignment_report", {"source_file_paths": ["main.conllu"], "target_file_paths": ["annotation.conllu"]}, {"source_count": 2, "exact_matches": 2}, "segments")
    add("tokenization_change_plan", {"source_tokenization_paths": ["words.conllu"], "target_file_paths": ["main.conllu"]}, {"status": "needs_annotation", "actions.0.requires_annotation_map": True}, "actions")
    add("sentence_segmentation_change_plan", {"source_segmentation_paths": ["main.conllu"], "target_file_paths": ["main.conllu"]}, {"status": "ready", "actions": []}, "actions")
    add("text_content_compare", {"left_path": "text.txt", "right_path": "text.txt", "left_format": "text", "right_format": "text"}, {"equal": True, "left_length": 9}, "equal")
    add("sentence_batch_extract", {"selection_path": "selection.json", "output_dir_path": "/out"}, {"selected.0.sent_id": "a", "artifacts.0.content": SAMPLE}, "selected")
    add("dataset_split_plan", {"split_spec_path": "split.json", "seed": 7}, {"counts.train": 1, "actions.0.type": "create_file"}, "assignments")
    add("format_convert", {"input_paths": ["main.conllu"], "target_format": "text", "output_dir_path": "/out"}, {"artifacts.0.content": "Birds fly\n", "requires_host_export": True}, "losses")
    add("tagset_conversion_plan", {"source_tagset": "penn", "target_tagset": "ud", "options": {"mapping": {"NN": "NOUN", "VB": "VERB"}}}, {"status": "ready", "unmapped": []}, "actions")
    add("treebank_profile", {}, {"sentence_count": 1, "word_count": 2}, "word_count")
    add("lexeme_pos_report", {"lexeme_filter": {"lemma": "bird"}}, {"entries.0.lemma": "bird", "entries.0.count": 1}, "entries")
    add("observed_paradigms", {"paradigm_filter": {"lemma": "bird"}}, {"forms.0.form": "Birds", "forms.0.count": 1}, "forms")
    add("relation_profile", {"relation_filter": {"deprel": "nsubj"}}, {"denominator": 1, "relations.0.relation": "nsubj"}, "relations")
    add("feature_agreement_report", {"feature_name": "Number", "relation_filter": {}}, {"compared": 0, "skipped.missing_feature": 1}, "comparisons")
    add("dependency_order_profile", {}, {"orders.0.value": "before_head", "orders.0.count": 1}, "orders")
    add("multiword_token_patterns", {"file_paths": ["special.conllu"]}, {"patterns.0.form": "Birdsfly", "patterns.0.component_upos": ["NOUN", "VERB"]}, "patterns")
    add("proper_name_sequences", {"file_paths": ["proper.conllu"]}, {"sequences.0.forms": ["Birds"]}, "sequences")
    add("script_composition_report", {"peer_treebank_paths": ["peer"]}, {"corpora.0.scripts.0.value": "LATIN", "corpora.0.scripts.0.count": 8}, "corpora")
    add("english_relative_clause_classify", {"file_paths": ["relative.conllu"], "output_dir_path": "/out"}, {"clause_count": 1}, "clause_count")
    add("conventions_compare", {"dimensions": ["upos"], "peer_treebank_paths": ["peer"]}, {"corpora.0.dimensions.upos.NOUN": 1}, "corpora")
    add("feature_value_report", {"feature_name": "Number", "peer_treebank_paths": ["peer"]}, {"corpora.0.words": 2, "corpora.0.missing_feature": 2}, "corpora")
    put("duplicate.conllu", SAMPLE + SAMPLE.replace("sent_id = a", "sent_id = duplicate"))
    add("duplicate_report", {"file_paths": ["duplicate.conllu"]}, {"groups.0.text": "Birds fly"}, "groups")
    add("overlap_report", {"peer_treebank_paths": ["peer"], "split_spec_path": None}, {"matches.0.peer_treebank": "peer", "matches.0.text": "Birds fly"}, "matches")
    add("enhanced_graph_report", {}, {"sentences.0.graph_present": True, "sentences.0.unreachable_from_root": []}, "sentences")
    add("enhanced_edge_explanations", {"output_dir_path": "/out"}, {"edge_count": 2}, "edge_count")
    add("enhanced_empty_node_collapse_plan", {"file_paths": ["special.conllu"], "transformation_spec_path": "collapse.json"}, {"actions.0.type": "replace_file", "losses.0.empty_node_id": "2.1"}, "losses")
    add("parallel_corpus_report", {"peer_treebank_paths": ["peer"], "alignment_spec_path": "alignment.json"}, {"coverage.requested": 1, "coverage.complete": 1}, "alignments")
    add("bible_passage_concordance", {"file_paths": ["bible.conllu"], "peer_file_paths": ["bible-peer.conllu"]}, {"passages.0.book": "MAT", "passages.0.correspondence_complete": True}, "passages")
    add("predictions_evaluate", {"gold_file_paths": ["main.conllu"], "prediction_file_paths": ["annotation.conllu"]}, {"scores.LAS.correct": 2, "scores.LAS.f1": 1.0}, "scores")
    add("annotation_pair_scores", {"reference_annotation_path": "main.conllu", "comparison_annotation_path": "annotation.conllu"}, {"scores.UAS.correct": 2, "scores.UAS.f1": 1.0}, "scores")
    add("changes_review", {"base_revision": "base", "options": {"file_paths": ["main.conllu"]}}, {"coverage.base_identity_verified": True, "changes.0.change": "modified"}, "changes", evidence=evidence)
    add("contribution_plan", {"patch_path": "change.patch"}, {"actions.0.type": "replace_file", "plan_type": "contribution"}, "actions")
    add("language_rules_report", {"language_code": "ud", "peer_treebank_paths": []}, {"language_code": "ud", "rules.upos": ["NOUN", "VERB", "X", "PROPN"]}, "rules")
    add("language_rule_change_plan", {"language_code": "ud", "proposed_rules_path": "proposed"}, {"changed_files": ["upos.json"], "actions.0.type": "prepare_context"}, "actions")
    add("language_rule_impact_report", {"proposed_rules_path": "proposed", "affected_treebank_paths": ["peer"], "options": validation_options}, {"comparisons.0.before.passed": True, "comparisons.0.after.passed": True}, "comparisons")
    add("metadata_change_plan", {"proposed_metadata_path": "metadata.json"}, {"changes.0.field": "Contact", "changes.0.after": "new@example.org"}, "changes")
    add("documentation_preview", {"output_dir_path": "/out"}, {"status": "complete", "files.0.examples.0.word_count": 2}, "files")
    add("guideline_example_preview", {"example_markup_path": "example.md", "output_dir_path": "/out"}, {"status": "complete", "examples.0.word_count": 2}, "examples")
    add("sentence_render", {"sentence_conllu": SAMPLE, "output_format": "svg", "output_path": "/out/sentence.svg"}, {"status": "complete", "artifacts.0.mime_type": "image/svg+xml"}, "artifacts")
    release_args = {**base, "target_release": "2.0", "options": {"language_code": "ud", "file_paths": ["main.conllu", "LICENSE", "README.md"]}}
    release_plan = release.release_plan(release_args)
    js("release-plan.json", release_plan)
    release_candidate = release.release_candidate_build({**base, "release_plan_path": "release-plan.json", "output_dir_path": "/out"})
    put("candidate.tar", base64.b64decode(release_candidate["artifacts"][0]["content_base64"]))
    js("deposit.json", {"title": "Fixture", "license": "MIT"})
    add("release_plan", {"target_release": "2.0", "previous_release_path": None, "options": release_args["options"]}, {"status": "complete", "target_release": "2.0"}, "files")
    add("release_candidate_build", {"release_plan_path": "release-plan.json", "output_dir_path": "/out"}, {"status": "complete", "artifacts.0.relative_path": "release-candidate.tar"}, "manifest")
    add("release_deposit_prepare", {"release_candidate_path": "candidate.tar", "deposit_metadata_path": "deposit.json", "output_dir_path": "/out"}, {"status": "complete", "artifacts.0.relative_path": "deposit-preparation.json"}, "artifacts")
    add("maintenance_report", {"maintenance_policy_path": "maintenance.json"}, {"status": "complete", "passed": True}, "checks")
    add("handover_package_build", {"output_dir_path": "/out", "options": {"file_paths": ["main.conllu", "LICENSE"]}}, {"status": "complete", "artifacts.0.relative_path": "handover.tar"}, "manifest")
    add("treebank_rename_plan", {"new_identity_path": "identity.json", "related_repository_paths": []}, {"status": "complete", "new_name": "renamed"}, "actions")
    add("star_rating_report", {"options": {"language_code": "ud"}}, {"status": "complete", "word_count": 2, "weights.size": 10}, "stars")
    decisions = {key: "explicit" for key in ["basic", "enhanced", "surface", "metadata"]}
    split_target = SAMPLE.replace("1\tBirds\tbird\tNOUN\tNN\t_\t2\tnsubj\t2:nsubj\t_", "1\tBird\tbird\tNOUN\tNN\t_\t3\tnsubj\t3:nsubj\t_\n2\ts\t_\tX\t_\t_\t1\tdep\t1:dep\t_").replace("\n2\tfly", "\n3\tfly")
    split_map = {"id_mapping": {"a#1": ["a#1", "a#2"], "a#2": ["a#3"]}, "sentences": [{"sent_id": "a", "conllu": split_target}], "decisions": decisions}
    candidate("token_split", {"replacement_words": ["Bird", "s"], "annotation_map": split_map}, {"details.id_mapping.a#2": ["a#3"]})
    merged = "# sent_id = a\n# text = Birdsfly\n1\tBirdsfly\t_\tX\t_\t_\t0\troot\t0:root\t_\n\n"
    candidate("tokens_merge", {"token_ids": ["1", "2"], "merged_word": "Birdsfly", "annotation_map": {"id_mapping": {"a#1": ["a#1"], "a#2": ["a#1"]}, "sentences": [{"sent_id": "a", "conllu": merged}], "decisions": decisions}}, {"details.target_sentence_ids": ["a"]})
    left = "# sent_id = left\n1\tBirds\tbird\tNOUN\tNN\t_\t0\troot\t0:root\t_\n\n"
    right = "# sent_id = right\n1\tfly\tfly\tVERB\tVB\t_\t0\troot\t0:root\t_\n\n"
    candidate("tree_split", {"split_boundaries": ["1"], "new_sent_ids": ["left", "right"], "annotation_map": {"id_mapping": {"a#1": ["left#1"], "a#2": ["right#1"]}, "sentences": [{"sent_id": "left", "conllu": left}, {"sent_id": "right", "conllu": right}], "decisions": decisions}}, {"details.target_sentence_ids": ["left", "right"]})
    merged_two = SAMPLE.replace("sent_id = a", "sent_id = merged").replace("\n\n", "\n3\tBirds\tbird\tNOUN\tNN\t_\t4\tnsubj\t4:nsubj\t_\n4\tfly\tfly\tVERB\tVB\t_\t2\tparataxis\t2:parataxis\t_\n\n")
    merge_mapping = {"a#1": ["merged#1"], "a#2": ["merged#2"], "b#1": ["merged#3"], "b#2": ["merged#4"]}
    add("trees_merge", {"tree_refs": [{"file_path": "two-sentences.conllu", "sent_id": "a"}, {"file_path": "two-sentences.conllu", "sent_id": "b"}], "new_sent_id": "merged", "annotation_map": {"id_mapping": merge_mapping, "sentences": [{"sent_id": "merged", "conllu": merged_two}], "decisions": decisions}}, {"status": "candidate", "details.target_sentence_ids": ["merged"]}, "status")
    return cases


def execute_case(root, case):
    with tempfile.TemporaryDirectory(prefix="ud-operation-case-") as temporary:
        stage = Path(temporary).resolve(strict=True)
        shutil.copytree(root, stage, dirs_exist_ok=True)
        catalog = json.loads((Path(__file__).resolve().parents[3] / "contracts/ud-interfaces.json").read_text())
        allowed = {item["name"] for operation in catalog if operation["name"] == case["operation"] for item in operation["parameters"]}
        arguments = {name: value for name, value in case["arguments"].items() if name in allowed}
        explicit, directories = set(), set()
        def paths(value):
            if isinstance(value, str):
                if value.endswith(".conllu"):
                    explicit.add(value)
                elif value and not Path(value).is_absolute() and (stage / value).is_dir():
                    directories.add(value.rstrip("/"))
            elif isinstance(value, list):
                for item in value:
                    paths(item)
            elif isinstance(value, dict):
                for item in value.values():
                    paths(item)
        paths(arguments)
        for file in stage.rglob("*.conllu"):
            relative = file.relative_to(stage).as_posix()
            if (relative != "main.conllu" and relative not in explicit and not relative.startswith(".ud-agent-inputs/")
                    and not any(relative.startswith(directory + "/") for directory in directories)):
                file.unlink()
        arguments["working_tree_path"] = str(stage)
        return _execute_case(stage, case, arguments)


def _execute_case(root, case, arguments):
    evidence = broker_evidence(case["evidence"], "f" * 64) if "evidence" in case else nullcontext()
    child = patch("ud_agent.domain.validation._project_child", side_effect=case["child_reports"]) if "child_reports" in case else nullcontext()
    graph = graph_fixture() if case["operation"] == "enhanced_graph_report" else nullcontext()
    with evidence, child, graph:
        response = wire.process({"operation": case["operation"], "arguments": arguments})
    if response.get("error", {}).get("code") == "WORKER_FAILED":
        # An unexpected implementation exception remains an invalid mutation
        # outcome. Only the public, controlled failure contract is assertable.
        raise RuntimeError(case["operation"] + " encountered an unexpected worker failure")
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise AssertionError(f"{case['operation']} rejected its valid input: {response!r}")
    result = response["result"]
    for path, expected in case["checks"].items():
        actual = result
        for part in path.split("."):
            if isinstance(actual, list):
                if not part.isdecimal() or int(part) >= len(actual):
                    raise AssertionError(f"{case['operation']}/{path}: missing expected list entry {part}")
                actual = actual[int(part)]
            else:
                if not isinstance(actual, dict) or part not in actual:
                    raise AssertionError(f"{case['operation']}/{path}: missing expected result field {part}")
                actual = actual[part]
        if actual != expected:
            raise AssertionError(f"{case['operation']}/{path}: {actual!r} != {expected!r}")
    if (root / "main.conllu").read_bytes() != SAMPLE.encode("utf-8"):
        raise AssertionError(case["operation"] + " mutated the original staged file")
    return {"operation": case["operation"], "arguments": arguments, "negative_field": case["negative_field"], "result": result}


def run_cases():
    with tempfile.TemporaryDirectory(prefix="ud-operation-matrix-") as temporary:
        root = Path(temporary).resolve(strict=True)
        return [execute_case(root, case) for case in make_cases(root)]


if __name__ == "__main__":
    import sys
    try:
        print(json.dumps(run_cases(), ensure_ascii=False, allow_nan=False))
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise SystemExit(1)
