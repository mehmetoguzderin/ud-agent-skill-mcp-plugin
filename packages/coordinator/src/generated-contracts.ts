// Generated from contracts/ud-interfaces.json and shared contracts.
export type DomainOperationName = "treebank_create" | "workspace_inspect" | "workspace_sync_plan" | "treebank_snapshot" | "treebank_review" | "treebank_edit" | "tree_edit" | "token_edit" | "tree_metadata_edit" | "enhanced_graph_edit" | "tree_list" | "tree_get" | "tree_add" | "tree_replace" | "tree_remove" | "tree_copy" | "tree_move" | "tree_id_set" | "tree_text_set" | "tree_comment_set" | "tree_comment_remove" | "token_list" | "token_get" | "token_add" | "token_remove" | "token_form_set" | "token_lemma_set" | "token_upos_set" | "token_xpos_set" | "token_features_replace" | "token_feature_set" | "token_feature_remove" | "token_misc_replace" | "token_misc_set" | "token_misc_remove" | "basic_dependency_set" | "basic_dependency_label_set" | "enhanced_edge_add" | "enhanced_edge_remove" | "enhanced_dependencies_replace" | "multiword_token_add" | "multiword_token_edit" | "multiword_token_remove" | "empty_node_add" | "empty_node_edit" | "empty_node_remove" | "tree_reindex" | "validation_report" | "sentence_validation_report" | "project_consistency_report" | "fix_plan" | "plan_apply" | "annotation_import_plan" | "token_alignment_report" | "tokenization_change_plan" | "sentence_segmentation_change_plan" | "text_content_compare" | "sentence_batch_extract" | "dataset_split_plan" | "format_convert" | "tagset_conversion_plan" | "treebank_profile" | "lexeme_pos_report" | "observed_paradigms" | "relation_profile" | "feature_agreement_report" | "dependency_order_profile" | "multiword_token_patterns" | "proper_name_sequences" | "script_composition_report" | "english_relative_clause_classify" | "conventions_compare" | "feature_value_report" | "duplicate_report" | "overlap_report" | "enhanced_graph_report" | "enhanced_edge_explanations" | "enhanced_empty_node_collapse_plan" | "parallel_corpus_report" | "bible_passage_concordance" | "predictions_evaluate" | "annotation_pair_scores" | "changes_review" | "contribution_plan" | "language_rules_report" | "language_rule_change_plan" | "language_rule_impact_report" | "metadata_change_plan" | "documentation_preview" | "guideline_example_preview" | "sentence_render" | "release_plan" | "release_candidate_build" | "release_deposit_prepare" | "maintenance_report" | "handover_package_build" | "treebank_rename_plan" | "star_rating_report" | "token_split" | "tokens_merge" | "tree_split" | "trees_merge";
export const domainMetadata = [
  {
    "id": "001",
    "name": "treebank_create",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.workspace:treebank_create",
    "output_schema": "contracts/schema/results/treebank_create.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "002",
    "name": "workspace_inspect",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.workspace:workspace_inspect",
    "output_schema": "contracts/schema/results/workspace_inspect.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "003",
    "name": "workspace_sync_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.workspace:workspace_sync_plan",
    "output_schema": "contracts/schema/results/workspace_sync_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "004",
    "name": "treebank_snapshot",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.workspace:treebank_snapshot",
    "output_schema": "contracts/schema/results/treebank_snapshot.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "005",
    "name": "treebank_review",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.workspace:treebank_review",
    "output_schema": "contracts/schema/results/treebank_review.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "006",
    "name": "treebank_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.edit_batch:treebank_edit",
    "output_schema": "contracts/schema/results/treebank_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "007",
    "name": "tree_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.edit_batch:tree_edit",
    "output_schema": "contracts/schema/results/tree_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "008",
    "name": "token_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.edit_batch:token_edit",
    "output_schema": "contracts/schema/results/token_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "009",
    "name": "tree_metadata_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.edit_batch:tree_metadata_edit",
    "output_schema": "contracts/schema/results/tree_metadata_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "010",
    "name": "enhanced_graph_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.edit_batch:enhanced_graph_edit",
    "output_schema": "contracts/schema/results/enhanced_graph_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "011",
    "name": "tree_list",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_list",
    "output_schema": "contracts/schema/results/tree_list.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "012",
    "name": "tree_get",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_get",
    "output_schema": "contracts/schema/results/tree_get.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "013",
    "name": "tree_add",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_add",
    "output_schema": "contracts/schema/results/tree_add.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "014",
    "name": "tree_replace",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_replace",
    "output_schema": "contracts/schema/results/tree_replace.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "015",
    "name": "tree_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_remove",
    "output_schema": "contracts/schema/results/tree_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "016",
    "name": "tree_copy",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_copy",
    "output_schema": "contracts/schema/results/tree_copy.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "017",
    "name": "tree_move",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_move",
    "output_schema": "contracts/schema/results/tree_move.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "018",
    "name": "tree_id_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_id_set",
    "output_schema": "contracts/schema/results/tree_id_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "019",
    "name": "tree_text_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_text_set",
    "output_schema": "contracts/schema/results/tree_text_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "020",
    "name": "tree_comment_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_comment_set",
    "output_schema": "contracts/schema/results/tree_comment_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "021",
    "name": "tree_comment_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.sentences:tree_comment_remove",
    "output_schema": "contracts/schema/results/tree_comment_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "022",
    "name": "token_list",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_list",
    "output_schema": "contracts/schema/results/token_list.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "023",
    "name": "token_get",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_get",
    "output_schema": "contracts/schema/results/token_get.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "024",
    "name": "token_add",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_add",
    "output_schema": "contracts/schema/results/token_add.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "025",
    "name": "token_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_remove",
    "output_schema": "contracts/schema/results/token_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "026",
    "name": "token_form_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_form_set",
    "output_schema": "contracts/schema/results/token_form_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "027",
    "name": "token_lemma_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_lemma_set",
    "output_schema": "contracts/schema/results/token_lemma_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "028",
    "name": "token_upos_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_upos_set",
    "output_schema": "contracts/schema/results/token_upos_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "029",
    "name": "token_xpos_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_xpos_set",
    "output_schema": "contracts/schema/results/token_xpos_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "030",
    "name": "token_features_replace",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_features_replace",
    "output_schema": "contracts/schema/results/token_features_replace.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "031",
    "name": "token_feature_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_feature_set",
    "output_schema": "contracts/schema/results/token_feature_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "032",
    "name": "token_feature_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_feature_remove",
    "output_schema": "contracts/schema/results/token_feature_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "033",
    "name": "token_misc_replace",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_misc_replace",
    "output_schema": "contracts/schema/results/token_misc_replace.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "034",
    "name": "token_misc_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_misc_set",
    "output_schema": "contracts/schema/results/token_misc_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "035",
    "name": "token_misc_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.tokens:token_misc_remove",
    "output_schema": "contracts/schema/results/token_misc_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "036",
    "name": "basic_dependency_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.dependencies:basic_dependency_set",
    "output_schema": "contracts/schema/results/basic_dependency_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "037",
    "name": "basic_dependency_label_set",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.dependencies:basic_dependency_label_set",
    "output_schema": "contracts/schema/results/basic_dependency_label_set.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "038",
    "name": "enhanced_edge_add",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.dependencies:enhanced_edge_add",
    "output_schema": "contracts/schema/results/enhanced_edge_add.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "039",
    "name": "enhanced_edge_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.dependencies:enhanced_edge_remove",
    "output_schema": "contracts/schema/results/enhanced_edge_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "040",
    "name": "enhanced_dependencies_replace",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.dependencies:enhanced_dependencies_replace",
    "output_schema": "contracts/schema/results/enhanced_dependencies_replace.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "041",
    "name": "multiword_token_add",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:multiword_token_add",
    "output_schema": "contracts/schema/results/multiword_token_add.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "042",
    "name": "multiword_token_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:multiword_token_edit",
    "output_schema": "contracts/schema/results/multiword_token_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "043",
    "name": "multiword_token_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:multiword_token_remove",
    "output_schema": "contracts/schema/results/multiword_token_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "044",
    "name": "empty_node_add",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:empty_node_add",
    "output_schema": "contracts/schema/results/empty_node_add.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "045",
    "name": "empty_node_edit",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:empty_node_edit",
    "output_schema": "contracts/schema/results/empty_node_edit.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "046",
    "name": "empty_node_remove",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:empty_node_remove",
    "output_schema": "contracts/schema/results/empty_node_remove.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "047",
    "name": "tree_reindex",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.special_rows:tree_reindex",
    "output_schema": "contracts/schema/results/tree_reindex.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "048",
    "name": "validation_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.validation:validation_report",
    "output_schema": "contracts/schema/results/validation_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "049",
    "name": "sentence_validation_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.validation:sentence_validation_report",
    "output_schema": "contracts/schema/results/sentence_validation_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "050",
    "name": "project_consistency_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.validation:project_consistency_report",
    "output_schema": "contracts/schema/results/project_consistency_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": true
    }
  },
  {
    "id": "051",
    "name": "fix_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.plans:fix_plan",
    "output_schema": "contracts/schema/results/fix_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "052",
    "name": "plan_apply",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.plans:plan_apply",
    "output_schema": "contracts/schema/results/plan_apply.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "053",
    "name": "annotation_import_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:annotation_import_plan",
    "output_schema": "contracts/schema/results/annotation_import_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "054",
    "name": "token_alignment_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:token_alignment_report",
    "output_schema": "contracts/schema/results/token_alignment_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "055",
    "name": "tokenization_change_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:tokenization_change_plan",
    "output_schema": "contracts/schema/results/tokenization_change_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "056",
    "name": "sentence_segmentation_change_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:sentence_segmentation_change_plan",
    "output_schema": "contracts/schema/results/sentence_segmentation_change_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "057",
    "name": "text_content_compare",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:text_content_compare",
    "output_schema": "contracts/schema/results/text_content_compare.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "058",
    "name": "sentence_batch_extract",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:sentence_batch_extract",
    "output_schema": "contracts/schema/results/sentence_batch_extract.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "059",
    "name": "dataset_split_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:dataset_split_plan",
    "output_schema": "contracts/schema/results/dataset_split_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "060",
    "name": "format_convert",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:format_convert",
    "output_schema": "contracts/schema/results/format_convert.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "061",
    "name": "tagset_conversion_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.conversion:tagset_conversion_plan",
    "output_schema": "contracts/schema/results/tagset_conversion_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "062",
    "name": "treebank_profile",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:treebank_profile",
    "output_schema": "contracts/schema/results/treebank_profile.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "063",
    "name": "lexeme_pos_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:lexeme_pos_report",
    "output_schema": "contracts/schema/results/lexeme_pos_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "064",
    "name": "observed_paradigms",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:observed_paradigms",
    "output_schema": "contracts/schema/results/observed_paradigms.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "065",
    "name": "relation_profile",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:relation_profile",
    "output_schema": "contracts/schema/results/relation_profile.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "066",
    "name": "feature_agreement_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:feature_agreement_report",
    "output_schema": "contracts/schema/results/feature_agreement_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "067",
    "name": "dependency_order_profile",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:dependency_order_profile",
    "output_schema": "contracts/schema/results/dependency_order_profile.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "068",
    "name": "multiword_token_patterns",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:multiword_token_patterns",
    "output_schema": "contracts/schema/results/multiword_token_patterns.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "069",
    "name": "proper_name_sequences",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:proper_name_sequences",
    "output_schema": "contracts/schema/results/proper_name_sequences.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "070",
    "name": "script_composition_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:script_composition_report",
    "output_schema": "contracts/schema/results/script_composition_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "071",
    "name": "english_relative_clause_classify",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.analysis:english_relative_clause_classify",
    "output_schema": "contracts/schema/results/english_relative_clause_classify.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "072",
    "name": "conventions_compare",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.comparison:conventions_compare",
    "output_schema": "contracts/schema/results/conventions_compare.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "073",
    "name": "feature_value_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.comparison:feature_value_report",
    "output_schema": "contracts/schema/results/feature_value_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "074",
    "name": "duplicate_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.comparison:duplicate_report",
    "output_schema": "contracts/schema/results/duplicate_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "075",
    "name": "overlap_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.comparison:overlap_report",
    "output_schema": "contracts/schema/results/overlap_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "076",
    "name": "enhanced_graph_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.enhanced:enhanced_graph_report",
    "output_schema": "contracts/schema/results/enhanced_graph_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "077",
    "name": "enhanced_edge_explanations",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.enhanced:enhanced_edge_explanations",
    "output_schema": "contracts/schema/results/enhanced_edge_explanations.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "078",
    "name": "enhanced_empty_node_collapse_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.enhanced:enhanced_empty_node_collapse_plan",
    "output_schema": "contracts/schema/results/enhanced_empty_node_collapse_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "079",
    "name": "parallel_corpus_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.parallel:parallel_corpus_report",
    "output_schema": "contracts/schema/results/parallel_corpus_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "080",
    "name": "bible_passage_concordance",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.parallel:bible_passage_concordance",
    "output_schema": "contracts/schema/results/bible_passage_concordance.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "081",
    "name": "predictions_evaluate",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.evaluation:predictions_evaluate",
    "output_schema": "contracts/schema/results/predictions_evaluate.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "082",
    "name": "annotation_pair_scores",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.evaluation:annotation_pair_scores",
    "output_schema": "contracts/schema/results/annotation_pair_scores.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "083",
    "name": "changes_review",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.review:changes_review",
    "output_schema": "contracts/schema/results/changes_review.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "084",
    "name": "contribution_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.review:contribution_plan",
    "output_schema": "contracts/schema/results/contribution_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "085",
    "name": "language_rules_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.rules:language_rules_report",
    "output_schema": "contracts/schema/results/language_rules_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "086",
    "name": "language_rule_change_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.rules:language_rule_change_plan",
    "output_schema": "contracts/schema/results/language_rule_change_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "087",
    "name": "language_rule_impact_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.rules:language_rule_impact_report",
    "output_schema": "contracts/schema/results/language_rule_impact_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "088",
    "name": "metadata_change_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.metadata:metadata_change_plan",
    "output_schema": "contracts/schema/results/metadata_change_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "089",
    "name": "documentation_preview",
    "runtime_pack": "render",
    "handler": "ud_agent.domain.rendering:documentation_preview",
    "output_schema": "contracts/schema/results/documentation_preview.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "090",
    "name": "guideline_example_preview",
    "runtime_pack": "render",
    "handler": "ud_agent.domain.rendering:guideline_example_preview",
    "output_schema": "contracts/schema/results/guideline_example_preview.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "091",
    "name": "sentence_render",
    "runtime_pack": "render",
    "handler": "ud_agent.domain.rendering:sentence_render",
    "output_schema": "contracts/schema/results/sentence_render.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "092",
    "name": "release_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.release:release_plan",
    "output_schema": "contracts/schema/results/release_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "093",
    "name": "release_candidate_build",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.release:release_candidate_build",
    "output_schema": "contracts/schema/results/release_candidate_build.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "094",
    "name": "release_deposit_prepare",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.release:release_deposit_prepare",
    "output_schema": "contracts/schema/results/release_deposit_prepare.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "095",
    "name": "maintenance_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.maintenance:maintenance_report",
    "output_schema": "contracts/schema/results/maintenance_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "096",
    "name": "handover_package_build",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.maintenance:handover_package_build",
    "output_schema": "contracts/schema/results/handover_package_build.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": true,
      "executes_project_code": false
    }
  },
  {
    "id": "097",
    "name": "treebank_rename_plan",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.maintenance:treebank_rename_plan",
    "output_schema": "contracts/schema/results/treebank_rename_plan.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "098",
    "name": "star_rating_report",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.maintenance:star_rating_report",
    "output_schema": "contracts/schema/results/star_rating_report.schema.json",
    "access": {
      "writes_workspace": false,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "099",
    "name": "token_split",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.structural:token_split",
    "output_schema": "contracts/schema/results/token_split.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "100",
    "name": "tokens_merge",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.structural:tokens_merge",
    "output_schema": "contracts/schema/results/tokens_merge.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "101",
    "name": "tree_split",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.structural:tree_split",
    "output_schema": "contracts/schema/results/tree_split.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  },
  {
    "id": "102",
    "name": "trees_merge",
    "runtime_pack": "core",
    "handler": "ud_agent.domain.structural:trees_merge",
    "output_schema": "contracts/schema/results/trees_merge.schema.json",
    "access": {
      "writes_workspace": true,
      "writes_outputs": false,
      "executes_project_code": false
    }
  }
] as const;
