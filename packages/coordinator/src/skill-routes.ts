/** Operation -> skills that document it (from quality/skills.json; a test guards drift). MIT.
 * Used only to point a rejected call back to the instructions that hold its exact arguments. */
const routes: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "annotation_import_plan": ["ud-edit"],
  "annotation_pair_scores": ["ud-compare"],
  "basic_dependency_label_set": ["ud-edit"],
  "basic_dependency_set": ["ud-edit"],
  "bible_passage_concordance": ["ud-investigate"],
  "changes_review": ["ud-compare"],
  "contribution_plan": ["ud-compare", "ud-release"],
  "conventions_compare": ["ud-compare", "ud-investigate"],
  "dataset_split_plan": ["ud-investigate"],
  "dependency_order_profile": ["ud-investigate"],
  "documentation_preview": ["ud-rules-docs"],
  "duplicate_report": ["ud-compare", "ud-investigate"],
  "empty_node_add": ["ud-edit"],
  "empty_node_edit": ["ud-edit"],
  "empty_node_remove": ["ud-edit"],
  "english_relative_clause_classify": ["ud-investigate"],
  "enhanced_dependencies_replace": ["ud-edit"],
  "enhanced_edge_add": ["ud-edit"],
  "enhanced_edge_explanations": ["ud-investigate"],
  "enhanced_edge_remove": ["ud-edit"],
  "enhanced_empty_node_collapse_plan": ["ud-investigate"],
  "enhanced_graph_edit": ["ud-edit"],
  "enhanced_graph_report": ["ud-investigate"],
  "feature_agreement_report": ["ud-investigate"],
  "feature_value_report": ["ud-compare", "ud-investigate"],
  "fix_plan": ["ud-validate"],
  "format_convert": ["ud-investigate"],
  "guideline_example_preview": ["ud-rules-docs"],
  "handover_package_build": ["ud-release"],
  "language_rule_change_plan": ["ud-rules-docs"],
  "language_rule_impact_report": ["ud-rules-docs"],
  "language_rules_report": ["ud-rules-docs"],
  "lexeme_pos_report": ["ud-investigate"],
  "maintenance_report": ["ud-release"],
  "metadata_change_plan": ["ud-rules-docs"],
  "multiword_token_add": ["ud-edit"],
  "multiword_token_edit": ["ud-edit"],
  "multiword_token_patterns": ["ud-investigate"],
  "multiword_token_remove": ["ud-edit"],
  "observed_paradigms": ["ud-investigate"],
  "overlap_report": ["ud-compare", "ud-investigate"],
  "parallel_corpus_report": ["ud-investigate"],
  "plan_apply": ["ud-edit", "ud-validate"],
  "predictions_evaluate": ["ud-compare"],
  "project_consistency_report": ["ud-validate"],
  "proper_name_sequences": ["ud-investigate"],
  "relation_profile": ["ud-investigate"],
  "release_candidate_build": ["ud-release"],
  "release_deposit_prepare": ["ud-release"],
  "release_plan": ["ud-release"],
  "script_composition_report": ["ud-investigate"],
  "sentence_batch_extract": ["ud-investigate"],
  "sentence_render": ["ud-rules-docs"],
  "sentence_segmentation_change_plan": ["ud-edit"],
  "sentence_validation_report": ["ud-validate"],
  "star_rating_report": ["ud-release"],
  "tagset_conversion_plan": ["ud-edit", "ud-investigate"],
  "text_content_compare": ["ud-investigate"],
  "token_add": ["ud-edit"],
  "token_alignment_report": ["ud-investigate"],
  "token_edit": ["ud-edit"],
  "token_feature_remove": ["ud-edit"],
  "token_feature_set": ["ud-edit"],
  "token_features_replace": ["ud-edit"],
  "token_form_set": ["ud-edit"],
  "token_get": ["ud-edit"],
  "token_lemma_set": ["ud-edit"],
  "token_list": ["ud-edit"],
  "token_misc_remove": ["ud-edit"],
  "token_misc_replace": ["ud-edit"],
  "token_misc_set": ["ud-edit"],
  "token_remove": ["ud-edit"],
  "token_split": ["ud-edit"],
  "token_upos_set": ["ud-edit"],
  "token_xpos_set": ["ud-edit"],
  "tokenization_change_plan": ["ud-edit"],
  "tokens_merge": ["ud-edit"],
  "tree_add": ["ud-edit"],
  "tree_comment_remove": ["ud-edit"],
  "tree_comment_set": ["ud-edit"],
  "tree_copy": ["ud-edit"],
  "tree_edit": ["ud-edit"],
  "tree_get": ["ud-edit"],
  "tree_id_set": ["ud-edit"],
  "tree_list": ["ud-edit"],
  "tree_metadata_edit": ["ud-edit"],
  "tree_move": ["ud-edit"],
  "tree_reindex": ["ud-edit"],
  "tree_remove": ["ud-edit"],
  "tree_replace": ["ud-edit"],
  "tree_split": ["ud-edit"],
  "tree_text_set": ["ud-edit"],
  "treebank_create": ["ud-release"],
  "treebank_edit": ["ud-edit"],
  "treebank_profile": ["ud-investigate"],
  "treebank_rename_plan": ["ud-release"],
  "treebank_review": ["ud-validate"],
  "treebank_snapshot": ["ud-release"],
  "trees_merge": ["ud-edit"],
  "validation_report": ["ud-validate"],
  "workspace_inspect": ["ud-validate"],
  "workspace_sync_plan": ["ud-release"],
});

export function skillsForOperation(operation: string): readonly string[] {
  return routes[operation] ?? [];
}

/** One short pointer for a rejected call; skill names are instructions, never tool names. */
export function rejectionGuidance(operation: string): string | undefined {
  const skills = skillsForOperation(operation);
  if (!skills.length) return undefined;
  return `Exact arguments for ${operation} are in the ${skills.join(' or ')} skill instructions; load ${skills.length > 1 ? 'one' : 'it'} with the skill loader (not as a tool), then retry.`;
}

export const SKILL_ROUTES = routes;

/**
 * A skill or operation name typed as a CLI command (`ud-agent ud-validate`, or a shell alias for it) is
 * answered with the exact next command instead of a bare "Unknown command". `skillFile` is the skill's
 * SKILL.md as the caller should read it; `describes` is the operation its description names.
 */
export function commandGuidance(command: string, options: { operations: readonly string[]; arguments?: readonly string[]; skillFile?: (skill: string) => string | undefined; describes?: (skill: string) => string | undefined }): string | undefined {
  const skills = [...new Set(Object.values(routes).flat())];
  // Named files that are all non-CoNLL-U (report.txt) mean no UD skill applies; say so instead of pointing at the skill.
  const files = (options.arguments ?? []).filter(item => !item.startsWith('-') && /\.[A-Za-z0-9]+$/.test(item));
  if (skills.includes(command) && files.length && !files.some(file => /\.conllu$/i.test(file))) return `${command} is a skill for CoNLL-U .conllu files, not a command, and ${files.join(', ')} ${files.length > 1 ? 'are not' : 'is not'} CoNLL-U, so no UD skill or tool applies. Run: cat ${files.join(' ')}`;
  if (skills.includes(command)) {
    const file = options.skillFile?.(command), operation = options.describes?.(command);
    return `${command} is a skill (an instructions document), not a command. Read it first${file ? `: cat ${file}` : ''}, then run the ud-agent commands it gives${operation ? ` (start with: ud-agent describe ${operation})` : ''}. It is for CoNLL-U .conllu work only.`;
  }
  if (options.operations.includes(command)) return `${command} is an operation, not a command. Run: ud-agent describe ${command} (it prints the exact Run: or Call: line to use).`;
  return undefined;
}

/** POSIX single-quoting for an argument embedded in a generated sh script. */
const shellQuote = (value: string) => `'${value.replaceAll("'", `'\\''`)}'`;

/** A skill name typed as a shell command reaches `ud-agent NAME`, whose guidance names the SKILL.md to read
 * and the exact ud-agent command; the alias never runs an operation and always exits 127 (command not found). */
export function skillCommandAlias(launcher: readonly string[], name: string): string {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error(`Invalid skill name: ${name}`);
  return `#!/bin/sh\n${[...launcher, name].map(shellQuote).join(' ')} "$@"\nexit 127\n`;
}
