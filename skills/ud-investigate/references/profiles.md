# Focused profiles and denominators

Use `treebank_profile` (062) for totals, `lexeme_pos_report` (063) for lexical POS,
`observed_paradigms` (064) for observed inflection, `relation_profile` (065) for
dependency labels, `feature_agreement_report` (066) for named features/relations,
and `dependency_order_profile` (067) for order. `multiword_token_patterns` (068)
and `proper_name_sequences` (069) answer those specific questions.

Define the counting unit: sentences, words, annotated features, basic edges,
MWTs and enhanced edges have different populations. Report missing annotation
and exclusions. Sum counts before computing corpus proportions; averaging unequal
file percentages changes the statistic. Observed paradigms do not establish a
complete grammatical paradigm or registered rule inventory.

Use `feature_value_report` (073) and `conventions_compare` (072) for peers, with
consistent dimensions, context and file selection. `token_alignment_report`
(054) checks alignment before projection/tokenization comparisons; alignment is
not annotation correctness. Retain file/sentence/token/edge evidence. Zero means
no observations only when the relevant execution and scope completed.

`format_convert` (060) prepares a requested export with explicit input/output
formats and a loss report. Inspect omitted annotation and authorized outputs.
`dataset_split_plan` (059) proposes a reproducible split from a specification and
seed; review assignments/leakage evidence before any apply. Neither operation
should silently replace the source corpus.
