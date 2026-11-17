# Choose validation scope

`validation_report` (048) takes `working_tree_path`, `file_paths`,
`ud_context_path` and `options`. Select repository-relative files explicitly and
keep the corpus together for cross-file checks such as duplicate sentence IDs.
An empty selection is not proof that a corpus passed.

Options include `language_code`, `level` (1–5), `coref`, `check_families`,
`test_filters`, `exclude_filters` and `repository_name`. The check families are
`content`, `repository` and `documentation`. Report exclusions: content-only
validation is not repository/documentation certification. Use the intended
language and immutable rule context; a lower level can omit language checks.

`sentence_validation_report` (049) takes complete `sentence_conllu` and
`language_code`. Preserve tabs, Unicode and the final sentence separator. Its
scope is only that sentence regardless of the surrounding project.

`project_consistency_report` (050) takes `validator_module_path` and
`validator_class_name`. Project code runs in a fresh OCI job; official validation
runs independently and cannot be suppressed by custom code. Userspace rejects
this capability. Never import the module into the coordinator or an ambient
interpreter. A missing validator is a prerequisite failure, not a clean report.

For “is this treebank ready?”, inspect the workspace, select applicable families,
and explain remaining release/online requirements. One validator invocation is
not a complete release assessment.
