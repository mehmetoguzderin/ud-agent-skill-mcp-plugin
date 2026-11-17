# Establish local readiness

Use `workspace_inspect` (002), applicable `validation_report` (048) families and
`treebank_review` (005) for a prior revision. `workspace_sync_plan` (003) uses
explicit repository evidence; a local snapshot cannot establish live remote state.
`treebank_create` (001) and `treebank_snapshot` (004) provide local scaffolds or
byte-bound baselines without making a release.

`release_plan` (092) needs target and intended previous release. Report selected
data, identity/metadata proposals, required checks, license/source obligations,
outputs and unresolved choices. Callable actions alone do not establish readiness.

`star_rating_report` (098) requires real validator evidence; a missing validator
cannot yield favorable stars. Retain its rubric and scope; it is not official
online acceptance. `maintenance_report` (095) checks the supplied policy rather
than an unspecified universal checklist.

Distinguish completed findings, failed/incomplete execution, unsupported local
capabilities and external requirements. Preserve selected dirty/untracked data
and exact hashes instead of switching to a cleaner source.
