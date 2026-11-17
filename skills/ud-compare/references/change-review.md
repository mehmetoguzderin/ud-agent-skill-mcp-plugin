# Revision and contribution review

`changes_review` (083) and `treebank_review` (005) use the intended
`base_revision`. Retain its broker-verified resolved identity and current snapshot,
including selected dirty/untracked bytes. Do not replace current data with a
clean checkout or treat an unverified base name as a commit identity.

Review additions/removals, annotations, metadata, surface/spacing and byte-only
changes separately. Reindexing/movement can mislead a line diff; inspect mappings
and sentence matches. When validation is requested, validate current/candidate
bytes rather than the untouched base.

`contribution_plan` (084) analyzes a local patch into constrained proposed work.
Do not execute patch text or treat the plan as authority to push, open remote
contributions or modify unrelated repositories. Report unsupported/ambiguous
effects and stale preconditions. Include base/current hashes, meaningful evidence,
actual validation coverage and remaining questions. A partial review cannot
approve the whole treebank by absence of findings.
