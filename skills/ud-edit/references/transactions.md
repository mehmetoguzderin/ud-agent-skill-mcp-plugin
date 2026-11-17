# Preview, apply and recover

Edit options support `mode: "preview"` or `"apply"`, original fingerprints,
validation options and `idempotency_key`. Preview does not commit workspace bytes.
Review the candidate/scope, then apply with the same original preconditions and
intended language/context for independent validation of candidate bytes.

`plan_apply` takes `plan_path`, `selected_action_ids` and options. Supported plans
use `schema_version: "ud-plan-v1"` with constrained actions, dependencies and
hashes. Select dependencies deliberately; unresolved plans cannot be applied.
Use the authorized plan resource/export route for managed plans. A plan is data,
not shell commands or authority to execute project code.

A stale hash means the preview no longer describes the workspace. Re-inspect and
regenerate against new bytes; do not remove the expected fingerprint. For response
loss, retry the exact request with the same idempotency identity and inspect
recorded recovery before starting another edit.

The broker uses cooperative locks, recoverable journals and per-file atomic
replacement. It does not promise portable compare-and-swap or globally atomic
multi-file commits. Distinguish replaced/pending/restored files through verified
journal state after interruption. Do not invent a completed rollback. Required
metadata/ACL/durability guarantees are probed on the actual platform; missing
guarantees block the affected operation.
