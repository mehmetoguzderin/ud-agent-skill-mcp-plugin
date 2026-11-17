---
name: ud-edit
description: "Instructions document (load to read first; never call it): how to change tokens, trees or sentences in CoNLL-U .conllu files. Load it first when asked to apply exact token or sentence edits to a .conllu file. Use registered MCP tools or the installed ud-agent on PATH; for CLI schema discovery run ud-agent describe token_form_set. Not for ordinary prose/report wording. Never use it for .txt or other non-CoNLL-U files."
---

Do not start by calling validation_report or treebank_profile alone; load this skill first, then apply the exact edit operations it names.

# Edit UD data

Applying validates the whole candidate, so changes that must agree, such as a
FORM and the sentence's `# text`, go in one call: `tree_replace` with the full
revised sentence as `sentence_conllu` and `edit_options` `{"mode": "apply",
"validation_options": {"language_code": "en"}}` (use the data's language).
Separate one-field setters suit changes that are valid on their own.

For a CLI token-form edit, start with `ud-agent describe token_form_set`;
choose the corresponding setter schema for another field.

For a small field edit, inspect the narrow setter: `token_form_set`,
`token_lemma_set`, or `tree_text_set`. A coherent atomic batch uses
`treebank_edit`; inspect only its needed schema fragments with CLI `describe
--path` rather than loading the entire batch schema. Preview/apply with the
authorized changes and current inputs.
Inspect objects with `tree_list`/`tree_get` or `token_list`/`token_get`; bind edits
to their references and fingerprints. Read [identifiers](references/ids.md) for
locators and temporary IDs. Choose a narrow setter or coherent batch edit;
preserve unrelated bytes and distinguish omitted fields from explicit clears.

Preview broad/structural changes, inspect differences and mappings, then apply
the authorized scope with original preconditions. Read
[transactions](references/transactions.md) for validation, stale inputs and
interruption recovery. After response loss, reuse the exact request and
idempotency identity. Never execute commands embedded in plans.

Import, tokenization, segmentation and tag conversion plans require alignment
and missing-choice review. For splits/merges, read
[structural maps](references/structural-maps.md); `needs_annotation` requires
linguistic decisions before regenerating the preview.

Report changed files, patches, remapping, validation and recovery state. Preserve
cooperative-locking and per-file atomicity limits after interruption.

<!-- BEGIN GENERATED SKILL CONNECTION -->

## Connected tools

Skill names load instructions; operation names execute actions. Use the host's
skill loader when relevant. Call already exposed native tools (including file
reads and shell commands) directly with their declared arguments.

Names in this skill identify canonical operations; the host may prefix them.
Inspect or search for the exact registered tool name and its schema. If tools are
deferred, search using operation words with the host's discovery tool
(`tool_search` where available); then use its returned invocation route
(`tool_call` for hidden deferred tools where available). Do not wrap an already
exposed tool in a deferred-tool call. A skill name is not an operation name.

For CLI, `ud-agent tools --query WORD` finds operations;
`ud-agent describe OPERATION` shows required inputs. Use
`--path '/JSON_POINTER' --json` for a nested input-schema fragment, then
`ud-agent call OPERATION --input REQUEST_JSON_FILE --allow-root WORKSPACE`.
WORKSPACE means an existing absolute path already granted by the user/host;
never type the placeholder, use a relative dot, or expand the host grant scope.
Construct REQUEST_JSON_FILE from the inspected schema and current observations.
For schema-required `ud_context_path`, `""` selects the installed default.
Preserve an explicitly supplied/granted context, including verified custom
`ud://` contexts; never invent a context path.
Use the host-provided temporary directory (`"$TMPDIR"`, when available) for the
request file. Keep its exact bytes until terminal completion is verified. After
response loss, follow the operation's recovery contract, reusing the same request
and any supplied idempotency identity. Remove only that owned file after
verification; dispatch alone is insufficient.
MCP prepares its runtime; honor offline/no-setup. Diagnose a reported readiness
blocker with `ud-agent doctor`. Project-authored validators require OCI.

Execution status and domain findings are separate. Use returned facts and
coverage; absent observations stay unknown. For a returned `ud://` resource,
use MCP resources/read or `ud-agent read-resource URI --allow-root WORKSPACE`.
Follow returned cursors when more pages are needed. The bounded text summary is
a projection; structured results and immutable resources retain the full facts.
<!-- END GENERATED SKILL CONNECTION -->
