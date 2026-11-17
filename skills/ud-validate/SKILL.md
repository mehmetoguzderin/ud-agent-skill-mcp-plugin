---
name: ud-validate
description: "Instructions document (load to read first; never call it): how to check CoNLL-U .conllu files for annotation structure and sentence-identifier errors. Load it first when asked to check or find those errors in .conllu files. Use registered MCP tools or the installed ud-agent on PATH; for CLI schema discovery run ud-agent describe validation_report. Not for ordinary prose/report wording. Never use it for .txt or other non-CoNLL-U files."
---

Do not start by calling treebank_profile or predictions_evaluate; those belong to other skills. Load this skill first, then use validation_report.

# Validate UD data

For CLI checks, start with `ud-agent describe validation_report`.

Use this only for CoNLL-U (`.conllu`) files. For ordinary prose or report
wording, do not use UD tools; answer directly.

## Do this (3 steps)

1. Call `validation_report` once with every requested file together:

   ```json
   {"working_tree_path": "ABSOLUTE_WORKSPACE_PATH", "file_paths": ["a.conllu", "b.conllu"], "ud_context_path": "", "options": {"language_code": "en"}}
   ```

   - `working_tree_path`: the absolute workspace path given by the host, e.g. `/home/me/treebank`; never `.` or a relative name.
   - `file_paths`: names relative to that workspace.
   - `ud_context_path`: always `""` unless the user gave one.
   - Deferred tools: first `tool_search` with `select:validation_report`, then call it.
   - Shell (from the workspace): `ud-agent validate --working-tree "$PWD" --lang en`
     checks every `.conllu` file there; the JSON above also works with
     `ud-agent call validation_report --input FILE --allow-root "$PWD"`.
2. A sentence with a tree error (for example a bad HEAD) skips its `sent_id`
   check. If the result has errors, read each file (`read_file`, or
   `grep -H "sent_id" *.conllu`) and compare their `# sent_id = ...` lines;
   report any repeated ID with both file names.
3. Answer with each finding (file, sent_id, line, message), the checks that
   ran (`coverage`), and that the files were not changed. A result with
   `passed: false` is a completed check that found errors, not a tool failure.

If a call is rejected, read its `reason`, fix that argument and retry once.

## More detail

Validation authorizes no rewrite. For requested fixes, inspect `fix_plan` actions
and unresolved choices; use `plan_apply` with selected actions and current
preconditions. A pasted sentence uses `sentence_validation_report`, which cannot
establish corpus validity. `treebank_review` compares a base revision. Use
`workspace_inspect` only when the files to check are unclear. Read
[checks](references/checks.md) for scope/project rules, [results](references/results.md)
for large reports, [setup](references/setup.md) for blockers, and adapt
[requests](assets/request-examples.json) to the authorized workspace/language.
Missing inputs, crashes, timeouts or truncated findings cannot establish a pass.

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
