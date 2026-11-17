---
name: ud-rules-docs
description: "Instructions document (load to read first; never call it): how to inspect a CoNLL-U .conllu tree diagram and look up language rules or guideline previews. Load it first when asked to explain a highlighted dependency arc or prepare a guideline preview. Use registered MCP tools or the installed ud-agent on PATH; for CLI schema discovery run ud-agent describe language_rules_report. Not for ordinary prose/report wording. Never use it for .txt or other non-CoNLL-U files."
---

Do not start by calling validation_report or treebank_profile; load this skill first, then use language_rules_report or sentence_render.

# Work with UD rules and documentation

For CLI rule inspection, start with `ud-agent describe language_rules_report`;
for a sentence preview, inspect `sentence_render` instead.

## Do this for a guideline example preview (3 steps)

1. Read the guideline file (and view any image the user names) yourself.
2. Call `guideline_example_preview` once; `example_markup_path` is the Markdown
   file with the CoNLL-U example, not the image:

   ```json
   {"working_tree_path": "ABSOLUTE_WORKSPACE_PATH", "example_markup_path": "GUIDELINE_FILE.md", "output_dir_path": "preview", "ud_context_path": ""}
   ```

   - Deferred tools: first `tool_search` with `select:guideline_example_preview`, then call it.
   - Shell: write that JSON to a file outside the workspace, then
     `ud-agent call guideline_example_preview --input FILE --allow-root "$PWD"`.
3. Answer with the relation, head and dependent you identified, how they match
   the guideline example, and the preview files written.

Use `language_rules_report` to inspect rules, `guideline_example_preview` for
guideline examples, or `sentence_render` for a sentence preview. Inspect the
selected operation schema and supply the requested inputs.

Identify language, treebanks and immutable context. Read [rules](references/rules.md)
to distinguish observations, registered rules and proposals. Use
`language_rules_report`, `language_rule_change_plan` and
`language_rule_impact_report` for those separate stages.

Read [metadata](references/metadata.md), inspect existing values and propose
`metadata_change_plan`. Never infer licenses, contacts, annotation methods or
identity from names/statistics.

For documentation, guideline examples or sentence images, read
[rendering](references/rendering.md). Keep previews offline, outputs authorized
and sandbox/font controls intact; prepare browser assets only when needed.

Report source/proposal/context identities, affected files, rule coverage,
candidate validation, losses/limitations and artifact references. Local plans
and previews do not update upstream repositories, websites or catalogs.

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
