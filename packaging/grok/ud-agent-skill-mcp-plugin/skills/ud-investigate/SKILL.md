---
name: ud-investigate
description: "Instructions document (load to read first; never call it): how to count or find patterns across a CoNLL-U .conllu corpus. Load it first when asked to investigate a corpus subset, frequencies, or examples. Use registered MCP tools or the installed ud-agent on PATH; for CLI schema discovery run ud-agent describe treebank_profile. Not for ordinary prose/report wording. Never use it for .txt or other non-CoNLL-U files."
---

Do not start by calling validation_report or predictions_evaluate; load this skill first, then use treebank_profile or the focused count it names.

# Investigate UD data

For CLI corpus counts, start with `ud-agent describe treebank_profile`;
use the focused operation schema when the question selects another dimension.

## Do this for a relation count or word order (3 steps)

1. Call `relation_profile` once with the relation asked about (DEPREL such as `nsubj` for nominal subjects):

   ```json
   {"working_tree_path": "ABSOLUTE_WORKSPACE_PATH", "relation_filter": {"deprel": "DEPREL"}, "ud_context_path": ""}
   ```

   - Deferred tools: first `tool_search` with `select:relation_profile`, then call it.
   - Shell: write that JSON to a file outside the workspace, then
     `ud-agent call relation_profile --input FILE --allow-root "$PWD"`.
2. Read `order_counts` (before_head / after_head) with `order_examples`. When
   the request limits the corpus by a sentence comment such as `# genre = VALUE`,
   use `by_sentence_metadata` for that value only: its `count` is the eligible
   denominator and it names one example per order.
3. Answer with numerator/denominator for exactly the requested subset (say what
   was excluded), a sentence/token example for each order, what the denominator
   counts, and that the inputs were not changed.

Use `treebank_profile` for corpus counts, `relation_profile` for dependencies,
and `enhanced_graph_report` for enhanced-graph investigation. Inspect the schema
of the operation matching the question; a report does not authorize edits.

Define corpus scope, annotation dimension and comparison unit. Use
`treebank_profile` for broad orientation or a focused report directly; read
[profiles](references/profiles.md) for operation choice and count interpretation.

Support findings with sentence/token locations and denominators. Separate
observations from normative rules, and suspected errors from proven violations.
Read [heuristics](references/heuristics.md) for script, agreement, name,
relative-clause and enhanced-graph limitations.

For alignments or passage concordance, read
[parallel data](references/parallel-data.md); preserve corpus identities and
unaligned populations. Report scope, filters, units, representative evidence,
context identity and limitations. Analysis authorizes no edits; requested fixes
need an inspectable plan and explicit linguistic decisions.

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
