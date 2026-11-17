---
name: ud-release
description: "Instructions document (load to read first; never call it): how to package a CoNLL-U .conllu treebank as a local release handover. Load it first when asked to prepare a local handover package with treebank contents and hashes. Use registered MCP tools or the installed ud-agent on PATH; for CLI schema discovery run ud-agent describe handover_package_build. Not for ordinary prose/report wording. Never use it for .txt or other non-CoNLL-U files."
---

Do not start by calling validation_report alone; load this skill first, then use handover_package_build for the local package.

# Prepare a UD delivery

For a CLI handover request, start with `ud-agent describe handover_package_build`.

## Do this for a local handover (3 steps)

1. Call `handover_package_build` once with exactly the requested files:

   ```json
   {"working_tree_path": "ABSOLUTE_WORKSPACE_PATH", "ud_context_path": "", "output_dir_path": "handover", "options": {"file_paths": ["DATA_FILE.conllu", "README.md", "LICENSE"]}}
   ```

   - Deferred tools: first `tool_search` with `select:handover_package_build`, then call it.
   - Shell: write that JSON to a file outside the workspace, then
     `ud-agent call handover_package_build --input FILE --allow-root "$PWD"`.
2. Read `manifest.files` (path, sha256, size per packaged file) and the
   `limitations`.
3. Answer with each packaged file and its sha256, which checks ran on the
   packaged bytes, that official publication and registry requirements were not
   assessed, and that the inputs were preserved.

Use `handover_package_build` for a requested handover, `maintenance_report` for
maintenance findings, or `release_plan` for release readiness. Inspect the schema
of the requested operation; do not run unrelated release stages.

Establish treebank, release/context and requested local outputs. Read
[readiness](references/readiness.md), inspect the workspace and validate current
bytes before claiming readiness.

Use `release_plan`, `release_candidate_build` and `release_deposit_prepare` as
separate stages. Read [packaging](references/packaging.md); verify contents,
licensing, hashes and provenance, then validate packaged bytes. Source-tree
validity alone does not prove candidate validity.

For maintenance, renaming, contributions or transfer, read
[handover](references/handover.md). Plans require selected actions and current
preconditions; reports/star ratings are evidence, not approval.

Report readiness, incomplete checks, artifact identities and source/context
evidence. Local preparation grants no upload, push, tag, signing, account-change
or catalog-promotion authority.

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
