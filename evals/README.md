# Workflow corpus

For explicitly opted-in real native-agent model evaluation, see
[`local/README.md`](local/README.md). That separate path keeps inference outside
ordinary tests and CI and retains blocked or incomplete coverage explicitly.

`cases/workflows.json` is the shared corpus. Routing cases contain independent
expected skill choices, including negatives and competing skills. They are inputs
for model evaluation, not claims that routing has been executed. No adapter
invokes a hosted model. Each host adapter points at its actual connector format.

Replay cases contain authored files, public tool requests, independent result
assertions and exact allowed filesystem effects. Run them against a supplied
unchanged installed candidate:

```sh
node scripts/quality/run-workflow-evals.mjs --installation /absolute/installed-candidate --host codex --output /absolute/new-report.json --engine docker
```

Use `claude` or `gemini` for the other adapters. The runner creates a private
profile, invokes the installed connector, reads the generated configuration and
uses that exact server entry. It never authenticates to a model or contacts a
model provider. `--engine` selects a supported already prepared runtime using
offline setup; all candidate bytes are reverified after execution.

For a closed offline candidate, supply `--offline-assets /candidate-inputs
--python /absolute/locked-python`. The producer's verified inputs must bind the
exact assembled installation; copied/relabelled payloads are rejected. To force a
userspace route, use `--engine userspace --installer uv` (or `venv`) together with
`--search-path /absolute/isolated-bin`. The report checks the actual installer;
seeding uv is disabled for the venv route. These are acceptance options, not
additional requirements for ordinary installation.

The grader checks actual tool results, resource bytes, workspace preservation and
declared output effects. Replay does not establish model routing or OS-level
network/process observation; those remain separate model/provider acceptance.
Reports bind the corpus, adapter, runner and installed inventory. Failed or
missing cases cannot be summarized as a passing replay.
