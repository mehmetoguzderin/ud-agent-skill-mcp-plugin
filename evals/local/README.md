# Local native-model evaluation

This opt-in evaluator measures completed user intents through real native agents.
It is separate from the deterministic installed-MCP replay in `evals/README.md`.
Importing its modules, `npm test`, and CI do not load models. Live commands reject CI.

```sh
npm run build
npm run eval:local -- inventory
npm run eval:local -- prepare --opt-in
npm run eval:local -- prepare --opt-in --clients
npm run eval:local -- run --opt-in --windows 3
```

Preparation installs locked private Python environments and downloads immutable
revisions of all three exact artifacts into `.artifacts/local-evals/`. It does
not edit account configuration or install global packages. A failed dependency
or exact-artifact acquisition is retained in `preparation.json`. Do not edit that
receipt to relabel a failed preparation. Retain its evidence before retrying a
fresh preparation. Preparation does not consume the experiment clock.

To repair missing processor or pinned translation dependencies, use
`npm run eval:local -- prepare --opt-in --repair-runtime`. The bounded repair
creates new environments and an immutable receipt, verifies processor loading and translator imports
without weights or generation, and switches only the private selection pointer.
Prior environments, receipts, and campaign results remain intact.

`run` defaults to one four-hour window. `--windows 3` uses one twelve-hour
campaign with progress checkpoints at four and eight hours. Its maximum phase
allocations are 30 minutes admission, 315 baseline, 30 diagnosis/repair, 300 replay,
and 45 reconciliation. All windows and candidate replay share the original
deadline and twelve-request calibration ledger (four requests per model).
`run` persists its deadline before admission. Resume with
`run --opt-in --campaign ABSOLUTE_CAMPAIGN_DIRECTORY`; the deadline and calibration
allowance do not reset. Reconcile interrupted/expired work without inference:

```sh
npm run eval:local -- report --campaign ABSOLUTE_CAMPAIGN_DIRECTORY --output NEW_REPORT_DIRECTORY
```

Add `--require-qualified` to independently recheck complete native evidence and
return a failing exit status when any required row or observation is missing.
Reconciliation never generates model output. Claimed pass flags alone cannot
satisfy this gate: installed bytes, task state, operation events, provider traffic,
token usage, cleanup, and independent scenario grading must agree.

Build runtime assets before admission, using fresh repository-owned outputs:

```sh
python3 scripts/quality/prepare-mutation-runtime.py --ensure-ci --asset-root "$PWD/.artifacts/mutation-ci-sdk" --output "$PWD/.artifacts/mutation-ci-context" --download
python3 scripts/runtime/build-workers.py --download --output .artifacts/local-evals/worker-build
```

The worker builder verifies source contents and exports immutable ARM64 transports.
The evaluator binds these into its private installation and preserves the source
runtime lock. Heavy stages run sequentially. Use the SDK receipt's exact image ID
with `npm run test:mutation -- --runner protected --image sha256:...`; generated
variants must never execute on the host. Failed build attempts retain their
evidence and require a fresh owned output or verified reconciliation.

If an evaluator defect is corrected during admission before any scored episode,
`run --opt-in --admission-restart-from PRIOR_CAMPAIGN_DIRECTORY` creates a fresh
manifest while retaining the original start, deadline, and calibration spending.
The earlier evidence stays immutable. This option rejects campaigns containing
scored episodes; it cannot reset the experiment clock.

For an evaluator-only defect discovered in an unfinished baseline, the separate
`run --opt-in --no-controls --mechanical-rebaseline-from PRIOR_CAMPAIGN_DIRECTORY`
permits one corrected baseline. It retains the prior diagnostic rows, independent
process-release receipt, model admissions, spent calibration allowance, original
phase deadline, and campaign deadline. UD product bytes, task/oracle identities,
model settings, seeds, and assignments must remain unchanged. At most 18 prior
rows fit alongside both complete 171-row snapshots under the 360-row ceiling.
The original attempt remains immutable and cannot receive another rebaseline.

The 171-row starter inventory retains 18 distinct surfaces, three models, seven
scenario families, and seeds 17/23/47. It tests assigned workflows, not the full
Cartesian operation matrix. Optional skills-disabled controls add exactly18
baseline rows when the whole block fits admission. The conservative forecast uses
the 90-second episode ceiling for mechanically executable rows and also budgets
blocked-row reconciliation. It selects diagnostic mode if paired replay cannot fit;
it does not assume a short text benchmark predicts native-agent throughput.
Reports preserve every unfinished or blocked row and
require all three seeds for a qualifying combination.
Disabled controls retain their own outcomes; their failure does not disqualify
enabled product coverage. Full starter qualification still requires all 171
required rows, including unavailable desktop/IDE surfaces.

Pinned private acquisition and configuration recipes cover all eleven headless
clients. Installation alone does not admit a route: byte-bound inert conformance
must prove native provider/tool/skill execution, output, cancellation, and oracle
isolation. ARM64 containers use private profiles and an authenticated stdio bridge
to the actual host coordinator; no engine socket enters an agent container.
Desktop/IDE application identities and lifecycle evidence remain separate.
CLI launches cannot certify these surfaces. Claude non-Claude interoperability
remains experimental. Every unavailable or unverified route stays visible.

- Grok Build 1.0.77 starts an automatic session-title request independently of
  the main model selection. Its bundled configuration reference documents
  `models.session_summary`; the private recipe binds it to the same local model.
  The initial title path has no verified disable switch or attributable native
  completion observation, and background inference must still satisfy the
  single-request budget. Current upstream [title generation](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/session/summary.rs)
  and [persistence](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/session/persistence.rs)
  explain this concern; they do not substitute for conformance of the pinned
  binary. The route remains attempted and visibly blocked until exact native
  evidence satisfies every gate.

MLX serving is pinned to MLX-VLM 0.7.11. MiniCPM's exact NF4 load is probed without
conversion. A compatible checkpoint, tokenizer, image processor, tool parser,
sampling configuration, cancellation, and context must be verified before a
route qualifies. Unsupported image/protocol token accounting remains blocked.
Native conformance receipts bind the product source as well as adapter and client
identity. A candidate gets fresh mechanical checks and new receipt paths; it
cannot inherit a baseline registration claim after product changes.
The transparent gateway observes and gates native protocols. An owned sidecar uses
pinned LiteLLM 1.109.0 for required wire translations, retaining native and backend
traffic. Custom Responses tools use reversible exact-input encoding with grammar
validation; they are not silently dropped by native MLX. Neither component selects
skills, repairs semantic arguments, supplies answers, or replaces an agent loop.
No external endpoint is enabled.

Admission uses compact transport probes, exact CPU tokenization, inspected model
context configuration, image transport, and owned cancellation. A calibration
refusal or wording difference is recorded without rejecting a sound transport.
Long-context and pixel-understanding success require actual scored S4/S5 evidence.

Private socket capabilities count requested and subordinate UD operations across
CLI processes before effects. Tool arrays count each invocation. Provider requests
and complete responses are captured, with credentials redacted; streaming tool
blocks are withheld until budget validation. The coordinator observation hook is
dormant unless supplied an evaluation capability. Large unknown counts fail closed.

Fixtures contain only task inputs. Independent oracles stay outside agent grants.
S2 drops one completed mutation response through the campaign fault boundary;
this is labeled an injected transport failure, not a real network outage.
Missing activation, domain, final-answer, or cleanup observations cannot pass.
S1 begins with cold readiness and verified cached assets. Other positive scenarios
use explicitly labeled deterministic warm fixtures; those setup actions never
count as native model completion. Fixture archives are reclaimed only after
verified worker release and exact file-identity checks. Context measurements retain
observed request totals and bounded count-only ablations, with unavailable costs
explicitly labeled.

Campaigns retain source/runtime identities, all row outcomes, and seven readable
reference traces selected before results. Baseline and candidate comparisons
require identical evaluator, oracle, fixture, and model-configuration hashes.
A paired candidate replay uses `run --opt-in --baseline BASELINE_DIRECTORY
--patches PATCH_BATCH_JSON`; the patch receipt documents observed failure, layer,
reproduction, remedy, and focused tests for at most two defects. It reuses the
original deadline/admission and permits only one candidate replay.
A product repair is permitted only after a complete comparable baseline, a
direct reproduction, and sufficient time for the required replay. Diagnostic
campaigns do not authorize an unreplayed behavioral patch.
Reports distinguish `execution_complete` (all declared rows have terminal records,
with none `not_run`) from `grading_complete`. A fully executed baseline with
unresolved independent grades may support the ordinary paired replay; those
grades remain incomplete and cannot qualify. A missing row, reduced starter
inventory, diagnostic mode, or already-passing baseline cannot admit that replay.

Native tool failures are observed before the next dispatch. Their recovery
lineage survives changed arguments and failed recovery attempts; parallel calls
each consume an allowance and are admitted atomically. Unknown result status or
ambiguous recovery fails closed. This observes native call results, not hidden
shell command exit statuses masked by a successful compound command. Underlying
UD operations continue to be independently charged by the coordinator authority.

Readiness, fresh profile registration and private network preparation happen
before the native process receives its one user request. Preparation has a
separate 60-second bound; the native conversation retains its 90-second limit and
five-second cancellation grace. Reports retain preparation and conversation
durations separately, and forecasting charges both. No inference or tool budget
is replenished when the conversation begins.

Live storage admission reserves 32 MB scratch and 3 GB output, including up to
2 GB transient fixture output and 1 GB persistent evidence. These are stricter
per-run plans within the existing 40 GB owned-total ceiling, 10 GB transient
ceiling and 10 GB free reserve. Full repository inventories run in workers so
they cannot block provider I/O. Boundary checks await complete inventories;
single-flight monitoring covers the campaign and admission output roots during
execution. Missing measurements fail closed. Cleanup retains individual native,
bridge and worker observations; an unknown generation count stays unknown even
when the budget ledger contains a conservative reservation.

CLI request JSON may be carried in the exact private profile temporary directory
without adding that directory as a workspace grant. Foreign paths, escaping
links and attempts to grant the profile remain rejected. Resource reads use the
installed grant-checked store; the bridge does not resolve IDs or alter inputs.

Focused inert checks: `npx vitest run tests/evals/local-*.test.mjs`.
Repository acceptance additionally requires `npm run check` and the complete
discovered original inventories on a frozen snapshot. Native model evidence,
external hosted-provider evidence, release acceptance, and publication remain
separate claims.

## Twelve-hour headless optimization

The `headless-12h-v2` profile runs the exact registry models through eleven
private Linux ARM64 Docker harnesses, one agent and one macOS model at a time.
Preparation downloads weights without loading them and builds owned client images:

```sh
npm run eval:local -- prepare --opt-in --containers
npm run eval:local -- iterate-prepare --opt-in --profile headless-12h-v2 --session .artifacts/local-evals/iterations/NEW_SESSION
npm run eval:local -- iterate --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION
```

Build the guard and native workers described above before `iterate-prepare`.
If acquisition failed after downloading assets, `prepare --opt-in --retry-acquisition`
creates a bounded new receipt after re-verifying cached publisher identities. It
preserves the failed preparation and never relabels it as successful.
Container preparation pins the actual ARM64 base manifests and Linux dependency
closure. Every native route must independently demonstrate inert conformance;
installation alone earns no model-execution credit. Preparation is outside the
clock. The twelve-hour deadline starts at first model admission and includes
reloads, diagnosis, candidate edits/checks, execution and cleanup. Resume keeps
the original deadline and twelve-request calibration allowance. The final
45 minutes are reserved for reconciliation.

The frozen baseline has 63 enabled rows (seven intents, three models, three
seeds) and nine S3 controls with skill exposure disabled. Core assignments are
Gemini/S1, Qwen/S2, mini-swe/S3, Pi/S4, Codex/S5, Kimi/S6 and Qwen/S7. The
controls alternate order with enabled S3 rows according to the frozen schedule.
All six skills remain discoverable; no oracle-derived operation allowlist is used.
S4 has a separately admitted 32,768-token envelope; other rows use 16,384.

One evidence-backed repair may replay the same 63 enabled core rows. Admit it
only after the complete baseline and only when checks, fresh conformance for all
eleven routes, replay, remaining breadth and reconciliation fit. Retention needs
a verified completion gain and no paired completion or S7 regression. The
immutable `decideRound` review records the decision; restore baseline product
bytes after rejecting a repair. No replay means no established product improvement.

Run `iterate --round transfer` on the retained product for 54 additional rows:
Codex/S2, Claude Code/S2, Hermes/S3, DeepSeek/S3, Grok/S4 and OpenClaw/S4, each
with every model and seed. This is unpaired breadth evidence. A completed core
with failures can proceed to breadth so those failures do not hide other routes.
Maximum execution is 189 scored rows with repair, or 126 without. The retained
core and breadth provide 117 distinct enabled combinations.

```sh
npm run eval:local -- iterate-report --session .artifacts/local-evals/iterations/NEW_SESSION --output NEW_REPORT_DIRECTORY --require-headless-qualified
```

The gate fails unless every required retained-product combination passes all
three seeds with verified evidence and owned release. Reports retain all missing
and blocked combinations, seven predetermined reference traces, a failure ledger,
and context/resource observations. Controls and rejected candidate rows never
qualify the retained product. This profile leaves the existing 171-row starter
qualification and actual desktop/IDE evidence separate. Legacy iteration sessions
retain their original policy and reader behavior.

## Bounded local iteration

Use a separate repository-owned session for short development rounds:

```sh
npm run eval:local -- iterate-prepare --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION
npm run eval:local -- iterate --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION
npm run eval:local -- iterate --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION --round repair --evidence REPAIR_EVIDENCE_JSON
npm run eval:local -- iterate --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION --round transfer
npm run eval:local -- iterate --opt-in --session .artifacts/local-evals/iterations/NEW_SESSION --round claude-transfer
npm run eval:local -- iterate-report --session .artifacts/local-evals/iterations/NEW_SESSION --output NEW_REPORT_DIRECTORY
```

The default round is `baseline`. Only `repair` accepts an evidence path, and that
round requires it. Preparation and execution require explicit opt-in; reporting
reads retained evidence without inference. Iteration commands reject campaign,
study, window and qualification switches. These rounds provide focused development
evidence and do not satisfy the complete 171-row starter qualification gate.

## Separate scientific diagnostic study

The causal study is a distinct opt-in campaign. It preserves earlier campaign
records and cannot provide starter qualification. Prepare frozen native request
captures, installations, interventions and analysis identities without loading
weights or starting a live clock:

```sh
npm run eval:local -- study-prepare --opt-in
# Alternatively choose a new repository-owned directory:
npm run eval:local -- study-prepare --opt-in --study .artifacts/local-evals/studies/STUDY_ID
npm run eval:local -- study-run --opt-in --study .artifacts/local-evals/studies/STUDY_ID
npm run eval:local -- study-report --study .artifacts/local-evals/studies/STUDY_ID --output .artifacts/local-evals/study-reports/NEW_REPORT_ID
```

Preparation requires existing verified private model/runtime and harness assets.
It records actual native requests against an inert provider, including native
skill-body loading. Preparation failures provide no model execution credit.
`study-run` rejects CI and starts one immutable eight-hour live deadline at first
model admission. Resume uses the same manifest, consumed counters and deadlines.
Only one model and one unit may be active; model order is MiniCPM, LFM3, Bonsai,
with seeds 17, 23 and 47 inside each model block. Each model receives at most 145
minutes; 45 minutes remain reserved for reconciliation.

The frozen schedule retains 252 single-decision probes, 108 native episodes and
72 forward probes, crossing editing/comparison through Qwen and mini-swe. S7
checks ordinary wording without UD activation. Twelve mechanical calibration
requests (at most four per model) are separate from the row ceilings; neither
resume nor reporting replenishes them. Forced activation is diagnostic only.
Missing evidence remains unknown. Counter reservations are upper bounds, not
measured inference or token usage. Reports verify referenced file bytes and
retain every unattempted row.

New lifecycle-version-2 studies retain an unresolved model block after failed
unit cleanup. Continuation requires a hash-bound independent episode-release
proof; it preserves the original failed grade and deadlines. Legacy manifests
and their original release decisions remain unchanged.

Forward pairs use initial prompts for seed 17 instrumentation parity, observed
tool-result requests for seed 23 component interventions, and observed skill or
tool-result requests for seed 47 representation tests. The representation test
preserves decoded CoNLL-U bytes and the shell return code; absent eligible data
produces an explicit sham. Attention summaries describe selected query rows and
hybrid-state paths. They are descriptive; component interventions and lexical
marker likelihoods do not establish complete action correctness or skill-specific
causality. Repeated token contexts count once in observational correlations.

The subsequent repair/qualification campaign has its own separately approved
twelve-hour deadline, one normal baseline, one reviewed repair batch and complete
candidate replay. Its 171 required rows per snapshot and optional whole control
block remain distinct from diagnostic units. The new qualification campaign
cannot reuse the old campaign's deadline, patch allowance or diagnostic-staging
exception. Use `report --require-qualified` for its strict acceptance result.

A completed repair needs an immutable retention decision before another round.
The session store's `decideRound(roundId, { retained, reason, evidence })` API
accepts hash-bound review files. It rejects completion regressions and newly
introduced UD activation on ordinary prose. Keeping a repair requires a verified
completion gain or an observed action-stage advance in two seeds. Restore the
last retained product bytes after rejecting a patch; the rejected records stay
in the report. `report().retained_product_round` identifies the comparison parent.
The three-hour clock includes review, edits, checks and reloads after admission.

## QSLM improvement loop

The campaign above qualifies native desktop and ARM64-container surfaces. For
fast, repeatable improvement rounds on any Linux or macOS host (including CPU-only
linux/amd64), the `loop-*` commands run one scenario group at a time:

```sh
npm run build
cargo build --locked -p ud-agent-launcher --bin ud-agent-guard
python3 scripts/runtime/build-workers.py --download --output .artifacts/local-evals/worker-build
npm run eval:local -- loop-groups
npm run eval:local -- loop-prepare --opt-in          # prints the diagnostic installation path
npm run eval:local -- loop-run --opt-in --group G1 --label before \
  --installation INSTALLATION --python MODEL_VENV/bin/python --model-dir MINICPM_DIR --device cpu
# edit skills/docs/tool texts, rebuild, loop-prepare again, then:
npm run eval:local -- loop-run --opt-in --group G1 --label after ...
npm run eval:local -- loop-analyze --runs RUN_BEFORE,RUN_AFTER --output REPORT_DIR --python MODEL_VENV/bin/python
```

- **Model.** MiniCPM-V-4.7-1B-int4 is the only registry model with a non-MLX
  runtime. Use the exact NF4 artifact (revision 0fdd1c14). MLX models need Apple
  silicon. The model environment uses the pinned
  `transformers==5.22.2 torch==2.15.0 torchvision==0.29.2 bitsandbytes==0.50.2`
  set plus `matplotlib` for the figures. `minicpm_server.py --device auto`
  selects MPS, CUDA or CPU. On CPU, `--generation-seconds` (the loop defaults to
  300) replaces the 90-second Apple-silicon bound.
- **Other registry models (diagnostic).** `loop-run --model-id lfm3|bonsai` serves the
  exact MLX artifacts with `evals/local/loop_mlx_server.py` (MLX-VLM 0.7.11; pass the
  MLX environment's Python as `--python` and the artifact directory as `--model-dir`).
  They target Apple silicon. On Linux MLX runs on the CPU only: with `--cpu-throughput`
  (or `UD_MLX_CPU_THROUGHPUT=1`) and `UD_MLX_CPU_BLAS` pointing at an OpenBLAS, LFM3
  decodes at about 0.7 token/s on 8 vCPUs. A request can take longer than the client's
  default 300-second timeout (the same bound as undici's response-header timeout, so
  MiniCPM is unchanged). Raise it for a CPU MLX run with `--request-timeout-seconds`
  or `UD_LOOP_REQUEST_TIMEOUT_MS`, and raise `--generation-seconds` to match.
- **Harnesses.**
  - `mcp-all` registers all 104 MCP tools but defers them, the way Qwen Code
    and Claude Code handle large servers. The prompt lists the deferred names.
    `tool_search` returns first-line descriptions (at most 160 characters) or,
    with `select:NAME`, loads one schema. `tool_call` invokes a hidden tool.
  - `mcp-scoped` applies a host include-list of the group skill's operations.
    Like Claude Code's automatic MCP tool search (schemas above ~10% of the context are deferred), it sends
    schemas only up to `limits.scopedToolTokens` (8,192 estimated tokens, a quarter of the 32k context): operations
    named in the skill body first, in order of first mention, then the rest in catalog order. Operations that do
    not fit are listed by name and reached through `tool_search`/`tool_call`. The split depends only on schema
    sizes and skill text. G1 (`ud-validate`, about 3.7k tokens) is sent entirely; G2 (`ud-edit`, 51 operations,
    about 275k tokens of schemas) previously overflowed the context on the first request.
  - In every MCP harness the host runs only tools present in the request. Calling a deferred tool whose schema is
    not loaded returns a rejection that names `tool_search {"query": "select:NAME"}`. A failed `tool_call` to an
    unloaded tool appends the same hint.
  - `cli-shell` gives a single `bash` tool, the `ud-agent` CLI on PATH and
    skills as files.
  - `mcp-eager` is diagnostic only. It sends every schema eagerly, as a
    non-deferring host does, at about 118k tokens. It cannot fit a 32k model.
  - MCP harnesses add the workspace folder structure to the prompt, as Gemini
    CLI and Qwen Code do. Every harness gets the same short system prompt and
    the skill catalog (frontmatter descriptions). Each also gets one generic
    format-error retry when the transport returns unparsable call markup as
    text; the retry is counted. All harnesses use the real installed MCP
    server, CLI and worker.
  - Skill catalog placement follows the mirrored host (`--catalog-layout
    host`, the default). The MCP harnesses send the catalog as a
    `<system-reminder>` ahead of the task in the first user message, as
    current Claude Code and Qwen Code do (Qwen Code since #4896 sends an
    `<available_skills>` startup prelude). `cli-shell` keeps it in the system
    prompt, as Codex lists skills in its instructions and Gemini CLI renders
    `# Available Agent Skills`. `--catalog-layout system` reproduces the
    earlier layout (catalog in every system prompt); each run records its
    placement per harness in `run.json` (`catalog_layout`).
- **Episodes.** Each episode uses a fresh short temporary workspace with a
  labeled deterministic warm runtime (not model work), at most 8 model requests
  and 512 output tokens per request.
- **Grading.** Each episode is graded in ordered stages: context fit,
  well-formed calls, skill activation, tool choice, successful call, scope,
  answer facts and unchanged inputs. The first failed stage is the failure locus.
- **Analysis.** `loop-analyze` writes a stage × episode heatmap, a harness ×
  scenario pass-rate map, a first-failure locus heatmap, a per-request
  prompt-token plot against the 32k window, Wilson intervals and a paired exact
  McNemar test between the first and last run.

Groups follow the skills: G1 validate (S1, plus the S7 prose negative), G2 edit,
G3 compare, G4 investigate, G5 rules/docs, G6 release. Only groups whose grader
is defined can run. Extend `gradeLoopEpisode` before starting the next group.
Loop rows are focused diagnostics: they never satisfy starter qualification.

### Interpretability at the tool-name decision (opt-in)

`loop-interpret` explains a wrong first tool name, for example a skill name
emitted as a function (`<function=ud-investigate>`):

```sh
npm run eval:local -- loop-interpret --opt-in --installation INSTALLATION \
  --python MODEL_VENV/bin/python --model-dir MINICPM_DIR --output REPORT_DIR \
  --runs RUN_DIR[,RUN_DIR] [--candidates CANDIDATES.json] [--objective skill-call|uptake]
```

`--objective skill-call` (the default) is described below. `--objective uptake`
explains the opposite failure on positive scenarios (G1: S1; negatives are
listed in `LOOP_GROUPS.G1.negatives` and keep the skill-call objective): the
model never loads the skill.

- **Uptake case.** At the first decision it compares the reference action,
  `activate_skill` (MCP) or `cat` of the skill's `SKILL.md` by relative or
  absolute path (shell), with the alternatives: every other offered tool name
  on MCP, and on the shell the first commands the model actually ran in failing
  episodes (workspace paths are mapped onto the current request).
- **After-skill case** (`HARNESS/S1@after-skill`). The skill load and its text
  are teacher-forced into the conversation, and the reference is the route the
  skill itself advertises: its operation (mcp-scoped), `tool_search`
  (mcp-all), or the `ud-agent` commands quoted in the skill body (shell). The
  loaded text is its own span (`loaded_skill`). Together the two cases separate
  "the skill is not loaded" from "the loaded skill does not lead to the tool".
- **Sequence margin.** Each action is a whole continuation, tokenized as the
  decoder emits it after the prefix, scored by its summed token
  log-probabilities; the margin is logsumexp(references) − logsumexp(alternatives).
  Integrated gradients use the softmax-weighted per-sequence gradients of that
  margin. The summary lists every sequence and the reference's per-token
  log-probabilities, which show where it loses mass.
- **Cached scoring.** Forward-only scoring encodes the prompt once and
  deep-copies the hybrid attention and linear-attention cache for each
  continuation; it matches the uncached float32 forward to four decimals and is
  about three times faster.

- **Requests.** For each default harness and G1 scenario it rebuilds the exact
  first request: system prompt, skill catalog and tool list from the installed
  MCP server. It teacher-forces the model's own failing assistant prefix up to
  `<function=`, taken from the runs' private generation evidence, or a
  canonical `<tool_call>\n<function=`.
- **Margin.** The decision margin is the log-sum-exp probability of the valid
  tool names' first tokens minus that of the skill names' first tokens.
- **Attention.** `evals/local/loop_interpret.py` captures attention from the
  decision position to labeled prompt spans in every full-attention layer and
  head. Spans cover the system rules, each skill line, the loader rule, each
  tool definition, the deferred list, the user task and the assistant prefix.
  The hybrid model's linear-attention layers have no attention map.
- **Gradients.** It computes input × gradient and integrated gradients (zero
  baseline, `--steps`, default 6) of the margin with respect to the prompt
  embeddings, aggregated per span.
- **Precision.** bitsandbytes' CPU `gemv_4bit` has no autograd kernel, so the
  NF4 layers are replaced by dense layers holding the identical dequantized NF4
  values, computed in float32 by default (`--dtype`). bfloat16 halves memory,
  but its CPU reductions are not reproducible: the same prompt scored 5.96 and
  6.47 nats in two passes, which can reorder candidates. float32 repeats exactly.
  Forward scoring takes about 3 s for a 1.5k-token prompt. Gradient steps use
  checkpointing; `loop-interpret` runs one case per process (`--only H/S
  --case-only --dtype bfloat16`, then `--cached-only` in float32 for the
  candidates) to keep peak memory under about 11 GB. Prompts above `--max-gradient-tokens`
  (default 3000; the scoped MCP prompts are about 3.4k) get attention and
  margins without gradients.
- **Tokens.** The decoder emits `<`, `function`, `=` and then the name, so each
  name's first token is taken from the name tokenized on its own. A first token
  shared by a valid and a skill name is excluded from the margin.
- **Candidates.** `--candidates` takes a JSON list of
  `{id, note, replace: [[old, new], ...]}`. It applies each replacement to the
  prompt and tool texts and ranks the candidates by mean and minimum margin
  (forward only). This is a discrete, margin-guided search over wording.
- **Outputs.** It writes `interpret-summary.{json,md}` and three figures:
  attention to the skill catalog by layer × head, attention versus IG by span,
  and IG for each skill line and tool, plus `interpret-candidates.png` (candidate × case margins) with `--candidates`. Everything goes under `--output`, which
  should stay outside the repository; `.artifacts/` is ignored. This command
  is never part of `npm test`.
