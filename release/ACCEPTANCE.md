# Acceptance discovery and evidence

Discovery creates requirements before test or mutation outcomes are consumed. It
does not report a successful test, provider check, installation or release.

Use a fixed source copy, the locked dependencies, and native executables for the
machine collecting the inventory:

```sh
node scripts/release/discover-acceptance.mjs \
  --output .artifacts/acceptance/discovered-tests.json \
  --python /absolute/path/to/private/python \
  --cargo /absolute/path/to/cargo
```

Vitest collects executable test declarations with `--staticParse=false`, including
parameterized cases. Identical display names retain separate occurrence IDs.
Python's unittest loader collects every discovered test directory, including Perl
bridge and mutation-grader tests. Cargo discovers test executables from its JSON
build output; each executable lists its tests without running their bodies. All
three collections must complete. Missing files, filtered commands, duplicate
identities and source changes fail discovery. A cross-build is build evidence;
it does not enumerate or execute tests on another native platform.

The catalog records exact test-source hashes, command arguments, executable
hashes, collection transcripts and the input-source hash. Its source hash omits
only the generated `quality/acceptance-inventory.json`, avoiding a circular hash.
The final candidate source hash includes that file and binds its discovery
receipts. Evidence can move with an identical source copy; absolute paths in raw
collection transcripts are resolved against their recorded collection root.

Each mutation backend must supply an independently generated schedule before
outcomes. The normalized schedule has `schema_version: 1`, `inventory_only: true`,
a required mutation `suite_id`, discovered `tests`, and exact `mutants`. Each test
binds its source hash and independent catalog ID (`discovered_id` when a backend
uses another test ID). Each mutant binds its source hash, complete versioned
definition and canonical definition hash. Outcome fields such as `status`,
`killed_by` and `failure_kind` are rejected in schedules. Backend reconciliation
must also prove that every applicable operator instance was scheduled; a partial
diagnostic schedule cannot establish full mutation acceptance.

Large schedules can use separate bounded JSON shards. Each shard carries the
same tests and a `shard` object with zero-based `index`, total `count`, total
`scheduled` mutants, and `inventory_sha256`. That hash covers the complete,
ID-sorted array of `{id, file, source_sha256, definition_sha256}` records. Every
index must appear exactly once; missing shards, changed test lists, inconsistent
plans and duplicate definitions fail reconciliation. Complete definitions remain
in their receipt-bound shards; the generated source inventory keeps their compact
fingerprints. Verification reads one shard at a time, with a 256 MiB limit per
JSON record, and consumes no mutation outcomes during this step.

After complete backend discovery, assemble the frozen inventory:

```sh
node scripts/release/discover-acceptance.mjs \
  --freeze .artifacts/acceptance/discovered-tests.json \
  --output .artifacts/acceptance/frozen-inventory.json \
  --schedule .artifacts/acceptance/typescript-schedule.json \
  --schedule .artifacts/acceptance/python-schedule.json
```

Include schedules for **every** required mutation suite; the abbreviated example
fails while any required schedule is absent. Install the resulting complete file
as `quality/acceptance-inventory.json` before freezing the final source snapshot.
Generation and verification consume no outcome report. Production verification
reconstructs required suites from the bound catalog and schedules, then requires
exact test and mutant reconciliation with independently signed results.

Installed tasks identify their actual driver and execution kind. Native archive,
npm and MCPB installation checks remain separate. OCI worker acceptance remains
separate from image construction; native provider acceptance remains separate
from fixtures and portable cross-builds. Userspace matrices include an explicit
assertion of operation 050's OCI requirement, rather than recording unsupported
execution as successful. The legacy signing suites require actual publisher
authority and native verification. The `publisher-beta` profile verifies the
detached Ed25519 manifest signature as part of final release verification.

Acceptance reports record passed, pending native, pending external and failed
checks separately. No deferred row is converted into a passing result.

For `0.1.0-beta.1`, the publisher-signed manifest binds two acceptance reports.
The `github-ci` report records the completed `main` push and six successful
platform and source check jobs on the exact source commit. The `installed-smoke` report binds the macOS
ARM64 native and MCPB archives to the candidate and records successful validation
over modern and legacy MCP and successful cleanup. The final verifier checks the exact release
assets, runtime locks, signature, corresponding sources, and redistribution
authority. Apple Container PNG and PDF rendering and the Windows WSL provider
checks are advisory for this beta.

## Protected mutation discovery, seal and resume

The default npm task, `npm run test:mutation`, selects the named bounded profile.
It freezes the eighteen-case `bounded-reviewed-v1` corpus before outcomes, including
its language/category metadata, source and test fingerprints, and actual runner
inputs. TypeScript/JavaScript, Python, Rust and Perl must each be represented.
The separate `mutation-bounded` suite reports `profile: bounded`,
`qualification: bounded-reviewed-corpus`, `exhaustive: false`, its corpus hash,
and exact per-language scheduled/killed counts. Every case must have a clean
assertion kill; missing cases, errors, timeouts, survivors and equivalent
exceptions fail this policy. These are reviewed critical-path mutations and do
not establish whole-language coverage.

The sibling APIs `discoverBoundedMutationSession`, `sealBoundedMutationSession`
and `openBoundedMutationSession` use a complete original-test catalog plus the
single protected `faults` generation provider. Original collection is a separate
phase with no test outcomes. Candidate-bound execution still runs the complete
original baseline once and checks its exact candidate subjects. It does not run
a complete original baseline separately for every corpus case.

Prepare a new bounded session through those APIs using the selected immutable
SDK image and absolute pinned original tools, then run the explicit profile:

```sh
node scripts/quality/mutation-gate.mjs --profile bounded \
  --session .artifacts/mutation/bounded-session \
  --candidate /absolute/available-candidate.json \
  --candidate-root /absolute/available-candidate-root
```

Candidate-bound execution requires an already sealed explicit session. Ordinary
source-only npm execution can discover and seal its new owned bounded session.
No outcome list can create a schedule or alter the reviewed corpus.

`npm run test:mutation:exhaustive` retains the legacy full six-backend path and its
nine required mutation suites. The direct API/CLI defaults remain exhaustive.
The existing `discoverMutationSession`, `sealMutationSession` and
`openMutationSession` APIs retain their full-profile contract, including separate
Python generators and complete per-source materialization. A bounded session is
rejected by the legacy opener, and cannot claim that these exhaustive suites ran.

New OCI execution retains compact evidence only: at most 16 MiB per exported file and 64 MiB total. Disposable source copies, compiler caches and generated work stay in owned temporary storage and are removed. Oversized optional exhaustive CONTROL or schedule data fails export before any bulk copy; it is not an assertion kill or accepted coverage. Existing exhaustive-report verification remains supported, but historical raw corpora are not recreated or retained by the default bounded workflow.

Both profiles require the pinned native Linux ARM64 SDK, private test identities,
no network, unchanged worker limits and verified owned cleanup. The SDK must
match its receipt-bound harness source. Native foreign-target gaps remain pending
under their actual source/compiler applicability; they are never kills.

Sealing installs only the exact generated `quality/acceptance-inventory.json`.
Every executable, test, corpus and configuration input retains its prior hash.
The inventory-only composition transition preserves the previous composition and
original discovery receipts and binds the final candidate Source hash. Neither a
local seal nor either profile grants signing or publisher authority.

Reusing `--session` resumes at backend boundaries. A backend is retained only
after its strict assessment succeeds; partial or failed execution remains
evidence and runs again from the beginning. Every reuse checks the source,
schedule, image, SDK and complete retained evidence bytes, then runs the existing
graders again. Stored statuses never establish acceptance. A native kernel lease
prevents concurrent execution of the same session and releases on process death.
Any other source change requires new discovery. Diagnostic `--backend` or range
runs cannot satisfy the full gate. Verified foreign-target rows retain the
`pending-native` qualification and a nonzero exit status.

## Per-case original test evidence

`npm test` discovers the complete test catalog and reconciles every original
outcome, retaining its report in a new `.artifacts/original-tests/` directory.
To choose the output directory and exact Python/cargo executables, use the same
execution driver directly:

```sh
npm run test:evidence -- --output .artifacts/original-local-tests \
  --python "$PWD/.venv/bin/python" --cargo "$(command -v cargo)"
```

The output directory must be new. The driver first collects the complete test
catalog, then runs static checks, Vitest, every discovered unittest directory,
and every listed Rust test binary. It matches exact test names, duplicate-name
occurrences and source hashes. Missing cases, skips, expected failures, runner
errors, stale sources and filtered Rust tests fail the report. Raw commands and
observations remain beside `report.json`, including when execution fails.

This report covers original local tests only. It does not certify installed
packages, mutation detection, another platform or a production release. Running
the driver with Node 24 and Node 26 produces separate reports; neither changes
the source or fabricates a native-provider result.

When a real local candidate already exists, `--candidate PATH_TO_CANDIDATE_JSON`
also writes `unit-evidence.unsigned.json`. This checks every referenced artifact's
actual bytes, the current source snapshot and runtime lock before and after the
tests, then binds the same subjects used by release verification. It retains the
raw discovery and execution receipts. The output is unsigned unit evidence;
independent signing, installed acceptance and every other release gate remain
separate. Missing artifacts or a stale candidate fail instead of producing that
file.

For an available-target candidate, pass both the actual manifest and its own
artifact root: `--candidate /absolute/candidate/available-candidate.json
--candidate-root /absolute/candidate`. Its retained manifest, final material
stage, source/runtime and candidate/member inventories must match. The report
records byte bindings with `source_replay_performed:false` and
`source_replay_required:true`. It remains unsigned local original evidence with
`acceptance_eligible:false`, not full production release acceptance. Legacy local
candidates still resolve artifacts relative to the source root unless an explicit
`--candidate-root` selects a different artifact root.

Original tests need an ordinary writable source copy: Cargo and Vite write build
and cache files. Do not reuse the installed driver's frozen
`runtime-execution-profile`. With absolute `SOURCE`, `QA_ROOT`, a new `COPY`, and
the selected `NODE`, the existing retain/inventory functions prepare that copy:

```sh
"$NODE" --input-type=module - "$SOURCE" "$QA_ROOT" "$COPY" <<'JS'
import assert from 'node:assert/strict';
import {chmodSync,constants,cpSync,lstatSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const [source,qa,copy]=process.argv.slice(2);
const load=name=>import(pathToFileURL(path.join(source,name)));
const {sourceReceipt,fileReceipt}=await load('scripts/release/candidate.mjs');
const {retainSourceSnapshot}=await load('scripts/release/prepare.mjs');
const {nodeDependencyInventory,validateNodeTargetPackages}=await load('scripts/quality/node-dependencies.mjs');
assert.ok([source,qa,copy].every(path.isAbsolute));
assert.equal(fileReceipt(source,'package-lock.json').sha256,fileReceipt(qa,'package-lock.json').sha256);
const modules=path.join(qa,'node_modules'),inventory=nodeDependencyInventory(modules);
const target={os:process.platform,cpu:process.arch,libc:process.platform==='linux'?(process.report.getReport().header.glibcVersionRuntime?'glibc':'musl'):undefined};
validateNodeTargetPackages(modules,JSON.parse(readFileSync(path.join(source,'package-lock.json'))),target);
const receipt=sourceReceipt(source);retainSourceSnapshot(source,receipt,copy);
const privateModules=path.join(copy,'node_modules');
cpSync(modules,privateModules,{recursive:true,dereference:false,verbatimSymlinks:true,errorOnExist:true,force:false,mode:constants.COPYFILE_FICLONE});
function writable(dir){chmodSync(dir,lstatSync(dir).mode&0o777|0o700);for(const name of readdirSync(dir)){const p=path.join(dir,name),s=lstatSync(p);if(s.isSymbolicLink())continue;if(s.isDirectory())writable(p);else chmodSync(p,s.mode&0o777|0o200);}}
writable(privateModules); // only this new private copy, never the selected QA installation
assert.deepEqual(nodeDependencyInventory(privateModules),inventory);
assert.deepEqual(nodeDependencyInventory(modules),inventory);
assert.deepEqual(sourceReceipt(copy),receipt);assert.deepEqual(sourceReceipt(source),receipt);
writeFileSync(path.join(copy,'ORIGINAL-QA-INSTALLATION.json'),JSON.stringify({schema_version:1,qualification:'actual-selected-QA-installation',package_lock:fileReceipt(qa,'package-lock.json'),inventory})+'\n',{flag:'wx'});
JS
```

Invoke `"$NODE" "$COPY/scripts/quality/original-acceptance.mjs"` with the
explicit output/Python/cargo/candidate arguments above. The candidate remains
untouched. Keep the writable copy until any mutation gate using its compiled
original guard finishes. This one run includes the static gate and complete
original catalog; running `npm test` again repeats it. Input/build caches can be
reused with their exact receipts; outcomes from another source snapshot cannot.

For a small protected Stryker investigation with the **complete original test
suite**, the native ARM runner accepts one explicit source range:

```sh
node scripts/quality/oci-python-diagnostic.mjs .artifacts/stryker-investigation \
  --backend typescript --image localhost/ud-agent-mutation-runtime:arm64-final3 \
  --diagnostic-stryker-range packages/coordinator/src/operation-evidence.ts:24:1-26:2
```

The original configuration and test bytes remain unchanged. The fixed coordinator
validates the range against the closed snapshot and selects per-test coverage in
its generated wrapper. Every pre-outcome receipt records `selected-diagnostic`
and `scope_complete: false`; even perfect detection in this diagnostic cannot
satisfy the complete mutation gate. The production mutation configuration keeps
its full scope and default coverage mode.

## Published candidate provider workflow

`runtime-matrix.yml` requires five actual native ephemeral runner profiles with their owner-managed prerequisites already available. It downloads the exact `candidate-runtime-inputs` artifact from the selected trusted build run; it does not assemble another package, acquire another architecture, install an administrator-managed engine or start unrelated shared services. The original archive inspector verifies the original archives against each extracted complete package inventory before and after execution.

For local available-target preparation, `prepareRuntimeInputs(candidateRoot, recipe, output, { available: true, supportRoot, python, verifierRuntime })` reads the immutable candidate directly. Supplemental fixture, history and offline-asset entries use `input_root: "support"` with exact receipts. The output keeps one copy of each required payload and a small `available_candidate_root` reference; verification rechecks the original candidate's source, runtime, materials and artifact bytes at that canonical local root. This local reference is not a transferable provider bundle or production certification. Existing self-contained available-input manifests remain readable, and full-release input preparation remains self-contained. Temporary preparation is bounded and removed on failure.

`scripts/quality/native-provider-acceptance.mjs` launches the packaged native/MCPB coordinator through public MCP, stages only frozen selected offline transports into private product caches, executes all 102 independent authored cases, reads hash-bound public artifact resources, observes a new owned live job before cancellation, checks warm reuse, and invokes ownership-bound cleanup. A missing candidate architecture/provider prerequisite is a failed or pending row with nonzero exit, never a substituted Linux result.

`upstream-canary.yml` is a separate read-only maintained-head drift signal. Its exact HTTP observation receipts never change locks or execute new upstream code. Any drift fails the canary for review; compatibility of updated inputs still requires their complete source, behavior, mutation and native acceptance gates.

The same public MCP operation matrix supports explicit userspace routes with
`--engine userspace --installer uv` or `--installer venv` and an absolute
`--search-path`. That path must contain the selected compatible Python and an
explicit host Git executable for the two revision-snapshot fixtures. Do not add
an ambient directory containing uv when testing the venv fallback. The driver
records the actual installer marker and Git path, version, file identity and
hash; it never installs Git. It stages only the selected frozen offline assets.

Each installed format executes 101 supported operations against the same
independent fields and artifact bytes. Operation050's exact OCI-policy rejection
is counted separately. Cancellation observes a newly held native userspace
lease during a real validation request and requires its release after aborting.
`--jobs 2` or `--jobs 3` permits bounded parallel operation workspaces; the default
is one. Exact format/operation identities, warm cache reuse, resource bytes,
owned cleanup and unchanged candidate archives remain mandatory at every setting.
