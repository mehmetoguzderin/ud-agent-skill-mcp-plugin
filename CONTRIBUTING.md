# Contributing

Preserve the operation IDs, provenance, and user-facing parameter meanings in the
shared contracts. Add behavior tests for changes, exercise failure paths, and preserve the
distinction between execution failure, incomplete coverage, and invalid UD data.

Run `npm run build`, `npm test`, and `npm run test:mutation`. Original acceptance
includes static checks; use `npm run check` for a standalone check. CI and release
acceptance require all 18 source-bound cases in the bounded mutation corpus to be
detected by behavioral assertions. Errors, timeouts and missing outcomes fail.
Keep the report's bounded scope explicit. Exhaustive language mutation testing is
optional through `npm run test:mutation:exhaustive`. Generated catalog data and
schemas are produced with `python3 scripts/generate/contracts.py`.

CI runs the full matrix on pushes to `main` and pull requests targeting `main`.
For a manual `workflow_dispatch` run, select native jobs with the
`native_targets` JSON array (`linux-x64`, `macos-arm64`, `windows-x64`,
`windows-arm64`); `[]` skips them. Separate `linux_arm64` and `node24` booleans
select the mutation and compatibility jobs. Defaults run the full matrix. After
checking a fix locally, select only the affected targets to avoid repeating
successful platforms. `sdk_run_id` and `sdk_run_attempt` can reuse a retained SDK
artifact from an earlier run; its locked inputs and image are verified again
before use, and changed SDK inputs require fresh preparation. Results from a
selected subset do not establish a complete matrix pass for a changed snapshot.

Native POSIX test declarations use `posixTest` and a purpose in
`quality/native-test-scopes.json`. Windows still runs each file's applicable
policy and refusal cases. Its discovery and report retain the POSIX declarations
as pending native obligations, bound to the source, helper and manifest hashes;
they are never passed, executed or skipped Windows cases. Every test file must
retain actual applicable cases. A Windows applicable-case pass cannot satisfy
those POSIX obligations or a complete signed unit claim; the native matrix must
provide the corresponding POSIX execution evidence.

Quality and release runners admit storage plans before large writes. Shared
admission limits are 40 GB owned working storage, 2 GB ordinary scratch or 4 GB
release scratch, and a 10 GB free-space reserve (decimal bytes). SDK preparation
and import explicitly admit a 12 GB scratch plan with
`--transient-bytes 12000000000`. Local Actions also admits a 12 GB plan for its
SDK transfer, tool cache and owned container writes. Windows original tests
admit 8 GB scratch through the `release` resource profile and
`--transient-bytes 8000000000` for native builds and test state. These profiles
are storage plans, not release certification.
The storage CLI, SDK, mutation gate and local Actions wrappers perform initial
admission only: they do not periodically scan growth or turn a completed command
into a failure for exceeding its scratch plan. Disk exhaustion can still fail
the underlying command. Source and result verification, process cancellation
and owned cleanup remain required.
Protected mutation discovery initially plans 1 GiB beyond its source copy for
compiler output and staged executables within the 2 GB ordinary scratch plan.
Protected OCI workers retain their CPU, memory
and process isolation, without a per-file write quota or recurring storage-budget
polling. Test output volume does not determine whether the tests pass.
Run one heavy stage at a time. Reuse verified inputs;
never copy generated artifacts into source snapshots. Runners clean owned
scratch on completion or interruption and recover abandoned reservations on
restart. Candidate preparation retains one current candidate and compact receipts
for earlier candidates. Generated mutation variants are disposable and are not
retained as raw evidence. An admission failure stops launch; any larger initial
allowance must be explicit.
The original-test command runs its writable source and private Node dependencies
inside an owned reservation; nested original tests inherit that reservation.
Native original tests do not require Docker, including when diagnostics from
earlier runs remain in the checkout. Engine-backed provider and mutation jobs
retain their own Docker requirements.
The synchronous orchestration exports are intended for small fixtures or an
already-supervised job; they do not independently reserve storage.
Available-candidate assembly and replay use supervised workers. Compact replay
still needs the remaining component families to stop using the legacy input
catalog before it can run within the release scratch limit. Neither focused
fixtures nor a cross-build alone count as release acceptance.
