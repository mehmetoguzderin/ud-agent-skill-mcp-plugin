# Local development candidates and release gates

`node scripts/release/prepare.mjs --development` assembles local candidate
archives only. It checks the source fingerprints and five cross-built launcher
receipts, verifies the signed Node distribution checksums, and uses offline
`npm pack`. The output is marked unaccepted. Generated distribution packages
declare public scoped access. The source package retains `private: true`; no
manual registry transport bypasses npm's private-package safeguard.
No registry or account is contacted for publication.

`--candidate` creates immutable preacceptance packages only when the current
runtime and complete corresponding-source gates pass. Those exact bytes are
then installed and tested; acceptance never rewrites their marker. See
[first publication](FIRST-PUBLICATION.md), [acceptance](ACCEPTANCE.md) and
[recovery](RECOVERY.md).

`node scripts/release/verify.mjs --local <candidate.json>` verifies local
candidate bytes and current source inventory. It cannot certify runtime,
signatures, mutation results, or platform support.

Production verification requires a trusted Ed25519 key in the protected
`trust/policy.json`, a signed accepted manifest and artifact digests, actual
source and publisher commits on the configured protected ancestry, source
files matching that commit, frozen core/render OCI platform/index digests,
and all evidence in `quality/requirements.json`. Evidence must have nonzero
executions and no skipped/error results; mutation evidence must account for
every scheduled mutant and separately justify equivalent exceptions.

The default npm mutation task uses `bounded-reviewed-v1`: exactly eighteen
reviewed cases spanning TypeScript/JavaScript, Python, Rust and Perl, plus their
declared data-policy case. Its separate `mutation-bounded` inventory and reports
record `profile: bounded`, `qualification: bounded-reviewed-corpus` and
`exhaustive: false`. The source-bound corpus, case definitions, required tests,
runner inputs and candidate subjects must agree, and every case must have a
clean assertion kill. Counts are also reconciled per language. This is sampled
critical-path evidence, not whole-language mutation coverage.

`npm run test:mutation:exhaustive` retains the full six-backend, nine-suite path.
The direct mutation-gate API and CLI keep their legacy exhaustive default unless
`--profile bounded` is selected. Legacy inventories retain their requirements;
bounded evidence cannot be relabelled as those suites. Both profiles retain the
same production signature, source-ancestry, artifact and native-execution gates.

Accepted publication requires publisher, inventory, evidence and independent
review trust authorities. Evidence reports must be signed by a separately
trusted Ed25519 key and bind the source-tree hash, the exact test
file inventory, artifact identities, and runtime lock. Each report must identify
its nonempty executed tests and their source files. Mutation reports enumerate
each outcome and identify assertion failures by test ID; an equivalent outcome
requires a separately signed review binding the source and mutation definition
from an independent reviewer. Results must also reconcile with the source-bound
acceptance inventory. Generate the inventory
test catalog with `scripts/release/discover-acceptance.mjs` before collecting
outcomes, then freeze the complete backend schedules with `--freeze`.
Discovery outputs belong under `.artifacts/`; the generated final inventory is
copied to `quality/acceptance-inventory.json`. Only that generated output is
excluded from discovery's input hash; the candidate source hash includes it.

Each mutation schedule references a complete `backend_discovery` receipt. The
master binds the exact versioned backend, source scope, generators, configuration,
raw generation artifacts, runtime identity, and every canonical mutation
definition. Raw generation includes parser or generated-code evidence for every
applicable source, including files with zero mutants. The verifier independently
derives those source and configuration inventories and reconciles every shard
against the complete master. A shortened unsharded list, an omitted source, a
filtered generation command, or a changed definition fails verification.
For the bounded profile, completeness means all eighteen definitions in the
reviewed corpus; the inventory does not claim the exhaustive suites passed.

An independent inventory producer must sign that master under the dedicated
`inventory_keys` trust policy, with purpose `mutation-inventory`. Its signing key
must differ from the release key and the outcome key for the affected suite.
An unsigned local discovery can prepare an inventory but cannot certify it.
The producer must reconstruct definitions from actual backend materialization
before signing; a signature over a supplied list is insufficient.
Git commit verification compares exact blob bytes and executable modes rather
than relying on working-tree filters. The verifier also reads each
uncompressed OCI image-layout archive without extracting it and checks the index,
both platform manifests, configurations, compressed layers and their recorded
digests, and decompressed layer diff IDs.
These checks do not create or establish the authenticity of evidence: trusted
test infrastructure and actual platform execution remain prerequisites.
Local HTTP registry, release, catalog and signing fixtures exercise the real
transport adapters, immutable conflicts, response-loss recovery and delayed
promotion. They do not authorize a production endpoint or publish artifacts.
Native runtime, platform signing, mutation and public retrieval remain separate
acceptance gates, not claims implied by creating local packages.

Component source-coverage JSON keeps schema version 1. Format revision 2 stores
repeated multi-fact lists once in `binding_fact_sets`; a physical binding's
`facts` is either its single-element fact-ID array or an integer index into that
table. The table is sorted, unique and fully referenced; its fact IDs are sorted
and unique too. Every physical member, source fact, source relationship and
inspection input remains present. The reader also accepts legacy reports with
fact-ID arrays and no format revision. Independent replay expands the indexed
form before exact comparison. Reports use compact UTF-8 JSON and must still fit
the existing 128 MiB reader limit; indexing grants no source or publisher waiver.
