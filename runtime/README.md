# Runtime sources, receipts and local builds

The published installation guide is [the primary README](../README.md). This
file describes runtime development and artifact ownership. A prepared context,
built image, cross-built helper or diagnostic run is separate evidence; none
certifies the final release by itself. Production signing and publication remain
excluded from local development. Run AMD64 validation on native AMD64 hosts or
runners.

## Offline worker builds

`core-image.lock.json`, `ud-sources.lock.json`, `uv.lock`, the Perl dependency
lock and the render dependency locks identify the exact upstream inputs. Source
receipts record versions, commits, sizes, hashes and licenses. `Containerfile.core`
and the generated render context install verified local dependencies with build
networking disabled. Ordinary workers use numeric UID/GID 10001.

Prepare and verify a core build context with:

```sh
python3 scripts/runtime/prepare-core-build.py --download --output .artifacts/core-build-context
python3 scripts/runtime/verify-core-build.py .artifacts/core-build-context
```

`--download` explicitly permits acquisition of locked inputs. Omit it to use the
verified offline cache. Preparation rejects an existing output directory;
choose a new output after source changes. Verification rejects missing,
additional, changed and aliased members. Rebuild after changing the worker,
bootstrap, native helper, upstream source, rules or dependency closure.

The native worker builder prepares both contexts, builds core and render for
the local Linux provider's architecture, and exports verified transports:

```sh
python3 scripts/runtime/build-workers.py --output .artifacts/native-worker-build
```

On a fresh checkout the private Perl closure and the frozen render Debian
inputs are not cached yet; `--download` builds and acquires them from their
locked public sources (no release-pipeline pack is needed):

```sh
python3 scripts/runtime/build-workers.py --download --output .artifacts/native-worker-build
```

With `--download` the builder runs `scripts/runtime/build-linux-perl.py
--platform linux/<arch> --download` when `.artifacts/native-perl/linux-<arch>-source`
is absent (perl and CPAN sources from cpan.metacpan.org, Interset from GitHub,
all SHA-256 pinned, compiled offline in the pinned runner image from
`quality/act.lock.json`, about five minutes) and `scripts/runtime/fetch_perl_inputs.py
--render --download`. Release signatures are checked with `gpgv`, or with `gpg`
when `gpgv` is absent (Debian 13). The standalone `prepare-core-build.py` route
above stages every architecture unless restricted; on a single native host run
`build-linux-perl.py` first and add `--platform linux/amd64` (or `linux/arm64`).

The builder checks the local Docker endpoint and daemon architecture, uses the
pinned local base without implicit pulls, disables build networking and records
manifest, configuration and layer identities. `--download` explicitly permits
acquiring a missing pinned base and other locked inputs. Per-architecture OCI
and Docker archives have independent hashes; a per-architecture OCI archive's
`index_digest` need not equal the complete multiarchitecture index digest.
Verification checks the closed descriptor graph and each uncompressed layer
DiffID. Local image admission verifies actual engine identities and does not
invent repository digests or require prior registry publication.

Native ARM64 diagnostics have exercised installed public workflows through
Docker, Apple Container and the owned Lima adapter. Diagnostic evidence is retained under
`.artifacts/test-evidence`; it is source and artifact specific. Its existence is
not acceptance of another provider, platform or later source snapshot. The full
native/provider matrix and mutation reconciliation remain separate release
gates. Linux containers never count as native Windows or macOS evidence.

## Worker and provider admission

OCI-compatible bytes do not imply interchangeable engine flags. Docker,
rootless Podman, Apple Container, Lima/nerdctl and WSL Containers have dedicated
inspection, import, transfer, execution and cleanup paths. Setup verifies their
actual containment controls, immutable image identity, nonzero worker identity,
confined inputs and outputs, bounded resources, ordinary-worker networking and
cleanup. A required property that cannot be proved blocks execution.

Apple Container verifies the complete local worker/init/kernel closure before
creating a job and uses only local import/tag operations. Its maintained service
may mutate a cache concurrently under an external engine administrator's
control; the adapter reports this boundary and does not claim atomic no-pull
semantics. Lima uses an exclusively owned, short physical home, a pinned guest
configuration and rootless guest containerd. Existing unrelated VMs and shared
services are preserved. WSL sessions and their SDK/native control handles are
bound to durable ownership records. No adapter starts or stops unrelated
services during ordinary checks.

The bundled Perl bridges execute the pinned private Perl/module closure with
trusted library directories replacing ambient module lookup. Rendering uses
verified offline assets; browser-free SVG/HTML requests do not acquire a browser.
PNG/PDF acquire the selected render pack only when required. Project-authored
validators execute only in their separate fresh OCI sandbox, independently of
official validation; userspace does not execute untrusted project code.

## Private userspace packs

`userspace.lock.example.json` is illustrative and is never executable authority.
A frozen runtime lock binds the real `userspace.lock.json` bytes through
`userspace_sha256`. Each selected platform inventories its worker, bootstrap,
upstream modules, context, wheels, private Perl closure and native guard with
exact relative path, size and SHA-256. Closed inventories reject symbolic links,
unlisted files and missing dependencies.

Native archives and MCPB bundles may embed their selected closure. A fully
embedded, verified closure takes precedence over acquisition. Universal npm can
instead contain metadata plus `lazy_core: {url, sha256, size}`. Setup acquires
that exact product-versioned archive into product-owned storage, verifies its
closed inventory, then atomically admits it. Read-only checks never download.
Partial or corrupt embedded/cache assets fail integrity; they do not trigger a
fallback download. Optional `lazy_assets` descriptors provide the same policy
for selected provider assets. Unselected providers are not installed.

Setup reuses a compatible uv or acquires its pinned verified binary. It reuses a
compatible interpreter, obtains the pinned managed Python only when necessary,
or creates a private venv with the same hash-locked requirements if uv is
unavailable. CPython 3.14/3.15 are explicit ABI contracts. Runtime environments
are keyed by platform, ABI and dependency-lock identity in platform data/cache
directories. They are shared safely across workspaces without modifying shell
profiles, global packages or treebank directories. Userspace reports reduced
isolation and supports trusted built-in operations only.

## Ownership, repair and cleanup

Provider jobs hold unique kernel-released leases; maintenance refuses active
leases. Import staging records the destination root identity, native directory
ownership token, source contract, expected hash/size and publication phase
before moving bytes. Interrupted creates, bounded partial transfers and lost
publication responses are recovered only from those records. Hash-shaped
filenames alone are never ownership authority.

The private image-cache index binds each admitted transport to its root and
file identities, source contract and access sequence. Quiescent maintenance
bounds retained inactive entries to eight archives/4 GiB while preserving the
current frozen transports. Current legacy cache bytes can be adopted only after
a complete expected-hash verification; unknown or corrupt unindexed files stay
protected. Runtime cleanup does not globally prune engine images or services.

Explicit repair verifies available product source bytes before quarantining an
owned damaged cache object. A native maintenance scope and the exact import
lock protect quarantine, verified reacquisition and rollback. Corrupt evidence
is retained, with a bounded record/byte budget. Integrity failures never become
availability fallback. Explicit owned-runtime uninstall can remove that known
evidence through a durable cleanup intent; interruption resumes exact remaining
identities and preserves unknown additions. Cache-only cleanup retains it.

File editing uses cooperative workspace locks, stale-input hashes, journaled
recovery and per-file atomic publication. It does not promise portable
compare-and-swap or a globally atomic multi-file commit. Windows preserves
metadata through its native routes, including a probed transactional NTFS route
where privileged security-descriptor capture is unavailable; unsupported
filesystems fail explicitly. Cross-build evidence is separate from actual
Windows filesystem and Job Object acceptance.

## Binary/source correspondence

`materials/provider-binary-sources.lock.json` identifies actual release source
archives separately from maintained source inputs. In the WSL asset lock,
`source_commit` identifies the shipped 3.0.3 release; `maintained_source_commit`
retains the independently reviewed upstream head. SDK header and NOTICE joins
record the exact source and distributed hashes, including the vendor's LF to
CRLF transformation. An upstream head is not substituted for release source.

`scripts/release/apple-binary-components.py` verifies the official dSYM archive,
matches its Mach-O UUIDs to selected payload bytes, and joins file compilation
units to exact source archive members through that release's `Package.resolved`.
Imported SDK module declarations are separate from compiled source files.
Missing released symbols remain explicit; matching symbols do not prove a
bit-identical rebuild or identify every compiler-generated byte. The CLI's
Containerization dependency and the separately distributed VM init image have
independent source identities.

Windows launcher and guard release builds use LLVM-MinGW, the Rust gnullvm
targets, and the UCRT supplied by Windows. The cross-build receipt binds actual
PE imports and link maps to the executable hashes. Stage the compiler archive
and original source archives listed in `materials/windows-open-toolchain.lock.json`
under `.artifacts/llvm-mingw-inputs/` before running `scripts/release/cross-build.mjs`.
The build verifies the pins and emits a source collection receipt for the
corresponding-source planner. Native Windows acceptance uses the exact
packaged files on both supported architectures.

The original MSVC launcher and uv source-build records retain their own
distribution terms and source-duty reviews. Grant verification for the
publisher-signed beta checks the component hashes actually present in the
release.

Original Microsoft terms and distributable declarations are component metadata,
not MIT-licensed project code or proof of publisher authority. Source attribution,
native runtime execution and external redistribution authority are separate
acceptance states. Missing publisher authority continues to block promotion.
