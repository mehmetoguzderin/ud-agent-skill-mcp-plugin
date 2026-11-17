# First publication

This guide describes the protected artifact publication workflow.

1. Stabilize the implementation, complete every locally applicable inventory and
   source/component/license binding, and retain unavailable native execution as
   explicit pending evidence. Missing current worker builds cannot become stale
   index entries.
2. Provision the separate release, inventory, evidence and review trust roles
   through a reviewed protected-source change. Record exact fingerprints and
   activation in `trust/rotation.json`; keep private keys outside source and
   package files. An inventory key cannot sign its own outcome evidence.
   Provision the verifier interpreter independently of those keys.
   `release/verifier-runtimes.lock.json` admits only reviewed full runtime
   inventories. Select an approved profile from that lock and an existing
   matching prefix, for example:

   ```sh
   export UD_RELEASE_PYTHON="$PWD/.artifacts/python315-native-quality/runtime/python/bin/python3.15"
   ```

   The public verifier checks every inventoried file and alias, creates a new
   private prefix, excludes original bytecode caches and runs with `-I -S -B`
   and an empty private cache. Venv site packages, `.pth` files and ambient
   startup configuration cannot supply verification code. An unverified `.venv`
   default or arbitrary override fails closed; no download or installer runs
   automatically. A relocated override must match the complete approved prefix.
   `prepare-verifier-runtime.py` derives inventory data from the exact locked
   archive without executing it; it does not approve a runtime. Provisioning
   another host requires its native architecture/loader inventory and an exact
   independent origin/byte-closure review before a policy change. Verifier
   runtime approval is separate from product-platform acceptance. Standalone
   runtime-inputs acceptance drivers need the same verified session admission.
3. Plan corresponding sources in two passes. First assemble unaccepted
   provisional artifacts with `prepare.mjs --materials-provisional`; retain that
   exact source snapshot and its original input receipts. Run
   `prepare.mjs --plan-materials --candidate PROVISIONAL_MANIFEST --recipe RECIPE
   --source-tree RETAINED_SOURCE --collection ID=RECEIPT --output NEW_PLAN` for
   every original collection. The command reconstructs source relationships
   from actual archive members, then independently verifies the exact USTAR
   source membership. Missing native artifacts remain missing. Partial local
   plans require `--diagnostic` and cannot establish complete product coverage.
   Freeze the verified source-material index/parts and canonical replay recipe
   through a reviewed source change; source-lock paths must resolve to the
   original physical bytes. Assemble new artifacts after that change rather
   than relabeling the provisional packages. Freeze the complete runtime and
   source inputs, then use
   `node scripts/release/prepare.mjs --candidate --output .artifacts/CANDIDATE`.
   The candidate marker and complete content inventories are created before
   installation tests. Acceptance binds those exact archive bytes; do not remove
   or replace a development marker after testing.
   This second assembly independently replays all 16 actual distribution
   subjects, emits `component-source-coverage`, and requires the physical source
   set to equal the derived requirement set exactly. Its production verifier
   authenticates the source-bound signature and protected ancestry before
   expensive replay. Public negative fixtures exercise real local signatures
   and bounded metadata rejection; deep replay additionally uses fixed source
   pipelines. No synthetic Git fixture represents a production success.
   The coverage report also retains a bounded inspection-input catalog. It
   records actual Python file reads and fixed Node backend input receipts,
   embeds small JSON inspection metadata, and references original source blobs
   or actual released members by content hash. Inspection commands are separate
   nonredistributed prerequisites. Every otherwise unretained input remains an
   explicit row: a local cache pathname or a caller completeness flag cannot
   admit it. Production rejects those rows after authentication and independently
   regenerates the catalog with the coverage report. A portable input cache must
   contain the exact retained/referenced bytes; missing bytes fail verification.
   Proprietary SDK/library/header bytes are never copied into source parts merely
   to make that replay work. Their source-duty and publisher-authority obligations
   remain separate from correspondence review.
4. Produce the `candidate-runtime-inputs` tree with `runtime-inputs.mjs`, including
   the original native/MCPB archives, their verified installed roots, closed
   operation fixtures, existing read-only Git history and offline dependencies.
   Run public installed workflows on the actual declared platforms/providers.
5. Independently discover and reconcile all scheduled tests and applicable
   mutants. Sign complete source-, runtime- and artifact-bound reports with the
   appropriate independently trusted roles. Production verification must pass
   before any credentialed transport is constructed.
6. With separate explicit owner authorization, the protected publication job
   consumes `accepted-release`, reconciles immutable artifacts, then promotes
   only after every target is verified. `channels.yaml` selects npm `beta` for
   this prerelease. OCI tags are versioned; no mutable `latest` alias is created.

## Publisher-signed `0.1.0-beta.1`

The publisher signs one final manifest. It binds the exact source, release
files, and test reports. Add the owner's Ed25519 public key to
`publisher_beta.keys` in `release/trust/policy.json` with `id`, `status: active`,
`algorithm: ed25519`, and `public_key_pem`. Record activation and the key's SPKI
SHA-256 fingerprint in `release/trust/rotation.json`. Store the private key
outside the checkout. The `publisher-beta` profile is available only for the
policy's pinned version.

This beta uses one detached Ed25519 signature over the final manifest. macOS
Developer ID, Apple notarization and Windows Authenticode are outside this
signing profile. The five native platforms ship their own original and MCPB
packages. The release push runs source checks across five native targets and
Node 24. Pull requests and manual runs can run full originals and the bounded
mutation corpus on the protected Linux ARM64 runner.

Freeze the worker and corresponding-source inputs, then build the packages:

```sh
node scripts/release/prepare.mjs --candidate --output .artifacts/beta-packages \
  --transient-bytes 48000000000
```

Windows setup acquires the pinned Node,
uv, Perl and VC runtime bytes directly from their suppliers. The component
inventory records which actual release files still require a publisher grant.
For those files, bind owner and reviewer attestations and their evidence
fingerprint to the exact artifact and component hashes via
`publisherAuthoritySubjects` using `signing_profile: publisher-beta`. Stage
the verified grant receipt before finalizing `SHA256SUMS`. The signed outer
manifest binds the checksum file, every distribution file and any grant.
Use the same ordered artifact list for every report and the final signed manifest.

Smoke-test the verified original macOS ARM64 native and MCPB archives with the
packaged coordinator. Record archive, source and runtime digests, the successful
validation result and report hash for each MCP era, and successful cleanup.
Preserve the installed smoke JSON.
After the full CI matrix succeeds on the final push to `main`, save both
`gh api repos/OWNER/REPO/actions/runs/RUN_ID` and
`gh api 'repos/OWNER/REPO/actions/runs/RUN_ID/jobs?filter=latest'`.
Combine their original JSON results in one object with the keys `run` and
`jobs`, respectively.

From `.artifacts/beta-packages/local-candidate.json`, create a separate
`accepted-candidate.json` with the final artifact inventory, the original source
and runtime hashes, and these acceptance fields:

- Set `status` to `accepted_candidate` and `signing_profile` to `publisher-beta`.
- Set `source_commit` and `publisher_commit` to the same verified release commit
  on `origin/main`.
- Set `runtime_lock_path` to `runtime/runtime.lock.json`, and copy
  `runtime_lock_size` from that file's receipt.
- Set `evidence` to the `github-ci` and `installed-smoke` receipts with
  `suite_id`, `path`, `size`, and `sha256`. Keep receipt paths relative to the
  checkout.

Sign the exact manifest bytes with the enrolled Ed25519 key using Node's
`crypto.sign(null, bytes, privateKey)`. Write the signature to the sibling
`accepted-candidate.json.sig.json` as `{ "key_id": "…", "signature": "…" }`
using Base64 for the signature. Run the verifier with the approved interpreter
before any upload:

```sh
node scripts/release/verify.mjs --production .artifacts/beta-packages/accepted-candidate.json
```

The build replays the component-source checks from the retained originals. The
verifier checks the signed coverage report against every release subject and
independently checks the physical corresponding-source parts and redistribution
authority. Follow the [local npm CLI sequence](RECOVERY.md)
after verification.

For the beta OCI images, keep the original Python provider layers in the
verifier checkout's private input cache. Acquire them before the offline replay:

```sh
python3 scripts/release/collect-core-image-provenance.py --with-donor-layers \
  --output .artifacts/source-materials-data/core-image-provenance-v1
```

Keep the pinned original pip wheel in the Python runtime source collection's
`blobs` directory as well. The verifier uses that wheel to check generated
entry-point source. It verifies the original OCI layer digests and compares
surviving Python files, aliases and ownership metadata to the final image.
Keep both private inputs outside release assets and corresponding-source parts.
