# Candidate and deposit material

`release_candidate_build` (093) consumes `release_plan_path`, context and
`output_dir_path`. Inspect exact files, source fingerprints, rule/context
identities, notices and licenses. Portable manifests describe logical included
material, not ephemeral worker mount paths.

Validate packaged bytes independently, including required repository/docs files.
Selection, generation and transformation can change a candidate from source.
Retain selection and loss reports for omitted/converted material; source-only
validation cannot prove candidate validity.

`release_deposit_prepare` (094) consumes `release_candidate_path` and explicit
`deposit_metadata_path` to prepare local material, not a remote submission.
Confirm identity/authorship/license metadata from authoritative inputs; do not
manufacture missing legal or administrative values.

Return names, sizes, hashes, source/context provenance and actual validation
coverage. Keep detached checksums separate from an enclosing archive's self-hash.
Changed source/plan inputs require a new candidate and validation; relabeling
an old artifact is not a rebuild.
