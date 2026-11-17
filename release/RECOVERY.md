# Publication recovery

Use the same exact accepted candidate and private durable publication journal.
`publisher.mjs --plan CANDIDATE` is read-only and makes no remote requests.
Publication and promotion commands still require explicit owner authority.

After an interrupted authorized publication, `--reconcile CANDIDATE JOURNAL`
re-verifies the candidate and inspects each immutable remote coordinate. A lost
response is recovered by matching the remote bytes, not by assuming a failed
request wrote nothing. Conflicting bytes at a versioned coordinate stop the
operation. Never replace an immutable published artifact or invent a repository
digest to reconcile a locally built image.

`--promote CANDIDATE JOURNAL` requires every planned target to be verified. It
does not rebuild, relabel or re-sign packages. If candidate bytes, source,
runtime locks, reports or protected ancestry change, construct and test a new
candidate rather than editing the journal to make old evidence fit.

Trust retirement is a protected-source policy change recorded in
`trust/rotation.json`; it is not a registry account change. Suspected key
compromise blocks use of that key and requires independently reviewed new
evidence. For the first beta, use the enrolled publisher key recorded in both
the trust policy and the rotation ledger.

## Publish the first beta with the local npm CLI

Use the owner-signed `publisher-beta` manifest and the production verifier
before starting publication. Run reconciliation locally to stage the GitHub
draft and the two OCI image digests. Reconciliation pauses at npm when the
verified version is absent. Use the `npm` artifact path in the signed manifest
as `$tarball`.

```sh
npm login --auth-type=web --registry=https://registry.npmjs.org/
npm whoami --registry=https://registry.npmjs.org/
npm publish "$tarball" --access public --tag candidate --ignore-scripts --registry=https://registry.npmjs.org/
```

Confirm the operator is `mehmetoguzderin` before publishing. Complete npm's
browser prompts directly. Rerun reconciliation to download and compare the
published tarball. After an interruption, check the existing version and
tarball bytes before retrying.

For the first beta, reconciliation reads the public MCP Registry without
credentials. If the version is missing, the checkpoint prints the accepted
`mcp-registry-record` file path. From the repository root, use that path as
`$mcp_record` and sign in as `mehmetoguzderin` immediately before submitting it.

```sh
mcp-publisher login github
mcp-publisher publish "$mcp_record"
```

Rerun reconciliation to verify the public record against the signed candidate
and check its catalogs. If the CLI loses its response, rerun reconciliation
before submitting the version again. An operator supplying a valid
`MCP_REGISTRY_TOKEN` can still publish the same record through reconciliation.

Run promotion to set the versioned OCI tags and publish the GitHub prerelease.
After verifying those public downloads, set the beta tag locally and rerun
promotion to record the verified npm channel.

```sh
npm dist-tag add @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 beta --registry=https://registry.npmjs.org/
```
