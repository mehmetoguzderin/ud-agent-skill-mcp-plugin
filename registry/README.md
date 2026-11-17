# MCP Registry record

`server.json` describes the npm coordinator, which launches its selected local worker runtime. GHCR core/render images are OCI workers and are not standalone MCP servers. Publisher identity, version and npm coordinate are generated from `release/identity.yaml` and `release/product.yaml`.

`schemas.lock.json` freezes the official Registry schema URL, exact bytes and draft. `schema/server-2025-12-11.schema.json` is used for offline metadata validation. Updating a schema requires recording the new authoritative bytes, reviewing compatibility and rerunning metadata tests.

The primary published-install guide is [README.md](../README.md). Production publication requires complete source/artifact/test binding plus the independently provisioned publisher authority in `release/trust/policy.json`. That authority is currently unprovisioned. Local fixture transports are used to test reconciliation and response-loss recovery.
