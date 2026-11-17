# Read a validation result

Inspect `execution` before `result.passed`. A completed report with
`result.passed: false` found invalid data; it need not be an MCP tool failure.
Cancelled/incomplete execution, policy errors and unavailable prerequisites
cannot establish a linguistic pass.

Summarize actual scope, input paths/hashes, language/rule identity, incident counts
and requested/completed/omitted coverage. Cite stable incident codes and source
locations. Keep warnings distinct from errors; an absent coverage entry is not
an assumed completed check.

Large reports use managed resources. Read the returned URI, retain its hash and
follow every immutable cursor needed for the requested findings. Report expiry or
incomplete retrieval. Never turn a worker pathname/resource URI into an invented
host path. For long work use negotiated Tasks or resume the same tool with its
returned continuation, preserving its request identity and scope.

A useful response gives execution outcome, selected files/sentences, content
outcome, findings with locations, report reference and omitted/incomplete checks.
Do not claim official release acceptance from local validation.
