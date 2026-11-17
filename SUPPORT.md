# Support

Start with the installation and troubleshooting section for your host in [README.md](README.md). `ud-agent doctor` observes the environment; `ud-agent doctor --fix` performs explicit owned setup/repair. Ordinary OCI engines, including Docker Desktop/Engine, are supported independently of daemon privilege. A worker must still satisfy its containment contract.

A useful report contains the product version, OS/process/worker architecture, selected runtime and reason, exact failing command/tool, structured error code, whether setup was offline, and a minimal authored CoNLL-U fixture. Include redacted diagnostics and relevant receipt hashes; do not include credentials, private corpus data, user paths or runtime sockets. State whether this was a source build, native archive, npm, MCPB or plugin installation.

Use the [issue tracker](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/issues). Supported installation routes are documented in [README.md](README.md). Report sensitive findings through [SECURITY.md](SECURITY.md). A linguistic validation failure differs from an incomplete/failed execution; include check-family coverage and limitations in either case.
