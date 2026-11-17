# Setup and recovery

Start with the domain request: first use prepares dependencies automatically.
For a failure, use `check_ud_environment` for read-only diagnosis scoped to the
desired operations. Report selected runtime, selection reason, actual isolation,
available capabilities and exact missing prerequisite. An installed CLI alone
is not readiness; a core validation probe does not establish render readiness.

`setup_ud_environment` performs explicit preparation or owned repair. Honor an
explicit selection, then usable saved state, then a working OCI runtime. Ordinary
Docker is suitable even with an administrative daemon; the worker still runs
confined without privilege, networking or an engine socket. `docker-rootless`
is a separate stricter request. Do not shut down unrelated services.

If no OCI route works, private userspace reuses/acquires verified uv and a
compatible interpreter, with private venv as the final supported route. Supported
CPython 3.14/3.15 and the complete locked dependency set are required. Reuse
product-owned storage across workspaces; do not install into a treebank, edit
shell profiles, use ambient Perl modules or install global packages.

Integrity, ownership or containment failures require repair or a concrete failure;
they do not authorize silent fallback. Prepare browser assets only for outputs
that require them. Preserve exact administrator-managed prerequisites in results.
