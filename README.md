# UD Agent Skill MCP Plugin

Validate, edit, compare and investigate Universal Dependencies treebanks and CONLL-U in your own agent. Install the plugin through your agent, open a treebank folder, and ask it to work. The package supplies six skills and 104 application tools.

Why? Use upstream UD tools without the hassle. Tested for you and your agent.

## Start here

1. Find your agent below and install through its own plugin or MCP interface.
2. Open the treebank folder and start a new session.
3. Ask: **“Use ud-validate to validate this treebank, then show all errors.”**

The first operation prepares the correct worker automatically. You do not need to install Python, Perl or browser dependencies yourself. Existing working containers are reused; verified private userspace dependencies are prepared if no OCI runtime works. The agent reports administrator-managed prerequisites when they are genuinely needed.

## Contents

| | | |
| --- | --- | --- |
| [ChatGPT Desktop](#chatgpt-desktop) | [Codex](#codex-desktop-cli-and-ide) | [Claude Code](#claude-code) |
| [Claude Desktop / Cowork](#claude-desktop-and-cowork) | [Grok Build](#grok-build) | [mini-swe-agent](#mini-swe-agent) |
| [Kimi Code](#kimi-code) | [Hermes Agent](#hermes-agent) | [Qwen Code](#qwen-code) |
| [DeepSeek Harness](#deepseek-harness) | [OpenClaw](#openclaw) | [Pi](#pi-harness) |
| [Gemini CLI](#gemini-cli) | [Cursor](#cursor) | [VS Code GitHub Copilot](#vs-code-github-copilot) |

[Runtime choices](#runtime-choices) · [Doctor and repair](#doctor-and-repair) · [Native downloads](#native-downloads) · [Skills](#skills) · [Advanced MCP configuration](#advanced-mcp-configuration) · [Development](#development)

## Install in your agent

Each route below includes installation, activation, a validation smoke test and removal. Use the native plugin manager where offered. The `connect` command is an alternative for hosts without a suitable plugin route, and for doctoring an existing direct connection.

<!-- BEGIN GENERATED HOST GUIDES -->

### ChatGPT Desktop

Open your treebank folder in the desktop app. In **Plugins**, install `ud-agent-skill-mcp-plugin` from the owned `ud-agent-skill-mcp-plugin` marketplace. If the marketplace is not listed, add it through the desktop's Codex terminal:

```sh
codex plugin marketplace add mehmetoguzderin/ud-agent-skill-mcp-plugin --ref v0.1.0-beta.1
codex plugin add ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin
```

Start a new local session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** The first tool call prepares its worker automatically. The npm-backed catalog route needs Node 24 or 26. Native archives prepare Node automatically. The app stores local MCP settings in `~/.codex/config.toml`; folder grants are discovered from the selected project, with no JSON to type. Hosted ChatGPT chats cannot launch a local program.

Upgrade through the plugin browser or refresh the marketplace and reinstall. Remove the plugin in **Plugins → Installed**. If tools are missing, restart the local session and inspect `/mcp`. For direct MCP, run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect chatgpt-desktop` in the treebank folder. It merges the shared user `~/.codex/config.toml`, adds the six skills under `~/.agents/skills/`, and binds the selected folder grant. The same registration is visible to Codex desktop, CLI and IDE. Alternatively use **Settings → MCP servers → Add → STDIO**, enter the native coordinator with `mcp --allow-root /absolute/path/to/treebank`, save, and restart. Use `connect chatgpt-desktop --check` to inspect or `--remove` to undo the owned direct registration. Public directory availability requires separate desktop-only partner eligibility and approval. [Desktop plugins](https://developers.openai.com/plugins/deploy/desktop-only) · [Local MCP](https://learn.chatgpt.com/docs/extend/mcp)

### Codex desktop, CLI, and IDE

Open the treebank project. With current Codex and Node 24 or 26, install through Codex itself:

```sh
codex plugin marketplace add mehmetoguzderin/ud-agent-skill-mcp-plugin --ref v0.1.0-beta.1
codex plugin add ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin
```

Start a new session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Skills and the MCP server arrive together; the first operation prepares its worker. Desktop and CLI can install plugins. The IDE uses the shared MCP configuration at `~/.codex/config.toml`; where its plugin surface is unavailable, run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect codex` in the project terminal. Native archive users can run `ud-agent connect codex` without a separate Node installation. That direct command preserves the project `.codex/config.toml` route; use `connect codex-global` for the shared user configuration also used by ChatGPT Desktop.

Check with `codex plugin list` and `/mcp`. Upgrade by refreshing the marketplace and reinstalling its new version; remove with `codex plugin remove ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin`. If the wrong folder is selected, run the direct connector in the intended treebank folder. [Codex plugins](https://developers.openai.com/plugins/build/plugins)

### Claude Code

In a trusted treebank project, use Claude Code's plugin manager:

```sh
claude plugin marketplace add 'mehmetoguzderin/ud-agent-skill-mcp-plugin#v0.1.0-beta.1'
claude plugin install ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin
```

The npm-backed plugin needs Node 24 or 26. Start a new session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** It includes all six skills and prepares dependencies on first use. Claude owns the marketplace/plugin records; `/plugin` and `/mcp` show their status.

Upgrade in `/plugin`; uninstall with `claude plugin uninstall ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin`. If a marketplace is blocked or Node is unavailable, use the native archive and run `ud-agent connect claude-code` in the treebank folder. The npm direct alternative is `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect claude-code`. Restart after changing a connection. [Claude plugin installation](https://code.claude.com/docs/en/discover-plugins)

### Claude Desktop and Cowork

For **Claude Desktop**, download the MCPB matching your computer from the [native downloads](#native-downloads). Open **Settings → Desktop app → Extensions → Manage → Advanced settings → Install Extension…**, select the bundle, and choose your treebank folder. Enable it, start a new conversation, and ask: **“Validate this treebank and show all errors.”** Worker setup happens on first use. The bundle's folder setting supplies its grant; no configuration file editing is needed.

Desktop skill activation is separate from MCP registration: extract the [standalone skills](#skills), ZIP each of the six skill folders, then use **Customize → Skills → + → Create skill → Upload a skill** and enable them. `connect claude-desktop` also stages those folders and reports their location; it does not claim that Desktop reads Claude Code's skill directory. Skills require code execution to be enabled. [Claude skill installation](https://support.claude.com/en/articles/12512180-use-skills-in-claude)

For **Cowork**, use its plugin browser to add `mehmetoguzderin/ud-agent-skill-mcp-plugin`, choose `ud-agent-skill-mcp-plugin` from `ud-agent-skill-mcp-plugin`, and open the treebank folder. Its npm-backed plugin requires Node 24 or 26; activate `ud-validate` in a new task. Desktop extensions and Cowork plugins are separate installations.

Upgrade by installing the new bundle or updating the Cowork plugin. Uninstall in the same Extensions/Plugins panel.

For direct Desktop MCP, first launch Claude Desktop once, then run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect claude-desktop` in the treebank folder. It merges `mcpServers.ud` in `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows, or `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` on Linux (default `~/.config`). Fully quit and reopen Desktop, then inspect its local MCP status and request validation. Rerun the new exact package version to upgrade this direct route; use `connect claude-desktop --check` or `--remove` for the owned registration. The npm route requires Node 24 or 26. Cowork does not load this Desktop JSON configuration; if its plugin route is unavailable, use the [Claude Code local route](#claude-code) for the same treebank. [Desktop local MCP configuration](https://py.sdk.modelcontextprotocol.io/get-started/real-host/) · [Cowork connection boundary](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) · [Desktop extensions](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) · [Cowork plugins](https://support.claude.com/en/articles/13837440-use-plugins-in-claude)

### Grok Build

Use the current **Grok Build local harness** in your treebank folder. Install through Grok's marketplace:

```sh
grok plugin marketplace add mehmetoguzderin/ud-agent-skill-mcp-plugin
grok plugin install ud-agent-skill-mcp-plugin --trust
```

This grants Grok's normal plugin trust to the selected publisher. The npm-backed server requires Node 24 or 26. Open a new session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Grok loads the plugin's skills and MCP server; first use prepares the worker. Its owned catalog is `.grok-plugin/marketplace.json`, and user plugin state lives under `~/.grok/`.

Inspect with `grok plugin list` and `grok inspect`. Update or uninstall in `/plugins` or the Marketplace tab. If native plugin loading is unavailable, use `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect grok`. Grok also reads Claude-compatible plugins. Grok.com and a cloud-only API client cannot start this local server. [Grok Build plugins](https://docs.x.ai/build/features/skills-plugins-marketplaces)

### mini-swe-agent

mini-swe-agent uses shell-accessible workflows. In its local treebank project, ask the agent to run:

```sh
npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect mini-swe-agent
```

This installs six workflow instructions and `.ud-agent/WORKFLOW.md` for that project. The npm route needs Node 24 or 26. Ask: **“Read .ud-agent/WORKFLOW.md, follow ud-validate and validate this treebank with the installed CLI.”** This shell route does not require an MCP client. Setup and validation use the same runtime policy as MCP.

Upgrade by rerunning the connector with the desired exact package version. Check with the same command plus `--check`; uninstall its owned integration with `--remove`. Project instructions and `.agents/skills/` supply skill activation. If the agent uses a remote shell, install and run the coordinator on that machine beside the treebank. [mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent)

### Kimi Code

With current Kimi Code and Node 24 or 26, enter these commands **inside Kimi**:

```text
/plugins install https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/tag/v0.1.0-beta.1
/reload
```

The native Kimi manifest includes the MCP server and all six skills. Open your treebank folder and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Kimi stores the managed plugin under `~/.kimi-code/plugins/`; its first operation prepares the worker.

Upgrade in `/plugins` by selecting the plugin and pressing Enter; remove it with `/plugins remove ud-agent-skill-mcp-plugin`, then reload. Inspect `/plugins info ud-agent-skill-mcp-plugin` and `/mcp` if tools are missing. Direct alternative: `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect kimi` in the treebank folder; or run `ud-agent connect kimi` from the native archive. [Kimi plugins](https://moonshotai.github.io/kimi-code/en/customization/plugins.html)

### Hermes Agent

Use a current local Hermes installation with its native MCP support. In the treebank session, ask Hermes: **“Connect the published UD coordinator and its six skills to this folder using the command below, then use ud-validate to validate the treebank.”**

```sh
npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect hermes
```

The connector merges the native MCP configuration in `~/.hermes/config.yaml` and installs owned skills under `~/.hermes/skills/`. The npm route needs Node 24 or 26. Restart Hermes or reload MCP, then request validation; the first tool call prepares the worker.

Check with the connector's `--check` and Hermes' MCP panel. Upgrade by rerunning the exact new package version; uninstall the owned connection and skills with `connect hermes --remove`. If a gateway runs elsewhere, the coordinator and granted folder must exist on the gateway's machine. Hermes' curated MCP catalog requires separate Nous review; this custom connection does not claim catalog approval. [Hermes MCP](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp/)

### Qwen Code

Current Qwen Code can install this through its native extension manager:

```sh
qwen extensions install https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin
qwen extensions list
```

Its Claude/Gemini-compatible extension includes skills and the local MCP server. The npm-backed coordinator requires Node 24 or 26. Start Qwen in the treebank folder and ask: **“Use ud-validate to validate this treebank, then show all errors.”** First use prepares its worker. Qwen manages installed extensions under `~/.qwen/extensions/`.

Update with `qwen extensions update ud-agent-skill-mcp-plugin`; uninstall with `qwen extensions uninstall ud-agent-skill-mcp-plugin`. Restart after either action. If extension conversion or workspace discovery fails, run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect qwen` in the project, or use a native archive's `ud-agent connect qwen` to include Node. Inspect `/mcp` for connection errors. [Qwen extensions](https://qwenlm.github.io/qwen-code-docs/en/users/extension/introduction/)

### DeepSeek Harness

Use the official local developer-preview harness, pinned to `@deepseek-ai/dsh@0.2.2-rc.1`, with Node 24 or 26. In its treebank session, ask it to connect the published UD MCP client and six skills:

```sh
npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect deepseek
```

The connector registers the official `@deepseek-ai/dsh-mcp-client` in the selected profile and copies skills into `.dsh/skills/`. Start a new session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Look for `mcp__ud__` tools; the first operation prepares its worker.

Upgrade the UD integration by rerunning the connector with its exact new version; use `--check` for diagnostics and `--remove` to uninstall its owned entry. Keep the harness preview version pinned until its new configuration has been checked. Missing tools usually mean the wrong profile or a session created before the change. [Official MCP client](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md)

### OpenClaw

Use current OpenClaw on the machine holding your treebank. Install the compatible bundle through its own plugin manager:

```sh
openclaw plugins install ud-agent-skill-mcp-plugin --marketplace mehmetoguzderin/ud-agent-skill-mcp-plugin
openclaw plugins list
```

The bundle maps its skills and MCP tools into eligible local agent runtimes. Its coordinator uses Node 24 or 26, already required for the npm-backed route. Start a new session in the treebank and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Worker preparation is automatic on first use. OpenClaw owns the bundle registration; inspect it with `openclaw plugins inspect ud-agent-skill-mcp-plugin`.

Upgrade or uninstall through OpenClaw's plugin manager. Direct alternative: ask the agent to run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect openclaw`. That route merges `~/.openclaw/openclaw.json` at `mcp.servers.ud` and installs owned skills; use `--check` or `--remove` to manage it. ACP and remote runtimes have separate projection rules; inspect whether the selected runtime wires MCP tools before requesting work. [OpenClaw bundles](https://docs.openclaw.ai/plugins/bundles)

### Pi harness

Pi has native MCP support. In the treebank folder, register the pinned published coordinator:

```sh
pi mcp add ud -- npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 mcp --discover-workspace
pi mcp list
```

Node 24 or 26 is needed for this route. To install the six skills as well, ask Pi to run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect pi`; native archive users can run `ud-agent connect pi`. Start a new session, or `/reload`, and ask: **“Use ud-validate to validate this treebank, then show all errors.”** First use prepares the worker. Pi stores MCP configuration in `~/.pi/agent/mcp.json` or project `.pi/mcp.json`.

Upgrade by reconnecting with the new exact package version. Remove with `pi mcp remove ud`; use the connector's `--remove` for owned skills too. `/mcp` shows connection errors and configuration scope. [Pi MCP](https://raw.githubusercontent.com/earendil-works/pi/main/packages/coding-agent/docs/mcp.md)

### Gemini CLI

Use Gemini's native extension installer in the treebank folder:

```sh
gemini extensions install https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin
gemini extensions list
```

The extension includes the MCP connection and six skills; its npm-backed coordinator requires Node 24 or 26. Restart Gemini and ask: **“Use ud-validate to validate this treebank, then show all errors.”** The first operation prepares its worker. Gemini owns extension state under `~/.gemini/extensions/`.

Update through Gemini's extension manager; uninstall with `gemini extensions uninstall ud-agent-skill-mcp-plugin`. If extension loading is blocked, run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect gemini` in the project; the native archive also provides `ud-agent connect gemini`. Inspect `/mcp` and restart after connection changes. [Gemini extensions](https://geminicli.com/docs/extensions/)

### Cursor

With current Cursor and Node 24 or 26, open the treebank project and ask Cursor's agent to register the published MCP server and six skills:

```sh
npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect cursor
```

The connector merges Cursor's native MCP configuration and installs the skills for this workspace. Restart the agent session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** First use prepares its worker. Cursor's MCP panel shows the connection; user/project configuration remains in `~/.cursor/mcp.json` or `.cursor/mcp.json`.

Upgrade by rerunning the exact new package version. Use `connect cursor --check` to diagnose and `--remove` to remove only the owned integration. If the server appears in another workspace only, run the connector in the intended treebank project. [Cursor MCP](https://cursor.com/docs/context/model-context-protocol)

### VS Code GitHub Copilot

Use current VS Code with GitHub Copilot enabled. Open the treebank folder and select the **Copilot** harness. In **Agent Customizations → Browse → Configure Marketplaces → Add Marketplace**, enter `mehmetoguzderin/ud-agent-skill-mcp-plugin`. Return to Browse, select that marketplace, and install `ud-agent-skill-mcp-plugin`. Review the normal marketplace trust prompt. This npm-backed plugin needs Node 24 or 26.

Start a new Copilot agent session and ask: **“Use ud-validate to validate this treebank, then show all errors.”** Skills and MCP arrive together; first use prepares its worker. Update or remove the plugin from the same Customizations editor. If plugins are disabled by your organization, ask Copilot to run `npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 connect vscode` in the project.

Inspect MCP status in the selected harness. Copilot Global stores MCP registrations in `~/.copilot/mcp-config.json`; VS Code Local uses `.vscode/mcp.json`. Use `connect vscode` (or `connect vscode-copilot`) for the project `.vscode/mcp.json` registration and `.github/skills/`. The legacy `connect copilot` route preserves its project `.mcp.json` registration; it does not edit Copilot Global's user file. Manage that separate global scope in its host UI. Portable skills can also use `~/.copilot/skills/` where supported. Use the connector's `--check` or `--remove` for its direct integration. [VS Code agent plugins](https://code.visualstudio.com/docs/agent-customization/agent-plugins)

<!-- END GENERATED HOST GUIDES -->

## Runtime choices

An explicit choice wins. Otherwise a usable saved selection is reused, followed by an already available OCI runtime. Docker Desktop or Engine is accepted when it works. Podman is another option on Linux.

In `0.1.0-beta.1`, core validation passed on Apple Container. PNG and PDF rendering failed during Chromium sandbox startup. WSL Containers setup failed in the Windows x64 test, and Windows ARM64 WSL Containers has no native test result. If Docker is already available, run this from your treebank folder to select it for rendering or to work around WSL Containers setup.

```sh
ud-agent doctor --fix --engine docker --required-tools sentence_render
```

The first Lima guest startup can take several minutes while the guest initializes. Later requests reuse the verified VM and cached dependencies.

When OCI is genuinely unavailable, setup downloads only this host's verified userspace core: reuse compatible uv, acquire its verified pinned binary if needed, then use a compatible verified Python. A private Python venv is the final fallback when uv is unavailable. Supported interpreter ABIs are CPython 3.14 and 3.15. Private environments are reused across workspaces. SVG and HTML use the core pack; PNG and PDF prepare the browser pack only on demand. Provider assets are downloaded only when that provider is selected for setup. Other platforms' Perl, browser and VM payloads are not installed. Corrupt artifacts fail integrity checks rather than triggering a fallback.

Offline installations can preseed the exact versioned `ud-agent-userspace-PLATFORM-ARCH.tar.gz`, `ud-agent-provider-ENGINE-PLATFORM-ARCH.tar.gz` and render-base archives with their release checksums in the product's owned cache. Vendor browsers also require the exact publisher archive named by the browser recipe. The same integrity and containment checks apply to cached bytes.

For a fully offline machine, transfer its native archive, the matching dependency archives and the final release checksum manifest. Verify those checksums before extraction. The default userspace data directory is `~/Library/Application Support/ud-agent/userspace` on macOS, `$XDG_DATA_HOME/ud-agent/userspace` (otherwise `~/.local/share/ud-agent/userspace`) on Linux, and `%LOCALAPPDATA%\ud-agent\data\userspace` on Windows. Keep these directories private to your account.

| Offline asset | Cache location relative to the userspace directory |
|---|---|
| Selected host core archive | `core-cache/<archive-sha256>.tar.gz` |
| Selected host render base | `render-cache/<archive-sha256>.tar.gz` |
| Browser ZIP from its verified Google recipe | `render-vendor-cache/<publisher-sha256>.zip` |
| Browser MSI from its verified Microsoft recipe | `render-vendor-cache/<publisher-sha256>.msi` |
| Windows uv ZIP from Astral | `tools/uv-<publisher-sha256>.zip` |
| Windows Perl and VC runtime supplier archives | `perl-vendor-cache/<publisher-sha256>.conda` or `perl-vendor-cache/<publisher-sha256>.tar.bz2`, matching the supplier format |

Use the 64 hexadecimal digest characters without the `sha256:` prefix in cache filenames. Provider archives use the adjacent profile directory `<userspace-directory>-ENGINE/provider-cache/<archive-sha256>.tar.gz`, where `ENGINE` is the selected `apple-container`, `lima-nerdctl` or `wslc`. The render base's `manifest.json` identifies its hash-bound acquisition recipe; use that recipe's publisher URL, size and checksum for the browser archive. Preseed only the selected host and requested provider. Then run `ud-agent doctor --fix --offline --engine userspace` from the treebank to prepare core work, or add `--required-tools sentence_render` to prepare PNG/PDF as well. The corresponding platform runtime can be selected with `--engine ENGINE`. Missing offline inputs are reported as prerequisites; they never cause an unverified download or a weaker integrity check.

OCI worker archives have their own checksums in the release manifest. Cache the selected architecture's archive at `<userspace-directory>-ENGINE/images/<archive-sha256>.tar`; use an OCI transport for Apple Container, Lima or WSL Containers. Docker and Podman accept their declared OCI or Docker transports; both Docker selectors use the `-docker` cache directory. The coordinator verifies the image content as well as the archive bytes before execution.

The result identifies the selected runtime and its actual isolation. Ordinary workers use a nonzero identity, confined input/output, resource bounds and disabled networking. Userspace supports trusted built-in operations with reduced isolation; project-authored executable code requires OCI. No engine socket or credentials are passed into workers.

GHCR core and render images are worker packs, **not standalone MCP servers**. Your agent connects to the coordinator, which selects and prepares the worker.

## Doctor and repair

From the treebank folder, ask your agent to run:

```sh
npx -y @mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1 doctor
```

Use `doctor --fix` for idempotent repair. Native archive users run `ud-agent doctor` or `ud-agent doctor --fix`. To inspect a direct connection, use `connect HOST --check`; `connect HOST --remove` removes only that connector's owned integration. Changing a connection requires a fresh agent session.

For advanced maintenance, `ud-agent clean --cache --all` cleans owned caches across configured runtime profiles, and `ud-agent uninstall --owned-runtime --all` removes owned runtime installations. Use `--engine NAME` to select one profile instead. These commands retain shared engines and shared images; removing the host plugin remains the first uninstall step.

If a folder is not recognized, select the actual treebank with `--working-tree /absolute/path/to/treebank`. Home and filesystem roots are not silently granted. If `npx` is missing, install Node 24 or 26 or use a native archive. If a GUI cannot launch a command, use the connector with the native executable's absolute path. Existing linguistic errors are validation findings; a cancelled, incomplete or failed execution is not a validation pass.

Revision and history comparisons also need Git available to the coordinator. Use your existing Git installation; ordinary file validation and editing do not require a Git repository. A missing Git prerequisite is reported before a history comparison can run.

## Native downloads

Choose a native archive when you want Node prepared automatically. Keep its directory structure intact, run its `bin/ud-agent` (`bin\ud-agent.exe` on Windows), and use `connect HOST` or `doctor`. Download and compare the SHA-256 against the matching final release manifest before extraction.

<!-- BEGIN GENERATED RELEASE ARCHIVES -->
| OS | CPU | Native archive | MCPB |
| --- | --- | --- | --- |
| macOS | Apple silicon | [`ud-agent-skill-mcp-plugin-darwin-arm64.tar.gz`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-darwin-arm64.tar.gz) | [bundle](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-darwin-arm64.mcpb) |
| Linux | arm64 | [`ud-agent-skill-mcp-plugin-linux-arm64.tar.gz`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-linux-arm64.tar.gz) | [bundle](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-linux-arm64.mcpb) |
| Linux | x86-64 | [`ud-agent-skill-mcp-plugin-linux-x64.tar.gz`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-linux-x64.tar.gz) | [bundle](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-linux-x64.mcpb) |
| Windows | arm64 | [`ud-agent-skill-mcp-plugin-win32-arm64.zip`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-win32-arm64.zip) | [bundle](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-win32-arm64.mcpb) |
| Windows | x86-64 | [`ud-agent-skill-mcp-plugin-win32-x64.zip`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-win32-x64.zip) | [bundle](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-skill-mcp-plugin-win32-x64.mcpb) |

Download [SHA256SUMS](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/SHA256SUMS) alongside your selected asset. The checksum manifest covers the final release files and intentionally does not hash itself.
<!-- END GENERATED RELEASE ARCHIVES -->

macOS and Linux archives and MCPB bundles include Node. On Windows, the native launcher downloads the pinned Node executable from Node.js on first start and checks its SHA-256 and size before running it. Run `bin\ud-agent.exe --help` from the extracted archive to prepare Node before opening the extension. For offline use, take the URL and SHA-256 from `runtime/windows-node.json` in the extracted package and preseed the verified executable at `%LOCALAPPDATA%\ud-agent\data\node-cache\node-SHA256.exe`. Use the 64 hexadecimal characters without the `sha256:` prefix. Set `UD_AGENT_OFFLINE=1` to require the local cache.

On macOS use `shasum -a 256 ARCHIVE`; on Linux use `sha256sum ARCHIVE`; on Windows use `Get-FileHash ARCHIVE -Algorithm SHA256`. Install a new release beside the old one, reconnect your agent to its executable, then remove the old extracted directory. No global Python or Perl installation is needed.

## Skills

The six skills guide complete workflows: [validation](skills/ud-validate/SKILL.md), [editing](skills/ud-edit/SKILL.md), [investigation](skills/ud-investigate/SKILL.md), [comparison](skills/ud-compare/SKILL.md), [rules and previews](skills/ud-rules-docs/SKILL.md), and [local release preparation](skills/ud-release/SKILL.md). Each includes its own supporting references. Native plugin routes include them. Direct connectors copy their complete folders into the host's skill directory with ownership receipts. Start a new session and ask, for example: **“Use ud-validate to validate this treebank and explain every error.”**

Standalone skills are also available as `ud-agent-skill-mcp-plugin-skills.tar.gz`. Extract the six skill directories into the host's skill location and connect the coordinator separately; instructions alone do not supply tools or workspace access.

## Published coordinates

<!-- BEGIN GENERATED RELEASE COORDINATES -->
| Distribution | Release coordinate |
| --- | --- |
| npm | `@mehmetoguzderin/ud-agent-skill-mcp-plugin@0.1.0-beta.1` |
| GitHub Releases | [mehmetoguzderin/ud-agent-skill-mcp-plugin `v0.1.0-beta.1`](https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/tag/v0.1.0-beta.1) |
| Core worker image | `ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-core` |
| Render worker image | `ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-render` |
| MCP Registry | `io.github.mehmetoguzderin/ud-agent-skill-mcp-plugin` |
| Owned marketplace | `ud-agent-skill-mcp-plugin@ud-agent-skill-mcp-plugin` |
<!-- END GENERATED RELEASE COORDINATES -->

## Advanced MCP configuration

Most users can use the host's plugin manager or `connect` without editing configuration. For a custom local MCP client, launch the installed coordinator with `mcp --allow-root /absolute/path/to/your-treebank`. The npm route requires Node 24 or 26. Existing explicit `UD_AGENT_ALLOWED_ROOTS` configurations remain supported:

```json
{
  "mcpServers": {
    "ud": {
      "command": "/absolute/path/to/ud-agent",
      "args": ["mcp"],
      "env": {
        "UD_AGENT_ALLOWED_ROOTS": "[\"/absolute/path/to/your-treebank\"]"
      }
    }
  }
}
```

VS Code Local uses a different envelope from Copilot Global:

```json
{
  "servers": {
    "ud": {
      "type": "stdio",
      "command": "/absolute/path/to/ud-agent",
      "args": ["mcp"],
      "env": {
        "UD_AGENT_ALLOWED_ROOTS": "[\"/absolute/path/to/your-treebank\"]"
      }
    }
  }
}
```

Merge an entry into an existing configuration; preserve unrelated servers. On Windows, escape backslashes in JSON. Workspace paths must be absolute, and a tool argument is not itself a grant. The coordinator keeps stdout exclusively for MCP protocol traffic.


### Small local models

All 104 tool definitions together measure about 118k tokens (MiniCPM tokenizer). A host that sends every MCP tool schema eagerly cannot fit a 32k-context local model. Hosts that defer large tool sets behind a tool search (Qwen Code, Claude Code) need about 1.4k tokens. With a small model, limit the `ud` server to the operations of the skills you use. For Qwen Code and Gemini CLI, set `"includeTools"` in the `ud` entry of `mcpServers`. For Codex, set `enabled_tools` in `[mcp_servers.ud]`. Validation needs `["validation_report", "sentence_validation_report", "workspace_inspect", "fix_plan", "plan_apply", "treebank_review", "project_consistency_report"]` (about 2.5k tokens). `quality/skills.json` lists the operations of each skill. The opt-in [QSLM loop](evals/local/README.md#qslm-improvement-loop) measures the effect.

### Editing and recovery guarantees

Edits use cooperative locks, stale-input checks, recoverable journals and per-file atomic changes. Multi-file edits do not promise a globally atomic commit or portable compare-and-swap. On Windows, ordinary-user NTFS edits preserve the same file object and its security/stream metadata when the actual TxF capability probe succeeds. Microsoft warns that [Transactional NTFS may become unavailable](https://learn.microsoft.com/en-us/windows/win32/fileio/about-transactional-ntfs); the alternative metadata route requires the current token's existing security privileges. Missing guarantees block the affected apply operation. See the [filesystem transaction contract](contracts/filesystem-transactions.md) for interruption and recovery behavior. Windows execution remains a separate native acceptance check.

## Development

For the three exact QSLMs on Apple silicon, the opt-in [twelve-hour headless profile](evals/local/README.md#twelve-hour-headless-optimization) prepares eleven Docker harnesses and measures a common before/after core plus final harness coverage. Its reports preserve blockers and require all 117 enabled combinations to pass before claiming headless qualification.

Explicit local model experiments use `npm run eval:local -- inventory`, followed
by opted-in private preparation and execution. See the
[local evaluation guide](evals/local/README.md) for the three exact models,
seven scenarios, bounded native-agent campaign, evidence, and current adapter
limitations. For short group-by-group improvement rounds with one CPU-capable
quantized model across three harness surfaces, use the `loop-*` commands in
the same guide. Live inference is excluded from ordinary tests and CI.

Use the exact dependency locks with Node 24/26, Python 3.14/3.15 and the pinned Rust toolchain. Run `npm ci --ignore-scripts`, the locked Python setup, `npm test` and `npm run test:mutation`. Original acceptance includes static and generated-file checks; `npm run check` is also available for a quick standalone check. No empty, skipped or missing required suites pass. Local fixture publication tests do not publish to production.

Concretely, on a fresh checkout (verified on native Linux amd64 with Node 26.13.0, uv 0.13.7 and Python 3.15.2):

```sh
npm ci --ignore-scripts
uv sync --locked --all-groups --python 3.15   # the locked Python setup; CI passes --python python
cargo fetch --locked                          # npm test builds Rust offline, so prefetch both lockfiles
cargo fetch --locked --manifest-path scripts/quality/rust-assertion-parser/Cargo.toml
npm run build
npm run check
npm test                                      # prints {"status":"passed-locally",...} when complete
```

`--python python` (as in CI) needs a `python` executable on `PATH`; otherwise name the version as above and uv uses or downloads a matching interpreter. `rustup` installs the toolchain pinned in `rust-toolchain.toml` on first use. `npm test` copies the source into a private temporary directory and fails if the working tree changes while it runs, so do not edit files during a run. Remove `.artifacts/` to start again from scratch.

On a native Linux amd64 (x64) host, first confirm the platform as the CI `linux/x64` job does, then run the same steps:

```sh
EXPECTED_PLATFORM=linux EXPECTED_ARCH=x64 node scripts/quality/assert-platform.mjs
```

On native Windows x64 the CI `windows/x64` job (`windows-2025-vs2026`) uses the same steps in PowerShell, with Node from `.node-version`, Python 3.15.2, uv 0.13.7, Git, and Rust using the MSVC Build Tools (C++ workload). Confirm the platform with `$env:EXPECTED_PLATFORM='windows'; $env:EXPECTED_ARCH='x64'; node scripts/quality/assert-platform.mjs`. `npm run test:mutation` uses the portable runner there.

To repeat this in a clean container (Docker on the native host; the tests run as a non-root user):

```sh
docker run --rm --init -v "$PWD":/src:ro node:26.13.0-trixie bash -euc '
  useradd -m dev
  su dev -c "set -eux
    umask 022
    cp -a /src \$HOME/ud-mcp && cd \$HOME/ud-mcp && rm -rf node_modules .venv target .artifacts dist
    curl -LsSf https://astral.sh/uv/0.13.7/install.sh | sh
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.99.0
    . \$HOME/.cargo/env && export PATH=\$HOME/.local/bin:\$PATH
    uv python install 3.15.2
    EXPECTED_PLATFORM=linux EXPECTED_ARCH=x64 node scripts/quality/assert-platform.mjs
    npm ci --ignore-scripts && uv sync --locked --all-groups --python 3.15
    cargo fetch --locked && cargo fetch --locked --manifest-path scripts/quality/rust-assertion-parser/Cargo.toml
    npm run build && npm run check && npm test"'
```

The tests check executable and file ownership/permission bits, so they need `umask 022` (Debian's `su` defaults to `002`), a default Rust toolchain (tests also run Cargo outside the checkout), a Python 3.14/3.15 executable on `PATH` (`uv python install` puts `python3.15` in `~/.local/bin`), and an init process (`--init`) that reaps orphaned test processes. The same applies on a bare host.

If the Docker daemon has no outbound NAT, add `--network host`. `npm run test:mutation` runs the same way after `npm test` (inside the container too); off Linux arm64 it uses the portable runner described below.

CI and releases use 18 reviewed mutation cases covering JavaScript/TypeScript, Python, Rust, Perl, contracts, generators and release integrity. Every scheduled case must fail its independent behavioral assertion under the protected OCI runner. The reported score is **100% of the bounded mutation corpus**. Optional exhaustive language mutation testing is available through `npm run test:mutation:exhaustive`; its results have their own scope and do not replace the bounded report.

Mutation tests require Docker with native Linux arm64 execution and the verified development SDK. CI prepares that SDK in a separate cached setup job and verifies it again after restoration. A cold SDK setup can take longer than the warm checks. The warm CI timing target is approximately ten minutes; retained reports record actual durations. On any other host (for example Linux x64), or with `npm run test:mutation -- --runner portable`, the bounded gate runs the same 18 reviewed cases, assertions and assessment as host processes in a private snapshot, needing only the Development toolchain (Node, Python via `.venv`, Cargo). Its summary records `runner.kind` `portable-host` with `isolation` `host-process`, so it is not protected OCI evidence; `--runner protected` keeps the arm64 OCI path.

Release evidence starts with [independent test and mutation discovery](release/ACCEPTANCE.md), before consuming results. `npm test` retains per-case original-test outcomes and rejects omissions against that discovery. Use `npm run test:evidence` to choose exact executables and the report directory; see the linked guide for its arguments. Installed, native-provider and image-build evidence remain separate.

Run platform validation on native hosts or Actions runners for the target architecture. Use the platform assertion above before the Development steps, and follow [runtime/README.md](runtime/README.md) for native worker image builds. Cross-builds, original tests, portable mutation tests, protected mutation tests and release acceptance retain their respective evidence scopes.

[Public contracts](contracts/public-contract.md) · [Release and acceptance](release/README.md) · [Security](SECURITY.md)
