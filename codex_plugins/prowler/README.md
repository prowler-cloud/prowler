# Prowler for Codex

Prowler for Codex adds Prowler Cloud security and compliance skills and connects Codex to the Prowler MCP server.

## Prerequisites

- Codex CLI with plugin support. Check with `codex --version` and `codex plugin --help`.
- A Prowler Cloud API key. Create one in [Prowler Cloud](https://cloud.prowler.com).

## Install

Export the API key in the shell that launches Codex. Set `PROWLER_API_KEY` to the raw API key only, without the `Bearer` prefix. Codex adds the bearer prefix automatically. Do not add a real key to a repository, shell history, or shared configuration file.

```bash
export PROWLER_API_KEY=...
codex plugin marketplace add prowler-cloud/prowler --ref master
codex plugin add prowler@prowler-plugins
```

The marketplace does not install Prowler by default. The `codex plugin add` command explicitly installs it.

## Verify

```bash
codex plugin list --marketplace prowler-plugins
```

Start Codex from the same shell, then ask it to list your Prowler providers or to help triage a compliance framework.

## Update and Uninstall

Refresh the marketplace snapshot:

```bash
codex plugin marketplace upgrade prowler-plugins
```

Remove the plugin:

```bash
codex plugin remove prowler@prowler-plugins
```

If you no longer use the marketplace, remove it after uninstalling the plugin:

```bash
codex plugin marketplace remove prowler-plugins
```

## Environment Limitation

The Codex CLI reliably receives `PROWLER_API_KEY` when it starts from the shell where you exported it. Codex Desktop and IDE integrations may not inherit variables from your shell profile, so the plugin can fail to authenticate there even when it works in the CLI.

The Codex plugin workflow does not securely prompt for or store arbitrary API keys. If your Codex surface cannot inherit `PROWLER_API_KEY`, use the manual MCP setup in the [Prowler Codex guide](https://docs.prowler.com/user-guide/ai-agents/codex) instead.
