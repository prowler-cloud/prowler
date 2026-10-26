# Prowler for Claude Code

End-to-end cloud security and compliance from inside [Claude Code](https://www.claude.com/product/claude-code), powered by the [Prowler MCP server](https://docs.prowler.com/projects/prowler-mcp/). The plugin lets Claude walk a Prowler Cloud-connected account through a compliance assessment and remediate findings until the chosen security or industry framework is compliant.

> **Preview**: this plugin is under active development. Report issues at <https://github.com/prowler-cloud/prowler/issues> or join the [Slack community](https://goto.prowler.com/slack).

## What it does

Prowler Cloud connects Claude to your cloud security posture. The bundled `framework-compliance-triage` skill checks that a provider account is connected to Prowler Cloud, reads the latest scan and compliance report for the framework you pick (CIS, PCI-DSS, NIST, Prowler ThreatScore and more), and then walks you through fixing each failed requirement. Every change is proposed first and applied only after you approve it.

## Supported providers

Any provider Prowler Cloud supports, including AWS, Azure, GCP, Kubernetes, Microsoft 365, GitHub, Google Workspace, Cloudflare, Oracle Cloud, Alibaba Cloud, Huawei Cloud, OpenStack, Linode, Scaleway, STACKIT, E2E Networks, NHN Cloud, MongoDB Atlas, Okta, Vercel, VCF, Infrastructure as Code, container images and LLMs. The full, growing list lives in the [Prowler Registry](https://registry.prowler.com/providers). Prowler also supports custom providers, so you can add your own and use them with this plugin.

## Requirements

- [Claude Code](https://www.claude.com/product/claude-code) installed and signed in.
- A [Prowler Cloud](https://cloud.prowler.com) account (the free tier is enough to start).
- A Prowler API key — create one at <https://cloud.prowler.com/profile>.

## Installation

From the Claude directory, open **Customize > Plugins > Discover**, search for **Prowler Cloud** and select **Add**. In Claude Code you can also install it from the command line:

Inside a Claude Code session:

```text
/plugin marketplace add prowler-cloud/prowler
/plugin install prowler@prowler-plugins
```

Or, if you already have the repo checked out locally:

```text
/plugin marketplace add /absolute/path/to/prowler
/plugin install prowler@prowler-plugins
```

## Configuration

On first install, Claude Code prompts for your **Prowler API key**. It is stored securely (macOS keychain or `~/.claude/.credentials.json`) and used to authenticate against Prowler Cloud.

To rotate the key, uninstall and reinstall the plugin — Claude Code will prompt again.

## Verify the install

In a Claude Code session:

```text
/mcp          → "prowler" appears as a connected server
/plugin       → "prowler" enabled, skill listed as prowler:framework-compliance-triage
```

If `/mcp` reports the `prowler` server as failed, the most common cause is a rejected API key — re-issue one in Prowler Cloud and reinstall the plugin so it re-prompts.

## Usage

Open a conversation that mentions the framework you want to comply with. Examples:

- *"Make my AWS production account compliant with CIS 4.0."*
- *"Make my current Terraform project compliant with the Prowler ThreatScore Compliance Framework based on the latest scan results."*
- *"Help me get to 100% on PCI-DSS for this GCP project."*

You pick a **primary tool** (Terraform, gh / az / aws CLI, web console, or mixed) and a **mode**:

- **Claude-assisted** (default). Claude shows each fix — target resource, exact commands, side effects, reversibility — and waits for your go-ahead before applying.
- **Claude autonomous**. Claude presents a single up-front plan grouped by shared fixes, waits for one confirmation, then proceeds. It pauses mid-loop if a fix has wide blast radius or a finding is not applicable.

Claude tracks progress in a markdown report under `.prowler/` at your project root — one file per framework × account. Open it any time to see exactly where the flow is. When all findings are addressed, Claude proposes a fresh Prowler scan to verify everything end-to-end.

## Data and privacy

The plugin stores nothing itself. It connects to the Prowler MCP server at `https://mcp.prowler.com/mcp`, authenticating with the API key you provide (kept in your system keychain and sent only as a bearer token to that server). Through it, Claude reads your Prowler Cloud providers, scans, findings, compliance results and resource metadata, and can trigger scans. It also queries the public Prowler Hub and Prowler documentation. The remediation report is written locally under `.prowler/` in your project. Nothing is sent to any other service. See the [Prowler privacy policy](https://prowler.com/privacy-policy) for how Prowler Cloud handles account data.

## Uninstalling

```text
/plugin uninstall prowler@prowler-plugins
/plugin marketplace remove prowler-plugins
```

The stored API key is removed automatically.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `/mcp` shows `prowler` as failed | Rejected API key | Generate a new one in Prowler Cloud and reinstall the plugin to re-prompt. |
| Skill not invoked when expected | The skill description didn't match the prompt | Mention the framework name plus "compliance" or "compliant" in your prompt. |
| "Framework not supported" | Prowler Hub does not list the framework for that provider | Open an issue or PR at <https://github.com/prowler-cloud/prowler>. |

## License

Apache 2.0 — see [LICENSE](LICENSE).
