# Prowler MCP Server

**Prowler MCP Server** brings the entire Prowler ecosystem to AI assistants through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It enables seamless integration with AI tools like Claude Desktop, Cursor, and other MCP clients, allowing interaction with Prowler's security capabilities through natural language.

> **Preview Feature**: This MCP server is currently under active development. Features and functionality may change. We welcome your feedback—please report any issues on [GitHub](https://github.com/prowler-cloud/prowler/issues) or join our [Slack community](https://goto.prowler.com/slack).

## Key Capabilities

### Prowler Cloud, Prowler Private Cloud & Prowler Local Server

Full access to your Prowler data (Prowler Cloud, Prowler Private Cloud, or Prowler Local Server) for:
- **Findings Analysis**: Query, filter, and analyze security findings across all your cloud environments
- **Finding Groups Analysis**: Triage findings grouped by check ID and drill down into affected resources
- **Provider Management**: Create, configure, and manage your configured Prowler providers (AWS, Azure, GCP, etc.)
- **Scan Orchestration**: Trigger on-demand scans, track their progress, and schedule a daily scan
- **Resource Inventory**: Search and view detailed information about your audited resources
- **Muting Management**: Create and manage muting rules to suppress non-critical findings
- **Compliance Reporting**: View compliance status across frameworks and drill into requirement-level details
- **Attack Paths Analysis**: Analyze privilege escalation chains through graph-based analysis of cloud resource relationships
- **Integrations Management**: Set up and troubleshoot where Prowler sends its results (Amazon S3, AWS Security Hub, Jira), and turn findings into Jira work items
- **User & Role Management**: List the users in your tenant, identify the authenticated user, browse RBAC roles, and set the role a user holds

### Prowler Cloud Management

Prowler Cloud-only workflow and configuration features (`prowler_cloud_*` tools). These are available only on the [hosted Prowler MCP](#1-hosted-prowler-mcp-recommended), since they manage features that exist only in Prowler Cloud:
- **Scan Configurations**: Read, create, update, and delete reusable scan configurations and attach them to providers (providers without one use the default)
- **Findings Triage**: Read and set a finding's triage status and leave notes documenting the decision, without suppressing the finding
- **Scan Scheduling**: Read and configure recurring scan schedules (daily, interval, weekly, monthly), one provider at a time or in bulk
- **Alerts**: Read and manage alert rules and recipients, dry-run rule conditions before saving, and browse the fired-alert history

### Prowler Hub

Access to Prowler's comprehensive security knowledge base:
- **Security Checks Catalog**: Browse and search **over 2,000 security checks** across multiple Prowler providers
- **Check Implementation**: View the Python code that powers each security check
- **Automated Fixers**: Access remediation scripts for common security issues
- **Compliance Frameworks**: Explore mappings to **over 70 compliance standards and frameworks**
- **Provider Services**: View available services and checks for all supported Prowler providers

### Prowler Documentation

Search and retrieve official Prowler documentation:
- **Intelligent Search**: Full-text search across all Prowler documentation
- **Contextual Results**: Get relevant documentation pages with highlighted snippets
- **Document Retrieval**: Access complete markdown content of any documentation file

## Documentation

For comprehensive guides and tutorials, see the official documentation:

| Guide | Description |
|-------|-------------|
| [Overview](https://docs.prowler.com/getting-started/products/prowler-mcp) | Key capabilities, use cases, and deployment options |
| [Installation](https://docs.prowler.com/getting-started/installation/prowler-mcp) | Docker, PyPI, and source installation |
| [Configuration](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp) | Configure Claude Desktop, Cursor, and other MCP clients |
| [Tools Reference](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp-tools) | Complete reference of all tools |
| [Developer Guide](https://docs.prowler.com/developer-guide/mcp-server) | How to extend with new tools |

## Deployment Options

Prowler MCP Server can be used in three ways:

### 1. Hosted Prowler MCP (Recommended)

**Use Prowler's managed MCP server at `https://mcp.prowler.com/mcp`**

- No installation required
- Managed and maintained by Prowler team
- Always up-to-date

Install a reviewed version of `mcp-remote` in a dedicated local workspace first. Avoid running `npx mcp-remote` directly because it can download and execute a new package version on each run.

```bash
mkdir -p ~/.local/share/prowler-mcp-bridge
cd ~/.local/share/prowler-mcp-bridge
npm init -y
npm install --save-exact mcp-remote@0.1.38
```

```json
{
  "mcpServers": {
    "prowler": {
      "command": "/absolute/path/to/.local/share/prowler-mcp-bridge/node_modules/.bin/mcp-remote",
      "args": [
        "https://mcp.prowler.com/mcp",
        "--header",
        "Authorization: Bearer pk_YOUR_API_KEY_HERE"
      ]
    }
  }
}
```

### 2. Local STDIO Mode

Run the server locally on your machine:

- Runs as a subprocess of your MCP client
- Requires Python 3.12+ or Docker

### 3. Self-Hosted HTTP Mode

Deploy your own remote MCP server:

- Full control over deployment
- Requires Python 3.12+ or Docker

See the [Installation Guide](https://docs.prowler.com/getting-started/installation/prowler-mcp) for complete instructions.

## Quick Installation

### Docker (Recommended)

```bash
docker pull prowlercloud/prowler-mcp

# STDIO mode
docker run --rm -i prowlercloud/prowler-mcp

# HTTP mode
docker run --rm -p 8000:8000 prowlercloud/prowler-mcp --transport http --host 0.0.0.0 --port 8000
```

### From Source

```bash
git clone https://github.com/prowler-cloud/prowler.git
cd prowler/mcp_server
uv run prowler-mcp --help
```

## Available Tools

For complete tool descriptions and parameters, see the [Tools Reference](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp-tools).

### Tool Naming Convention

All tools follow a consistent naming pattern with prefixes:
- `prowler_*` - Prowler Cloud, Prowler Private Cloud & Prowler Local Server management tools
- `prowler_cloud_*` - Prowler Cloud-only management tools (hosted Prowler MCP only)
- `prowler_hub_*` - Prowler Hub catalog and compliance tools
- `prowler_docs_*` - Prowler documentation search and retrieval

## Architecture

```text
prowler_mcp_server/
├── server.py                 # Main orchestrator (mounts sub-servers with namespaces)
├── main.py                   # CLI entry point
├── prowler_hub/              # tools - no authentication required
├── prowler_app/              # tools - authentication required
│   ├── tools/                # Tool implementations
│   ├── models/               # Pydantic models for LLM-optimized responses
│   └── utils/                # API client, authentication, tool loader
└── prowler_documentation/    # tools - no authentication required
```

**Key Features:**
- **Modular Design**: Three independent sub-servers with prefixed namespacing
- **Auto-Discovery**: Prowler tools are automatically discovered and registered
- **LLM Optimization**: Response models minimize token usage by excluding empty values
- **Dual Transport**: Supports both STDIO (local) and HTTP (remote) modes

## Use Cases

The Prowler MCP Server enables powerful workflows through AI assistants:

### Security Operations

- "Show me all critical findings from my AWS production accounts"
- "Register my new AWS account in Prowler and run a scheduled scan every day"
- "List all muted findings and flag the ones whose mute reason is too weak for their severity"
- "Send my failed CIS findings for this provider to Jira as work items"

### Prowler Cloud Management

- "Preview an alert rule for critical AWS findings and create it for my confirmed recipients"
- "Show the triage notes for this finding and mark it as under review"
- "Apply a weekly Monday 06:00 scan schedule to every AWS provider"
- "Create a scan configuration that runs only CIS checks and attach it to my production providers"

### Security Research

- "Explain what the S3 bucket public access Prowler check does"
- "Find all Prowler checks related to encryption at rest"
- "What is the latest version of the CIS that Prowler is covering per provider?"

### Documentation & Learning

- "How do I configure Prowler to scan my GCP organization?"
- "What authentication methods does Prowler support for Azure?"
- "How can I contribute with a new security check to Prowler?"

## Requirements

**For the hosted Prowler MCP:**
- Prowler Cloud account and API key (only for Prowler features)

**For self-hosted STDIO/HTTP Mode:**
- Python 3.12+ or Docker
- Network access to:
  - `https://hub.prowler.com` (for Prowler Hub)
  - `https://docs.prowler.com` (for Prowler Documentation)
  - Prowler Cloud API or Prowler Local Server API (for Prowler features)

> **No Authentication Required**: Prowler Hub and Prowler Documentation features work without authentication. A Prowler API key is only required for the `prowler_*` and `prowler_cloud_*` tools (Prowler Cloud, Prowler Private Cloud, or Prowler Local Server).

## Configuring MCP Hosts

To configure your MCP host (Claude Code, Cursor, etc.) see the [Configuration Guide](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp) for detailed setup instructions.

## Contributing

For developers looking to extend the MCP server with new tools or features:

- **[Developer Guide](https://docs.prowler.com/developer-guide/mcp-server)**: Step-by-step instructions for adding new tools
- **[AGENTS.md](./AGENTS.md)**: AI agent guidelines and coding patterns

## Related Products

- **[Prowler Hub](https://hub.prowler.com)**: Browse security checks and compliance frameworks
- **[Prowler Cloud](https://cloud.prowler.com)**: Fully managed Prowler in the cloud
- **[Lighthouse AI](https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai)**: AI security analyst

## License

This project follows the repository's main license. See the [LICENSE](../LICENSE) file at the repository root.
