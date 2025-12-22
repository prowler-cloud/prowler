# Prowler MCP Server

**Prowler MCP Server** brings the entire Prowler ecosystem to AI assistants through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It enables seamless integration with AI tools like Claude Desktop, Cursor, and other MCP clients, allowing interaction with Prowler's security capabilities through natural language.

> **Preview Feature**: This MCP server is currently under active development. Features and functionality may change. We welcome your feedback—please report any issues on [GitHub](https://github.com/prowler-cloud/prowler/issues) or join our [Slack community](https://goto.prowler.com/slack).

## Key Capabilities

### Prowler Cloud and Prowler App (Self-Managed)

Full access to Prowler Cloud platform and self-managed Prowler App for:
- **Findings Analysis**: Query, filter, and analyze security findings across all your cloud environments
- **Provider Management**: Create, configure, and manage your configured Prowler providers (AWS, Azure, GCP, etc.)
- **Scan Orchestration**: Trigger on-demand scans and schedule recurring security assessments
- **Resource Inventory**: Search and view detailed information about your audited resources
- **Muting Management**: Create and manage muting rules to suppress non-critical findings
- **Compliance Reporting**: View compliance status across frameworks and drill into requirement-level details

### Prowler Hub

Access to Prowler's comprehensive security knowledge base:
- **Security Checks Catalog**: Browse and search **over 1000 security checks** across multiple Prowler providers
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

### 1. Prowler Cloud MCP Server (Recommended)

**Use Prowler's managed MCP server at `https://mcp.prowler.com/mcp`**

- No installation required
- Managed and maintained by Prowler team
- Always up-to-date

```json
{
  "mcpServers": {
    "prowler": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.prowler.com/mcp",
        "--header",
        "Authorization: Bearer pk_YOUR_API_KEY_HERE"
      ]
    }
  }
}
```

### 2. Local STDIO Mode

**Run the server locally on your machine**

- Runs as a subprocess of your MCP client
- Requires Python 3.12+ or Docker

### 3. Self-Hosted HTTP Mode

**Deploy your own remote MCP server**

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
- `prowler_app_*` - Prowler Cloud and App (Self-Managed) management tools
- `prowler_hub_*` - Prowler Hub catalog and compliance tools
- `prowler_docs_*` - Prowler documentation search and retrieval

## Architecture

```
prowler_mcp_server/
├── server.py                 # Main orchestrator (imports sub-servers with prefixes)
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
- **Auto-Discovery**: Prowler App tools are automatically discovered and registered
- **LLM Optimization**: Response models minimize token usage by excluding empty values
- **Dual Transport**: Supports both STDIO (local) and HTTP (remote) modes

## Use Cases

The Prowler MCP Server enables powerful workflows through AI assistants:

**Security Operations**
- "Show me all critical findings from my AWS production accounts"
- "Register my new AWS account in Prowler and run a scheduled scan every day"
- "List all muted findings and detect what findgings are muted by a not enough good reason in relation to their severity"

**Security Research**
- "Explain what the S3 bucket public access Prowler check does"
- "Find all Prowler checks related to encryption at rest"
- "What is the latest version of the CIS that Prowler is covering per provider?"

**Documentation & Learning**
- "How do I configure Prowler to scan my GCP organization?"
- "What authentication methods does Prowler support for Azure?"
- "How can I contribute with a new security check to Prowler?"

## Requirements

**For Prowler Cloud MCP Server:**
- Prowler Cloud account and API key (only for Prowler Cloud/App features)

**For self-hosted STDIO/HTTP Mode:**
- Python 3.12+ or Docker
- Network access to:
  - `https://hub.prowler.com` (for Prowler Hub)
  - `https://docs.prowler.com` (for Prowler Documentation)
  - Prowler Cloud API or self-hosted Prowler App API (for Prowler Cloud/App features)

> **No Authentication Required**: Prowler Hub and Prowler Documentation features work without authentication. A Prowler API key is only required to access Prowler Cloud or Prowler App (Self-Managed) features.

## Configuring MCP Hosts

To configure your MCP host (Claude Code, Cursor, etc.) see the [Configuration Guide](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp) for detailed setup instructions.

## Contributing

For developers looking to extend the MCP server with new tools or features:

- **[Developer Guide](https://docs.prowler.com/developer-guide/mcp-server)**: Step-by-step instructions for adding new tools
- **[AGENTS.md](./AGENTS.md)**: AI agent guidelines and coding patterns

## Related Products

- **[Prowler Hub](https://hub.prowler.com)**: Browse security checks and compliance frameworks
- **[Prowler Cloud](https://cloud.prowler.com)**: Managed Prowler platform
- **[Lighthouse AI](https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai)**: AI security analyst

## License

This project follows the repository's main license. See the [LICENSE](../LICENSE) file at the repository root.
