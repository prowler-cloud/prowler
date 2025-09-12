# Prowler MCP Server

Access the entire Prowler ecosystem through the Model Context Protocol (MCP), the supported capabilities right now are:

- Prowler Hub for checking the current covering in checks, fixers and compliance frameworks in Prowler.

## Requirements

- Python 3.12+
- Network access to `https://hub.prowler.com`

## Installation

### From Sources

It is needed to have [uv](https://docs.astral.sh/uv/) installed.

```bash
git clone https://github.com/prowler-cloud/prowler.git
```

## Running

After installation, start the MCP server via the console script:

```bash
cd prowler/mcp_server
uv run prowler-mcp
```

Alternatively, you can run from wherever you want using `uvx` command:

```bash
uvx /path/to/prowler/mcp_server/
```

## Available Tools

### Prowler Hub

All tools are exposed under the `prowler_hub` prefix.

- prowler_hub_get_check_filters: Return available filter values for checks (providers, services, severities, categories, compliances). Call this before `prowler_hub_get_checks` to build valid queries.
- prowler_hub_get_checks: List checks with option of advanced filtering.
- prowler_hub_search_checks: Full‑text search across check metadata.
- prowler_hub_get_compliance_frameworks: List/filter compliance frameworks.
- prowler_hub_search_compliance_frameworks: Full-text search across frameworks.
- prowler_hub_list_providers: List Prowler official providers and their services.
- prowler_hub_get_artifacts_count: Return total artifact count (checks + frameworks).

## MCP Client Configuration

Configure your MCP client to launch the server with the `uvx` command. Below is a generic snippet; consult your client's documentation for exact locations.

```json
{
  "mcpServers": {
    "prowler": {
      "command": "uvx",
      "args": ["/path/to/prowler/mcp_server/"]
    }
  }
}
```

### Claude Desktop (macOS/Windows)

Add the server to Claude Desktop’s config file, then restart the app.

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%AppData%\Claude\claude_desktop_config.json` (e.g. `C:\\Users\\<you>\\AppData\\Roaming\\Claude\\claude_desktop_config.json`)

Example content to append/merge:

```json
{
  "mcpServers": {
    "prowler": {
      "command": "uvx",
      "args": ["/path/to/prowler/mcp_server/"]
    }
  }
}
```

## License

This project follows the repository’s main license. See the [LICENSE](../LICENSE) file at the repository root.
