# Prowler MCP Server

Access the entire Prowler ecosystem through the Model Context Protocol (MCP). This server provides two main capabilities:

- **Prowler Cloud and Prowler App (Self-Managed)**: Full access to Prowler Cloud platform and Prowler Self-Managed for managing providers, running scans, and analyzing security findings
- **Prowler Hub**: Access to Prowler's security checks, fixers, and compliance frameworks catalog


## Requirements

- Python 3.12+
- Network access to `https://hub.prowler.com` (for Prowler Hub)
- Network access to Prowler Cloud and Prowler App (Self-Managed) API (it can be Prowler Cloud API or self-hosted Prowler App API)
- Prowler Cloud account credentials (for Prowler Cloud and Prowler App (Self-Managed) features)

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

- `prowler_hub_get_check_filters`: Return available filter values for checks (providers, services, severities, categories, compliances). Call this before `prowler_hub_get_checks` to build valid queries.
- `prowler_hub_get_checks`: List checks with option of advanced filtering.
- `prowler_hub_search_checks`: Full‑text search across check metadata.
- `prowler_hub_get_compliance_frameworks`: List/filter compliance frameworks.
- `prowler_hub_search_compliance_frameworks`: Full-text search across frameworks.
- `prowler_hub_list_providers`: List Prowler official providers and their services.
- `prowler_hub_get_artifacts_count`: Return total artifact count (checks + frameworks).

### Prowler Cloud and Prowler App (Self-Managed)

All tools are exposed under the `prowler_app` prefix.

#### Findings Management
- `prowler_app_list_findings`: List security findings from Prowler scans with advanced filtering
- `prowler_app_get_finding`: Get detailed information about a specific security finding
- `prowler_app_get_latest_findings`: Retrieve latest findings from the latest scans for each provider
- `prowler_app_get_findings_metadata`: Fetch unique metadata values from filtered findings
- `prowler_app_get_latest_findings_metadata`: Fetch metadata from latest findings across all providers

#### Provider Management
- `prowler_app_list_providers`: List all providers with filtering options
- `prowler_app_create_provider`: Create a new provider in the current tenant
- `prowler_app_get_provider`: Get detailed information about a specific provider
- `prowler_app_update_provider`: Update provider details (alias, etc.)
- `prowler_app_delete_provider`: Delete a specific provider
- `prowler_app_test_provider_connection`: Test provider connection status

#### Provider Secrets Management
- `prowler_app_list_provider_secrets`: List all provider secrets with filtering
- `prowler_app_add_provider_secret`: Add or update credentials for a provider
- `prowler_app_get_provider_secret`: Get detailed information about a provider secret
- `prowler_app_update_provider_secret`: Update provider secret details
- `prowler_app_delete_provider_secret`: Delete a provider secret

#### Scan Management
- `prowler_app_list_scans`: List all scans with filtering options
- `prowler_app_create_scan`: Trigger a manual scan for a specific provider
- `prowler_app_get_scan`: Get detailed information about a specific scan
- `prowler_app_update_scan`: Update scan details
- `prowler_app_get_scan_compliance_report`: Download compliance report as CSV
- `prowler_app_get_scan_report`: Download ZIP file containing scan report

#### Schedule Management
- `prowler_app_schedules_daily_scan`: Create a daily scheduled scan for a provider

#### Processor Management
- `prowler_app_processors_list`: List all processors with filtering
- `prowler_app_processors_create`: Create a new processor (e.g., mutelist)
- `prowler_app_processors_retrieve`: Get processor details by ID
- `prowler_app_processors_partial_update`: Update processor configuration
- `prowler_app_processors_destroy`: Delete a processor

## Configuration

### Environment Variables

For Prowler Cloud and Prowler App (Self-Managed) features, you need to set the following environment variables:

```bash
# Required for Prowler Cloud and Prowler App (Self-Managed) authentication
export PROWLER_APP_EMAIL="your-email@example.com"
export PROWLER_APP_PASSWORD="your-password"

# Optional - in case not provided the first membership that was added to the user will be used
export PROWLER_APP_TENANT_ID="your-tenant-id"

# Optional - for custom API endpoint, in case not provided Prowler Cloud API will be used
export PROWLER_API_BASE_URL="https://api.prowler.com"
```

### MCP Client Configuration

Configure your MCP client, like Claude Desktop, Cursor, etc, to launch the server with the `uvx` command. Below is a generic snippet; consult your client's documentation for exact locations.

```json
{
  "mcpServers": {
    "prowler": {
      "command": "uvx",
      "args": ["/path/to/prowler/mcp_server/"],
      "env": {
        "PROWLER_APP_EMAIL": "your-email@example.com",
        "PROWLER_APP_PASSWORD": "your-password",
        "PROWLER_APP_TENANT_ID": "your-tenant-id",  // Optional
        "PROWLER_API_BASE_URL": "https://api.prowler.com"  // Optional
      }
    }
  }
}
```

### Claude Desktop (macOS/Windows)

Add the example server to Claude Desktop's config file, then restart the app.

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%AppData%\Claude\claude_desktop_config.json` (e.g. `C:\\Users\\<you>\\AppData\\Roaming\\Claude\\claude_desktop_config.json`)

### Cursor (macOS/Linux)

If you want to have it globally available, add the example server to Cursor's config file, then restart the app.

- macOS/Linux: `~/.cursor/mcp.json`

If you want to have it only for the current project, add the example server to the project's root in a new `.cursor/mcp.json` file.

## License

This project follows the repository’s main license. See the [LICENSE](../LICENSE) file at the repository root.
