# Prowler MCP Server

> ⚠️ **Preview Feature**: This MCP server is currently in preview and under active development. Features and functionality may change. We welcome your feedback—please report any issues on [GitHub](https://github.com/prowler-cloud/prowler/issues) or join our [Slack community](https://goto.prowler.com/slack) to discuss and share your thoughts.

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

### Using Docker

Alternatively, you can build and run the MCP server using Docker:

```bash
# Clone the repository
git clone https://github.com/prowler-cloud/prowler.git
cd prowler/mcp_server

# Build the Docker image
docker build -t prowler-mcp .

# Run the container with environment variables
docker run --rm --env-file ./.env -it prowler-mcp
```

## Running

The Prowler MCP server supports two transport modes:
- **STDIO mode** (default): For direct integration with MCP clients like Claude Desktop
- **HTTP mode**: For remote access over HTTP with Bearer token authentication

### Transport Modes

#### STDIO Mode (Default)

STDIO mode is the standard MCP transport for direct client integration:

```bash
cd prowler/mcp_server
uv run prowler-mcp
# or
uv run prowler-mcp --transport stdio
```

#### HTTP Mode (Remote Server)

HTTP mode allows the server to run as a remote service accessible over HTTP:

```bash
cd prowler/mcp_server
# Run on default host and port (127.0.0.1:8000)
uv run prowler-mcp --transport http

# Run on custom host and port
uv run prowler-mcp --transport http --host 0.0.0.0 --port 8080
```

For self-deployed MCP remote server, you can use also configure the server to use a custom API base URL with the environment variable `PROWLER_API_BASE_URL`; and the transport mode with the environment variable `PROWLER_MCP_MODE`.

```bash
export PROWLER_API_BASE_URL="https://api.prowler.com"
export PROWLER_MCP_MODE="http"
```

### Using uv directly

After installation, start the MCP server via the console script:

```bash
cd prowler/mcp_server
uv run prowler-mcp
```

Alternatively, you can run from wherever you want using `uvx` command:

```bash
uvx /path/to/prowler/mcp_server/
```

### Using Docker

#### STDIO Mode (Default)

Run the pre-built Docker container in STDIO mode:

```bash
cd prowler/mcp_server
docker run --rm --env-file ./.env -it prowler-mcp
```

#### HTTP Mode (Remote Server)

Run as a remote HTTP server:

```bash
cd prowler/mcp_server
# Run on port 8000 (accessible from host)
docker run --rm --env-file ./.env -p 8000:8000 -it prowler-mcp --transport http --host 0.0.0.0 --port 8000

# Run on custom port
docker run --rm --env-file ./.env -p 8080:8080 -it prowler-mcp --transport http --host 0.0.0.0 --port 8080
```

## Command Line Arguments

The Prowler MCP server supports the following command line arguments:

```
prowler-mcp [--transport {stdio,http}] [--host HOST] [--port PORT]
```

**Arguments:**
- `--transport {stdio,http}`: Transport method (default: stdio)
  - `stdio`: Standard input/output transport for direct MCP client integration
  - `http`: HTTP transport for remote server access
- `--host HOST`: Host to bind to for HTTP transport (default: 127.0.0.1)
- `--port PORT`: Port to bind to for HTTP transport (default: 8000)

**Examples:**
```bash
# Default STDIO mode
prowler-mcp

# Explicit STDIO mode
prowler-mcp --transport stdio

# HTTP mode with default host and port (127.0.0.1:8000)
prowler-mcp --transport http

# HTTP mode accessible from any network interface
prowler-mcp --transport http --host 0.0.0.0

# HTTP mode with custom port
prowler-mcp --transport http --host 0.0.0.0 --port 8080
```

## Available Tools

### Prowler Hub

All tools are exposed under the `prowler_hub` prefix.

- `prowler_hub_get_check_filters`: Return available filter values for checks (providers, services, severities, categories, compliances). Call this before `prowler_hub_get_checks` to build valid queries.
- `prowler_hub_get_checks`: List checks with option of advanced filtering.
- `prowler_hub_get_check_raw_metadata`: Fetch raw check metadata JSON (low-level version of get_checks).
- `prowler_hub_get_check_code`: Fetch check implementation Python code from Prowler.
- `prowler_hub_get_check_fixer`: Fetch check fixer Python code from Prowler (if it exists).
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
- `prowler_app_processors_create`: Create a new processor. For now, only mute lists are supported.
- `prowler_app_processors_retrieve`: Get processor details by ID
- `prowler_app_processors_partial_update`: Update processor configuration
- `prowler_app_processors_destroy`: Delete a processor

## Configuration

### Prowler Cloud and Prowler App (Self-Managed) Authentication

> [!IMPORTANT]
> Authentication is not needed for using Prowler Hub features.

The Prowler MCP server supports different authentication in Prowler Cloud and Prowler App (Self-Managed) methods depending on the transport mode:

#### STDIO Mode Authentication

For STDIO mode, authentication is handled via environment variables using an API key:

```bash
# Required for Prowler Cloud and Prowler App (Self-Managed) authentication
export PROWLER_APP_API_KEY="pk_your_api_key_here"

# Optional - for custom API endpoint, in case not provided Prowler Cloud API will be used
export PROWLER_API_BASE_URL="https://api.prowler.com"
```

#### HTTP Mode Authentication

For HTTP mode (remote server), authentication is handled via Bearer tokens. The MCP server supports both JWT tokens and API keys:

**Option 1: Using API Keys (Recommended)**
Use your Prowler API key directly in the MCP client configuration with Bearer token format:
```
Authorization: Bearer pk_your_api_key_here
```

**Option 2: Using JWT Tokens**
You need to obtain a JWT token from Prowler Cloud/App and include the generated token in the MCP client configuration. To get a valid token, you can use the following command (replace the email and password with your own credentials):

```bash
curl -X POST https://api.prowler.com/api/v1/tokens \
  -H "Content-Type: application/vnd.api+json" \
  -H "Accept: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "tokens",
      "attributes": {
        "email": "your-email@example.com",
        "password": "your-password"
      }
    }
  }'
```

The response will be a JWT token that you can use to [authenticate your MCP client](#http-mode-configuration-remote-server).

### MCP Client Configuration

Configure your MCP client, like Claude Desktop, Cursor, etc, to connect to the server. The configuration depends on whether you're running in STDIO mode (local) or HTTP mode (remote).

#### STDIO Mode Configuration

For local execution, configure your MCP client to launch the server directly. Below are examples for both direct execution and Docker deployment; consult your client's documentation for exact locations.

##### Using uvx (Direct Execution)

```json
{
  "mcpServers": {
    "prowler": {
      "command": "uvx",
      "args": ["/path/to/prowler/mcp_server/"],
      "env": {
        "PROWLER_APP_API_KEY": "pk_your_api_key_here",
        "PROWLER_API_BASE_URL": "https://api.prowler.com"  // Optional, in case not provided Prowler Cloud API will be used
      }
    }
  }
}
```

##### Using Docker

```json
{
  "mcpServers": {
    "prowler": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--env", "PROWLER_APP_API_KEY=pk_your_api_key_here",
        "--env", "PROWLER_API_BASE_URL=https://api.prowler.com",  // Optional, in case not provided Prowler Cloud API will be used
        "prowler-mcp"
      ]
    }
  }
}
```

#### HTTP Mode Configuration (Remote Server)

For HTTP mode, you can configure your MCP client to connect to a remote Prowler MCP server.

**Important Limitations:**
- HTTP mode support varies by client - some clients may not support HTTP transport yet.
- Some MCP clients like Claude Desktop only support OAuth authentication for HTTP connections, which is not currently supported by our MCP server.

Example configuration for clients that support HTTP transport:

**Using API Key (Recommended):**
```json
{
  "mcpServers": {
    "prowler": {
      "url": "http://mcp.prowler.com/mcp",  // Replace with your own MCP server URL, by default when server is run in local it is http://localhost:8000/mcp
      "headers": {
        "Authorization": "Bearer pk_your_api_key_here"
      }
    }
  }
}
```

**Using JWT Token:**
```json
{
  "mcpServers": {
    "prowler": {
      "url": "http://mcp.prowler.com/mcp",  // Replace with your own MCP server URL, by default when server is run in local it is http://localhost:8000/mcp
      "headers": {
        "Authorization": "Bearer <your-jwt-token-here>"
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
