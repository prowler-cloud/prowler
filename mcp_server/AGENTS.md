# Prowler MCP Server - AI Agent Ruleset

**Complete guide for AI agents and developers working on the Prowler MCP Server - the Model Context Protocol server that provides AI agents access to the Prowler ecosystem.**

## Project Overview

The Prowler MCP Server brings the entire Prowler ecosystem to AI assistants through
the Model Context Protocol (MCP). It enables seamless integration with AI tools
like Claude Desktop, Cursor, and other MCP hosts, allowing interaction with
Prowler's security capabilities through natural language.

---

## Critical Rules

### Tool Implementation

- **ALWAYS**: Extend `BaseTool` ABC for new Prowler App tools (auto-registration)
- **ALWAYS**: Use `@mcp.tool()` decorator for Hub/Docs tools (manual registration)
- **NEVER**: Manually register BaseTool subclasses (auto-discovered via `load_all_tools()`)
- **NEVER**: Import tools directly in server.py (tool_loader handles discovery)

### Models

- **ALWAYS**: Use `MinimalSerializerMixin` for LLM-optimized responses
- **ALWAYS**: Implement `from_api_response()` factory method for API transformations
- **ALWAYS**: Use two-tier models (Simplified for lists, Detailed for single items)
- **NEVER**: Return raw API responses (transform to simplified models)

### API Client

- **ALWAYS**: Use singleton `ProwlerAPIClient` via `self.api_client` in tools
- **ALWAYS**: Use `build_filter_params()` for query parameter normalization
- **NEVER**: Create new httpx clients in tools (use shared client)

---

## Architecture

### Three Sub-Servers Pattern

The main server (`server.py`) orchestrates three independent sub-servers with prefixed tool namespacing:

```python
# server.py imports sub-servers with prefixes
await prowler_mcp_server.import_server(hub_mcp_server, prefix="prowler_hub")
await prowler_mcp_server.import_server(app_mcp_server, prefix="prowler_app")
await prowler_mcp_server.import_server(docs_mcp_server, prefix="prowler_docs")
```

This pattern ensures:
- Failures in one sub-server do not block others
- Clear tool namespacing for LLM disambiguation
- Independent development and testing

### Tool Naming Convention

All tools follow a consistent naming pattern with prefixes:
- `prowler_hub_*` - Prowler Hub catalog and compliance tools
- `prowler_docs_*` - Prowler documentation search and retrieval
- `prowler_app_*` - Prowler Cloud and App (Self-Managed) management tools

### Tool Registration Patterns

**Pattern 1: Prowler Hub/Docs (Direct Decorators)**

```python
# prowler_hub/server.py or prowler_documentation/server.py
hub_mcp_server = FastMCP("prowler-hub")

@hub_mcp_server.tool()
async def get_checks(providers: str | None = None) -> dict:
    """Tool docstring becomes LLM description."""
    # Direct implementation
    response = prowler_hub_client.get("/check", params=params)
    return response.json()
```

**Pattern 2: Prowler App (BaseTool Auto-Registration)**

```python
# prowler_app/tools/findings.py
class FindingsTools(BaseTool):
    async def search_security_findings(
        self,
        severity: list[str] = Field(default=[], description="Filter by severity")
    ) -> dict:
        """Docstring becomes LLM description."""
        response = await self.api_client.get("/api/v1/findings")
        return SimplifiedFinding.from_api_response(response).model_dump()
```

NOTE: Only public methods of `BaseTool` subclasses are registered as tools.

---

## Tech Stack

- **Language**: Python 3.12+
- **MCP Framework**: FastMCP 2.13.1
- **HTTP Client**: httpx (async)
- **Validation**: Pydantic with MinimalSerializerMixin
- **Package Manager**: uv

---

## Project Structure

```
mcp_server/
├── README.md                              # User documentation
├── AGENTS.md                              # This file - AI agent guidelines
├── CHANGELOG.md                           # Version history
├── pyproject.toml                         # Project metadata and dependencies
├── Dockerfile                             # Container image definition
├── entrypoint.sh                          # Docker entrypoint script
└── prowler_mcp_server/
    ├── __init__.py                        # Version info
    ├── main.py                            # CLI entry point
    ├── server.py                          # Main FastMCP server orchestration
    ├── lib/
    │   └── logger.py                      # Structured logging
    ├── prowler_hub/
    │   └── server.py                      # Hub tools (10 tools, no auth)
    ├── prowler_app/
    │   ├── server.py                      # App server initialization
    │   ├── tools/
    │   │   ├── base.py                    # BaseTool abstract class
    │   │   ├── findings.py                # Findings tools
    │   │   ├── providers.py               # Provider tools
    │   │   ├── scans.py                   # Scan tools
    │   │   ├── resources.py               # Resource tools
    │   │   └── muting.py                  # Muting tools
    │   ├── models/
    │   │   ├── base.py                    # MinimalSerializerMixin
    │   │   ├── findings.py                # Finding models
    │   │   ├── providers.py               # Provider models
    │   │   ├── scans.py                   # Scan models
    │   │   ├── resources.py               # Resource models
    │   │   └── muting.py                  # Muting models
    │   └── utils/
    │       ├── api_client.py              # ProwlerAPIClient singleton
    │       ├── auth.py                    # ProwlerAppAuth (STDIO/HTTP)
    │       └── tool_loader.py             # Auto-discovery and registration
    └── prowler_documentation/
        ├── server.py                      # Documentation tools (2 tools, no auth)
        └── search_engine.py               # Mintlify API integration
```

---

## Commands

NOTE: To run a python command always use `uv run <command>` from within the `mcp_server/` directory.

### Development

```bash
# Navigate to MCP server directory
cd mcp_server

# Run in STDIO mode (default)
uv run prowler-mcp

# Run in HTTP mode
uv run prowler-mcp --transport http --host 0.0.0.0 --port 8000

# Run from anywhere using uvx
uvx /path/to/prowler/mcp_server/
```

---

## Development Patterns

### Adding New Tools to Prowler App

1. **Create or extend a tool class** in `prowler_app/tools/`:

```python
# prowler_app/tools/new_feature.py
from pydantic import Field
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from prowler_mcp_server.prowler_app.models.new_feature import FeatureResponse

class NewFeatureTools(BaseTool):
    async def list_features(
        self,
        status: str | None = Field(default=None, description="Filter by status")
    ) -> dict:
        """List all features with optional filtering.

        Returns a simplified list of features optimized for LLM consumption.
        """
        params = {}
        if status:
            params["filter[status]"] = status

        clean_params = self.api_client.build_filter_params(params)
        response = await self.api_client.get("/api/v1/features", params=clean_params)

        return FeatureResponse.from_api_response(response).model_dump()
```

2. **Create corresponding models** in `prowler_app/models/`:

```python
# prowler_app/models/new_feature.py
from pydantic import Field
from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin

class SimplifiedFeature(MinimalSerializerMixin):
    """Lightweight feature for list operations."""
    id: str
    name: str
    status: str

class DetailedFeature(SimplifiedFeature):
    """Extended feature with complete details."""
    description: str | None = None
    created_at: str
    updated_at: str

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedFeature":
        """Transform API response to model."""
        attributes = data.get("attributes", {})
        return cls(
            id=data["id"],
            name=attributes["name"],
            status=attributes["status"],
            description=attributes.get("description"),
            created_at=attributes["created_at"],
            updated_at=attributes["updated_at"],
        )
```

3. **No registration needed** - the tool loader auto-discovers BaseTool subclasses

### Adding Tools to Prowler Hub/Docs

Use the `@mcp.tool()` decorator directly:

```python
# prowler_hub/server.py
@hub_mcp_server.tool()
async def new_hub_tool(param: str) -> dict:
    """Tool description for LLM."""
    response = prowler_hub_client.get("/endpoint")
    return response.json()
```

---

## Code Quality Standards

### Tool Docstrings

Tool docstrings become AI agent descriptions. Write them in a clear, concise manner focusing on LLM-relevant behavior:

```python
async def search_security_findings(
    self,
    severity: list[str] = Field(default=[], description="Filter by severity levels")
) -> dict:
    """Search security findings with advanced filtering.

    Returns a lightweight list of findings optimized for LLM consumption.
    Use get_finding_details for complete information about a specific finding.
    """
```

### Model Design

- Use `MinimalSerializerMixin` to exclude None/empty values
- Implement `from_api_response()` for consistent API transformation
- Create two-tier models: Simplified (lists) and Detailed (single items)

### Error Handling

Return structured error responses rather than raising exceptions:

```python
try:
    response = await self.api_client.get(f"/api/v1/items/{item_id}")
    return DetailedItem.from_api_response(response["data"]).model_dump()
except Exception as e:
    self.logger.error(f"Failed to get item {item_id}: {e}")
    return {"error": str(e), "status": "failed"}
```

---

## QA Checklist Before Commit

- [ ] Tool docstrings are clear and describe LLM-relevant behavior
- [ ] Models use `MinimalSerializerMixin` for LLM optimization
- [ ] API responses are transformed to simplified models
- [ ] No hardcoded secrets or API keys
- [ ] Error handling returns structured responses
- [ ] New tools are auto-discovered (BaseTool subclass) or properly decorated
- [ ] Parameter descriptions use Pydantic `Field()` with clear descriptions

---

## References

- **Root Project Guide**: `../AGENTS.md`
- **FastMCP Documentation**: https://gofastmcp.com/llms.txt
- **Prowler API Documentation**: https://api.prowler.com/api/v1/docs
