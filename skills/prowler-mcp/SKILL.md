---
name: prowler-mcp
description: >
  FastMCP patterns for Prowler MCP Server - AI agent tools.
  Trigger: When working on mcp_server/ directory - tools, models, API client.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
---

## Architecture

Three sub-servers with prefixes:
- `prowler_hub_*` - Catalog tools (no auth)
- `prowler_docs_*` - Documentation tools (no auth)
- `prowler_app_*` - Management tools (auth required)

---

## Critical Rules

### Tool Implementation

- **ALWAYS**: Extend `BaseTool` ABC for Prowler App tools (auto-registration)
- **ALWAYS**: Use `@mcp.tool()` decorator for Hub/Docs tools (manual registration)
- **NEVER**: Manually register BaseTool subclasses (auto-discovered via `load_all_tools()`)
- **NEVER**: Import tools directly in server.py (tool_loader handles discovery)

### Models

- **ALWAYS**: Use `MinimalSerializerMixin` for LLM-optimized responses
- **ALWAYS**: Implement `from_api_response()` factory method
- **ALWAYS**: Use two-tier models (Simplified for lists, Detailed for single items)
- **NEVER**: Return raw API responses (transform to simplified models)

### API Client

- **ALWAYS**: Use singleton `ProwlerAPIClient` via `self.api_client` in tools
- **ALWAYS**: Use `build_filter_params()` for query parameter normalization
- **NEVER**: Create new httpx clients in tools

---

## Project Structure

```
mcp_server/
├── prowler_mcp_server/
│   ├── server.py              # Main FastMCP orchestration
│   ├── prowler_hub/
│   │   └── server.py          # Hub tools (10 tools, no auth)
│   ├── prowler_app/
│   │   ├── server.py          # App server init
│   │   ├── tools/
│   │   │   ├── base.py        # BaseTool ABC
│   │   │   ├── findings.py    # Findings tools
│   │   │   ├── providers.py   # Provider tools
│   │   │   └── scans.py       # Scan tools
│   │   ├── models/
│   │   │   ├── base.py        # MinimalSerializerMixin
│   │   │   └── *.py           # Domain models
│   │   └── utils/
│   │       ├── api_client.py  # ProwlerAPIClient singleton
│   │       ├── auth.py        # Auth (STDIO/HTTP)
│   │       └── tool_loader.py # Auto-discovery
│   └── prowler_documentation/
│       ├── server.py          # Doc tools (2 tools, no auth)
│       └── search_engine.py   # Mintlify API
```

---

## Tool Patterns

### Pattern 1: Prowler App (BaseTool - auto-registered)

```python
from pydantic import Field
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from prowler_mcp_server.prowler_app.models.feature import SimplifiedFeature

class FeatureTools(BaseTool):
    async def list_features(
        self,
        status: str | None = Field(default=None, description="Filter by status")
    ) -> dict:
        """List all features with optional filtering.

        Returns a simplified list optimized for LLM consumption.
        """
        params = {}
        if status:
            params["filter[status]"] = status

        clean_params = self.api_client.build_filter_params(params)
        response = await self.api_client.get("/api/v1/features", params=clean_params)
        return SimplifiedFeature.from_api_response(response).model_dump()
```

NOTE: Only public methods of `BaseTool` subclasses are registered as tools.

### Pattern 2: Hub/Docs (decorator)

```python
@hub_mcp_server.tool()
async def get_checks(providers: str | None = None) -> dict:
    """Tool docstring becomes LLM description."""
    response = prowler_hub_client.get("/check", params=params)
    return response.json()
```

---

## Model Patterns

### Two-Tier Models

```python
from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin

class SimplifiedFeature(MinimalSerializerMixin):
    """Lightweight for list operations."""
    id: str
    name: str
    status: str

class DetailedFeature(SimplifiedFeature):
    """Extended for single item details."""
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

---

## Error Handling

Return structured error responses (don't raise exceptions):

```python
try:
    response = await self.api_client.get(f"/api/v1/items/{item_id}")
    return DetailedItem.from_api_response(response["data"]).model_dump()
except Exception as e:
    self.logger.error(f"Failed to get item {item_id}: {e}")
    return {"error": str(e), "status": "failed"}
```

---

## Tool Docstrings

Docstrings become AI agent descriptions. Write clearly for LLM understanding:

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

---

## Tech Stack

- Python 3.12+
- FastMCP 2.13.1
- httpx (async)
- Pydantic with MinimalSerializerMixin
- uv (package manager)

---

## Commands

```bash
cd mcp_server && uv run prowler-mcp                            # STDIO mode (default)
cd mcp_server && uv run prowler-mcp --transport http --port 8000  # HTTP mode
uvx /path/to/prowler/mcp_server/                               # Run from anywhere
```

---

## QA Checklist

- [ ] Tool docstrings describe LLM-relevant behavior
- [ ] Models use `MinimalSerializerMixin`
- [ ] API responses transformed to simplified models
- [ ] No hardcoded secrets
- [ ] Error handling returns structured responses
- [ ] New tools auto-discovered (BaseTool) or decorated (`@mcp.tool()`)
- [ ] Parameters use `Field()` with descriptions

## Keywords
prowler mcp, fastmcp, ai tools, model context protocol, llm tools
