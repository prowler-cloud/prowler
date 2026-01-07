---
name: prowler-mcp
description: >
  FastMCP patterns for Prowler MCP Server - AI agent tools.
  Trigger: When working on mcp_server/ directory - tools, models, API client.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## Architecture

Three sub-servers with prefixes:
- `prowler_hub_*` - Catalog tools (no auth)
- `prowler_docs_*` - Documentation tools (no auth)
- `prowler_app_*` - Management tools (auth required)

## Tool Patterns

### Prowler App (BaseTool - auto-registered)

```python
from prowler_mcp_server.prowler_app.tools.base import BaseTool

class FeatureTools(BaseTool):
    async def list_items(
        self,
        status: str | None = Field(default=None, description="Filter")
    ) -> dict:
        """Docstring becomes LLM description."""
        response = await self.api_client.get("/api/v1/items")
        return SimplifiedItem.from_api_response(response).model_dump()
```

### Hub/Docs (decorator)

```python
@hub_mcp_server.tool()
async def get_checks(providers: str | None = None) -> dict:
    """Tool docstring."""
    return response.json()
```

## Model Pattern

```python
class SimplifiedItem(MinimalSerializerMixin):
    """Lightweight for lists."""
    id: str
    name: str

class DetailedItem(SimplifiedItem):
    """Extended for single items."""
    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedItem":
        return cls(id=data["id"], name=data["attributes"]["name"])
```

## Commands

```bash
cd mcp_server && uv run prowler-mcp
cd mcp_server && uv run prowler-mcp --transport http --port 8000
```
