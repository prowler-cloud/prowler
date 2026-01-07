
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-mcp
description: FastMCP patterns for Prowler MCP Server development. Covers tool implementation, models with MinimalSerializerMixin, and the three sub-servers architecture.
license: Apache 2.0
---

## When to use this skill

Use this skill when working on the Prowler MCP Server for:
- Adding new tools to Prowler Hub, App, or Docs servers
- Creating models optimized for LLM consumption
- Understanding the three sub-servers pattern

## Architecture

Three independent sub-servers with prefixed namespacing:
- \`prowler_hub_*\` - Prowler Hub catalog and compliance tools (no auth)
- \`prowler_docs_*\` - Documentation search and retrieval (no auth)
- \`prowler_app_*\` - Prowler Cloud/Self-Managed management (auth required)

## Critical Rules

### Tool Implementation
- ALWAYS: Extend \`BaseTool\` ABC for Prowler App tools (auto-registration)
- ALWAYS: Use \`@mcp.tool()\` decorator for Hub/Docs tools
- NEVER: Manually register BaseTool subclasses
- NEVER: Import tools directly in server.py

### Models
- ALWAYS: Use \`MinimalSerializerMixin\` for LLM-optimized responses
- ALWAYS: Implement \`from_api_response()\` factory method
- ALWAYS: Two-tier models (Simplified for lists, Detailed for single items)
- NEVER: Return raw API responses

### API Client
- ALWAYS: Use singleton \`ProwlerAPIClient\` via \`self.api_client\`
- ALWAYS: Use \`build_filter_params()\` for query parameters
- NEVER: Create new httpx clients in tools

## Patterns

### Prowler App Tool (BaseTool Auto-Registration)
\`\`\`python
from pydantic import Field
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from prowler_mcp_server.prowler_app.models.{feature} import {Feature}Response

class {Feature}Tools(BaseTool):
    async def list_{features}(
        self,
        status: str | None = Field(default=None, description="Filter by status")
    ) -> dict:
        """List all {features} with optional filtering.

        Returns a lightweight list optimized for LLM consumption.
        """
        params = {}
        if status:
            params["filter[status]"] = status

        clean_params = self.api_client.build_filter_params(params)
        response = await self.api_client.get("/api/v1/{features}", params=clean_params)

        return {Feature}Response.from_api_response(response).model_dump()
\`\`\`

### Prowler Hub/Docs Tool (Direct Decorator)
\`\`\`python
hub_mcp_server = FastMCP("prowler-hub")

@hub_mcp_server.tool()
async def get_checks(providers: str | None = None) -> dict:
    """Tool docstring becomes LLM description."""
    response = prowler_hub_client.get("/check", params=params)
    return response.json()
\`\`\`

### Model with MinimalSerializerMixin
\`\`\`python
from pydantic import Field
from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin

class Simplified{Feature}(MinimalSerializerMixin):
    """Lightweight for list operations."""
    id: str
    name: str
    status: str

class Detailed{Feature}(Simplified{Feature}):
    """Extended with complete details."""
    description: str | None = None
    created_at: str

    @classmethod
    def from_api_response(cls, data: dict) -> "Detailed{Feature}":
        attributes = data.get("attributes", {})
        return cls(
            id=data["id"],
            name=attributes["name"],
            status=attributes["status"],
            description=attributes.get("description"),
            created_at=attributes["created_at"],
        )
\`\`\`

## Project Structure
\`\`\`
mcp_server/prowler_mcp_server/
├── server.py                    # Main orchestration
├── prowler_hub/server.py        # Hub tools (no auth)
├── prowler_app/
│   ├── server.py
│   ├── tools/{feature}.py       # BaseTool subclasses
│   ├── models/{feature}.py      # Pydantic models
│   └── utils/api_client.py      # ProwlerAPIClient
└── prowler_documentation/
    └── server.py                # Docs tools (no auth)
\`\`\`

## Commands
\`\`\`bash
cd mcp_server && uv run prowler-mcp                              # STDIO mode
cd mcp_server && uv run prowler-mcp --transport http --port 8000 # HTTP mode
uvx /path/to/prowler/mcp_server/                                  # Run from anywhere
\`\`\`

## Keywords
prowler mcp, fastmcp, model context protocol, llm tools, ai agents
`;

export default tool({
  description: SKILL,
  args: {
    server: tool.schema.string().describe("Target server: hub, app, docs"),
    tool_name: tool.schema.string().describe("Name of the tool to create"),
  },
  async execute(args) {
    const serverPath = args.server === 'app'
      ? `mcp_server/prowler_mcp_server/prowler_app/tools/${args.tool_name}.py`
      : args.server === 'hub'
      ? 'mcp_server/prowler_mcp_server/prowler_hub/server.py'
      : 'mcp_server/prowler_mcp_server/prowler_documentation/server.py';

    return `
Prowler MCP Server Pattern for: ${args.server} - ${args.tool_name}

Target file: ${serverPath}

For "${args.server}" server:
${args.server === 'app' ? `
- Create a new BaseTool subclass in tools/${args.tool_name}.py
- Create corresponding models in models/${args.tool_name}.py
- Tool methods become MCP tools automatically (no manual registration)
- Use self.api_client for API calls
- Return SimplifiedModel.from_api_response(response).model_dump()
` : `
- Add @${args.server}_mcp_server.tool() decorated function
- Docstring becomes the LLM description
- Direct implementation without BaseTool
`}

Tech Stack:
- Python 3.12+ + FastMCP 2.13.1 + httpx
- Pydantic with MinimalSerializerMixin
- Package manager: uv

Remember:
- Tool docstrings are critical - they become AI agent descriptions
- Use Pydantic Field() for parameter descriptions
- Return structured error responses, don't raise exceptions
    `.trim()
  },
})
