# Prowler MCP Server - AI Agent Ruleset

> **Skills Reference**: See [`prowler-mcp`](../skills/prowler-mcp/SKILL.md)

## Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action | Skill |
|--------|-------|
| Add changelog entry for a PR or feature | `prowler-changelog` |
| Committing changes | `prowler-commit` |
| Create PR that requires changelog entry | `prowler-changelog` |
| Creating a git commit | `prowler-commit` |
| Review changelog format and conventions | `prowler-changelog` |
| Update CHANGELOG.md in any component | `prowler-changelog` |
| Working on MCP server tools | `prowler-mcp` |
| Writing tests for the MCP server | `prowler-test-mcp` |

## Project Overview

The Prowler MCP Server provides AI agents access to the Prowler ecosystem through the Model Context Protocol (MCP). It integrates with Claude Desktop, Cursor, and other MCP hosts.

---

## CRITICAL RULES

### Tool Implementation
- ALWAYS: Extend `BaseTool` ABC for Prowler tools (auto-registration)
- ALWAYS: Use `@mcp.tool()` decorator for Hub/Docs tools
- NEVER: Manually register BaseTool subclasses
- NEVER: Import tools directly in server.py

### Models
- ALWAYS: Use `MinimalSerializerMixin` for LLM-optimized responses
- ALWAYS: Implement `from_api_response()` factory method
- ALWAYS: Two-tier models (Simplified for lists, Detailed for single items)
- NEVER: Return raw API responses

### API Client
- ALWAYS: Use singleton `ProwlerAPIClient` via `self.api_client`
- ALWAYS: Use `build_filter_params()` for query parameters
- NEVER: Create new httpx clients in tools

---

## ARCHITECTURE

### Three Sub-Servers

```python
prowler_mcp_server.mount(hub_mcp_server, namespace="prowler_hub")
prowler_mcp_server.mount(app_mcp_server, namespace="prowler")
prowler_mcp_server.mount(docs_mcp_server, namespace="prowler_docs")
```

### Tool Naming
- `prowler_hub_*` - Catalog and compliance (no auth)
- `prowler_docs_*` - Documentation search (no auth)
- `prowler_*` - Prowler Cloud, Private Cloud & Local Server management (auth required)

---

## TECH STACK

Python 3.12+ | FastMCP 3.4.4 | httpx (async) | Pydantic | uv | pytest

---

## PROJECT STRUCTURE

```text
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
```

---

## COMMANDS

From `mcp_server/`:

```bash
cd mcp_server

uv run prowler-mcp                              # STDIO mode
uv run prowler-mcp --transport http --port 8000 # HTTP mode

uv run pytest                                   # Run the test suite
uv run pytest tests/prowler_app/models          # Run one area
uv run pytest --cov=./prowler_mcp_server        # With coverage
```

From the repository root:

```bash
make test-mcp   # Run the MCP test suite exactly as CI does
```

---

## QA CHECKLIST

- [ ] Tool docstrings describe LLM-relevant behavior
- [ ] Models use `MinimalSerializerMixin`
- [ ] API responses transformed to simplified models
- [ ] No hardcoded secrets
- [ ] Error handling returns structured responses
- [ ] Parameter descriptions use Pydantic `Field()`
- [ ] Tests added under `mcp_server/tests/`, mirroring the source path below the
      package root (`prowler_mcp_server/prowler_app/tools/` -> `tests/prowler_app/tools/`),
      as the SDK does for `prowler/` -> `tests/`
- [ ] `uv run pytest` passes
