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
- ALWAYS: Build sub-servers with `ProwlerMCP`, never `FastMCP` directly. It is what
  applies the error contract to every tool, whichever way it is registered
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

### Errors
One rule: **`ToolError` is a message you wrote for the caller. Any other exception is
a bug or an upstream failure**, and `render_tool_error` describes it.

- ALWAYS: `raise ToolError(...)` for anything the caller can act on — a rejected
  argument, a lookup that found nothing, a workflow step they must do first. Its text
  reaches the client verbatim, past `mask_error_details`
- NEVER: `raise ValueError(...)` in a tool. It is reported as a bug in this server,
  which is correct for a model factory rejecting an API payload and wrong for a
  refusal
- ALWAYS: Let an upstream failure propagate untouched. `ProwlerMCP.tool` wraps every
  registration, so it becomes a `ToolError` describing the call, the status and what
  the API said. There is nothing to remember to apply
- NEVER: `return {"error": ...}` or `{"success": False}`. A returned payload is
  `isError: false`, so the client is told the call succeeded
- NEVER: Raise a plain exception *after* a write has been accepted. `ToolError` is the
  only kind whose message reaches the client exactly as written
- ALWAYS: `render_tool_error(e)` when you surface an exception yourself, so a failure
  is never described two different ways. Use `warn=False` when embedding it in a
  result that already reports the outcome
- ALWAYS: Return a structured result, not an error, when a write may have partially
  landed (`status="unknown"`, `deleted="unknown"`, `safe_to_retry=False`). An agent
  reads `isError: true` as "nothing happened, safe to retry"
- ALWAYS: Return a structured result for an outcome that *is* the tool's job to
  report: `connected: false`, an empty list, an idempotent no-op
- NEVER: Wrap a whole tool body in `except Exception`. It reports bugs in this
  server as API failures, and the wrapper already handles the rest

See `prowler_mcp_server/lib/errors.py` and
`docs/developer-guide/mcp-server.mdx` for the message format.

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
├── lib/
│   ├── server.py                # ProwlerMCP: base class of every sub-server
│   └── errors.py                # Exception types + render_tool_error
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
- [ ] Failures raise (never `return {"error": ...}`); outcomes that may have changed
      something return a structured result
- [ ] Parameter descriptions use Pydantic `Field()`
- [ ] Tests added under `mcp_server/tests/`, mirroring the source path below the
      package root (`prowler_mcp_server/prowler_app/tools/` -> `tests/prowler_app/tools/`),
      as the SDK does for `prowler/` -> `tests/`
- [ ] `uv run pytest` passes
