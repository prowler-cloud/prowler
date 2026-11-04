---
name: prowler-mcp
description: >
  Creates MCP tools for Prowler MCP Server. Covers BaseTool pattern, tool annotations,
  model design, error handling and API client usage.
  Trigger: When working in mcp_server/ on tools (BaseTool), models (MinimalSerializerMixin/from_api_response), Hub/Docs tools, or API client patterns.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, mcp_server]
  auto_invoke: "Working on MCP server tools"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Overview

Stack: Python >= 3.12, FastMCP 3.4.x, httpx, Pydantic, uv (source of truth: `mcp_server/pyproject.toml`).

`prowler_mcp_server/server.py` mounts three sub-servers with prefixed namespaces:

| Sub-Server | Prefix | Auth | Source | How tools are defined |
|------------|--------|------|--------|-----------------------|
| Prowler App | `prowler_*` | Required (`PROWLER_API_KEY` in STDIO, bearer token in HTTP) | `prowler_app/` | `BaseTool` subclasses, auto-loaded |
| Prowler Hub | `prowler_hub_*` | No | `prowler_hub/server.py` | `@hub_mcp_server.tool(annotations=...)` |
| Prowler Docs | `prowler_docs_*` | No | `prowler_documentation/server.py` | `@docs_mcp_server.tool(annotations=...)` |

```text
mcp_server/prowler_mcp_server/
├── server.py                 # Root server: mounts, SharedFailureMiddleware, /health
├── main.py                   # CLI: --transport stdio|http --host --port
├── lib/                      # errors.py, types.py (NonBlankStr), logger.py, urls.py
├── prowler_app/
│   ├── server.py             # FastMCP("prowler-app") + load_all_tools()
│   ├── tools/{feature}.py    # BaseTool subclasses (tools/base.py = BaseTool)
│   ├── models/{feature}.py   # Pydantic models (models/base.py = MinimalSerializerMixin)
│   └── utils/                # api_client.py, auth.py, tool_loader.py
├── prowler_hub/server.py
└── prowler_documentation/    # server.py, search_engine.py
```

---

## Critical Rules (Prowler App Tools)

### Tool Implementation

- **ALWAYS**: Put a `BaseTool` subclass in `prowler_app/tools/{feature}.py`. `load_all_tools()` imports every module in that package and `BaseTool.register_tools()` registers every public `async` method (no `_` prefix) as a tool, exposed as `prowler_{method_name}`.
- **NEVER**: Register tools manually or import tool modules in `server.py`.
- **ALWAYS**: Name methods so the MCP annotations are right. `BaseTool._annotations_for()` marks `get_*`, `list_*`, `search_*` as read-only and `delete_*` as destructive. Any other name that only reads or that removes/replaces data goes in the class attribute `read_only_tools` or `destructive_tools` (see `tools/attack_paths.py`, `tools/roles.py`, `tools/muting.py`).
- **ALWAYS**: Declare every parameter with `pydantic.Field(default=..., description=...)`. Required identifiers use `NonBlankStr` from `prowler_mcp_server.lib.types` (rejects `""` and whitespace, adds `minLength` to the schema).
- **ALWAYS**: The method docstring is the tool description the model reads: say what it returns, the default behavior, and which tool to call next.
- A tool class whose `__init__` raises is logged and skipped by `load_all_tools`, so its tools silently vanish. The contract tests in `tests/test_server.py` catch an empty namespace.

### Models

- **ALWAYS**: Item models extend `MinimalSerializerMixin` (drops `None`, `""`, `[]`, `{}` from `model_dump()`); override `_should_exclude()` only when an empty value carries meaning.
- **ALWAYS**: Implement a `from_api_response()` classmethod that maps the JSON:API resource to the model.
- **ALWAYS**: Two tiers: `Simplified*` for lists, `Detailed*` (subclass) for one item, plus a `*ListResponse` built from `meta.pagination` (`count`, `pages`, `page`).
- **NEVER**: Return raw API responses. Return `model.model_dump()`.

### API Client

- **ALWAYS**: Use `self.api_client` (the `ProwlerAPIClient` singleton) with paths relative to `/api/v1` (e.g. `"/findings/latest"`).
- **ALWAYS**: Pass params through `self.api_client.build_filter_params()`: lists become CSV, bools become `"true"`/`"false"`, `None` is dropped.
- **ALWAYS**: Validate before requesting: `validate_page_size()` (1-1000), `normalize_date_range()` (YYYY-MM-DD, max window). Use `poll_task_until_complete()` for endpoints that return a task.
- **NEVER**: Create new httpx clients.

### Errors (`lib/errors.py`)

- **ALWAYS**: Raise failures; NEVER return an error dict (the client reports it as a success).
- Raise `InvalidArgument` for a bad argument; let `ProwlerAPIError` / `ProwlerAPIUnreachable` propagate. `SharedFailureMiddleware` (on the root server) turns them into a message the model can act on.
- Raise `fastmcp.exceptions.ToolError` **without a `from` clause** only for a sentence `lib/errors.py` cannot know (a resource name, a precondition, the next tool to call). Every server uses `mask_error_details=True`, so any other exception reaches the model masked.

---

## Hub/Docs Tools

Plain functions decorated on the sub-server; no `BaseTool` or models. Always set both hints:

```python
@hub_mcp_server.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
async def list_checks(providers: list[str] = Field(default=[], description="...")) -> dict: ...
```

---

## Quick Reference: New Prowler App Tool

1. Models in `prowler_app/models/{feature}.py` (see [assets/models.py](assets/models.py)).
2. Tool class in `prowler_app/tools/{feature}.py` extending `BaseTool` (see [assets/tool_implementation.py](assets/tool_implementation.py)).
3. Tests in `mcp_server/tests/prowler_app/{models,tools}/test_{feature}.py` (see `prowler-test-mcp`).
4. Changelog fragment `mcp_server/changelog.d/<slug>.<type>.md` (see `prowler-changelog`); never edit `CHANGELOG.md`.

---

## Commands

```bash
cd mcp_server
uv run prowler-mcp                               # STDIO mode
uv run prowler-mcp --transport http --port 8000  # HTTP mode (GET /health)
uv run pytest                                    # Test suite
uv run ruff check . && uv run ruff format --check .
```

---

## QA Checklist (Prowler App Tools)

- [ ] Tool docstrings describe LLM-relevant behavior and the follow-up tool
- [ ] Method name prefix (or `read_only_tools`/`destructive_tools`) gives correct annotations
- [ ] Models use `MinimalSerializerMixin` and `from_api_response()`
- [ ] Params use `Field()` with descriptions; required IDs use `NonBlankStr`
- [ ] Query params go through `build_filter_params()`
- [ ] Failures are raised, never returned
- [ ] No hardcoded secrets
- [ ] Tests added under `mcp_server/tests/`; changelog fragment added

---

## Resources

- **Full Guide**: [docs/developer-guide/mcp-server.mdx](../../docs/developer-guide/mcp-server.mdx)
- **Templates**: See [assets/](assets/) for BaseTool, tool and model templates
- **Testing**: See [prowler-test-mcp](../prowler-test-mcp/SKILL.md) for fixtures and test patterns
