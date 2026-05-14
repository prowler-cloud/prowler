---
name: prowler-mcp
description: >
  Creates MCP tools for Prowler MCP Server. Covers BaseTool pattern, model design,
  and API client usage.
  Trigger: When working in mcp_server/ on tools (BaseTool), models (MinimalSerializerMixin/from_api_response), or API client patterns.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, mcp_server]
  auto_invoke: "Working on MCP server tools"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Overview

The Prowler MCP Server uses three sub-servers with prefixed namespacing:

| Sub-Server | Prefix | Auth | Purpose |
|------------|--------|------|---------|
| Prowler App | `prowler_app_*` | Required | Cloud management tools |
| Prowler Hub | `prowler_hub_*` | No | Security checks catalog |
| Prowler Docs | `prowler_docs_*` | No | Documentation search |

For complete architecture, patterns, and examples, see [docs/developer-guide/mcp-server.mdx](../../../docs/developer-guide/mcp-server.mdx).

---

## Critical Rules (Prowler App Only)

### Tool Implementation

- **ALWAYS**: Extend `BaseTool` (auto-registered via `tool_loader.py`, only public methods from the class are exposed as a tool)
- **NEVER**: Manually register BaseTool subclasses
- **NEVER**: Import tools directly in server.py

### Models

- **ALWAYS**: Use `MinimalSerializerMixin` for responses
- **ALWAYS**: Implement `from_api_response()` factory method
- **ALWAYS**: Use two-tier models (Simplified for lists, Detailed for single items)
- **NEVER**: Return raw API responses

### API Client

- **ALWAYS**: Use `self.api_client` singleton
- **ALWAYS**: Use `build_filter_params()` for query parameters
- **NEVER**: Create new httpx clients

---

## Hub/Docs Tools

Use `@mcp.tool()` decorator directly—no BaseTool or models required.

---

## Quick Reference: New Prowler App Tool

1. Create tool class in `prowler_app/tools/` extending `BaseTool`
2. Create models in `prowler_app/models/` using `MinimalSerializerMixin`
3. Tools auto-register via `tool_loader.py`

---

## QA Checklist (Prowler App)

- [ ] Tool docstrings describe LLM-relevant behavior
- [ ] Models use `MinimalSerializerMixin`
- [ ] API responses transformed to simplified models
- [ ] Error handling returns `{"error": str, "status": "failed"}`
- [ ] Parameters use `Field()` with descriptions
- [ ] No hardcoded secrets

---

## Resources

- **Full Guide**: [docs/developer-guide/mcp-server.mdx](../../../docs/developer-guide/mcp-server.mdx)
- **Templates**: See [assets/](assets/) for tool and model templates
