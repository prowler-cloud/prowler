---
name: prowler-test-mcp
description: >
  Testing patterns for the Prowler MCP Server: in-memory FastMCP clients, the
  ProwlerAPIClient singleton, JSON:API model builders and mocked httpx transports.
  Trigger: When writing tests under mcp_server/tests/ (tools, models, api_client, auth, sub-servers).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0.0"
  scope: [root, mcp_server]
  auto_invoke:
    - "Writing Prowler MCP server tests"
    - "Testing MCP tools or models"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- ALWAYS drive tools through an in-memory client: `async with Client(mcp_root_server)`.
  Tool parameters use pydantic `Field(default=...)`, and only FastMCP's wrapper
  resolves those defaults. Calling a tool method directly with an argument omitted
  leaves it as a raw `FieldInfo` — which is truthy, so `if email:` silently builds
  a filter out of the `FieldInfo` repr. Direct calls MUST pass every argument.
- NEVER open a `fastmcp.Client` inside a fixture. FastMCP warns this causes
  hard-to-diagnose event-loop issues; open it inline in the test.
- ALWAYS use the `mock_api_client` fixture; NEVER construct a `ProwlerAPIClient`.
  Tool instances captured the singleton by reference at import time, so only an
  in-place patch of `.client` reaches them.
- NEVER clear `SingletonMeta._instances`. It orphans every registered tool on an
  instance holding a real `httpx.AsyncClient`. Use `isolated_api_client` if you
  genuinely need a fresh instance.
- NEVER strip `PROWLER_API_KEY`. Tools are built at import time and a construction
  failure is swallowed, so the whole `prowler_*` namespace silently drops to zero
  tools. It is pinned in `[tool.pytest_env]`.
- For `ProwlerAppAuth`, pass `mode=` / `base_url=` explicitly. Those are resolved in
  default arguments, evaluated once at module import, so `monkeypatch.setenv` has
  no effect on them.
- NEVER assert an exact tool count — every future branch would have to bump it.
- Assert on `result.data` (structured output), not `result.content[0].text`.
- Tests are `test_*.py` (prefix), like the API — not the SDK's `*_test.py` suffix.
- `__init__.py` IS required in every `tests/` subdirectory here (unlike the SDK's
  repo-root `tests/`), or same-named modules collide under pytest's import mode.
- Async tests need no marker (`asyncio_mode = "auto"`). Do not use `@pytest.mark.anyio`.
- Use only obviously-fake credentials from `tests.helpers.tokens` (TruffleHog).
- One behaviour per test; keep tests self-contained and order-independent.

---

## 1. Layout

Mirror the source tree *below the package root* — drop the `prowler_mcp_server/`
level, exactly as the SDK maps `prowler/providers/...` to `tests/providers/...`.
So `prowler_mcp_server/prowler_app/tools/` is tested in `tests/prowler_app/tools/`.

```text
mcp_server/tests/
├── conftest.py                  # all shared fixtures
├── helpers/                     # jsonapi.py, http.py, assertions.py, tokens.py
├── test_server.py               # mounted-server contract
├── test_health.py
├── prowler_app/{models,tools,utils}/
├── prowler_hub/
└── prowler_documentation/
```

---

## 2. Fixtures

| Fixture | Autouse | What it gives you |
|---------|---------|-------------------|
| `_pinned_environment` | yes | Deterministic env; blocks a developer's `.env` from leaking |
| `_no_real_network` | yes | Any real socket connect raises `RuntimeError` |
| `_singleton_registry_guard` | yes | Snapshots/restores `SingletonMeta._instances` |
| `mock_router` | no | Route registry + request recorder |
| `api_client` | no | The live `ProwlerAPIClient` singleton |
| `mock_api_client` | no | **The workhorse** — singleton with a mocked transport |
| `isolated_api_client` | no | Evicts the singleton, for construction/identity tests |
| `mcp_root_server` | no | The mounted root server (session-scoped) |
| `health_client` | no | Starlette `TestClient` for `/health` |
| `http_request_headers` | no | Injects headers for HTTP-mode auth |
| `hub_router` | no | Mocks the Hub sub-server's two sync clients |
| `docs_router` | no | Mocks the docs search engine's two sync clients |

### `MockRouter`

```python
mock_router.add("GET", "/api/v1/users", json=jsonapi_collection([...]))
mock_router.add("GET", "/api/v1/tasks/t1", json=task_document("t1", "completed"))

mock_router.request_for("GET", "/api/v1/users")     # last request, for header asserts
mock_router.query_params("GET", "/api/v1/users")    # decoded query string
mock_router.paths()                                 # everything requested so far
```

Register a route more than once to return a sequence — the last response repeats.
That is how you drive `poll_task_until_complete` (`executing`, `executing`,
`completed`). An unregistered request raises, listing what *was* registered.

---

## 3. Patterns

**Tool test** — see `assets/mcp_tool_test.py`. Register routes, call through the
in-memory client, assert on `result.data` *and* on the recorded request. When a
tool chooses between endpoints, assert `mock_router.paths()` — a wrong choice is
invisible in the response body.

**Model test** — see `assets/mcp_model_test.py`. Build the document with the
`jsonapi` helpers, run `from_api_response()`, assert on both the model and
`model_dump()`. `MinimalSerializerMixin` makes those differ, and an absent
relationship (`None`) must never be conflated with an empty one (`[]`).

**Contract test** — see `assets/mcp_contract_test.py`. Namespacing and
description coverage across every registered tool.

The worked example in the repo is `findings`, covered across both layers in
`tests/prowler_app/{models,tools}/test_findings.py`. Read those first — they
exercise every foundation capability in one feature.

### Reading coverage

Coverage has a meaningless high floor. Model modules are almost entirely class-body
`Field(...)` declarations that execute at import, and `prowler_app/server.py` imports
every model module at import time. **Importing the package with zero tests already
reports 36% overall**, and individual model modules 54–84%.

So a model module at ~68% with no tests has none of its logic covered — the missing
ranges are the `from_api_response()` bodies, which is the only part worth testing.
Compare against the import-only floor, never against zero, and do not set a Codecov
target from the raw total.

### Where fixture data lives

`tests/helpers/` is feature-agnostic and must stay that way: it holds the JSON:API
*shape*, not any feature's data. Per-feature attribute dictionaries
(`FINDING_ATTRIBUTES`, `CHECK_METADATA`, …) belong as module-level constants in
the test module that uses them. Do not add feature fixtures to `helpers/`.

---

## 4. Commands

From `mcp_server/`:

```bash
cd mcp_server

uv run pytest                              # whole suite
uv run pytest tests/prowler_app/models     # one area
uv run pytest --cov=./prowler_mcp_server   # with coverage
```

From the repository root:

```bash
make test-mcp   # runs the MCP suite exactly as CI does
```

---

## 5. Reference

- Fixtures and the reasoning behind them: `mcp_server/tests/conftest.py`
- Testing section of `docs/developer-guide/mcp-server.mdx`
- Official FastMCP testing guide: <https://gofastmcp.com/development/tests>
