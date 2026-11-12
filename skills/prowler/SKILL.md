---
name: prowler
description: >
  Main entry point for Prowler development - quick reference for all components.
  Trigger: General Prowler development questions, project overview, component navigation (NOT PR CI gates or GitHub Actions workflows).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke: "General Prowler development questions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Components

| Component | Stack | Location |
|-----------|-------|----------|
| SDK / CLI | Python 3.10-3.13, uv | `prowler/`, tests in `tests/` |
| API | Python 3.11-3.12, Django 5.2, DRF, Celery | `api/` |
| UI | Next.js 16, React 19, Tailwind 4, pnpm | `ui/` |
| MCP | Python 3.12+, FastMCP 3 | `mcp_server/` |

Each component has its own `pyproject.toml`/`package.json` and lockfile; check exact versions there instead of assuming.

## Quick Commands

```bash
# SDK
uv sync
uv run python prowler-cli.py aws --check {check_name}
uv run pytest -n auto tests/providers/aws/services/{service}/

# API (run from api/)
cd api && uv run python src/backend/manage.py runserver
cd api && uv run pytest src/backend

# UI
cd ui && pnpm run dev
cd ui && pnpm run healthcheck   # typecheck + lint + format check

# MCP
cd mcp_server && uv run prowler-mcp

# Quality (mirrors CI)
make lint     # SDK: flake8 + black + pylint; API and MCP: ruff
make format

# Full stack
docker compose up -d
```

## Providers

Built-in: AWS, Azure, GCP, Kubernetes, M365, GitHub, Google Workspace, Okta, Oracle Cloud, Alibaba Cloud, Cloudflare, OpenStack, Scaleway, StackIT, Vercel, Linode, Huawei Cloud, E2E Networks, NHN, MongoDB Atlas, plus the tool-wrapper providers IaC, Image and LLM. The authoritative list is `prowler/providers/` (and `prowler -h`). Providers, checks and compliance frameworks can also come from external packages via Python entry points (`prowler.providers`, `prowler.checks.<provider>`, `prowler.compliance`, `prowler.compliance.universal`).

## Workflow Conventions

| Topic | Rule | Skill |
|-------|------|-------|
| Commits / PR titles | Conventional commits with scope: `feat(aws): ...`, `fix(ui): ...`, `docs: ...`, `chore(...)` | `prowler-commit`, `prowler-pr` |
| Changelog | One fragment per entry in `<component>/changelog.d/<slug>.<type>.md`; never edit `CHANGELOG.md` directly | `prowler-changelog` |
| Git hooks | `prek install` (prek comes with `uv sync`), config in `.pre-commit-config.yaml` | `prowler-commit` |

## Related Skills

- `prowler-sdk-check` - Create or update security checks
- `prowler-provider` - New providers, plug-ins, services
- `prowler-compliance` - Compliance frameworks
- `prowler-api`, `prowler-ui`, `prowler-mcp` - Component patterns
- `prowler-test-sdk`, `prowler-test-api`, `prowler-test-ui`, `prowler-test-mcp` - Testing patterns
- `prowler-docs` - Documentation

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
