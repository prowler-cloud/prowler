---
name: prowler
description: >
  Main entry point for Prowler development - quick reference for all components.
  Trigger: General Prowler development questions, project overview, component navigation.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## Components

| Component | Stack | Location |
|-----------|-------|----------|
| SDK | Python 3.9+, Poetry | `prowler/` |
| API | Django 5.1, DRF, Celery | `api/` |
| UI | Next.js 15, React 19, Tailwind 4 | `ui/` |
| MCP | FastMCP 2.13.1 | `mcp_server/` |

## Quick Commands

```bash
# SDK
poetry install --with dev
poetry run python prowler-cli.py aws --check check_name
poetry run pytest tests/

# API
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run pytest

# UI
cd ui && pnpm run dev
cd ui && pnpm run healthcheck

# MCP
cd mcp_server && uv run prowler-mcp

# Full Stack
docker-compose up -d
```

## Providers

AWS, Azure, GCP, Kubernetes, GitHub, M365, OCI, AlibabaCloud, MongoDB Atlas, IaC

## Commit Style

`feat:`, `fix:`, `docs:`, `chore:`, `perf:`, `refactor:`, `test:`

## Related Skills

- `prowler-sdk-check` - Create security checks
- `prowler-api` - Django/DRF patterns
- `prowler-ui` - Next.js/React patterns
- `prowler-mcp` - MCP server tools
- `prowler-test` - Testing patterns
