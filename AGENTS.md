# Repository Guidelines

## How to Use This Guide

- Start here for cross-project norms. Prowler is a monorepo with several components.
- Each component has an `AGENTS.md` file with specific guidelines (e.g., `api/AGENTS.md`, `ui/AGENTS.md`).
- Component docs override this file when guidance conflicts.

## Available Skills

Use these skills for detailed patterns on-demand:

### Generic Skills (Any Project)
| Skill | Description |
|-------|-------------|
| `typescript` | Const types, flat interfaces, utility types |
| `react-19` | No useMemo/useCallback, React Compiler |
| `nextjs-15` | App Router, Server Actions, streaming |
| `tailwind-4` | cn() utility, no var() in className |
| `playwright` | Page Object Model, MCP workflow, selectors |
| `pytest` | Fixtures, mocking, markers, parametrize |
| `django-drf` | ViewSets, Serializers, Filters |
| `zod-4` | New API (z.email(), z.uuid()) |
| `zustand-5` | Persist, selectors, slices |
| `ai-sdk-5` | UIMessage, streaming, LangChain |

### Prowler-Specific Skills
| Skill | Description |
|-------|-------------|
| `prowler` | Project overview, component navigation |
| `prowler-api` | Django + RLS + JSON:API patterns |
| `prowler-ui` | Next.js + shadcn + HeroUI conventions |
| `prowler-sdk-check` | Create new security checks |
| `prowler-mcp` | MCP server tools and models |
| `prowler-test-sdk` | SDK testing (pytest + moto) |
| `prowler-test-api` | API testing (pytest-django + RLS) |
| `prowler-test-ui` | E2E testing (Playwright) |
| `prowler-compliance` | Compliance framework structure |
| `prowler-provider` | Add new cloud providers |
| `prowler-pr` | Pull request conventions |
| `prowler-docs` | Documentation style guide |

---

## Project Overview

Prowler is an open-source cloud security assessment tool supporting AWS, Azure, GCP, Kubernetes, GitHub, M365, and more.

| Component | Location | Tech Stack |
|-----------|----------|------------|
| SDK | `prowler/` | Python 3.9+, Poetry |
| API | `api/` | Django 5.1, DRF, Celery |
| UI | `ui/` | Next.js 15, React 19, Tailwind 4 |
| MCP Server | `mcp_server/` | FastMCP, Python 3.12+ |
| Dashboard | `dashboard/` | Dash, Plotly |

---

## Python Development

```bash
# Setup
poetry install --with dev
poetry run pre-commit install

# Code quality
poetry run make lint
poetry run make format
poetry run pre-commit run --all-files
```

---

## Commit & Pull Request Guidelines

Follow conventional-commit style: `<type>[scope]: <description>`

**Types:** `feat`, `fix`, `docs`, `chore`, `perf`, `refactor`, `style`, `test`

Before creating a PR:
1. Complete checklist in `.github/pull_request_template.md`
2. Run all relevant tests and linters
3. Link screenshots for UI changes
