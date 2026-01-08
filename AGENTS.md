# Repository Guidelines

## How to Use This Guide

- Start here for cross-project norms. Prowler is a monorepo with several components.
- Each component has an `AGENTS.md` file with specific guidelines (e.g., `api/AGENTS.md`, `ui/AGENTS.md`).
- Component docs override this file when guidance conflicts.

## Available Skills

Use these skills for detailed patterns on-demand:

### Generic Skills (Any Project)
| Skill | Description | URL |
|-------|-------------|-----|
| `typescript` | Const types, flat interfaces, utility types | [SKILL.md](skills/typescript/SKILL.md) |
| `react-19` | No useMemo/useCallback, React Compiler | [SKILL.md](skills/react-19/SKILL.md) |
| `nextjs-15` | App Router, Server Actions, streaming | [SKILL.md](skills/nextjs-15/SKILL.md) |
| `tailwind-4` | cn() utility, no var() in className | [SKILL.md](skills/tailwind-4/SKILL.md) |
| `playwright` | Page Object Model, MCP workflow, selectors | [SKILL.md](skills/playwright/SKILL.md) |
| `pytest` | Fixtures, mocking, markers, parametrize | [SKILL.md](skills/pytest/SKILL.md) |
| `django-drf` | ViewSets, Serializers, Filters | [SKILL.md](skills/django-drf/SKILL.md) |
| `zod-4` | New API (z.email(), z.uuid()) | [SKILL.md](skills/zod-4/SKILL.md) |
| `zustand-5` | Persist, selectors, slices | [SKILL.md](skills/zustand-5/SKILL.md) |
| `ai-sdk-5` | UIMessage, streaming, LangChain | [SKILL.md](skills/ai-sdk-5/SKILL.md) |

### Prowler-Specific Skills
| Skill | Description | URL |
|-------|-------------|-----|
| `prowler` | Project overview, component navigation | [SKILL.md](skills/prowler/SKILL.md) |
| `prowler-api` | Django + RLS + JSON:API patterns | [SKILL.md](skills/prowler-api/SKILL.md) |
| `prowler-ui` | Next.js + shadcn conventions | [SKILL.md](skills/prowler-ui/SKILL.md) |
| `prowler-sdk-check` | Create new security checks | [SKILL.md](skills/prowler-sdk-check/SKILL.md) |
| `prowler-mcp` | MCP server tools and models | [SKILL.md](skills/prowler-mcp/SKILL.md) |
| `prowler-test-sdk` | SDK testing (pytest + moto) | [SKILL.md](skills/prowler-test-sdk/SKILL.md) |
| `prowler-test-api` | API testing (pytest-django + RLS) | [SKILL.md](skills/prowler-test-api/SKILL.md) |
| `prowler-test-ui` | E2E testing (Playwright) | [SKILL.md](skills/prowler-test-ui/SKILL.md) |
| `prowler-compliance` | Compliance framework structure | [SKILL.md](skills/prowler-compliance/SKILL.md) |
| `prowler-provider` | Add new cloud providers | [SKILL.md](skills/prowler-provider/SKILL.md) |
| `prowler-pr` | Pull request conventions | [SKILL.md](skills/prowler-pr/SKILL.md) |
| `prowler-docs` | Documentation style guide | [SKILL.md](skills/prowler-docs/SKILL.md) |
| `skill-creator` | Create new AI agent skills | [SKILL.md](skills/skill-creator/SKILL.md) |

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
