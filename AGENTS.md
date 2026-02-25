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
| `jsonapi` | Strict JSON:API v1.1 spec compliance | [SKILL.md](skills/jsonapi/SKILL.md) |
| `zod-4` | New API (z.email(), z.uuid()) | [SKILL.md](skills/zod-4/SKILL.md) |
| `zustand-5` | Persist, selectors, slices | [SKILL.md](skills/zustand-5/SKILL.md) |
| `ai-sdk-5` | UIMessage, streaming, LangChain | [SKILL.md](skills/ai-sdk-5/SKILL.md) |
| `vitest` | Unit testing, React Testing Library | [SKILL.md](skills/vitest/SKILL.md) |
| `tdd` | Test-Driven Development workflow | [SKILL.md](skills/tdd/SKILL.md) |

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
| `prowler-compliance-review` | Review compliance framework PRs | [SKILL.md](skills/prowler-compliance-review/SKILL.md) |
| `prowler-provider` | Add new cloud providers | [SKILL.md](skills/prowler-provider/SKILL.md) |
| `prowler-changelog` | Changelog entries (keepachangelog.com) | [SKILL.md](skills/prowler-changelog/SKILL.md) |
| `prowler-ci` | CI checks and PR gates (GitHub Actions) | [SKILL.md](skills/prowler-ci/SKILL.md) |
| `prowler-commit` | Professional commits (conventional-commits) | [SKILL.md](skills/prowler-commit/SKILL.md) |
| `prowler-pr` | Pull request conventions | [SKILL.md](skills/prowler-pr/SKILL.md) |
| `prowler-docs` | Documentation style guide | [SKILL.md](skills/prowler-docs/SKILL.md) |
| `prowler-attack-paths-query` | Create Attack Paths openCypher queries | [SKILL.md](skills/prowler-attack-paths-query/SKILL.md) |
| `gh-aw` | GitHub Agentic Workflows (gh-aw) | [SKILL.md](skills/gh-aw/SKILL.md) |
| `skill-creator` | Create new AI agent skills | [SKILL.md](skills/skill-creator/SKILL.md) |

### Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action | Skill |
|--------|-------|
| Add changelog entry for a PR or feature | `prowler-changelog` |
| Adding DRF pagination or permissions | `django-drf` |
| Adding new providers | `prowler-provider` |
| Adding privilege escalation detection queries | `prowler-attack-paths-query` |
| Adding services to existing providers | `prowler-provider` |
| After creating/modifying a skill | `skill-sync` |
| App Router / Server Actions | `nextjs-15` |
| Building AI chat features | `ai-sdk-5` |
| Committing changes | `prowler-commit` |
| Configuring MCP servers in agentic workflows | `gh-aw` |
| Create PR that requires changelog entry | `prowler-changelog` |
| Create a PR with gh pr create | `prowler-pr` |
| Creating API endpoints | `jsonapi` |
| Creating Attack Paths queries | `prowler-attack-paths-query` |
| Creating GitHub Agentic Workflows | `gh-aw` |
| Creating ViewSets, serializers, or filters in api/ | `django-drf` |
| Creating Zod schemas | `zod-4` |
| Creating a git commit | `prowler-commit` |
| Creating new checks | `prowler-sdk-check` |
| Creating new skills | `skill-creator` |
| Creating/modifying Prowler UI components | `prowler-ui` |
| Creating/modifying models, views, serializers | `prowler-api` |
| Creating/updating compliance frameworks | `prowler-compliance` |
| Debug why a GitHub Actions job is failing | `prowler-ci` |
| Debugging gh-aw compilation errors | `gh-aw` |
| Fill .github/pull_request_template.md (Context/Description/Steps to review/Checklist) | `prowler-pr` |
| Fixing bug | `tdd` |
| General Prowler development questions | `prowler` |
| Implementing JSON:API endpoints | `django-drf` |
| Importing Copilot Custom Agents into workflows | `gh-aw` |
| Implementing feature | `tdd` |
| Inspect PR CI checks and gates (.github/workflows/*) | `prowler-ci` |
| Inspect PR CI workflows (.github/workflows/*): conventional-commit, pr-check-changelog, pr-conflict-checker, labeler | `prowler-pr` |
| Mapping checks to compliance controls | `prowler-compliance` |
| Mocking AWS with moto in tests | `prowler-test-sdk` |
| Modifying API responses | `jsonapi` |
| Modifying gh-aw workflow frontmatter or safe-outputs | `gh-aw` |
| Modifying component | `tdd` |
| Refactoring code | `tdd` |
| Regenerate AGENTS.md Auto-invoke tables (sync.sh) | `skill-sync` |
| Review PR requirements: template, title conventions, changelog gate | `prowler-pr` |
| Review changelog format and conventions | `prowler-changelog` |
| Reviewing JSON:API compliance | `jsonapi` |
| Reviewing compliance framework PRs | `prowler-compliance-review` |
| Testing RLS tenant isolation | `prowler-test-api` |
| Testing hooks or utilities | `vitest` |
| Troubleshoot why a skill is missing from AGENTS.md auto-invoke | `skill-sync` |
| Understand CODEOWNERS/labeler-based automation | `prowler-ci` |
| Understand PR title conventional-commit validation | `prowler-ci` |
| Understand changelog gate and no-changelog label behavior | `prowler-ci` |
| Understand review ownership with CODEOWNERS | `prowler-pr` |
| Update CHANGELOG.md in any component | `prowler-changelog` |
| Updating README.md provider statistics table | `prowler-readme-table` |
| Updating checks, services, compliance, or categories count in README.md | `prowler-readme-table` |
| Updating existing Attack Paths queries | `prowler-attack-paths-query` |
| Updating existing checks and metadata | `prowler-sdk-check` |
| Using Zustand stores | `zustand-5` |
| Working on MCP server tools | `prowler-mcp` |
| Working on Prowler UI structure (actions/adapters/types/hooks) | `prowler-ui` |
| Working on task | `tdd` |
| Working with Prowler UI test helpers/pages | `prowler-test-ui` |
| Working with Tailwind classes | `tailwind-4` |
| Writing Playwright E2E tests | `playwright` |
| Writing Prowler API tests | `prowler-test-api` |
| Writing Prowler SDK tests | `prowler-test-sdk` |
| Writing Prowler UI E2E tests | `prowler-test-ui` |
| Writing Python tests with pytest | `pytest` |
| Writing React component tests | `vitest` |
| Writing React components | `react-19` |
| Writing TypeScript types/interfaces | `typescript` |
| Writing Vitest tests | `vitest` |
| Writing documentation | `prowler-docs` |
| Writing unit tests for UI | `vitest` |

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
