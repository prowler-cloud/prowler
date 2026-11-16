# AI Agent Skills

This directory contains **Agent Skills** following the [Agent Skills open standard](https://agentskills.io). Skills provide domain-specific patterns, conventions, and guardrails that help AI coding assistants (Claude Code, Codex, Gemini CLI, GitHub Copilot, and other `AGENTS.md`-aware tools) understand project-specific requirements.

## What Are Skills?

[Agent Skills](https://agentskills.io) is an open standard format for extending AI agent capabilities with specialized knowledge. Originally developed by Anthropic and released as an open standard, it is now adopted by multiple agent products.

Skills teach AI assistants how to perform specific tasks. When an AI loads a skill, it gains context about:

- Critical rules (what to always/never do)
- Code patterns and conventions
- Project-specific workflows
- References to detailed documentation

## Setup

Run the setup script from the repository root:

```bash
./skills/setup.sh                    # Interactive menu (Claude Code preselected)
./skills/setup.sh --all              # Claude Code, Gemini CLI, Codex and GitHub Copilot
./skills/setup.sh --claude --codex   # Any combination of --claude, --gemini, --codex, --copilot
./skills/setup.sh --help
```

What each option creates (all paths are symlinks, so `skills/` and `AGENTS.md` stay the single source of truth):

| Tool | Flag | Created by setup |
|------|------|------------------|
| Claude Code | `--claude` | `.claude/skills -> skills/`, plus `CLAUDE.md -> AGENTS.md` next to every `AGENTS.md` (root, `api/`, `ui/`, `prowler/`, `mcp_server/`, `docs/`) |
| Gemini CLI | `--gemini` | `.gemini/skills -> skills/`, plus `GEMINI.md -> AGENTS.md` next to every `AGENTS.md` |
| Codex (OpenAI) | `--codex` | `.agents/skills -> skills/` (where Codex discovers repo skills) and the legacy `.codex/skills -> skills/`; Codex reads `AGENTS.md` natively, so no instruction file is linked |
| GitHub Copilot | `--copilot` | `.github/copilot-instructions.md -> ../AGENTS.md` (root `AGENTS.md` only) |

Notes:

- The script adds the generated paths to `.gitignore` if they are missing (they are already listed there).
- An existing real `.claude/skills`, `.gemini/skills`, `.agents/skills` or `.codex/skills` directory is moved to `skills.backup.<timestamp>` before linking; an existing symlink is replaced. Re-running is safe.
- Restart your AI coding assistant after running setup.
- Tests for the script (temporary directories only): `bash skills/setup_test.sh`

## How to Use Skills

Skills are discovered by the AI agent from the linked skills directory and from the **Auto-invoke Skills** tables in the `AGENTS.md` files. To load a skill manually during a session:

```text
Read skills/{skill-name}/SKILL.md
```

## Available Skills

### Generic Skills

Reusable patterns for common technologies:

| Skill | Description |
|-------|-------------|
| `typescript` | Const types, flat interfaces, utility types |
| `react-19` | React 19 patterns, React Compiler |
| `nextjs-16` | App Router, Server Actions, proxy.ts, streaming |
| `tailwind-4` | cn() utility, no var() in className |
| `zod-4` | Zod 4 API patterns (z.email(), z.uuid()) |
| `zustand-5` | Persist, selectors, slices |
| `ai-sdk-5` | Vercel AI SDK UIMessage API (installed `ai` 6.x) |
| `playwright` | Page Object Model, selectors, MCP exploration workflow |
| `vitest` | Unit and browser-integration testing with React Testing Library |
| `pytest` | Fixtures, mocking, markers, parametrize |
| `tdd` | Test-Driven Development workflow |
| `django-drf` | ViewSets, Serializers, Filters |
| `jsonapi` | Strict JSON:API v1.1 spec compliance |

### Prowler-Specific Skills

Patterns tailored for Prowler development:

| Skill | Description |
|-------|-------------|
| `prowler` | Project overview, component navigation |
| `prowler-api` | Django + RLS + RBAC + JSON:API patterns |
| `prowler-ui` | Next.js + shadcn conventions |
| `prowler-sdk-check` | Create and update security checks |
| `prowler-provider` | Add new cloud providers or services |
| `prowler-compliance` | Compliance frameworks (universal and legacy schemas) |
| `prowler-compliance-review` | Review compliance framework PRs |
| `prowler-registry-artifact` | Package checks, compliance frameworks and providers as plug-in wheels for the Prowler Registry |
| `prowler-mcp` | MCP server tools and models |
| `prowler-attack-paths-query` | Create Attack Paths openCypher queries |
| `prowler-readme-table` | Update the README provider statistics table |
| `django-migration-psql` | Django migration best practices for PostgreSQL |
| `postgresql-indexing` | PostgreSQL indexing, EXPLAIN, monitoring, maintenance |

### Prowler Testing Skills

| Skill | Description |
|-------|-------------|
| `prowler-test-sdk` | SDK testing (pytest + moto) |
| `prowler-test-api` | API testing (pytest-django + RLS) |
| `prowler-test-ui` | E2E testing (Playwright) |
| `prowler-test-mcp` | MCP server testing (FastMCP clients, mocked httpx) |

### Prowler Workflow Skills

| Skill | Description |
|-------|-------------|
| `prowler-changelog` | Changelog fragments in `<component>/changelog.d/` (towncrier) |
| `prowler-commit` | Conventional commits and prek hooks |
| `prowler-pr` | Pull request template, title and labels |
| `prowler-ci` | CI checks and PR gates (GitHub Actions) |
| `prowler-docs` | Documentation style guide and Mintlify conventions |
| `gh-aw` | GitHub Agentic Workflows (gh-aw) |

### Meta Skills

| Skill | Description |
|-------|-------------|
| `skill-creator` | Create new AI agent skills |
| `skill-sync` | Sync skill metadata to AGENTS.md Auto-invoke sections |

## Directory Structure

```text
skills/
├── {skill-name}/
│   ├── SKILL.md              # Required - main instructions and metadata
│   ├── assets/               # Optional - templates, schemas, scripts
│   └── references/           # Optional - links to local docs
├── setup.sh                  # Links skills into each AI assistant
├── setup_test.sh             # Tests for setup.sh
└── README.md                 # This file
```

## Why Auto-invoke Sections?

**Problem**: AI assistants don't reliably auto-invoke skills even when the `Trigger:` in the skill description matches the user's request.

**Solution**: The `AGENTS.md` files contain an **Auto-invoke Skills** section that explicitly commands the AI: "When performing X action, ALWAYS invoke Y skill FIRST." This is a [known workaround](https://scottspence.com/posts/claude-code-skills-dont-auto-activate) that makes the AI load skills.

**Automation**: The tables are generated from `metadata.scope` and `metadata.auto_invoke` in each `SKILL.md`. After creating or modifying a skill, run:

```bash
./skills/skill-sync/assets/sync.sh --dry-run   # preview
./skills/skill-sync/assets/sync.sh             # update AGENTS.md files
```

Valid scopes: `root` (`AGENTS.md`), `ui`, `api`, `sdk` (`prowler/AGENTS.md`), `mcp_server`.

## Creating New Skills

Use the `skill-creator` skill for guidance:

```text
Read skills/skill-creator/SKILL.md
```

### Quick Checklist

1. Create directory: `skills/{skill-name}/` (the directory name must equal `name`)
2. Add `SKILL.md` with required frontmatter, including a `Trigger:` sentence in `description`
3. Add `metadata.scope` and `metadata.auto_invoke`
4. Keep content concise (under 500 lines); verify every path and command against the code
5. Reference existing docs instead of duplicating
6. Run `./skills/skill-sync/assets/sync.sh` to update the Auto-invoke tables
7. Add the skill to the "Available Skills" tables in the root `AGENTS.md` and in this README (not generated)

## Design Principles

- **Concise**: Only include what AI doesn't already know
- **Progressive disclosure**: Point to detailed docs, don't duplicate
- **Critical rules first**: Lead with ALWAYS/NEVER patterns
- **Minimal examples**: Show patterns, not tutorials

## Resources

- [Agent Skills Standard](https://agentskills.io) - Open standard specification
- [Agent Skills GitHub](https://github.com/anthropics/skills) - Example skills
- [Claude Code Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices) - Skill authoring guide
- [Prowler AGENTS.md](../AGENTS.md) - AI agent general rules
- [AI Skills developer guide](../docs/developer-guide/ai-skills.mdx) - Contributor documentation
