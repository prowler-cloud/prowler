# AI Agent Skills

This directory contains **Agent Skills** following the [Agent Skills open standard](https://agentskills.io). Skills provide domain-specific patterns, conventions, and guardrails that help AI coding assistants (Claude Code, OpenCode, Cursor, etc.) understand project-specific requirements.

## What Are Skills?

[Agent Skills](https://agentskills.io) is an open standard format for extending AI agent capabilities with specialized knowledge. Originally developed by Anthropic and released as an open standard, it is now adopted by multiple agent products.

Skills teach AI assistants how to perform specific tasks. When an AI loads a skill, it gains context about:

- Critical rules (what to always/never do)
- Code patterns and conventions
- Project-specific workflows
- References to detailed documentation

## Setup

Run the setup script to configure skills for all supported AI coding assistants:

```bash
./skills/setup.sh
```

This creates symlinks so each tool finds skills in its expected location:

| Tool | Symlink Created |
|------|-----------------|
| Claude Code / OpenCode | `.claude/skills/` |
| Codex (OpenAI) | `.codex/skills/` |
| GitHub Copilot | `.github/skills/` |
| Gemini CLI | `.gemini/skills/` |

After running setup, restart your AI coding assistant to load the skills.

## How to Use Skills

Skills are automatically discovered by the AI agent. To manually load a skill during a session:

```
Read skills/{skill-name}/SKILL.md
```

## Available Skills

### Generic Skills

Reusable patterns for common technologies:

| Skill | Description |
|-------|-------------|
| `typescript` | Const types, flat interfaces, utility types |
| `react-19` | React 19 patterns, React Compiler |
| `nextjs-15` | App Router, Server Actions, streaming |
| `tailwind-4` | cn() utility, Tailwind 4 patterns |
| `playwright` | Page Object Model, selectors |
| `vitest` | Unit testing, React Testing Library |
| `tdd` | Test-Driven Development workflow |
| `pytest` | Fixtures, mocking, markers |
| `django-drf` | ViewSets, Serializers, Filters |
| `zod-4` | Zod 4 API patterns |
| `zustand-5` | Persist, selectors, slices |
| `ai-sdk-5` | Vercel AI SDK patterns |

### Prowler-Specific Skills

Patterns tailored for Prowler development:

| Skill | Description |
|-------|-------------|
| `prowler` | Project overview, component navigation |
| `prowler-api` | Django + RLS + JSON:API patterns |
| `prowler-ui` | Next.js + shadcn conventions |
| `prowler-sdk-check` | Create new security checks |
| `prowler-mcp` | MCP server tools and models |
| `prowler-test-sdk` | SDK testing (pytest + moto) |
| `prowler-test-api` | API testing (pytest-django + RLS) |
| `prowler-test-ui` | E2E testing (Playwright) |
| `prowler-compliance` | Compliance framework structure |
| `prowler-provider` | Add new cloud providers |
| `prowler-pr` | Pull request conventions |
| `prowler-docs` | Documentation style guide |
| `prowler-attack-paths-query` | Create Attack Paths openCypher queries |

### Meta Skills

| Skill | Description |
|-------|-------------|
| `skill-creator` | Create new AI agent skills |
| `skill-sync` | Sync skill metadata to AGENTS.md Auto-invoke sections |

## Directory Structure

```
skills/
├── {skill-name}/
│   ├── SKILL.md              # Required - main instrunsction and metadata
│   ├── scripts/              # Optional - executable code
│   ├── assets/               # Optional - templates, schemas, resources
│   └── references/           # Optional - links to local docs
└── README.md                 # This file
```

## Why Auto-invoke Sections?

**Problem**: AI assistants (Claude, Gemini, etc.) don't reliably auto-invoke skills even when the `Trigger:` in the skill description matches the user's request. They treat skill suggestions as "background noise" and barrel ahead with their default approach.

**Solution**: The `AGENTS.md` files in each directory contain an **Auto-invoke Skills** section that explicitly commands the AI: "When performing X action, ALWAYS invoke Y skill FIRST." This is a [known workaround](https://scottspence.com/posts/claude-code-skills-dont-auto-activate) that forces the AI to load skills.

**Automation**: Instead of manually maintaining these sections, run `skill-sync` after creating or modifying a skill:

```bash
./skills/skill-sync/assets/sync.sh
```

This reads `metadata.scope` and `metadata.auto_invoke` from each `SKILL.md` and generates the Auto-invoke tables in the corresponding `AGENTS.md` files.

## Creating New Skills

Use the `skill-creator` skill for guidance:

```
Read skills/skill-creator/SKILL.md
```

### Quick Checklist

1. Create directory: `skills/{skill-name}/`
2. Add `SKILL.md` with required frontmatter
3. Add `metadata.scope` and `metadata.auto_invoke` fields
4. Keep content concise (under 500 lines)
5. Reference existing docs instead of duplicating
6. Run `./skills/skill-sync/assets/sync.sh` to update AGENTS.md
7. Add to `AGENTS.md` skills table (if not auto-generated)

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
