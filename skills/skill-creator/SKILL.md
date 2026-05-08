---
name: skill-creator
description: "Trigger: When user asks to create a new skill, add agent instructions, or document patterns for AI. Creates new AI agent skills following the Agent Skills spec."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke: "Creating new skills"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when the task is to create a new skill or reshape rough agent guidance into a reusable skill package.

## Hard Rules

- Create a skill only for reusable, non-trivial patterns.
- Keep `description` on one quoted physical line with `Trigger:` first.
- Use local references only; never point `references/` at web URLs.
- Prefer short rules, decision tables, and minimal examples over tutorials.
- Add `metadata.scope` and `metadata.auto_invoke` when the skill should surface in `AGENTS.md` auto-invoke tables.
- Do not duplicate long docs inside the skill; point to local references instead.

## Decision Gates

| Question | Action |
|---|---|
| Is the pattern already documented well enough? | Reuse or reference the existing doc instead of creating a new skill. |
| Is the guidance specific to this repo or workflow? | Create a project-specific skill name such as `prowler-{component}` or `{action}-{target}`. |
| Do you need templates, schemas, or example configs? | Put them in `assets/`. |
| Do you need supporting documentation? | Link only local files from `references/`. |
| Will the skill be auto-invoked from `AGENTS.md`? | Add or update `metadata.scope` and `metadata.auto_invoke`, then decide whether `skill-sync` must run. |

## Execution Steps

1. Confirm the skill does not already exist under `skills/`.
2. Choose a reusable name that matches the repo naming conventions.
3. Create `skills/{skill-name}/SKILL.md` and required support folders only if needed (`assets/`, `references/`).
4. Write frontmatter with `name`, one-line quoted `description`, `license`, and metadata.
5. Write the body in this order: Activation Contract, Hard Rules, Decision Gates, Execution Steps, Output Contract, References.
6. Keep the body compact: operational instructions first, examples only when they unblock execution.
7. If auto-invoke metadata changed, run the `skill-sync` workflow appropriate to the scope.
8. Update any non-generated skill index entries the repository expects.

## Output Contract

- Return the created or updated skill path(s).
- State whether auto-invoke metadata changed and whether `skill-sync` was run, dry-run, or intentionally skipped.
- Summarize the reusable pattern the skill captures in 1-3 bullets.
- Call out any follow-up files the human should review, such as `AGENTS.md` or assets/templates.

## References

- [Template](assets/SKILL-TEMPLATE.md)
- [Skills overview](../README.md)
- [Repository agent rules](../../AGENTS.md)
