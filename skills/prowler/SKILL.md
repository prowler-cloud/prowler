---
name: prowler
description: "Trigger: When the task is general Prowler development, repository navigation, component selection, or project overview work outside PR CI workflow details. Routes the model to the right Prowler surface fast."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke: "General Prowler development questions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill first when the model needs to orient itself in the Prowler monorepo, choose the correct component, or point to the follow-up skill that should own the task.

## Hard Rules

- Treat this skill as a router, not the final authority for API, UI, SDK, MCP, CI, or testing implementation details.
- Redirect specialized work to the matching Prowler skill before giving deep guidance.
- Keep component guidance anchored to real repo paths and current stack names.
- Do not use this skill for PR workflow gates or GitHub Actions analysis; those belong to `prowler-pr` or `prowler-ci`.
- Prefer concise orientation over long cookbook explanations.

## Decision Gates

| Question | Action |
|---|---|
| Is the task about monorepo orientation or “where does this live”? | Use this skill and route to the right component. |
| Is the task inside `api/` with RLS, RBAC, providers, or Celery? | Load `prowler-api`. |
| Is the task inside `ui/` with app structure or component conventions? | Load `prowler-ui`. |
| Is the task about checks, providers, compliance, docs, CI, or PR gates? | Hand off to the corresponding specialized Prowler skill. |
| Is the task only about testing strategy? | Load `tdd` plus the matching test skill. |

## Execution Steps

1. Identify the affected surface: `prowler/`, `api/`, `ui/`, `mcp_server/`, or cross-cutting docs/CI.
2. Confirm the stack and runtime boundary for that surface.
3. Route to the correct specialized skill before proposing implementation details.
4. If multiple surfaces are involved, call out the primary owner and the supporting skills.
5. Return repo paths, component names, and the next best skill to load.

## Output Contract

- State the target component or components.
- Name the follow-up skill or skills that should own the work.
- Mention the canonical repo path(s) to inspect next.
- If the task is out of scope for this router skill, say so explicitly.

## References

- [Repository agent rules](../../AGENTS.md)
- [Prowler skill references](references/prowler-docs.md)
- [API component guidance](../../api/AGENTS.md)
- [UI component guidance](../../ui/AGENTS.md)
- [MCP component guidance](../../mcp_server/AGENTS.md)
