---
name: prowler-ui
description: "Trigger: When working inside `ui/` on Prowler-specific app structure, folder placement, shared UI conventions, shadcn adoption, or display-layer patterns beyond generic React/Next.js guidance. Applies the repo’s UI architecture rules."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Creating/modifying Prowler UI components"
    - "Working on Prowler UI structure (actions/adapters/types/hooks)"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when the work depends on Prowler UI structure rather than generic framework syntax: component placement, action/adapter boundaries, shared-vs-local scope decisions, legacy HeroUI avoidance, or shared display utilities. Pair it with `react-19`, `nextjs-15`, `tailwind-4`, `typescript`, `zod-4`, or `zustand-5` when those implementation details matter.

## Hard Rules

- Always prefer `components/shadcn/` for new UI; do not introduce new HeroUI usage.
- Always apply the scope rule first: code reused in 2+ places becomes shared, otherwise keep it local.
- Always keep server actions, adapters, types, hooks, and utilities in their intended folders.
- Always derive state directly when possible; do not mirror props or search params into effect-driven local state without a real buffering reason.
- Always reuse shared label, formatter, and display helpers before adding local maps.
- Never encode invalid prop combinations with unrelated optional fields when a discriminated union can model the API correctly.

## Decision Gates

| Question | Action |
|---|---|
| Is this a new component? | Build with shadcn + Tailwind conventions. |
| Is logic reused across multiple features? | Promote it to `components/`, `types/`, `hooks/`, or `lib/` as appropriate. |
| Is it only used in one feature? | Keep it inside that feature boundary. |
| Is styling conditional or compositional? | Use `cn()`; use plain `className` for static classes. |
| Does a third-party prop reject Tailwind classes? | Use a constant or `style` value, not `var()` inside `className`. |

## Execution Steps

1. Identify whether the change is component structure, state modeling, display formatting, or action/data flow.
2. Apply the scope rule to decide local versus shared placement.
3. Choose shadcn-first component patterns and keep legacy HeroUI isolated.
4. Check shared helpers in `ui/types`, `ui/lib`, and `ui/hooks` before adding duplicates.
5. Validate prop APIs, derived state, and styling decisions against the established UI rules.
6. Pull in generic framework skills only for the parts they specifically own.

## Output Contract

- State where the code should live in `ui/` and why.
- Call out the main UI rule applied: shadcn-first, scope rule, derived state, shared helper reuse, or discriminated unions.
- Mention any companion generic skills required.
- Flag any legacy HeroUI or state-sync risk that must be preserved or removed carefully.

## References

- [Repository agent rules](../../AGENTS.md)
- [UI component guidance](../../ui/AGENTS.md)
- [UI references](references/ui-docs.md)
- [TypeScript skill](../typescript/SKILL.md)
- [React 19 skill](../react-19/SKILL.md)
- [Next.js 15 skill](../nextjs-15/SKILL.md)
- [Tailwind 4 skill](../tailwind-4/SKILL.md)
