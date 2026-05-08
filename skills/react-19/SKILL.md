---
name: react-19
description: "Trigger: When writing React 19 components, hooks, or `.tsx` files, especially with React Compiler, `use()`, actions, or ref-as-prop patterns. Applies React 19 runtime and composition rules."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke: "Writing React components"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when the change is inside React 19 component code and the agent must choose between Server Components, Client Components, compiler-friendly patterns, or modern hook APIs.

## Hard Rules

- Do not add `useMemo` or `useCallback` for routine render-path optimization; React Compiler handles the common case.
- Prefer Server Components by default; add `"use client"` only for client-only behavior.
- Import named React APIs; do not use default `React` imports.
- Use `ref` as a prop in React 19 instead of introducing `forwardRef` by habit.
- If the task also involves App Router or Server Actions integration details, load `nextjs-15` too.

## Decision Gates

| Question | Action |
|---|---|
| Does the component use state, effects, browser APIs, or event handlers? | Mark it as a Client Component with `"use client"`. |
| Does the component only fetch or compose data for rendering? | Keep it as a Server Component. |
| Are you reading a promise or conditional context? | Consider `use()` instead of older workarounds. |
| Are you wiring form actions or pending state? | Prefer actions and `useActionState`. |
| Are you about to add memoization for performance? | Stop and justify it; default to compiler-friendly plain code first. |

## Execution Steps

1. Identify whether the file should stay server-side or become client-side.
2. Remove legacy React imports and manual memoization unless there is a proven exception.
3. Keep render logic direct and compiler-friendly.
4. Use `use()` for supported promise/context reads when it simplifies the flow.
5. Use action-based form patterns for mutation flows when relevant.
6. Pass refs as props in new React 19 component APIs.
7. Validate that the final component model matches the feature's runtime needs.

## Output Contract

- State whether the component is server or client and why.
- Call out any React 19 modernization applied, such as removing manual memoization, using `use()`, or replacing `forwardRef`.
- Mention whether `nextjs-15` was also required.

## References

- [Next.js 15 skill](../nextjs-15/SKILL.md)
- [TypeScript skill](../typescript/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
