---
name: typescript
description: "Trigger: When implementing or refactoring TypeScript in `.ts` or `.tsx`, including types, interfaces, generics, type guards, const maps, and stricter unknown handling. Enforces strict TypeScript modeling patterns."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke: "Writing TypeScript types/interfaces"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when the work changes TypeScript types or when runtime behavior depends on better compile-time modeling.

## Hard Rules

- Prefer strict, expressive types over `any`; use `unknown`, generics, or narrow unions instead.
- Model reusable literals from `as const` objects when values exist at runtime.
- Keep interfaces flat; extract nested object shapes into named types.
- Use discriminated unions when props or fields are only valid in coordinated sets.
- Import types with `import type` when only the type is needed.

## Decision Gates

| Question | Action |
|---|---|
| Need both runtime values and a type union? | Create a const object and derive the type from it. |
| Is a value shape deeply nested inline? | Extract dedicated named interfaces or types. |
| Are multiple optional props semantically coupled? | Replace them with discriminated union branches. |
| Is the input truly unknown? | Accept `unknown` and narrow with a type guard. |
| Are you duplicating a mapped or transformed shape manually? | Reach for utility types before inventing parallel interfaces. |

## Execution Steps

1. Identify the domain shape that needs stronger typing.
2. Replace `any` or weak optionals with precise unions, generics, or guards.
3. Convert literal unions to const-derived types when runtime values matter.
4. Flatten nested inline objects into named interfaces.
5. Use utility types for projections, partials, and derived shapes.
6. Re-check imports and convert type-only imports to `import type` where appropriate.
7. Validate that invalid states are now rejected by the type system.

## Output Contract

- Summarize the type-system improvement made.
- Call out any invalid state now prevented at compile time.
- Mention the main pattern used: const-derived type, discriminated union, utility type, or type guard.

## References

- [React 19 skill](../react-19/SKILL.md)
- [Zod 4 skill](../zod-4/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
