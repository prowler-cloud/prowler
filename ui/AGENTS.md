# Prowler UI - AI Agent Ruleset

> **Skills Reference**: For detailed patterns, use these skills:
>
> - [`prowler-ui`](../skills/prowler-ui/SKILL.md) - Prowler-specific UI patterns
> - [`no-use-effect`](../skills/no-use-effect/SKILL.md) - Derive state, use handlers and server data; no direct useEffect
> - [`prowler-ui-browser-review`](../skills/prowler-ui-browser-review/SKILL.md) - Browser sign-off for user-visible changes
> - [`prowler-test-ui`](../skills/prowler-test-ui/SKILL.md) - Playwright E2E testing (comprehensive)
> - [`typescript`](../skills/typescript/SKILL.md) - Const types, flat interfaces
> - [`react-19`](../skills/react-19/SKILL.md) - No useMemo/useCallback, compiler
> - [`nextjs-16`](../skills/nextjs-16/SKILL.md) - App Router, Server Actions
> - [`tailwind-4`](../skills/tailwind-4/SKILL.md) - cn() utility, no var() in className
> - [`zod-4`](../skills/zod-4/SKILL.md) - New API (z.email(), z.uuid())
> - [`zustand-5`](../skills/zustand-5/SKILL.md) - Selectors, persist middleware
> - [`ai-sdk-5`](../skills/ai-sdk-5/SKILL.md) - UIMessage, sendMessage
> - [`playwright`](../skills/playwright/SKILL.md) - Page Object Model, selectors
> - [`vitest`](../skills/vitest/SKILL.md) - Unit testing with React Testing Library
> - [`tdd`](../skills/tdd/SKILL.md) - Failing test first, one focused test per behavior
>
> **Code review**: [`REVIEW.md`](../REVIEW.md) holds the review rules and finding format.

## Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action                                                         | Skill                       |
| -------------------------------------------------------------- | --------------------------- |
| Add changelog entry for a PR or feature                        | `prowler-changelog`         |
| Add or edit changelog fragments in <component>/changelog.d/    | `prowler-changelog`         |
| Adding, changing or reviewing a React effect                   | `no-use-effect`             |
| App Router / Server Actions                                    | `nextjs-16`                 |
| Building AI chat features                                      | `ai-sdk-5`                  |
| Committing changes                                             | `prowler-commit`            |
| Create PR that requires changelog entry                        | `prowler-changelog`         |
| Creating Zod schemas                                           | `zod-4`                     |
| Creating a git commit                                          | `prowler-commit`            |
| Creating/modifying Prowler UI components                       | `prowler-ui`                |
| Fixing bug                                                     | `tdd`                       |
| Implementing feature                                           | `tdd`                       |
| Modifying component                                            | `tdd`                       |
| Refactoring code                                               | `tdd`                       |
| Review changelog format and conventions                        | `prowler-changelog`         |
| Reviewing Prowler UI components                                | `prowler-ui`                |
| Syncing React state with props, URL params or loaded data      | `no-use-effect`             |
| Testing hooks or utilities                                     | `vitest`                    |
| Using Zustand stores                                           | `zustand-5`                 |
| Verifying a user-visible UI change in the browser              | `prowler-ui-browser-review` |
| Working on Prowler UI structure (actions/adapters/types/hooks) | `prowler-ui`                |
| Working on task                                                | `tdd`                       |
| Working with Prowler UI test helpers/pages                     | `prowler-test-ui`           |
| Working with Tailwind classes                                  | `tailwind-4`                |
| Writing Playwright E2E tests                                   | `playwright`                |
| Writing Prowler UI E2E tests                                   | `prowler-test-ui`           |
| Writing React component tests                                  | `vitest`                    |
| Writing React components                                       | `react-19`                  |
| Writing TypeScript types/interfaces                            | `typescript`                |
| Writing Vitest tests                                           | `vitest`                    |
| Writing unit tests for UI                                      | `vitest`                    |

---

## CRITICAL RULES - NON-NEGOTIABLE

Rules marked **(lint)** fail `pnpm run lint:check`. Older violations are frozen in `eslint-suppressions.json`; new code must not add any.

### React

- ALWAYS: named imports, `import { useState } from "react"` **(lint)**
- NEVER: `useMemo`, `useCallback` or `memo`; the React Compiler memoizes **(lint)**
- NEVER: `useEffect` directly in a component. Derive in render, act in event handlers, load data on the server, reset with `key`. Real external-system sync goes in a named hook such as `hooks/use-mount-effect.ts` or `hooks/use-media-query.ts`. See `no-use-effect`.
- NEVER: `form.watch()` or `form.formState.<field>` read in render. `watch()` makes the compiler skip the component **(lint: `react-hooks/incompatible-library`)**, and a cached `formState` read goes stale. Use `useWatch({ control, name })` and `useFormState({ control })`

### Types

- ALWAYS: `const X = { A: "a", B: "b" } as const; type T = (typeof X)[keyof typeof X]`
- NEVER: hand-written string-literal unions, `type T = "a" | "b"` **(lint)**
- Label maps: `Record<T, string>`, never `Record<string, string>` when the keys are known
- Interfaces: one level deep; a nested object gets its own interface; reuse with `extends`

### Styling

- Colors come from the tokens in `styles/globals.css`. NEVER raw palette classes (`bg-blue-500`), hex values or `var()` in `className` **(lint)**
- Shared controls change look through their `variant`/`size` props, not call-site `className`
- `className="..."` for static classes, `cn()` for conditional ones, `style` for dynamic values

---

## WHERE CODE GOES

New features live with their route, like `app/(prowler)/alerts/`:

```text
app/(prowler)/<domain>/
├── page.tsx
├── _actions/      # server actions + adapters, index.ts barrel
├── _components/   # feature components, one index.ts per subfolder
├── _lib/          # pure helpers, schemas, stores
└── _types/        # feature types, index.ts barrel
```

| Code                                  | Location                                                                                                       |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Feature code                          | `app/(prowler)/<domain>/_*`                                                                                    |
| Used by 2+ domains                    | `components/shared/`, `lib/`, `types/`, `hooks/`                                                               |
| UI primitive or design-system pattern | `components/shadcn/` (compound components)                                                                     |
| API route handler                     | `app/api/...`                                                                                                  |
| Zustand store shared across routes    | `store/<feature>/`                                                                                             |
| Deprecated                            | `components/ui/` re-exports shadcn for the Prowler Cloud overlay. Never add to it or import from it **(lint)** |

- Import across `_` folders with `@/app/(prowler)/<domain>/_lib/...`; use relative paths inside one folder.
- Older features still live in global `actions/<feature>/` and `components/<domain>/`. When you only touch one, follow its existing layout; move it only when the task is the migration.

## SERVER AND CLIENT

- Server Components fetch; client components receive data or a promise to unwrap with `use()`.
- Never pass a function from a Server Component to a Client Component. `components/filters/data-filters.ts` stays plain data; formatters attach in a `"use client"` wrapper like `app/(prowler)/invitations/_components/invitations-filters.tsx`. Unit tests do not catch this; the real page does.
- Server actions call the API with `getAuthHeaders()` from `lib/helper.ts` and validate user input on the server (a Zod schema for form input). Never trust client-side validation alone.
- Next.js 16.4 ships its docs in `node_modules/next/dist/docs/`. Read the relevant page there before version-sensitive Next work.

## PROWLER CLOUD OVERLAY

Prowler Cloud builds on this code.

- Gate Cloud-only UI with `isCloud()` from `lib/shared/env.ts`. Never read `UI_CLOUD_ENABLED` in components.
- Paid-plan gates are seams whose OSS body returns the self-hosted default, and the overlay replaces the body: `lib/s3-integration-access.ts`, `lib/report-download-access.ts`, `lib/findings-access.ts`. Add new gates the same way.

## LAYOUT

- `sm:`…`2xl:` are container queries inside `[data-responsive-container]` (set on `<main>`) and media queries elsewhere. Use them as plain breakpoints; use `min-[64rem]:` when you need viewport semantics inside `<main>`.
- A `fixed` element rendered inside `<main>` must portal to `document.body` (see `components/findings/floating-selection-actions.tsx`).
- No layout shift: render the structure on first paint and put a skeleton sized like the real content where async data lands.
- Handle loading, empty and error states for every async view.

## FEATURE GUIDES

Read these before changing the feature:

- `app/(prowler)/lighthouse/AGENTS.md`: Lighthouse AI v1/v2 and the chat stream contract
- `app/(prowler)/realtime/AGENTS.md`: Prowler Realtime (Cloud only)

---

## TESTS

- A test earns its place only when it is fast, uses few or no mocks, and fails without the change it accompanies. Write it first and watch it fail.
- One focused test per bug or behavior, at the cheapest level that catches it. Extend the closest existing suite instead of starting a new file.
- Do not write tests that echo a mock (a stubbed `fetch` "was called with" the URL the code builds), tautologies, or checks that a removed thing is gone.
- When types, schemas or existing tests already cover the change, add no test and say so in one line in the PR.
- `*.test.ts(x)` (jsdom) runs without the React Compiler. Behavior that depends on it (forms, compiled memoization) needs a `*.integration.test.tsx` browser test.

## LINT AND KNIP RATCHET

- `eslint-suppressions.json` freezes existing violations. Never add entries, `eslint-disable` comments or lint config overrides without explicit human approval for that rule and scope.
- When you fix a suppressed violation, run `pnpm run lint:prune-suppressions`; lint fails until the stale entry is pruned.
- `lint:knip` runs in CI with `--max-issues` set to the current count. Lower it when you remove unused code; never raise it without approval.

## VERIFICATION

| Change                                          | Check                                                              |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| Any `ui/**` file                                | `pnpm run healthcheck` (typecheck, lint, format)                   |
| Helpers, adapters, actions, stores              | `pnpm exec vitest run --project unit <files>`                      |
| Components, forms, layout                       | `pnpm exec vitest run --project integration <files>`               |
| Added or removed files, exports or dependencies | `pnpm run lint:knip`                                               |
| Anything a user sees                            | `prowler-ui-browser-review`                                        |
| Flows covered by Playwright                     | `pnpm run test:e2e` (needs a running stack, see `prowler-test-ui`) |

End with evidence, not claims: quote each check's summary line (for example `Tests  12 passed (12)`), name the checks you skipped and why, and never report unverified work as done.

## HYGIENE

- Comments: one line, two at most, describing behavior. Never narrate the change or the review.
- No ticket keys, Slack ids, emails or other personal identifiers in code, commits, changelog fragments or PR text. This repository is public.
- No secrets in code; local config goes in `.env.local`. Error messages shown to users are sanitized.
- New npm dependencies need the package-health evidence the PR template asks for and a reason existing or native options do not work.
- User-facing changes need a changelog fragment in `ui/changelog.d/` (see `prowler-changelog`).

## COMMANDS

```bash
pnpm install && pnpm run dev
pnpm run healthcheck               # typecheck + lint:check + format:check
pnpm run lint:fix
pnpm run lint:prune-suppressions
pnpm run lint:knip
pnpm run test:unit
pnpm run test:integration
pnpm run test:e2e
```
