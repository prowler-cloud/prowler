# Code review

Review new or worsened code. Do not ask for unrelated legacy cleanup. A new violation of a team rule must be fixed before merge, even when it causes no bug. Exceptions need explicit human approval on the PR.

## References

Read the `AGENTS.md` that owns each changed path and the skills listed for that component. Use their technical rules, not their implementation or commit workflows. This file wins when they conflict on review behavior.

- **UI (`ui/**`)**: [`ui/AGENTS.md`](ui/AGENTS.md), [`prowler-ui`](skills/prowler-ui/SKILL.md), [`react-19`](skills/react-19/SKILL.md), [`no-use-effect`](skills/no-use-effect/SKILL.md), [`typescript`](skills/typescript/SKILL.md), [`tailwind-4`](skills/tailwind-4/SKILL.md), [`vitest`](skills/vitest/SKILL.md), [`prowler-test-ui`](skills/prowler-test-ui/SKILL.md)
- **API (`api/**`)**: [`api/AGENTS.md`](api/AGENTS.md), [`prowler-api`](skills/prowler-api/SKILL.md), [`django-drf`](skills/django-drf/SKILL.md), [`jsonapi`](skills/jsonapi/SKILL.md), [`django-migration-psql`](skills/django-migration-psql/SKILL.md)
- **SDK (`prowler/**`)**: [`prowler/AGENTS.md`](prowler/AGENTS.md), [`prowler-sdk-check`](skills/prowler-sdk-check/SKILL.md), [`prowler-test-sdk`](skills/prowler-test-sdk/SKILL.md)
- **Compliance frameworks**: [`prowler-compliance-review`](skills/prowler-compliance-review/SKILL.md)
- **MCP server (`mcp_server/**`)**: [`mcp_server/AGENTS.md`](mcp_server/AGENTS.md), [`prowler-mcp`](skills/prowler-mcp/SKILL.md)

Only the UI has team rules in this file so far. For other components, review against their `AGENTS.md` and skills, and report findings with the format below.

## Team rules for the UI

### Architecture

- New feature code lives with its route under `app/(prowler)/<domain>/` in `_actions/`, `_components/`, `_lib/` and `_types/`, like `app/(prowler)/alerts/`. Flag new feature code added to the global `actions/`, `components/<domain>/`, `lib/` or `types/` unless two or more domains use it. API route handlers stay under `app/api/`.
- Reuse shared display helpers before adding a map: `types/severities.ts`, `types/providers.ts`, `lib/date-utils.ts`, `lib/utils.ts`. Flag new local maps that duplicate them.
- Do not pass functions from a Server Component to a Client Component. `components/filters/data-filters.ts` stays plain data; formatters attach in a `"use client"` wrapper such as `app/(prowler)/invitations/_components/invitations-filters.tsx`. jsdom tests do not catch this, only the real page does.
- Cloud-only behavior goes through `isCloud()` (`lib/shared/env.ts`) or a seam whose OSS body is the self-hosted default (`lib/s3-integration-access.ts`, `lib/report-download-access.ts`, `lib/findings-access.ts`). Flag direct reads of `UI_CLOUD_ENABLED` or other env vars in components.
- Keep solutions simple. When you flag complexity, show the simpler alternative that meets the same requirement.

### Components and design system

- Primitives come from `components/shadcn/`. Flag new files in, or imports from, `components/ui/`: it only re-exports shadcn for the Prowler Cloud overlay.
- Modals use `@/components/shadcn/modal` and selects use `components/shadcn/select`. Flag custom wrappers that duplicate a shadcn primitive.
- Drive appearance with the component's `variant`, `size` or `tone` props. Flag visual `className` (color, opacity, hover, focus, disabled, spacing for looks) on shared controls, raw Tailwind palette colors (`bg-blue-500`), hex values and `var()` in `className`. Colors come from the tokens in `styles/globals.css`.
- A new variant or token is a design-system change: it goes into the shared component API with design sign-off, never at the call site.
- A design-system-shaped pattern (callout, hint, empty state) goes into `components/shadcn/` as a compound component, even with one consumer.
- Before a shared component changes for a request about one screen, every render context must still work. Nested finding rows have no header row and rely on per-cell labels; change the call site instead.
- Model coupled props as a discriminated union, never as independent optionals.
- `sm:` to `2xl:` are container queries inside `[data-responsive-container]` (`<main>` carries it) and media queries elsewhere. Use them as normal breakpoints. A `fixed` element rendered inside `<main>` must portal to `document.body`, like `components/findings/floating-selection-actions.tsx`; `<main>` is its containing block otherwise.
- No layout shift after load. Render the structure on first paint and put a skeleton sized like the real content where async data lands. Flag tabs, banners or callouts that appear late and push content down.
- Every async view handles loading, empty and error states. Interactive elements work with the keyboard and have accessible names.

### React and state

- React Compiler is on. Flag `useMemo`, `useCallback`, `React.memo` and default or namespace imports from `react`.
- Follow `no-use-effect`. Flag effects that derive state, relay a user action, mirror props or query results into state, or reset state when an id changes, and name the replacement (value derived in render, event handler, `key`, `useSyncExternalStore`, Server Component fetch). Effects that sync with a real external system (subscriptions, browser APIs, timers, `EventSource`) are fine. Use `useMountEffect` (`hooks/use-mount-effect.ts`) for mount-only setup.
- Before flagging an effect, show a working alternative that keeps the required timing, updates and cleanup. Moving avoidable state sync into a custom hook is not a fix.
- Under the compiler, a `form.formState.<field>` read inside an object literal or cached expression goes stale, and `form.watch()` makes the compiler skip the component. Use `useWatch({ control, name })` and `useFormState({ control })`.
- Types: string sets are `const` objects with a derived type (`(typeof X)[keyof typeof X]`), not hand-written string-literal unions. Label maps are typed `Record<ThatType, string>`, not `Record<string, string>`.
- Agent-run UIs (Lighthouse) show progress from real stream events. Flag progress bars or step counts that rely on the model reporting its own progress.

### Tests

- A test earns its place only when it is fast, uses few or no mocks, and fails without the change it accompanies.
- Flag tests that would pass without the fix: assertions that only echo a mock (a stubbed `fetch` "was called with" the URL the code builds), tautologies, and checks that a removed thing is gone.
- Flag duplicates of existing coverage and several tests where one meaningful test is enough. Say which one to keep.
- Do not ask for more tests unless a specific behavior change is untested. Then ask for one focused test of that behavior.
- Flag skipped or commented-out tests, tests that depend on another test's order or data, and tests that copy a limit or timeout from the code instead of importing the constant (unless the test pins that value on purpose).
- Unit tests (`*.test.ts(x)`, jsdom) do not run the React Compiler. Behavior that depends on it (forms, compiled memoization) needs a `*.integration.test.tsx` browser test.
- Prefer pure-logic tests for helpers, adapters and schemas. Test a server action or component only for a real decision: what gets revalidated on success, what is disabled without a permission.
- Use `toEqual` when the test checks that a result is exhaustive.
- E2E specs use page objects from `ui/tests/` and the tags described in `prowler-test-ui`.

### Security

- Server actions call the API with `getAuthHeaders()` (`lib/helper.ts`) and validate user input on the server, with a Zod schema for form input. Flag actions that rely on client-side validation alone.
- Write controls check the user's permission and render disabled with a tooltip when it is missing.
- Error messages shown to users are sanitized: no stack traces, raw API errors or tokens.
- Tokens stay on the server. The browser talks to same-origin routes; for example, the Lighthouse SSE stream goes through `app/api/lighthouse/v2/sessions/[sessionId]/event-stream/route.ts`.
- Icons ship in the bundle (air-gapped installs cannot reach icon CDNs). New npm dependencies need the package-health evidence the PR template asks for.

### Hygiene

- Comments describe behavior for future readers in one line, two at most. Flag comments that narrate the change or the review ("changed X to Y", "per review", "now also handles") or describe code that no longer exists.
- No internal ticket keys, Slack ids, emails or other personal identifiers in code, comments, commit messages, changelog fragments or PR text. This repository is public.
- Flag unrelated side fixes bundled into the PR.
- A new `eslint-disable` comment, lint config override, entry in `ui/eslint-suppressions.json` or higher `lint:knip` budget needs explicit human approval for that exact rule and scope.

## Findings

- **Defect**: a verified correctness, security or performance problem, or a design with a concrete harmful consequence. State impact and urgency from the evidence.
- **Convention**: a new violation of a team rule above or in the referenced skills. Quote the rule and the offending code. Do not imply runtime harm without separate evidence.
- Defect and Convention findings must be fixed before merge unless a human accepts them on the PR. Put the category in each finding's title.
- **Nit**: an optional improvement beyond the rules. Two at most.
- Leave out preferences, speculation, duplicates and failures CI already reports.

Before reporting, compare with the PR base and read the callers, safeguards and tests. Look for evidence that disproves the finding. A bug needs a reachable trigger and a consequence, backed by code, a reproducer, a test or an execution trace. State assumptions, and keep measurements apart from estimates. Unresolved risks go in questions, not findings.

List correctness, security and performance risks first, by impact, then rule violations. Report serious pre-existing bugs separately; they do not block the PR. Prefer local fixes over redesigns.

Give each finding a short title, a precise location, the evidence, and the fix or the next check. Group repeated causes. Report every Defect and Convention finding.

On re-review, check the fixes and report only new Defect and Convention findings. Do not repeat resolved feedback or add Nits. End with open questions and the checks you actually ran. When there are no findings, say so, without claiming that proves the change is safe.
