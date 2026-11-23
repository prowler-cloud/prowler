---
name: prowler-ui
description: >
  Prowler UI-specific patterns. For generic patterns, see: typescript, react-19, nextjs-16, tailwind-4.
  Trigger: When working inside ui/ on Prowler-specific conventions (shadcn, folder placement, actions/adapters, shared types/hooks/lib).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.3"
  scope: [root, ui]
  auto_invoke:
    - "Creating/modifying Prowler UI components"
    - "Reviewing Prowler UI components"
    - "Working on Prowler UI structure (actions/adapters/types/hooks)"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Related Generic Skills

- `typescript` - Const types, flat interfaces
- `react-19` - No useMemo/useCallback, compiler
- `no-use-effect` - Derive state, handlers, server data; no direct useEffect
- `prowler-ui-browser-review` - Browser sign-off for user-visible changes
- `nextjs-16` - App Router, Server Actions
- `tailwind-4` - cn() utility, styling rules
- `zod-4` - Schema validation
- `zustand-5` - State management
- `ai-sdk-5` - Chat/AI features (installed: AI SDK 6, `@ai-sdk/react` 3)
- `vitest` - Unit (jsdom) and browser integration tests
- `playwright` - E2E testing (see also `prowler-test-ui`)

## Tech Stack (Versions)

Source of truth is `ui/package.json` (pinned exact versions). At 5.48:

```text
Next.js 16.4 | React 19.2 (React Compiler on) | Tailwind 4.1 | shadcn/ui + Radix
Zod 4.4 | React Hook Form 7.62 | Zustand 5.0 | NextAuth 5.0.0-beta.32 | Recharts 2.15
AI SDK 6 (`ai`) + @ai-sdk/react 3 | LangChain/LangGraph (@langchain/*) for Lighthouse
Vitest 4.1 | Playwright 1.56 | TypeScript 5.5 | pnpm 11 | Node >= 22.13
```

## CRITICAL: Component Library Rule

- **ALWAYS**: Use `shadcn/ui` + Tailwind (`components/shadcn/`)
- **NEVER**: Add components to `components/ui/` (temporary re-export shims for the prowler-cloud overlay only)

## Design System Discipline (REQUIRED)

Applies to ALL UI work. The design system is the single source of truth — reuse it exactly, extend it deliberately.

- **Reuse first, never reinvent.** Before building anything, search `components/shadcn/` and existing usages in the codebase for an equivalent. Do NOT create a custom component, modal wrapper, or primitive when one already exists.
- **Use exactly the defined variants/styles — no more, no less.** At the call site, drive appearance through the component's `variant`/`size`/`tone` props. Never add ad-hoc visual `className` (color, opacity, hover/focus/disabled, spacing-for-looks) to shared controls (`Button`, `SelectTrigger`, `SelectItem`, `Modal`, badges…), and never skip the correct semantic variant.
- **Modals**: only `@/components/shadcn/modal`. **Selects**: `components/shadcn/select`.
- **Colors**: reuse existing semantic tokens from `ui/styles/globals.css`. No raw Tailwind color utilities (e.g. `bg-blue-950/40`), no hex. If no token fits, STOP and ask the design owner — do not invent or near-duplicate tokens.
- **Need a genuinely new variant/token?** That is a design-system change: add it to the shared component API (with design sign-off), then consume it. It is never a call-site decision.
- **Design-system-shaped patterns** (callouts, hints, empty states) go into `components/shadcn/` as compound components, even with one consumer. When a shadcn primitive carries stock tokens that `globals.css` does not define (e.g. `bg-popover`), fix the primitive with house tokens instead of patching call sites.
- **Shared components serve many screens.** Before changing one for a request about a single screen, grep its usages and check every render context. Nested finding rows have no header row and rely on per-cell labels; put the change at the call site.

Lint rejects raw palette classes, hex values, `var()` in `className` and imports from `components/ui/`. When reviewing UI PRs, also flag custom modals/primitives that duplicate shadcn, call-site visual `className` on shared controls, and new variants/tokens introduced without going through the shared component API.

## DECISION TREES

### Code Location

New features live with their route (reference: `app/(prowler)/alerts/`). Older features still live in the global folders; follow their layout unless the task is the migration.

```text
Server action + adapter → app/(prowler)/<domain>/_actions/ (index.ts barrel)
Feature component       → app/(prowler)/<domain>/_components/<sub>/ (index.ts per subfolder)
Pure helpers, schemas   → app/(prowler)/<domain>/_lib/
Feature types           → app/(prowler)/<domain>/_types/ (index.ts barrel)
Used by 2+ domains      → components/shared/, lib/, types/, hooks/
UI primitive            → components/shadcn/
API route handler       → app/api/...
Needs state/handlers    → "use client"; otherwise a Server Component (no directive)
```

Import across `_` folders with `@/app/(prowler)/<domain>/_lib/...`; use relative paths inside one folder.

> **Deprecated:** `components/ui/` is a temporary re-export shim that maps
> legacy import paths to `components/shadcn/` for the prowler-cloud overlay.
> HeroUI is fully removed. Never add or import components here — use
> `@/components/shadcn` (primitives) or `@/components/{domain}` instead.
> Delete the shim once the cloud repo migrates to `@/components/shadcn`.

### Styling Decision

```text
Tailwind class exists? → className
Dynamic value?         → style prop
Conditional styles?    → cn()
Static only?           → className (no cn())
Recharts/library?      → CHART_COLORS constant + var()
```

### Scope Rule (ABSOLUTE)

- Used 2+ domains → `components/shared/`, `lib/`, `types/` or `hooks/`
- Used by 1 feature → keep it in that feature's `app/(prowler)/<domain>/_*` folders
- Exception: design-system-shaped patterns go to `components/shadcn/` even with one consumer

## Project Structure

```text
ui/
├── app/
│   ├── (auth)/              # Sign-in, sign-up, invitation
│   ├── (prowler)/           # Main app; each route owns _actions/_components/_lib/_types
│   └── api/                 # Route handlers (proxies, auth, health)
├── components/
│   ├── shadcn/              # shadcn/ui primitives and design-system patterns (USE THIS)
│   ├── shared/              # Cross-domain composed components (2+ domains)
│   ├── ui/                  # DEPRECATED shim → re-exports shadcn for the Cloud overlay
│   ├── {domain}/            # Older domain components (findings, providers, scans...)
│   ├── filters/ graphs/ icons/
├── actions/                 # Older server actions ({feature}/{feature}.ts + .adapter.ts)
├── types/ hooks/ lib/       # Shared code (cn() in lib/utils.ts, isCloud() in lib/shared/env.ts)
├── store/                   # Zustand stores shared across routes
├── __tests__/               # Vitest shared harness (render-browser, MSW handlers)
├── tests/                   # Playwright E2E
├── changelog.d/             # Towncrier fragments (see prowler-changelog)
├── eslint-suppressions.json # Frozen lint violations (never add entries)
├── proxy.ts                 # Next 16 proxy (auth + security headers)
└── styles/globals.css       # Tailwind 4 config, design tokens, container-query breakpoints
```

## Feature Guides

Complex features keep their own `AGENTS.md` next to the code:

- `app/(prowler)/lighthouse/AGENTS.md`: Lighthouse v1 vs v2 owner map and the chat stream contract
- `app/(prowler)/realtime/AGENTS.md`: Prowler Realtime (Cloud only)

## Server and Client Boundary

- Server Components fetch; client components receive data or a promise unwrapped with `use()`.
- Never pass a function across the boundary. `components/filters/data-filters.ts` stays plain data; `labelFormatter` and similar attach in a `"use client"` wrapper such as `app/(prowler)/invitations/_components/invitations-filters.tsx`. TypeScript and jsdom tests accept the bad version; only the real page throws.
- Cloud-only UI is gated with `isCloud()` (`lib/shared/env.ts`). Paid gates are seams whose OSS body returns the self-hosted default (`lib/s3-integration-access.ts`, `lib/report-download-access.ts`, `lib/findings-access.ts`); the Cloud overlay replaces the body.

## Layout

- `sm:`…`2xl:` are redefined in `styles/globals.css`: container queries inside `[data-responsive-container]` (set on `<main>`, so the side panel's push re-evaluates them) and media queries elsewhere. Use `min-[64rem]:` when you need viewport semantics inside `<main>`.
- `<main>` is a container, so it becomes the containing block of `fixed` descendants. Portal them to `document.body` (`components/findings/floating-selection-actions.tsx`).
- Browser tests that check layout wrap the component in `<div data-responsive-container className="@container" style={{ width }}>`; otherwise the variants follow the test viewport.
- No layout shift: decide visibility from synchronous signals (the runtime config island), render the structure on first paint, and size skeletons like the real content.

## Recharts (Special Case)

For Recharts props that don't accept className:

Reuse shared color maps first (`SEVERITY_COLORS`, `MUTED_COLOR` in `ui/types/severities.ts`); otherwise a local constant
of existing tokens (pattern in `ui/components/graphs/donut-chart.tsx`):

```typescript
const CHART_COLORS = {
  emptyState: "var(--border-neutral-tertiary)",
};

// Only use var() for library props, NEVER in className
<Cell fill={SEVERITY_COLORS.critical} />
<CartesianGrid stroke={CHART_COLORS.emptyState} />
```

## Form + Validation Pattern

```typescript
"use client";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const schema = z.object({
  email: z.email(),  // Zod 4 syntax
  name: z.string().min(1),
});

type FormData = z.infer<typeof schema>;

export function MyForm() {
  const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (data: FormData) => {
    await serverAction(data);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register("email")} />
      {errors.email && <span>{errors.email.message}</span>}
      <button type="submit">Submit</button>
    </form>
  );
}
```

## Commands

```bash
# Development
cd ui && pnpm install
cd ui && pnpm run dev

# Code Quality
cd ui && pnpm run typecheck
cd ui && pnpm run lint:fix
cd ui && pnpm run format:write
cd ui && pnpm run healthcheck    # typecheck + lint:check + format:check
cd ui && pnpm run lint:knip      # unused files/exports

# Testing
cd ui && pnpm run test:unit          # Vitest jsdom
cd ui && pnpm run test:integration   # Vitest browser mode (Chromium)
cd ui && pnpm run test:e2e           # Playwright (needs running API)
cd ui && pnpm run test:e2e:ui
cd ui && pnpm run test:e2e:debug

# Build
cd ui && pnpm run build
cd ui && pnpm start
```

## Batch vs Instant Component API (REQUIRED)

When a component supports both **batch** (deferred, submit-based) and **instant** (immediate callback) behavior, model the coupling with a discriminated union — never as independent optionals. Coupled props must be all-or-nothing.

```typescript
// ❌ NEVER: Independent optionals — allows invalid half-states
interface FilterProps {
  onBatchApply?: (values: string[]) => void;
  onInstantChange?: (value: string) => void;
  isBatchMode?: boolean;
}

// ✅ ALWAYS: Discriminated union — one valid shape per mode
type BatchProps = {
  mode: "batch";
  onApply: (values: string[]) => void;
  onCancel: () => void;
};

type InstantProps = {
  mode: "instant";
  onChange: (value: string) => void;
  // onApply/onCancel are forbidden here via structural exclusion
  onApply?: never;
  onCancel?: never;
};

type FilterProps = BatchProps | InstantProps;
```

This makes invalid prop combinations a compile error, not a runtime surprise.

## Reuse Shared Display Utilities First (REQUIRED)

Before adding **local** display maps (labels, provider names, status strings, category formatters), search `ui/types/*` and `ui/lib/*` for existing helpers.

```typescript
// ✅ CHECK THESE FIRST before creating a new map:
// ui/lib/utils.ts            → cn() and general formatters
// ui/lib/date-utils.ts       → date formatting
// ui/types/providers.ts      → PROVIDER_TYPES, PROVIDER_DISPLAY_NAMES, getProviderDisplayName()
// ui/types/severities.ts     → SEVERITY_LEVELS, SEVERITY_DISPLAY_NAMES, SEVERITY_COLORS
// ui/types/compliance.ts     → compliance types/formatters
// ui/lib/categories.ts       → category helpers

// ❌ NEVER add a local map that already exists:
const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  // ...duplicating an existing shared map
};

// ✅ Import and reuse instead:
import { SEVERITY_DISPLAY_NAMES } from "@/types/severities";
```

If a helper doesn't exist and will be used in 2+ places, add it to `ui/lib/` or `ui/types/` and reuse it. Keep local only if used in exactly one place.

## Derived State Rule (REQUIRED)

Avoid `useState` + `useEffect` patterns that mirror props or searchParams — they create sync bugs and unnecessary re-renders. Derive values directly from the source of truth. The full effect rules live in `no-use-effect`.

```typescript
// ❌ NEVER: Mirror props into state via effect
const [localFilter, setLocalFilter] = useState(filter);
useEffect(() => { setLocalFilter(filter); }, [filter]);

// ✅ ALWAYS: Derive directly
const localFilter = filter; // or compute inline
```

If local state is genuinely needed (e.g., optimistic UI, pending edits before submit), add a short comment:

```typescript
// Local state needed: user edits are buffered until "Apply" is clicked
const [pending, setPending] = useState(initialValues);
```

## Strict Key Typing for Label Maps (REQUIRED)

Avoid `Record<string, string>` when the key set is known. Use an explicit union type or a const-key object so typos are caught at compile time.

```typescript
// ❌ Loose — typos compile silently
const STATUS_LABELS: Record<string, string> = {
  actve: "Active",   // typo, no error
};

// ✅ Tight — key type derived from a const (ui/AGENTS.md forbids hand-written string unions)
const STATUS = { ACTIVE: "active", INACTIVE: "inactive", PENDING: "pending" } as const;
type Status = (typeof STATUS)[keyof typeof STATUS];
const STATUS_LABELS: Record<Status, string> = {
  active: "Active",
  inactive: "Inactive",
  pending: "Pending",
  // actve: "Active"  ← compile error
};

// ✅ Also fine — const satisfies
const STATUS_LABELS = {
  active: "Active",
  inactive: "Inactive",
  pending: "Pending",
} as const satisfies Record<Status, string>;
```

## QA Checklist Before Commit

- [ ] The checks for your change type in the `ui/AGENTS.md` verification table pass, quoted with their summary lines
- [ ] User-visible changes reviewed in a browser (see `prowler-ui-browser-review`)
- [ ] Changelog fragment added in `ui/changelog.d/` when user-facing (see `prowler-changelog`)
- [ ] All UI states handled (loading, error, empty)
- [ ] No secrets in code (use `.env.local`)
- [ ] Error messages sanitized (no stack traces to users)
- [ ] Server-side validation present (don't trust client)
- [ ] Accessibility: keyboard navigation, ARIA labels
- [ ] Mobile responsive (if applicable)

## Pre-Re-Review Checklist (Review Thread Hygiene)

Before requesting re-review from a reviewer:

- [ ] Every unresolved inline thread has been either fixed or explicitly answered with a rationale
- [ ] If you agreed with a comment: the change is committed and the commit hash is mentioned in the reply
- [ ] If you disagreed: the reply explains why with clear reasoning — do not leave threads silently open
- [ ] Re-request review only after all threads are in a clean state

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
