---
name: prowler-ui
description: >
  Prowler UI-specific patterns. For generic patterns, see: typescript, react-19, nextjs-16, tailwind-4.
  Trigger: When working inside ui/ on Prowler-specific conventions (shadcn, folder placement, actions/adapters, shared types/hooks/lib).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2"
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

When reviewing UI PRs, flag: custom modals/primitives that duplicate shadcn, call-site visual `className` on shared controls, raw color utilities, and new variants/tokens introduced without going through the shared component API.

## DECISION TREES

### Component Placement

```text
New UI primitive?   → components/shadcn/ (shadcn/ui + Tailwind)
Used by 1 domain?   → components/{domain}/
Used by 2+ domains? → components/shared/
Needs state/hooks?  → "use client"
Server component?    → No directive needed
```

### Code Location

```text
Server action      → actions/{feature}/{feature}.ts
Data transform     → actions/{feature}/{feature}.adapter.ts
Types (shared 2+)  → types/{domain}.ts
Types (local 1)    → {feature}/types.ts
Utils (shared 2+)  → lib/
Utils (local 1)    → {feature}/utils/
Hooks (shared 2+)  → hooks/
Hooks (local 1)    → {feature}/hooks.ts
UI primitive       → components/shadcn/
Domain component   → components/{domain}/
```

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

- Used 2+ places → `lib/` or `types/` or `hooks/` (components go in `components/{domain}/`)
- Used 1 place → keep local in feature directory
- **This determines ALL folder structure decisions**

## Project Structure

```text
ui/
├── app/
│   ├── (auth)/              # Auth pages (login, signup)
│   └── (prowler)/           # Main app
│       ├── compliance/
│       ├── findings/
│       ├── providers/
│       ├── scans/
│       ├── services/
│       └── integrations/
├── components/
│   ├── shadcn/              # shadcn/ui primitives (USE THIS)
│   ├── shared/             # Cross-domain composed components (2+ domains)
│   ├── ui/                  # DEPRECATED shim → re-exports shadcn (do not use)
│   ├── {domain}/            # Domain-specific (compliance, findings, providers, etc.)
│   ├── filters/             # Filter components
│   ├── graphs/              # Chart components
│   └── icons/               # Icon components
├── actions/                 # Server actions ({feature}/{feature}.ts + .adapter.ts + tests)
├── types/                   # Shared types
├── hooks/                   # Shared hooks
├── lib/                     # Utilities (cn() in lib/utils.ts)
├── store/                   # Zustand stores ({feature}/store.ts, re-exported from store/index.ts)
├── __tests__/               # Vitest shared harness (render-browser, MSW handlers)
├── tests/                   # Playwright E2E
├── changelog.d/             # Towncrier fragments (see prowler-changelog)
├── proxy.ts                 # Next 16 proxy (auth + security headers)
└── styles/globals.css       # Tailwind 4 config + design tokens (@theme)
```

The route list above is partial; `app/(prowler)/` also has `attack-paths`, `issues`, `lighthouse`, `mutelist`, `registry`, `resources`, `roles`, `users`, etc.

## Lighthouse AI (two implementations)

| | Lighthouse v1 (OSS) | Lighthouse v2 (Cloud, `isCloud()`) |
|---|---|---|
| UI | `components/lighthouse-v1/` | `app/(prowler)/lighthouse/_components/`, `_lib/`, `_actions/` |
| Logic | `lib/lighthouse-v1/` (LangGraph workflow, MCP client, `analyst-stream.ts`) | Django sessions; SSE proxied by `app/api/lighthouse/v2/sessions/[sessionId]/event-stream/route.ts` |
| Transport | AI SDK `useChat` -> `app/api/lighthouse/analyst/route.ts` | `EventSource` on the Next.js route (token stays server-side) |
| Server actions / types | `actions/lighthouse-v1/`, `types/lighthouse-v1/` | `app/(prowler)/lighthouse/_actions` |

Shared, version-agnostic pieces: `lib/lighthouse/` (page context, skills), `components/lighthouse/`, `store/lighthouse-context/`, `lib/lighthouse-routes.ts`. Entry point that picks the version: `app/(prowler)/lighthouse/page.tsx`.

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

Avoid `useState` + `useEffect` patterns that mirror props or searchParams — they create sync bugs and unnecessary re-renders. Derive values directly from the source of truth.

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

- [ ] `pnpm run typecheck` passes
- [ ] `pnpm run lint:fix` passes
- [ ] `pnpm run format:write` passes
- [ ] Relevant Vitest (`test:unit` / `test:integration`) and E2E tests pass
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
