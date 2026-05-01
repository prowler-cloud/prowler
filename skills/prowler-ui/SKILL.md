---
name: prowler-ui
description: >
  Prowler UI-specific patterns. For generic patterns, see: typescript, react-19, nextjs-15, tailwind-4.
  Trigger: When working inside ui/ on Prowler-specific conventions (shadcn vs HeroUI legacy, folder placement, actions/adapters, shared types/hooks/lib).
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

## Related Generic Skills

- `typescript` - Const types, flat interfaces
- `react-19` - No useMemo/useCallback, compiler
- `nextjs-15` - App Router, Server Actions
- `tailwind-4` - cn() utility, styling rules
- `zod-4` - Schema validation
- `zustand-5` - State management
- `ai-sdk-5` - Chat/AI features
- `playwright` - E2E testing (see also `prowler-test-ui`)

## Tech Stack (Versions)

```
Next.js 15.5.9 | React 19.2.2 | Tailwind 4.1.13 | shadcn/ui
Zod 4.1.11 | React Hook Form 7.62.0 | Zustand 5.0.8
NextAuth 5.0.0-beta.30 | Recharts 2.15.4
HeroUI 2.8.4 (LEGACY - do not add new components)
```

## CRITICAL: Component Library Rule

- **ALWAYS**: Use `shadcn/ui` + Tailwind (`components/shadcn/`)
- **NEVER**: Add new HeroUI components (`components/ui/` is legacy only)

## DECISION TREES

### Component Placement

```
New feature UI? → shadcn/ui + Tailwind
Existing HeroUI feature? → Keep HeroUI (don't mix)
Used 1 feature? → features/{feature}/components/
Used 2+ features? → components/shared/
Needs state/hooks? → "use client"
Server component? → No directive needed
```

### Code Location

```
Server action      → actions/{feature}/{feature}.ts
Data transform     → actions/{feature}/{feature}.adapter.ts
Types (shared 2+)  → types/{domain}.ts
Types (local 1)    → {feature}/types.ts
Utils (shared 2+)  → lib/
Utils (local 1)    → {feature}/utils/
Hooks (shared 2+)  → hooks/
Hooks (local 1)    → {feature}/hooks.ts
shadcn components  → components/shadcn/
HeroUI components  → components/ui/ (LEGACY)
```

### Styling Decision

```
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

```
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
│   ├── shadcn/              # shadcn/ui (USE THIS)
│   ├── ui/                  # HeroUI (LEGACY)
│   ├── {domain}/            # Domain-specific (compliance, findings, providers, etc.)
│   ├── filters/             # Filter components
│   ├── graphs/              # Chart components
│   └── icons/               # Icon components
├── actions/                 # Server actions
├── types/                   # Shared types
├── hooks/                   # Shared hooks
├── lib/                     # Utilities
├── store/                   # Zustand state
├── tests/                   # Playwright E2E
└── styles/                  # Global CSS
```

## Recharts (Special Case)

For Recharts props that don't accept className:

```typescript
const CHART_COLORS = {
  primary: "var(--color-primary)",
  secondary: "var(--color-secondary)",
  text: "var(--color-text)",
  gridLine: "var(--color-border)",
};

// Only use var() for library props, NEVER in className
<XAxis tick={{ fill: CHART_COLORS.text }} />
<CartesianGrid stroke={CHART_COLORS.gridLine} />
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
cd ui && pnpm run healthcheck    # typecheck + lint

# Testing
cd ui && pnpm run test:e2e
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
// ui/lib/utils.ts            → general formatters
// ui/types/providers.ts      → provider display names, icons
// ui/types/findings.ts       → severity/status display maps
// ui/types/compliance.ts     → category/group formatters

// ❌ NEVER add a local map that already exists:
const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  // ...duplicating an existing shared map
};

// ✅ Import and reuse instead:
import { severityLabel } from "@/types/findings";
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

// ✅ Tight — union key
type Status = "active" | "inactive" | "pending";
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
- [ ] Relevant E2E tests pass
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

## Migrations Reference

| From | To | Key Changes |
|------|-----|-------------|
| React 18 | 19.1 | Async components, React Compiler (no useMemo/useCallback) |
| Next.js 14 | 15.5 | Improved App Router, better streaming |
| NextUI | HeroUI 2.8.4 | Package rename only, same API |
| Zod 3 | 4 | `z.email()` not `z.string().email()`, `error` not `message` |
| AI SDK 4 | 5 | `@ai-sdk/react`, `sendMessage` not `handleSubmit`, `parts` not `content` |

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
