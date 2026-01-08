---
name: prowler-ui
description: >
  Prowler UI-specific patterns. For generic patterns, see: typescript, react-19, nextjs-15, tailwind-4.
  Trigger: When working on ui/ directory - components, pages, actions, hooks.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
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

## Migrations Reference

| From | To | Key Changes |
|------|-----|-------------|
| React 18 | 19.1 | Async components, React Compiler (no useMemo/useCallback) |
| Next.js 14 | 15.5 | Improved App Router, better streaming |
| NextUI | HeroUI 2.8.4 | Package rename only, same API |
| Zod 3 | 4 | `z.email()` not `z.string().email()`, `error` not `message` |
| AI SDK 4 | 5 | `@ai-sdk/react`, `sendMessage` not `handleSubmit`, `parts` not `content` |

## Keywords
prowler ui, next.js, react 19, tailwind 4, shadcn, heroui legacy
