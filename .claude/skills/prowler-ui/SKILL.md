---
name: prowler-ui
description: >
  Prowler UI-specific patterns. For generic patterns, see: typescript, react-19, nextjs-15, tailwind-4.
  Trigger: When working on ui/ directory - components, pages, actions, hooks.
---

## Related Generic Skills

- `typescript` - Const types, flat interfaces
- `react-19` - No useMemo/useCallback, compiler
- `nextjs-15` - App Router, Server Actions
- `tailwind-4` - cn() utility, styling rules
- `zod-4` - Schema validation
- `zustand-5` - State management

## Prowler-Specific Rules

### Component Libraries
- **New features**: Use `shadcn/ui` + Tailwind (`components/shadcn/`)
- **Existing features**: Keep using HeroUI (`components/ui/`)

### Scope Rule (Absolute)
- Used 2+ places → `components/shared/` or `lib/` or `types/`
- Used 1 place → keep local in feature directory

### Code Location
```
Server action → actions/{feature}/{feature}.ts
Data transform → actions/{feature}/{feature}.adapter.ts
Types (shared) → types/{domain}.ts
Types (local) → {feature}/types.ts
```

## Structure

```
ui/
├── app/(prowler)/           # Main app pages
│   ├── compliance/
│   ├── findings/
│   ├── providers/
│   └── scans/
├── components/
│   ├── shadcn/              # New shadcn components
│   └── ui/                  # HeroUI (legacy)
├── actions/                 # Server actions
├── store/                   # Zustand state
├── tests/                   # Playwright E2E
└── types/                   # Shared types
```

## Recharts (Special Case)

For Recharts props that don't accept className:

```typescript
const CHART_COLORS = {
  primary: "var(--color-primary)",
  text: "var(--color-text)",
};

// Only use var() for library props
<XAxis tick={{ fill: CHART_COLORS.text }} />
```

## Commands

```bash
cd ui && pnpm run dev
cd ui && pnpm run healthcheck
cd ui && pnpm run test:e2e
```

## Keywords
prowler ui, next.js, react 19, tailwind 4, shadcn, heroui
