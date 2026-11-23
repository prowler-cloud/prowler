---
name: tailwind-4
description: >
  Tailwind CSS 4 patterns and best practices.
  Trigger: When styling with Tailwind (className, variants, cn()), especially when dynamic styling or CSS variables are involved (no var() in className).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, ui]
  auto_invoke: "Working with Tailwind classes"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Tailwind 4 Setup (CSS-first, no tailwind.config)

- Config lives in CSS: `ui/styles/globals.css` starts with `@import "tailwindcss";` plus `@plugin`, `@source`, `@custom-variant`, `@theme`, `@utility`.
- PostCSS plugin is `@tailwindcss/postcss` (`ui/postcss.config.js`). There is no `tailwind.config.*`; do not create one.
- Design tokens are declared in `@theme` (`--color-bg-neutral-primary: ...`) and become utilities (`bg-bg-neutral-primary`, `text-text-neutral-secondary`, `border-border-neutral-secondary`).
- Dark mode is class-based: `@custom-variant dark (&:where(.dark, .dark *));` (toggled by `next-themes`).
- New utilities use `@utility name { ... }`, not `@layer utilities` + `@apply` hacks.

**Prowler UI:** use the semantic token utilities above. Raw palette classes (`bg-slate-800`, `bg-blue-500`) appear below only as generic Tailwind examples; in `ui/` they are not allowed (see `prowler-ui` Design System Discipline).

## Styling Decision Tree

```text
Tailwind class exists?  → className="..."
Dynamic value?          → style={{ width: `${x}%` }}
Conditional styles?     → cn("base", condition && "variant")
Static only?            → className="..." (no cn() needed)
Library can't use class?→ style prop with var() constants
```

## Critical Rules

### Never Use var() in className

```typescript
// ❌ NEVER: var() in className
<div className="bg-[var(--color-primary)]" />
<div className="text-[var(--text-color)]" />

// ✅ ALWAYS: Use theme token utilities
<div className="bg-button-primary" />
<div className="text-text-neutral-secondary" />
```

Tailwind 4 also accepts the `bg-(--token)` shorthand for CSS variables; it is still an escape hatch. If a token is used repeatedly, it belongs in `@theme`.

### Never Use Hex Colors

```typescript
// ❌ NEVER: Hex colors in className
<p className="text-[#ffffff]" />
<div className="bg-[#1e293b]" />

// ✅ ALWAYS: Use theme color utilities
<p className="text-text-neutral-primary" />
<div className="bg-bg-neutral-secondary" />
```

## The cn() Utility

Already defined in `ui/lib/utils.ts` (built on `extendTailwindMerge` so custom token classes merge correctly); import it with `import { cn } from "@/lib/utils";`. Never redefine it. Simplified shape:

```typescript
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

### When to Use cn()

```typescript
// ✅ Conditional classes
<div className={cn("base-class", isActive && "active-class")} />

// ✅ Merging with potential conflicts
<button className={cn("px-4 py-2", className)} />  // className might override

// ✅ Multiple conditions
<div className={cn(
  "rounded-lg border",
  variant === "primary" && "bg-blue-500 text-white",
  variant === "secondary" && "bg-gray-200 text-gray-800",
  disabled && "opacity-50 cursor-not-allowed"
)} />
```

### When NOT to Use cn()

```typescript
// ❌ Static classes - unnecessary wrapper
<div className={cn("flex items-center gap-2")} />

// ✅ Just use className directly
<div className="flex items-center gap-2" />
```

## Style Constants for Charts/Libraries

When libraries don't accept className (like Recharts):

```typescript
// ✅ Constants with var() - ONLY for library props
// Prefer existing shared maps first, e.g. SEVERITY_COLORS in ui/types/severities.ts
const CHART_COLORS = {
  emptyState: "var(--border-neutral-tertiary)",
  critical: "var(--color-bg-data-critical)",
};

// Usage with Recharts (can't use className)
<Cell fill={CHART_COLORS.critical} />
<CartesianGrid stroke={CHART_COLORS.emptyState} />
```

## Dynamic Values

```typescript
// ✅ style prop for truly dynamic values
<div style={{ width: `${percentage}%` }} />
<div style={{ opacity: isVisible ? 1 : 0 }} />

// ✅ CSS custom properties for theming
<div style={{ "--progress": `${value}%` } as React.CSSProperties} />
```

## Common Patterns

### Flexbox

```typescript
<div className="flex items-center justify-between gap-4" />
<div className="flex flex-col gap-2" />
<div className="inline-flex items-center" />
```

### Grid

```typescript
<div className="grid grid-cols-3 gap-4" />
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6" />
```

### Spacing

```typescript
// Padding
<div className="p-4" />           // All sides
<div className="px-4 py-2" />     // Horizontal, vertical
<div className="pt-4 pb-2" />     // Top, bottom

// Margin
<div className="m-4" />
<div className="mx-auto" />       // Center horizontally
<div className="mt-8 mb-4" />
```

### Typography

```typescript
<h1 className="text-2xl font-bold text-white" />
<p className="text-sm text-slate-400" />
<span className="text-xs font-medium uppercase tracking-wide" />
```

### Borders & Shadows

```typescript
<div className="rounded-lg border border-slate-700" />
<div className="rounded-full shadow-lg" />
<div className="ring-2 ring-blue-500 ring-offset-2" />
```

### States

```typescript
<button className="hover:bg-blue-600 focus:ring-2 active:scale-95" />
<input className="focus:border-blue-500 focus:outline-none" />
<div className="group-hover:opacity-100" />
```

### Responsive

```typescript
<div className="w-full md:w-1/2 lg:w-1/3" />
<div className="hidden md:block" />
<div className="text-sm md:text-base lg:text-lg" />
```

### Dark Mode

```typescript
<div className="bg-white dark:bg-slate-900" />
<p className="text-gray-900 dark:text-white" />
```

## Arbitrary Values (Escape Hatch)

```typescript
// ✅ OK for one-off values not in design system
<div className="w-[327px]" />
<div className="top-[117px]" />
<div className="grid-cols-[1fr_2fr_1fr]" />

// ❌ Don't use for colors - use theme instead
<div className="bg-[#1e293b]" />  // NO
```
