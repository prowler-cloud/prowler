
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: tailwind-4
description: Tailwind CSS 4 patterns. cn() utility, theme variables, no var() in className.
license: MIT
---

## When to use this skill

Use this skill for Tailwind CSS 4 styling best practices.

## Critical Rules

### Never Use var() in className

\`\`\`typescript
// ❌ NEVER
<div className="bg-[var(--color-primary)]" />

// ✅ ALWAYS
<div className="bg-primary" />
\`\`\`

### Never Use Hex Colors

\`\`\`typescript
// ❌ NEVER
<p className="text-[#ffffff]" />

// ✅ ALWAYS
<p className="text-white" />
\`\`\`

## The cn() Utility

\`\`\`typescript
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
\`\`\`

### When to Use cn()

\`\`\`typescript
// ✅ Conditional classes
<div className={cn("base", isActive && "active")} />

// ✅ Merging with conflicts
<button className={cn("px-4 py-2", className)} />

// ❌ NOT for static classes
<div className={cn("flex items-center")} />  // Just use className=""
\`\`\`

## Common Patterns

\`\`\`typescript
// Flexbox
<div className="flex items-center justify-between gap-4" />

// Grid
<div className="grid grid-cols-3 gap-4" />

// Responsive
<div className="w-full md:w-1/2 lg:w-1/3" />

// States
<button className="hover:bg-blue-600 focus:ring-2" />

// Dark mode
<div className="bg-white dark:bg-slate-900" />
\`\`\`

## Style Constants for Libraries

When libraries don't accept className (like Recharts):

\`\`\`typescript
// ✅ Constants with var() - ONLY for library props
const CHART_COLORS = {
  primary: "var(--color-primary)",
  text: "var(--color-text)",
};

<XAxis tick={{ fill: CHART_COLORS.text }} />
\`\`\`

## Keywords
tailwind, css, styling, cn, utility classes
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: cn, responsive, flexbox, grid, dark-mode"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("cn")) {
      return `
## cn() Utility

\`\`\`typescript
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

// ✅ Use for conditionals
<div className={cn("base", condition && "variant")} />

// ✅ Use for merging (prop overrides)
<button className={cn("px-4", className)} />

// ❌ Don't use for static classes
<div className={cn("flex gap-2")} />  // Just use className=""
\`\`\`
      `.trim();
    }

    if (topic.includes("responsive")) {
      return `
## Tailwind Responsive

\`\`\`typescript
// Breakpoints: sm (640), md (768), lg (1024), xl (1280), 2xl (1536)

// Width
<div className="w-full md:w-1/2 lg:w-1/3" />

// Display
<div className="hidden md:block" />
<div className="block md:hidden" />

// Typography
<h1 className="text-lg md:text-2xl lg:text-4xl" />

// Grid columns
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4" />
\`\`\`
      `.trim();
    }

    return `
## Tailwind 4 Quick Reference

1. **Never** use var() in className
2. **Never** use hex colors - use semantic classes
3. **cn()** only for conditionals and merging
4. **style prop** for truly dynamic values
5. **Constants with var()** only for library props (Recharts)

\`\`\`typescript
// Common patterns
flex items-center justify-between gap-4
grid grid-cols-3 gap-4
w-full md:w-1/2
hover:bg-blue-600 focus:ring-2
bg-white dark:bg-slate-900
\`\`\`
    `.trim();
  },
})
