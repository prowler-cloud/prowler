
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-ui
description: Next.js 15 + React 19 patterns for Prowler UI development. Covers components, server actions, styling with Tailwind 4, and testing with Playwright.
license: Apache 2.0
---

## When to use this skill

Use this skill when working on the Prowler UI (Next.js frontend) for:
- Creating components (shadcn/ui for new, HeroUI for legacy)
- Server actions and data fetching
- Styling with Tailwind CSS 4
- E2E testing with Playwright

## Critical Rules

### React 19
- ALWAYS: \`import { useState, useEffect } from "react"\`
- NEVER: \`import React\`, \`import * as React\`
- NEVER: \`useMemo\`, \`useCallback\` (React Compiler handles optimization)

### Types
- ALWAYS: \`const X = { A: "a", B: "b" } as const; type T = typeof X[keyof typeof X]\`
- NEVER: \`type T = "a" | "b"\`

### Interfaces
- ALWAYS: One level depth only; nested objects -> dedicated interface
- ALWAYS: Reuse via \`extends\`
\`\`\`typescript
interface UserAddress { street: string; city: string; }
interface User { id: string; address: UserAddress; }
interface Admin extends User { permissions: string[]; }
\`\`\`

### Styling
- Single class: \`className="bg-slate-800 text-white"\`
- Merge: \`className={cn(BASE_STYLES, variant && "variant-class")}\`
- Dynamic: \`style={{ width: "50%" }}\`
- NEVER: \`var()\` in className, hex colors

### Component Placement
- Used 2+ places -> \`components/shared/\` or \`lib/\` or \`types/\`
- Used 1 place -> keep local in feature directory

## Patterns

### Server Component
\`\`\`typescript
export default async function Page() {
  const data = await fetchData();
  return <ClientComponent data={data} />;
}
\`\`\`

### Server Action
\`\`\`typescript
"use server";
export async function updateProvider(formData: FormData) {
  const validated = schema.parse(Object.fromEntries(formData));
  await updateDB(validated);
  revalidatePath("/path");
}
\`\`\`

### Form + Validation (Zod 4)
\`\`\`typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const schema = z.object({
  email: z.email(),  // Zod 4: z.email() not z.string().email()
  id: z.uuid(),      // Zod 4: z.uuid() not z.string().uuid()
});

const form = useForm({ resolver: zodResolver(schema) });
\`\`\`

### Zustand 5
\`\`\`typescript
const useStore = create(
  persist(
    (set) => ({
      value: 0,
      increment: () => set((s) => ({ value: s.value + 1 })),
    }),
    { name: "key" },
  ),
);
\`\`\`

### Playwright Test
\`\`\`typescript
export class FeaturePage extends BasePage {
  readonly submitBtn = this.page.getByRole("button", { name: "Submit" });
  async goto() { await super.goto("/path"); }
  async submit() { await this.submitBtn.click(); }
}

test("action works", { tag: ["@critical", "@feature"] }, async ({ page }) => {
  const p = new FeaturePage(page);
  await p.goto();
  await p.submit();
  await expect(page).toHaveURL("/expected");
});
\`\`\`

## Project Structure
\`\`\`
ui/
├── app/(auth)/          # Auth pages
├── app/(prowler)/       # Main app: compliance, findings, providers, scans
├── components/shadcn/   # New shadcn/ui components
├── components/ui/       # HeroUI base (legacy)
├── actions/             # Server actions
├── types/               # Shared types
├── hooks/               # Shared hooks
├── lib/                 # Utilities
├── store/               # Zustand state
└── tests/               # Playwright E2E
\`\`\`

## Commands
\`\`\`bash
cd ui && pnpm install && pnpm run dev
cd ui && pnpm run typecheck
cd ui && pnpm run lint:fix
cd ui && pnpm run healthcheck
cd ui && pnpm run test:e2e
cd ui && pnpm run test:e2e:ui
\`\`\`

## Keywords
prowler ui, next.js, react 19, tailwind 4, shadcn, heroui, playwright, zod 4, zustand 5
`;

export default tool({
  description: SKILL,
  args: {
    component_type: tool.schema.string().describe("Component type: page, component, action, hook, store, test"),
    feature: tool.schema.string().describe("Feature area: findings, providers, scans, compliance, integrations, etc."),
  },
  async execute(args) {
    return `
Prowler UI Pattern for: ${args.component_type} in ${args.feature}

File locations based on "${args.component_type}" for "${args.feature}":

- Page: ui/app/(prowler)/${args.feature}/page.tsx
- Component (shared): ui/components/${args.feature}/
- Component (local): ui/app/(prowler)/${args.feature}/components/
- Server Action: ui/actions/${args.feature}/${args.feature}.ts
- Types (shared): ui/types/${args.feature}.ts
- Types (local): ui/app/(prowler)/${args.feature}/types.ts
- Hook (shared): ui/hooks/use-${args.feature}.ts
- Store: ui/store/${args.feature}-store.ts
- Test: ui/tests/${args.feature}/

Tech Stack:
- Next.js 15.5.3 + React 19.1.1 + Tailwind 4.1.13
- shadcn/ui (new) + HeroUI 2.8.4 (legacy)
- Zod 4.1.11 + React Hook Form 7.62.0 + Zustand 5.0.8

Remember:
- No useMemo/useCallback (React Compiler handles it)
- Zod 4: z.email(), z.uuid(), z.url() directly
- Server components by default, "use client" only when needed
    `.trim()
  },
})
