# Prowler UI - AI Agent Ruleset

> **Skills Reference**: For detailed patterns, use these skills:
>
> - [`prowler-ui`](../skills/prowler-ui/SKILL.md) - Prowler-specific UI patterns
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
> - [`tdd`](../skills/tdd/SKILL.md) - TDD workflow (MANDATORY for UI tasks)
> - [`prowler-tour`](../skills/prowler-tour/SKILL.md) - Keep product-tour definitions aligned with the UI

## Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action                                                            | Skill               |
| ----------------------------------------------------------------- | ------------------- |
| Add changelog entry for a PR or feature                           | `prowler-changelog` |
| Adding, updating, or removing a tour definition (\*.tour.ts)      | `prowler-tour`      |
| App Router / Server Actions                                       | `nextjs-16`         |
| Building AI chat features                                         | `ai-sdk-5`          |
| Changing button labels or section headings on a tour-covered page | `prowler-tour`      |
| Committing changes                                                | `prowler-commit`    |
| Create PR that requires changelog entry                           | `prowler-changelog` |
| Creating Zod schemas                                              | `zod-4`             |
| Creating a git commit                                             | `prowler-commit`    |
| Creating/modifying Prowler UI components                          | `prowler-ui`        |
| Editing a UI file containing data-tour-id attributes              | `prowler-tour`      |
| Fixing bug                                                        | `tdd`               |
| Implementing feature                                              | `tdd`               |
| Modifying component                                               | `tdd`               |
| Refactoring code                                                  | `tdd`               |
| Renaming or removing a data-tour-id attribute value               | `prowler-tour`      |
| Restructuring routes or layouts covered by a tour                 | `prowler-tour`      |
| Review changelog format and conventions                           | `prowler-changelog` |
| Reviewing Prowler UI components                                   | `prowler-ui`        |
| Testing hooks or utilities                                        | `vitest`            |
| Update CHANGELOG.md in any component                              | `prowler-changelog` |
| Using Zustand stores                                              | `zustand-5`         |
| Working on Prowler UI structure (actions/adapters/types/hooks)    | `prowler-ui`        |
| Working on task                                                   | `tdd`               |
| Working with Prowler UI test helpers/pages                        | `prowler-test-ui`   |
| Working with Tailwind classes                                     | `tailwind-4`        |
| Writing Playwright E2E tests                                      | `playwright`        |
| Writing Prowler UI E2E tests                                      | `prowler-test-ui`   |
| Writing React component tests                                     | `vitest`            |
| Writing React components                                          | `react-19`          |
| Writing TypeScript types/interfaces                               | `typescript`        |
| Writing Vitest tests                                              | `vitest`            |
| Writing unit tests for UI                                         | `vitest`            |

---

## CRITICAL RULES - NON-NEGOTIABLE

### React

- ALWAYS: `import { useState, useEffect } from "react"`
- NEVER: `import React`, `import * as React`, `import React as *`
- NEVER: `useMemo`, `useCallback` (React Compiler handles optimization)

### Types

- ALWAYS: `const X = { A: "a", B: "b" } as const; type T = typeof X[keyof typeof X]`
- NEVER: `type T = "a" | "b"`

### Interfaces

- ALWAYS: One level depth only; object property → dedicated interface (recursive)
- ALWAYS: Reuse via `extends`
- NEVER: Inline nested objects

### Styling

- Single class: `className="bg-slate-800 text-white"`
- Merge multiple classes: `className={cn(BASE_STYLES, variant && "variant-class")}`
- Dynamic values: `style={{ width: "50%" }}`
- NEVER: `var()` in className, hex colors

### Scope Rule (ABSOLUTE)

- Used 2+ places → `lib/` or `types/` or `hooks/` (components go in `components/{domain}/`)
- Used 1 place → keep local in feature directory
- This determines ALL folder structure decisions

---

## DECISION TREES

### Component Placement

```text
New UI primitive? → components/shadcn/ (shadcn/ui + Tailwind)
Used by 1 domain? → components/{domain}/ | Used by 2+ domains? → components/shared/
Needs state/hooks? → "use client" | Server component? → No directive
```

### Code Location

```text
Server action → actions/{feature}/{feature}.ts
Data transform → actions/{feature}/{feature}.adapter.ts
Types (shared 2+) → types/{domain}.ts | Types (local 1) → {feature}/types.ts
Utils (shared 2+) → lib/ | Utils (local 1) → {feature}/utils/
Hooks (shared 2+) → hooks/ | Hooks (local 1) → {feature}/hooks.ts
shadcn components → components/shadcn/
```

---

## PATTERNS

### Server Component

```typescript
export default async function Page() {
  const data = await fetchData();
  return <ClientComponent data={data} />;
}
```

### Server Action

```typescript
"use server";
export async function updateProvider(formData: FormData) {
  const validated = schema.parse(Object.fromEntries(formData));
  await updateDB(validated);
  revalidatePath("/path");
}
```

### Form + Validation (Zod 4)

```typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const schema = z.object({
  email: z.email(), // Zod 4: z.email() not z.string().email()
  id: z.uuid(), // Zod 4: z.uuid() not z.string().uuid()
});

const form = useForm({ resolver: zodResolver(schema) });
```

### Zustand 5

```typescript
const useStore = create(
  persist(
    (set) => ({
      value: 0,
      increment: () => set((s) => ({ value: s.value + 1 })),
    }),
    { name: "key" },
  ),
);
```

### Playwright Test

```typescript
export class FeaturePage extends BasePage {
  readonly submitBtn = this.page.getByRole("button", { name: "Submit" });
  async goto() {
    await super.goto("/path");
  }
  async submit() {
    await this.submitBtn.click();
  }
}

test("action works", { tag: ["@critical", "@feature"] }, async ({ page }) => {
  const p = new FeaturePage(page);
  await p.goto();
  await p.submit();
  await expect(page).toHaveURL("/expected");
});
```

---

## TECH STACK

Next.js 16.2.3 | React 19.2.5 | Tailwind 4.1.18 | shadcn/ui
Zod 4.1.11 | React Hook Form 7.62.0 | Zustand 5.0.8 | NextAuth 5.0.0-beta.30 | Recharts 2.15.4

> **Note**: `components/ui/` only holds temporary re-export shims for the prowler-cloud overlay. Do NOT add new components there.

---

## PROJECT STRUCTURE

```text
ui/
├── app/(auth)/          # Auth pages
├── app/(prowler)/       # Main app: compliance, findings, providers, scans
├── components/shadcn/   # shadcn/ui components (USE THIS)
├── components/ui/       # Cloud-overlay re-export shims (do not add here)
├── actions/             # Server actions
├── types/               # Shared types
├── hooks/               # Shared hooks
├── lib/                 # Utilities
├── store/               # Zustand state
├── tests/               # Playwright E2E
└── styles/              # Global CSS
```

---

## COMMANDS

```bash
pnpm install && pnpm run dev
pnpm run typecheck
pnpm run lint:fix
pnpm run healthcheck
pnpm run test:e2e
pnpm run test:e2e:ui
```

---

## QA CHECKLIST BEFORE COMMIT

- [ ] `pnpm run typecheck` passes
- [ ] `pnpm run lint:fix` passes
- [ ] `pnpm run format:write` passes
- [ ] Relevant E2E tests pass
- [ ] All UI states handled (loading, error, empty)
- [ ] No secrets in code (use `.env.local`)
- [ ] New npm dependencies include package-health evidence (maintenance, popularity, known vulnerabilities, license, release age) and a rationale for not using existing/native alternatives.
- [ ] Error messages sanitized
- [ ] Server-side validation present
