# Prowler UI - AI Agent Ruleset

## CRITICAL RULES - NON-NEGOTIABLE

### React

- ALWAYS: `import { useState, useEffect } from "react"`
- NEVER: `import React`, `import * as React`, `import React as *`
- NEVER: `useMemo`, `useCallback` (React Compiler handles optimization)

### Types

- ALWAYS: `const X = { A: "a", B: "b" } as const; type T = typeof X[keyof typeof X]`
- NEVER: `type T = "a" | "b"`

### Styling

- Single class: `className="bg-slate-800 text-white"`
- Merge multiple classes: `className={cn(BUTTON_STYLES.base, BUTTON_STYLES.active, isLoading && "opacity-50")}` (cn() handles Tailwind conflicts with twMerge)
- Conditional classes: `className={cn("base", condition && "variant")}`
- Recharts props: `fill={CHART_COLORS.text}` (use constants with var())
- Dynamic values: `style={{ width: "50%", opacity: 0.5 }}`
- CSS custom properties: `style={{ "--color": "var(--css-var)" }}` (for dynamic theming)
- NEVER: `var()` in className strings (use Tailwind semantic classes instead)
- NEVER: hex colors (use `text-white` not `text-[#fff]`)

### Scope Rule (ABSOLUTE)

- Used 2+ places → `components/shared/` or `lib/` or `types/` or `hooks/`
- Used 1 place → keep local in feature directory
- This determines ALL folder structure decisions

### Memoization

- NEVER: `useMemo`, `useCallback`
- React 19 Compiler handles automatic optimization

---

## DECISION TREES

### Component Placement

```
New feature UI? → shadcn/ui + Tailwind | Existing feature? → HeroUI
Used 1 feature? → features/{feature}/components | Used 2+? → components/shared
Needs state/hooks? → "use client" | Server component? → No directive
```

### Code Location

```
Server action → actions/{feature}/{feature}.ts
Data transform → actions/{feature}/{feature}.adapter.ts
Types (shared 2+) → types/{domain}.ts | Types (local 1) → {feature}/types.ts
Utils (shared 2+) → lib/ | Utils (local 1) → {feature}/utils/
Hooks (shared 2+) → hooks/ | Hooks (local 1) → {feature}/hooks.ts
shadcn components → components/shadcn/ | HeroUI → components/ui/
```

### Styling Decision

```
Tailwind class exists? → className | Dynamic value? → style prop
Conditional styles? → cn() | Static? → className only
Recharts? → CHART_COLORS constant + var() | Other? → Tailwind classes
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

### Form + Validation

```typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
const form = useForm({ resolver: zodResolver(schema) });
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

### Zod v4

- `z.email()` not `z.string().email()`
- `z.uuid()` not `z.string().uuid()`
- `z.url()` not `z.string().url()`
- `z.string().min(1)` not `z.string().nonempty()`
- `error` param not `message` param

### Zustand v5

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

### AI SDK v5

```typescript
import { useChat } from "@ai-sdk/react";
const { messages, sendMessage } = useChat({
  transport: new DefaultChatTransport({ api: "/api/chat" }),
});
const [input, setInput] = useState("");
const handleSubmit = (e) => {
  e.preventDefault();
  sendMessage({ text: input });
  setInput("");
};
```

### Testing (Playwright)

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

test(
  "action works",
  { tag: ["@critical", "@feature", "@TEST-001"] },
  async ({ page }) => {
    const p = new FeaturePage(page);
    await p.goto();
    await p.submit();
    await expect(page).toHaveURL("/expected");
  },
);
```

Selector priority: `getByRole()` → `getByLabel()` → `getByText()` → other

---

## TECH STACK

Next.js 15.5.3 | React 19.1.1 | Tailwind 4.1.13 | shadcn/ui (new) | HeroUI 2.8.4 (legacy)
Zod 4.1.11 | React Hook Form 7.62.0 | Zustand 5.0.8 | NextAuth 5.0.0-beta.29 | Recharts 2.15.4

---

## PROJECT STRUCTURE

```
ui/
├── app/                  (Next.js App Router)
│   ├── (auth)/          (Auth pages)
│   └── (prowler)/       (Main app: compliance, findings, providers, scans, services, integrations)
├── components/
│   ├── shadcn/          (New shadcn/ui components)
│   ├── ui/              (HeroUI base)
│   └── {domain}/        (Domain components)
├── actions/             (Server actions)
├── types/               (Shared types)
├── hooks/               (Shared hooks)
├── lib/                 (Utilities)
├── store/               (Zustand state)
├── tests/               (Playwright E2E)
└── styles/              (Global CSS)
```

---

## COMMANDS

```
pnpm install && pnpm run dev        (Setup & start)
pnpm run typecheck                  (Type check)
pnpm run lint:fix                   (Fix linting)
pnpm run format:write               (Format)
pnpm run healthcheck                (typecheck + lint)
pnpm run test:e2e                   (E2E tests)
pnpm run test:e2e:ui                (E2E with UI)
pnpm run test:e2e:debug             (Debug E2E)
pnpm run build && pnpm start        (Build & start)
```

---

## QA CHECKLIST BEFORE COMMIT

- [ ] `npm run typecheck` passes
- [ ] `npm run lint:fix` passes
- [ ] `npm run format:write` passes
- [ ] Relevant E2E tests pass
- [ ] All UI states handled (loading, error, empty)
- [ ] No secrets in code (use `.env.local`)
- [ ] Error messages sanitized
- [ ] Server-side validation present

---

## MIGRATIONS (As of Jan 2025)

React 18 → 19.1.1 (async components, compiler)
Next.js 14 → 15.5.3
NextUI → HeroUI 2.8.4
Zod 3 → 4 (see patterns section)
AI SDK 4 → 5 (see patterns section)
