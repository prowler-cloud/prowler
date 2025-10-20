# Prowler UI Agent Guide

**Complete guide for AI agents and developers working on the Prowler UI Next.js application.**

## Mission & Scope

- Ship small, high-impact UI changes with minimal risk
- Align to current patterns: App Router, Server Components first, consistent styling, strict types
- Avoid broad refactors, library swaps, or reorganization unless requested
- Focus on safe, incremental frontend changes aligned with existing architecture

---

## Critical Architecture Rules (Non-Negotiable)

### 1. TypeScript Type Patterns (Required)

When defining union types for options, ALWAYS create a const object first, then extract the type:

**❌ DON'T:**

```typescript
type SortOption = "high-low" | "low-high" | "alphabetical";
```

**✅ DO:**

```typescript
const SORT_OPTIONS = {
  HIGH_LOW: "high-low",
  LOW_HIGH: "low-high",
  ALPHABETICAL: "alphabetical",
} as const;

type SortOption = (typeof SORT_OPTIONS)[keyof typeof SORT_OPTIONS];
```

### 2. Tailwind 4 Theme Variables

This project uses Tailwind 4 with @theme variables. **Tailwind is mainly semantic** - prioritize using Tailwind's naming system whenever possible.

#### In Template/JSX (className)

- ✅ Use Tailwind utility classes: `bg-card-bg`, `text-white`, `text-slate-400`, `border-slate-700`
- ✅ Use arbitrary values with classes: `h-3`, `w-3`, `min-w-[200px]`, `bg-slate-700/50`
- ✅ Use Tailwind for conditional styles: `className={isActive ? "bg-blue-500" : "bg-gray-500"}`
- ✅ Use style props only for truly dynamic values: `style={{ width: \`\${percentage}%\` }}`
- ❌ NEVER use `var()` in className
- ❌ NEVER use hex colors in className

#### Constants with var() (Only for library props that don't accept className)

- ✅ Use CHART_COLORS constants: `stroke={CHART_COLORS.gridLine}`, `tick={{ fill: CHART_COLORS.textSecondary }}`
- These props don't accept className, so we use constants that internally reference `var()`
- This is the **only** valid use case for `var()` - when the library doesn't support className

#### Examples

```tsx
// ✅ GOOD - Template with Tailwind classes
<div className="rounded-lg border border-slate-700 bg-slate-800 p-3">
  <p className="text-sm font-semibold text-white">{title}</p>
  <Bell size={14} className="text-slate-400" />
</div>

// ✅ GOOD - Conditional Tailwind classes
<button className={isActive ? "bg-blue-500" : "bg-gray-500"}>
  Click me
</button>

// ✅ GOOD - Recharts library props with CHART_COLORS (var() only here)
<XAxis tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }} />
<CartesianGrid stroke={CHART_COLORS.gridLine} />

// ✅ GOOD - Truly dynamic values (not available in Tailwind)
<div style={{ width: `${percentage}%`, opacity: isFaded ? 0.5 : 1 }} />

// ❌ BAD - var() in className
<div className="bg-[var(--color-card-bg)]" /> // Don't do this!

// ❌ BAD - Hex colors in className
<p className="text-[#ffffff]" /> // Use text-white instead

// ❌ BAD - Using var() for colors when Tailwind classes exist
const PROVIDER_COLORS = {
  AWS: "var(--color-orange)", // Use Tailwind classes instead!
};

// ❌ BAD - Using style when className is available
<div style={{ backgroundColor: "blue" }} /> // Use className="bg-blue-500" instead
```

### 3. The `cn()` Utility Function

#### What is `cn()`?

The `cn()` function is a utility that combines `clsx` and `tailwind-merge`:

```typescript
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

**Components:**

- **`clsx`**: Constructs conditional className strings (handles booleans, arrays, objects)
- **`twMerge`**: Intelligently merges Tailwind classes, resolving conflicts (e.g., `p-4` + `p-2` → `p-2`)

#### When to Use `cn()`

Use `cn()` **ONLY** when you have:

##### 1. Conditional Classes

```tsx
// ✅ GOOD - Conditional logic
<div className={cn("h-3 w-3", isCircle ? "rounded-full" : "rounded-sm")} />

// ✅ GOOD - Boolean conditionals
<button className={cn("btn", isActive && "btn-active", isDisabled && "opacity-50")} />
```

##### 2. Merging Props with Conflicting Classes

```tsx
// ✅ GOOD - Component accepting className prop
interface ButtonProps {
  className?: string;
}

function Button({ className }: ButtonProps) {
  return <button className={cn("bg-blue-500 px-4 py-2", className)} />;
}

// Usage: <Button className="px-6" /> → Results in "px-6 py-2 bg-blue-500"
```

##### 3. Dynamic String Interpolation

```tsx
// ✅ GOOD - Dynamic values that need proper merging
<span className={cn(`text-${size}`, "font-semibold text-white")} />
```

#### When NOT to Use `cn()`

**DO NOT** use `cn()` for static classes without conditional logic:

```tsx
// ❌ BAD - Unnecessary, no conditional logic
<div className={cn("rounded-lg border border-slate-700 bg-slate-800 p-3")} />

// ✅ GOOD - Just use className directly
<div className="rounded-lg border border-slate-700 bg-slate-800 p-3" />

// ❌ BAD - No conflicts or conditionals
<div className={cn("flex items-center gap-2")} />

// ✅ GOOD - Static classes don't need cn()
<div className="flex items-center gap-2" />
```

#### Real-World Examples

```tsx
// ❌ BAD - Overuse of cn()
function Tooltip({ active, payload }: any) {
  return (
    <div className={cn("rounded-lg border border-slate-700")}>
      <div className={cn("flex items-center gap-2")}>
        <div className={cn("h-3 w-3 rounded-sm")} />
        <span className={cn("text-sm font-semibold text-white")}>
          {payload.name}
        </span>
      </div>
    </div>
  );
}

// ✅ GOOD - Only use cn() where needed
function Tooltip({ active, payload, shape }: any) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-800 p-3">
      <div className="flex items-center gap-2">
        <div
          className={cn(
            "h-3 w-3",
            shape === "circle" ? "rounded-full" : "rounded-sm",
          )}
        />
        <span className="text-sm font-semibold text-white">{payload.name}</span>
      </div>
    </div>
  );
}
```

#### Key Takeaway

**`cn()` is a tool for conditional logic and conflict resolution, NOT a wrapper for every className.**

Use it purposefully where it adds value. Don't use it out of habit.

**Reference:** [The Story Behind Tailwind's cn() Function](https://tigerabrodi.blog/the-story-behind-tailwinds-cn-function)

### 4. React 19 with Compiler

This project uses React 19 with the React Compiler enabled. This means:

- **DO NOT use `useMemo`** - React Compiler handles memoization automatically
- **DO NOT use `useCallback`** - React Compiler optimizes callbacks automatically
- Only use these hooks if you have a specific, documented reason that the compiler cannot handle

### 5. Next.js 15 Architecture Principles

#### 1. App Router Architecture First

- **ALL routes MUST use App Router** - never use Pages Router for new projects
- Leverage Server Components by default, Client Components only when necessary
- Use proper file conventions: `page.tsx`, `layout.tsx`, `loading.tsx`, `error.tsx`, `not-found.tsx`
- Implement route groups `(group-name)` for organization without affecting URL structure
- Use private folders `_folder` to opt out of routing system

#### 2. Server-First Architecture

- **Server Components by default** - add `"use client"` only when required
- Optimize data fetching at the server level
- Implement streaming with `loading.tsx` and Suspense boundaries
- Use Server Actions for form handling and mutations
- Leverage static generation and ISR for performance
- Use DAL (Data Access Layer) patterns to separate data logic
- To prevent accidental usage in Client Components, you can use the server-only package, this is a MUST for Server Actions and recommended for all server-only code

#### 3. The Scope Rule - Your Unbreakable Law

**"Scope determines structure"**

- Code used by 2+ features → MUST go in global/shared directories
- Code used by 1 feature → MUST stay local in that feature
- NO EXCEPTIONS - This rule is absolute and non-negotiable

#### 4. Screaming Architecture

Your structures must IMMEDIATELY communicate what the application does:

- Feature names must describe business functionality, not technical implementation
- Directory structure should tell the story of what the app does at first glance
- Route structure should mirror business logic, not technical concerns

#### 5. Component Placement Decision Framework

When analyzing where to place a component, you MUST follow this process:

1. **Identify component type**: Server Component, Client Component, or hybrid
2. **Count usage**: Identify exactly how many features/routes use the component
3. **Apply the Scope Rule**:
   - Used by 1 feature → Local placement within that feature
   - Used by 2+ features → Global/shared directory
4. **Consider performance**: Optimize bundle splitting and server-side rendering
5. **Document the decision**: Always explain WHY the placement was chosen

### 6. File Organization Patterns

#### Co-location Principles

Follow these patterns for organizing related files:

**For Server Actions:**

```
ui/actions/
  └── feature-name/
      ├── feature-name.ts        # Server actions
      ├── models.ts              # Domain models/types
      └── feature-name.adapter.ts # Data transformations (if needed)
```

**For Components:**

```
ui/components/
  └── feature-name/
      ├── feature-component.tsx  # Main component
      ├── feature-client.tsx     # Client-specific logic
      └── feature-name/          # Utilities folder
          ├── types.ts
          ├── utils.ts
          ├── constants.ts
          └── hooks.ts
```

**Key Rules:**

- Models used by only one feature → Keep local in that feature's directory
- Utilities used by only one feature → Keep in feature's utils folder
- Types only used within a feature → Keep in feature's types file
- Only move to global/shared when used by 2+ features

---

## Project Overview

The Prowler UI is a Next.js 15 application providing a modern web interface for the Prowler security platform. It features a comprehensive dashboard for managing cloud security scans, compliance frameworks, and findings across multiple cloud providers.

## Tech Stack (Updated January 2025)

- **Framework**: Next.js 15.5.3 with App Router
- **Runtime**: React 19.1.1 (with Compiler enabled)
- **Language**: TypeScript 5.5.4
- **Styling**: Tailwind CSS 4.1.13 + **shadcn/ui** (new components) / HeroUI 2.8.4 (legacy)
- **State Management**: Zustand 5.0.8
- **Authentication**: NextAuth.js 5.0.0-beta.29
- **Forms/Validation**: React Hook Form 7.62.0 + Zod 4.1.11
- **AI/Chat**: AI SDK 5.0.59 + @ai-sdk/react 2.0.59
- **AI Backend**: LangChain @langchain/core 0.3.77 + @ai-sdk/langchain 1.0.59
- **Charts**: Recharts 2.15.4
- **Testing**: Playwright 1.53.2
- **Formatter**: Prettier 3.6.2

## Commands

### Development

```bash
npm install # Install dependencies
npm run dev # Start development server (localhost:3000)
npm run build # Build for production
npm start # Start production server
npm run start:standalone # Start standalone server
```

### Code Quality

```bash
npm run typecheck # TypeScript type checking
npm run lint:check # ESLint checking
npm run lint:fix # Fix ESLint issues
npm run format:check # Prettier format checking
npm run format:write # Format code with Prettier
npm run healthcheck # Run typecheck + lint together
```

### Testing

```bash
npm run test:e2e # Run Playwright tests
npm run test:e2e:ui # Run tests with UI
npm run test:e2e:debug # Debug tests
npm run test:e2e:headed # Run tests in headed mode
npm run test:e2e:report # Show test report
npm run test:e2e:install # Install Playwright browsers
```

## Project Structure

```
ui/
├── app/ # Next.js App Router
│ ├── (auth)/ # Authentication pages (sign-in, sign-up)
│ ├── (prowler)/ # Main application pages
│ │ ├── compliance/ # Compliance frameworks & reports
│ │ ├── findings/ # Security findings & vulnerabilities
│ │ ├── integrations/ # S3, Security Hub integrations
│ │ ├── lighthouse/ # AI-powered security assistant
│ │ ├── providers/ # Cloud provider management
│ │ ├── scans/ # Security scan management
│ │ └── services/ # Cloud services overview
│ └── api/ # API routes & server actions
├── components/ # Reusable UI components
│ ├── shadcn/ # shadcn/ui components (NEW)
│ │ ├── card.tsx # shadcn Card component
│ │ ├── resource-stats-card/ # Custom ResourceStatsCard built on shadcn
│ │ │ ├── resource-stats-card.tsx
│ │ │ ├── resource-stats-card.example.tsx
│ │ │ └── index.ts
│ │ ├── index.ts # Barrel exports
│ │ └── README.md
│ ├── ui/ # Base UI components (buttons, forms, etc.)
│ ├── compliance/ # Compliance-specific components
│ ├── findings/ # Findings table & filters
│ ├── providers/ # Provider management UI
│ ├── scans/ # Scan management UI
│ └── integrations/ # Integration configuration
├── actions/ # Server actions (data fetching/mutations)
├── lib/ # Utility functions & configurations
├── types/ # TypeScript type definitions
├── hooks/ # Custom React hooks
├── store/ # Zustand state management
└── styles/ # Global CSS & Tailwind config
```

## shadcn/ui Components

### Directory Structure

All shadcn/ui based components are located in `components/shadcn/`:

```
shadcn/
├── card.tsx                    # shadcn Card component
├── resource-stats-card/        # Custom ResourceStatsCard built on shadcn
│   ├── resource-stats-card.tsx
│   ├── resource-stats-card.example.tsx
│   └── index.ts
├── index.ts                    # Barrel exports
└── README.md
```

### Usage

All shadcn components can be imported from `@/components/shadcn`:

```tsx
import { Card, CardHeader, CardContent } from "@/components/shadcn";
import { ResourceStatsCard } from "@/components/shadcn";
```

### Adding New shadcn Components

When adding new shadcn components using the CLI:

```bash
npx shadcn@latest add [component-name]
```

The component will be automatically added to this directory due to the configuration in `components.json`:

```json
{
  "aliases": {
    "ui": "@/components/shadcn"
  }
}
```

### Component Guidelines

1. **shadcn base components** - Use as-is from shadcn/ui (e.g., `card.tsx`)
2. **Custom components built on shadcn** - Create in subdirectories (e.g., `resource-stats-card/`)
3. **CVA variants** - Use Class Variance Authority for type-safe variants
4. **Theme support** - Include `dark:` classes for dark/light theme compatibility
5. **TypeScript** - Always export types and use proper typing

### Resources

- [shadcn/ui Documentation](https://ui.shadcn.com)
- [CVA Documentation](https://cva.style/docs)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)

## Key Features

### Authentication System

- NextAuth.js with multiple providers (credentials, OAuth, SAML)
- Server-side authentication with middleware protection
- Session management and role-based access control

### Cloud Provider Management

- Multi-cloud support (AWS, Azure, GCP, GitHub, K8s, M365)
- Credential management with secure forms
- Connection testing and status monitoring

### Security Scanning

- Real-time scan progress monitoring
- Bulk operations and filtering
- Scheduled scan management
- Download and export capabilities

### Compliance Frameworks

- 36+ compliance frameworks (CIS, NIST, PCI-DSS, etc.)
- Interactive compliance reports with charts
- Requirement-level drill-down views
- Custom compliance mapping

### Lighthouse AI Assistant

- LangChain-powered security chatbot
- Context-aware responses about findings
- Integration with scan data and compliance frameworks

### Findings Management

- Advanced filtering and search
- Mute/unmute functionality with reasons
- Severity-based classification
- Detailed finding analysis

## Patterns & Conventions

### Component Architecture

```typescript
// Prefer server components when possible
export default async function PageComponent() {
  const data = await fetchData();
  return <ClientComponent data={data} />;
}
```

### State Management

```typescript
// Use Zustand for global state
import { useStore } from "@/hooks/use-store";

const { filters, setFilters } = useStore();
```

### Server Actions

```typescript
"use server";

export async function updateProvider(formData: FormData) {
  // Validate with Zod
  // Update via API
  // Revalidate cache
}
```

### Form Handling

```typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

const form = useForm({
  resolver: zodResolver(schema),
});
```

## File & Code Style

### Naming & Organization

- **Component Naming**: `PascalCase` for components, `camelCase` for helpers
- **Foldering**: Colocate domain components under domain folders (e.g., `components/integrations/jira/`)
- **Imports**: Honor alias paths (`@/components/...`). Keep import order consistent with ESLint rules
- **CSS**: Prefer Tailwind classes; avoid ad-hoc CSS files unless justified

### Import Organization

```typescript
// External libraries
import React from "react";
import { Button } from "@heroui/react";

// Internal utilities
import { cn } from "@/lib/utils";

// Types
import type { ComponentProps } from "@/types";
```

## Styling Guidelines

### Tailwind + shadcn/ui (New) / HeroUI (Existing)

- **Use shadcn/ui components for new UI features/pages** with the new Tailwind theme
- Existing features/pages should continue using HeroUI (migrated from NextUI) for consistency
- Custom Prowler color palette defined in tailwind.config.js
- Dark/light theme support via next-themes
- Custom shadows and animations for Prowler brand

## Library-Specific Guidelines

### Zod v4 (Schema Validation)

**Breaking changes from v3:**

- ❌ `.nonempty()` → ✅ `.min(1)` for strings
- ❌ `z.string().email()` → ✅ `z.email()` (top-level function)
- ❌ `z.string().uuid()` → ✅ `z.uuid()` (top-level function)
- ❌ `z.string().url()` → ✅ `z.url()` (top-level function)
- ❌ `required_error` parameter → ✅ `error` parameter
- ❌ `message` parameter → ✅ `error` parameter
- ⚠️ `.optional()` type inference changed - fields are now `T | undefined` in inferred types

**Example migration:**

```typescript
// ❌ Zod v3
const schema = z.object({
  email: z.string().email({ message: "Invalid email" }),
  name: z.string().nonempty("Required"),
  id: z.string().uuid(),
});

// ✅ Zod v4
const schema = z.object({
  email: z.email({ error: "Invalid email" }),
  name: z.string().min(1, "Required"),
  id: z.uuid(),
});
```

### Zustand v5 (State Management)

**Breaking changes from v4:**

- ✅ No API changes required for basic usage
- ⚠️ `shallow` comparison must use `useShallow` hook from `zustand/react/shallow`
- ⚠️ Selectors must return stable references to avoid infinite loops
- ⚠️ `persist` middleware no longer auto-stores initial state - call `setState()` explicitly if needed

**Best practices:**

```typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";

const useStore = create(
  persist(
    (set) => ({
      value: 0,
      increment: () => set((state) => ({ value: state.value + 1 })),
    }),
    { name: "my-store" },
  ),
);
```

### AI SDK v5 (Chat & AI Features)

**Breaking changes from v4:**

- ❌ `Message` type → ✅ `UIMessage` type
- ❌ `message.content` string → ✅ `message.parts` array structure
- ❌ `handleSubmit` / `handleInputChange` → ✅ `sendMessage` with manual state
- ❌ `append()` → ✅ `sendMessage({ text: "..." })`
- ❌ `api: "/endpoint"` → ✅ `transport: new DefaultChatTransport({ api: "/endpoint" })`
- ❌ `LangChainAdapter.toDataStreamResponse()` → ✅ `toUIMessageStream()` from `@ai-sdk/langchain`

**Example migration:**

```typescript
// ❌ AI SDK v4
import { useChat } from "ai";
const { messages, handleSubmit, input, handleInputChange } = useChat({
  api: "/api/chat",
});

// ✅ AI SDK v5
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
const { messages, sendMessage } = useChat({
  transport: new DefaultChatTransport({ api: "/api/chat" }),
});
// Manual input state management required
const [input, setInput] = useState("");
const handleSubmit = (e) => {
  e.preventDefault();
  sendMessage({ text: input });
  setInput("");
};
```

**UIMessage structure:**

```typescript
// Message parts-based structure
const message: UIMessage = {
  id: "msg-1",
  role: "assistant",
  parts: [{ type: "text", text: "Hello world" }],
};

// Extract text from parts
const text = message.parts
  .filter((p) => p.type === "text")
  .map((p) => ("text" in p ? p.text : ""))
  .join("");
```

## Testing

### Playwright E2E Tests

- Add/update E2E tests for critical flows you modify
- Scope: run only affected specs when iterating
- Commit snapshot updates only with real UI changes
- Determinism: avoid relying on real external services; mock or stub where possible

### Component Testing (Future)

- Jest + React Testing Library
- Component unit tests
- Integration tests for complex flows

## Performance

- Keep Client Components lean; avoid heavy client-side logic where server boundary is possible
- Use streaming, partial rendering, and skeletons for long operations
- **DO NOT use `useMemo` or `useCallback`** - React 19 Compiler handles this automatically
- App Router with server components
- Image optimization with next/image
- Font optimization with next/font
- Bundle analysis and code splitting

## Security

### Best Practices

- Do not commit secrets or `.env.local` values. Use placeholders in examples
- Avoid logging sensitive data. Sanitize error messages shown to users
- Strict CSP headers in next.config.js
- XSS protection and CSRF mitigation
- Secure cookie configuration

### Data Handling

- Client-side validation with Zod
- Server-side sanitization
- Secure credential storage patterns

### Authentication

- NextAuth: use server helpers and `server-only` where appropriate
- Protect routes through middleware and layout boundaries
- JWT tokens via NextAuth
- Automatic token refresh
- Protected routes via middleware

## Quality Gates (before submitting changes) IMPORTANT!

1. `npm run typecheck` shows 0 new errors
2. `npm run lint:check` passes or is fixed via `npm run lint:fix`
3. `npm run format:check` passes or is corrected via `npm run format:write`
4. Relevant Playwright specs pass locally
5. UI states (loading, error, empty) are handled

## Common Development Tasks

### Adding New Pages

1. Create page component in `app/(prowler)/`
2. Add route to navigation in `lib/menu-list.ts`
3. Implement required server actions
4. Add proper TypeScript types (using const-based type pattern). IMPORTANT!: avoid "any" type.

### Creating Components

1. **Use shadcn/ui for new UI components that belong to new features/pages**
2. Existing features/pages should continue using HeroUI for consistency
3. Follow established patterns in `components/shadcn/` for new components
4. Implement proper TypeScript interfaces (using const-based type pattern)
5. Add to component index files

### Integrating with Backend

1. Create server actions in `actions/`
2. Define TypeScript types in `types/` (using const-based type pattern)
3. Handle loading and error states
4. Implement proper caching strategy

### When Implementing New UI

- **Use shadcn/ui components with the new Tailwind theme for new UI features/pages**
- **For existing features/pages, continue using HeroUI components for consistency**
- Start from existing patterns in the closest domain folder
- Reuse primitives from `components/shadcn` (for new features) or `components/ui` (HeroUI for existing) and existing composables
- Add types to `types/` if they're shared (2+ features); otherwise colocate types near usage (1 feature)
- Follow The Scope Rule strictly - used by 2+ features = shared, 1 feature = local
- Update feature docs and `ui/CHANGELOG.md` when behavior changes

### Documentation Links Pattern (Integrations Only)

For integration features (e.g., API Keys, SAML, S3) that have dedicated documentation, include "Read the docs" links in both the main card/component and related modals:

**Main Card Header** (e.g., API Keys card):
```tsx
<p className="text-xs text-gray-500">
  Manage API keys for programmatic access.{" "}
  <CustomLink href="https://docs.prowler.com/user-guide/providers/prowler-app-api-keys">
    Read the docs
  </CustomLink>
</p>
```

**Modal/Form** (e.g., Create API Key modal):
```tsx
<p className="text-xs text-gray-500">
  Need help configuring API Keys?{" "}
  <CustomLink href="https://docs.prowler.com/user-guide/providers/prowler-app-api-keys">
    Read the docs
  </CustomLink>
</p>
```

**Rules:**
- **Only apply to integration components** (API Keys, SAML, S3, Security Hub, etc.)
- Use the same documentation URL across related components
- Tailor the helper text to the component context (card = general, modal = action-specific)
- Apply `text-xs text-gray-500` styling for consistency
- Place the link in a `<p>` tag or description area within the component
- Always use `CustomLink` component for documentation links

## Environment Configuration

### Required Environment Variables

```bash
# Authentication
NEXTAUTH_SECRET=your_secret_here
NEXTAUTH_URL=http://localhost:3000

# API Configuration
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080

# AI Features
OPENAI_API_KEY=your_openai_key
```

### Development Setup

1. Copy `.env.example` to `.env.local`
2. Configure authentication providers
3. Set up API backend connection
4. Install dependencies and start dev server

## Deployment

### Production Build

```bash
npm run build # Build optimized bundle
npm run start # Start production server
```

### Docker Deployment

- Dockerfile available for containerization
- Standalone output for minimal container size
- Health checks via `/api/health` endpoint

## Troubleshooting

### Common Issues

1. **TypeScript errors**: Run `npm run typecheck`
2. **Lint issues**: Run `npm run lint:fix`
3. **Build failures**: Check Next.js build logs
4. **Authentication issues**: Verify NextAuth configuration

### Debug Tools

- Next.js built-in debugger
- React Developer Tools
- Network tab for API debugging
- Lighthouse for performance analysis

## Recent Major Migrations (January 2025)

- ✅ React 18 → 19.1.1 (async components, useActionState, React Compiler)
- ✅ Next.js 14 → 15.5.3 (enhanced App Router)
- ✅ NextUI → HeroUI 2.8.4
- ✅ Zod 3.25.73 → 4.1.11 (breaking: deprecated methods)
- ✅ Zustand 4.5.7 → 5.0.8 (compatible)
- ✅ AI SDK 4.3.16 → 5.0.59 (breaking: new message structure)
- ✅ LangChain updates with new adapter patterns

## Summary

These guidelines ensure:

- ✅ Consistent code patterns across the project
- ✅ Optimal performance with Next.js 15 and React 19 with Compiler
- ✅ Clear, maintainable architecture following The Scope Rule
- ✅ Proper separation of concerns
- ✅ Type safety throughout the codebase using const-based types
- ✅ Semantic Tailwind usage without var() or hex colors in className
- ✅ Purposeful use of cn() only for conditionals and merging

**When in doubt, ask before deviating from these patterns.**

## References

- **High-level project guide**: `../AGENTS.md` (root Prowler project - takes priority)
- **UI Changelog**: `./CHANGELOG.md`
