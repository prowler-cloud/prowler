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
├── tests/ # Playwright E2E tests
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

**⚠️ MANDATORY: If you have access to Playwright MCP tools, ALWAYS use them to understand the actual application flow before creating any E2E test.**

- **IF Playwright MCP is available**: Use browser tools to navigate, interact, and understand the real UI behavior FIRST, then create tests
- **IF Playwright MCP is NOT available**: Proceed with test creation based on available documentation and code analysis
- Add/update E2E tests for critical flows you modify
- Scope: run only affected specs when iterating
- Commit snapshot updates only with real UI changes
- Determinism: avoid relying on real external services; mock or stub where possible
- **Organization**: Create a folder under `tests/` for each page (e.g., `tests/sign-in/`, `tests/sign-up/`, etc.)
- **File Structure**: Each page folder should contain 3 files:
  - `{page-name}-page.ts` - Page Object Model
  - `{page-name}.spec.ts` - Test specifications
  - `{page-name}.md` - Test documentation
- **Base Class**: `tests/base-page.ts` - Parent class that all `{page-name}-page.ts` files should extend
- **Helpers**: `tests/helpers.ts` - Utility functions and helper methods for tests

#### Playwright MCP Integration

**⚠️ CRITICAL WORKFLOW (When Available): If you have access to Playwright MCP browser tools, use them to explore the application BEFORE writing any test code.**

**Recommended Steps Before Creating Tests (Only if MCP Tools are Available):**

1. **Navigate to the application** to reach the target page
2. **Take a snapshot** to see the page structure and available elements
3. **Interact with forms and elements** to verify the exact user flow
4. **Take screenshots** to document expected states at each step
5. **Verify page transitions** by navigating through the complete flow to understand all states (loading, success, error)
6. **Document actual selectors** from the snapshots - use the real element references (ref) and labels you observe
7. **Only after exploring** the complete flow manually, create the test code with the exact selectors and steps you verified

**Why This Matters (When MCP Tools are Available):**

- ✅ **Precise test creation** - Only include the exact steps needed, no assumptions or guessing
- ✅ **Accurate selectors** - Use the actual DOM structure from real snapshots, not imagined selectors
- ✅ **Real flow validation** - Verify the complete user journey actually works as expected
- ✅ **Avoid over-engineering** - Create minimal tests that focus on what actually exists
- ✅ **Prevent flaky tests** - Tests based on real exploration are more stable and reliable
- ❌ **Never assume** - Don't create tests based on assumptions about how the UI "should" work

**Benefits:**
- **Precise test creation** - Only include the exact steps needed for the test requirement
- **Accurate selectors** - Use the actual DOM structure to create reliable locators
- **Real flow validation** - Verify the complete user journey works as expected
- **Avoid over-engineering** - Create minimal tests that focus on the specific requirement

#### Test Creation Guidelines

**IMPORTANT: Always ask for clarification if the request is ambiguous about scope.**

**When creating a specific test:**

- Create only a single `test()` entry implementing the specific functionality described
- Do NOT create the full test suite for this page
- **ALWAYS add the test to the page's main spec file** (e.g., `sign-up.spec.ts`), NOT in a separate file
- **REUSE existing page objects** from other pages when possible (e.g., use existing SignInPage, HomePage, etc.)
- If the page's spec file doesn't exist, create minimal structure:
  - `{page-name}-page.ts` - Page Object Model
  - `{page-name}.spec.ts` - Test specifications (add your specific test here)
- Focus on the exact requirement without additional test cases
- Do NOT create separate files like `{page-name}-critical-path.spec.ts` or `{page-name}-specific-test.spec.ts`

**When creating comprehensive page tests:**

- Create the full test suite with all files (page object, spec, documentation)
- Include multiple test cases covering various scenarios in `{page-name}.spec.ts`
- Follow the complete structure with validation, error handling, accessibility tests
- Create comprehensive documentation for all test cases in `{page-name}.md`

**File Naming Convention:**

- ✅ **CORRECT**: `sign-up.spec.ts` (contains all sign-up tests)
- ✅ **CORRECT**: `sign-up-page.ts` (page object)
- ✅ **CORRECT**: `sign-up.md` (documentation for all tests)
- ❌ **WRONG**: `sign-up-critical-path.spec.ts` (separate file for specific test)
- ❌ **WRONG**: `sign-up-validation.spec.ts` (separate file for specific test)

**Examples:**

```typescript
// ✅ Specific test request - create only this test
test("User can create account and login successfully",{
    tag: ['@critical', '@e2e', '@signup', '@SIGNUP-E2E-001']
  } async ({ page }) => {
  // Implementation for this specific test only
});

// ❌ Don't create full suite when only one test is requested
```

**Request Examples:**

- **"Create a test for user sign-up"** → Create only the sign-up test, not the full suite
- **"Generate E2E tests for the login page"** → Create comprehensive test suite with all scenarios
- **"Add a test to verify form validation"** → Add only the validation test to existing spec
- **"Create tests for the home page"** → Create full test suite for home functionality
- **"Create a new test e2e for sign-up"** → Create only the specific test mentioned
- **"Generate comprehensive E2E tests for sign-up"** → Create full test suite

**Key Phrases to Identify Scope:**

- **Single Test**: "a test", "one test", "new test", "add test"
- **Full Suite**: "comprehensive tests", "all tests", "test suite", "complete tests", "generate tests"

#### Page Object Model Pattern

- **Extend BasePage**: All page objects should extend `BasePage` for common functionality
- **REUSE Existing Page Objects**: Always check for existing page objects before creating new ones
- **Interface Definitions**: Define clear interfaces for form data and credentials
- **Method Organization**: Group methods by functionality (navigation, form interaction, validation, etc.)
- **Locator Strategy**: Use stable selectors (name attributes, labels) over fragile CSS selectors
- **Avoid Code Duplication**: When creating a new page object, verify if there are repeated methods across page objects that should be moved to `BasePage`
- **Shared Utilities**: If utility functions are repeated across tests, create or update `tests/helpers.ts` to centralize them
- **Refactor to BasePage**: Common patterns like form validation, notification checks, or navigation should be extracted to `BasePage`
- **Refactor to Helpers**: Data generation, test setup utilities, or common assertions should be extracted to `tests/helpers.ts`

#### Page Object Reuse Guidelines

- **Check existing page objects first**: Look in `tests/` directory for existing page objects
- **Import and reuse**: Use existing page objects like `SignInPage`, `HomePage`, etc.
- **Create page objects when needed**: If a test requires interaction with a page that doesn't have a page object yet, create it following the Page Object Model pattern
- **Only create new page objects** when the page doesn't exist or has unique functionality
- **Example**: For a sign-up test that needs to verify login after signup, reuse `SignInPage` and `HomePage` if they exist, or create them if needed
- **Avoid duplication**: Don't recreate functionality that already exists in other page objects
- **Complete dependencies**: When creating a test that requires multiple page interactions, ensure all necessary page objects exist (create them if they don't)

#### Code Refactoring Guidelines

**When to move code to `BasePage`:**

- ✅ **Navigation helpers** used by multiple pages (e.g., `waitForPageLoad()`, `getCurrentUrl()`)
- ✅ **Common UI interactions** (e.g., clicking notifications, handling modals, theme toggles)
- ✅ **Verification patterns** repeated across pages (e.g., `isVisible()`, `waitForVisible()`)
- ✅ **Error handling** that applies to all pages
- ✅ **Screenshot utilities** for debugging

**When to move code to `tests/helpers.ts`:**

- ✅ **Test data generation** (e.g., `generateUniqueEmail()`, `generateTestUser()`)
- ✅ **Setup/teardown utilities** (e.g., `createTestUser()`, `cleanupTestData()`)
- ✅ **Custom assertions** used across tests (e.g., `expectNotificationToContain()`)
- ✅ **API helpers** for test setup (e.g., `seedDatabase()`, `resetState()`)
- ✅ **Time utilities** (e.g., `waitForCondition()`, `retryAction()`)

**Example - Before Refactoring:**

```typescript
// ❌ BAD: Repeated code in multiple page objects
export class SignUpPage extends BasePage {
  async waitForNotification(): Promise<void> {
    await this.page.waitForSelector('[role="status"]');
  }
}

export class SignInPage extends BasePage {
  async waitForNotification(): Promise<void> {
    await this.page.waitForSelector('[role="status"]');
  }
}
```

**Example - After Refactoring:**

```typescript
// ✅ GOOD: Move to BasePage
export class BasePage {
  async waitForNotification(): Promise<void> {
    await this.page.waitForSelector('[role="status"]');
  }

  async verifyNotificationMessage(message: string): Promise<void> {
    const notification = this.page.locator('[role="status"]');
    await expect(notification).toContainText(message);
  }
}

// ✅ GOOD: Move to helpers.ts for data generation
export function generateUniqueEmail(): string {
  const timestamp = Date.now();
  return `test.user.${timestamp}@example.com`;
}

export function generateTestUser() {
  return {
    name: "Test User",
    email: generateUniqueEmail(),
    password: "TestPassword123!",
  };
}
```

**Page Object Reuse Example:**

```typescript
// ✅ GOOD: Check for existing page objects, create if needed
// 1. Check if SignInPage exists - if not, create it
// 2. Check if HomePage exists - if not, create it
import { SignInPage } from "../sign-in/sign-in-page";
import { HomePage } from "../home/home-page";

test("User can sign up and login", async ({ page }) => {
  const signUpPage = new SignUpPage(page);
  const signInPage = new SignInPage(page); // REUSE existing (or create if missing)
  const homePage = new HomePage(page); // REUSE existing (or create if missing)

  // Use existing functionality
  await signUpPage.signUp(userData);
  await homePage.verifyPageLoaded(); // REUSE existing method
  await homePage.signOut(); // REUSE existing method
  await signInPage.login(credentials); // REUSE existing method
});

// ❌ BAD: Don't recreate existing functionality in SignUpPage
export class SignUpPage extends BasePage {
  // Don't recreate logout functionality
  async logout() {
    /* ... */
  } // ❌ HomePage already has this

  // Don't recreate login functionality
  async login() {
    /* ... */
  } // ❌ SignInPage already has this

  // ✅ GOOD: Instead, use composition or delegation
  async loginAfterSignUp(credentials: LoginCredentials): Promise<void> {
    // Reuse SignInPage methods or delegate to it
    const emailField = this.page.getByRole("textbox", { name: "Email*" });
    const passwordField = this.page.getByRole("textbox", { name: "Password*" });
    const loginButton = this.page.getByRole("button", { name: "Log in" });

    await emailField.fill(credentials.email);
    await passwordField.fill(credentials.password);
    await loginButton.click();
  }
}
```

**Page Object Structure:**

```typescript
export interface FeatureData {
  email: string;
  password: string;
  // ... other fields
}

export class FeaturePage extends BasePage {
  // Form elements
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly submitButton: Locator;

  constructor(page: Page) {
    super(page);
    // Use stable selectors
    this.emailInput = page.getByLabel("Email");
    this.passwordInput = page.locator('input[name="password"]');
    this.submitButton = page.getByRole("button", { name: "Submit" });
  }

  async goto(): Promise<void> {
    await super.goto("/feature-path");
  }

  async performAction(data: FeatureData): Promise<void> {
    await this.emailInput.fill(data.email);
    await this.passwordInput.fill(data.password);
    await this.submitButton.click();
  }

  async verifyCriticalOutcome(): Promise<void> {
    await expect(this.page).toHaveURL("/expected-path");
    // ... verification logic
  }
}
```

#### Test Structure Best Practices

- **Page Object Usage**: Use Page Object Models for all page interactions
- **Tag Organization**: Use Playwright tag syntax for test categorization
- **Test IDs**: Include test case IDs in tags for traceability
- **Verification Steps**: Include clear verification steps for each major action

**Key Elements:**

- **Page Objects**: All interactions through Page Object Models
- **Clear Tags**: Use `{ tag: ['@priority', '@type', '@feature', '@test-id'] }` syntax
- **Verification**: Explicit verification of critical outcomes

#### Playwright Selector Best Practices

When creating locators in Page Objects, follow this priority order for maximum reliability:

**✅ Primary Selectors (Recommended):**

- **`getByRole()`**: The best and most robust for all interactive elements (buttons, links, main sections)
- **`getByLabel()`**: The best for form controls that have an associated label

**⚠️ Secondary Selectors (Use Sparingly):**

- **`getByText()`**: Use only when the above fail or for static text verification (headings, paragraphs, messages)
- **Others (e.g. `getByTestId()`)**: Use only as a last resort when the above fail or are not applicable

**Examples:**

```typescript
// ✅ GOOD - Using getByRole for interactive elements
this.submitButton = page.getByRole("button", { name: "Submit" });
this.navigationLink = page.getByRole("link", { name: "Dashboard" });

// ✅ GOOD - Using getByLabel for form controls
this.emailInput = page.getByLabel("Email");
this.passwordInput = page.getByLabel("Password");

// ⚠️ SPARINGLY - Using getByText only when necessary
this.errorMessage = page.getByText("Invalid credentials"); // Only if no better selector exists
this.pageTitle = page.getByText("Welcome to Prowler"); // Only for static content verification

// ❌ AVOID - Using fragile selectors when better options exist
this.submitButton = page.locator(".btn-primary"); // Use getByRole instead
this.emailInput = page.locator("#email"); // Use getByLabel instead
```

**Tag Syntax Example:**

```typescript
test(
  "Test description",
  { tag: ["@critical", "@e2e", "@signup", "@SIGNUP-E2E-001"] },
  async ({ page }) => {
    // Test implementation
  },
);
```

#### E2E Test Documentation Format

Each test documentation file (`{page-name}.md`) should follow this structured format:

```markdown
### E2E Tests: {Feature Name}

**Suite ID:** `{SUITE-ID}`
**Feature:** {Feature description}

---

## Test Case: `{TEST-ID}` - {Test case title}

**Priority:** `{critical|high|medium|low}`

**Tags:**

- type → @e2e
- feature → @{feature-name}

**Description/Objective:** {Brief description of what the test validates}

**Preconditions:**

- {List of prerequisites for the test to run}
- {Any required data or state}

### Flow Steps:

1. {Step 1 description}
2. {Step 2 description}
3. {Step 3 description}
   ...

### Expected Result:

- {Expected outcome 1}
- {Expected outcome 2}
  ...

### Key verification points:

- {Key assertion 1}
- {Key assertion 2}
- {Key assertion 3}

### Notes:

- {Any additional notes or considerations}
- {Test data requirements or constraints}
```

#### Test Documentation Best Practices
- **Suite ID Format**: Use descriptive suite IDs (e.g., `SIGNUP-E2E`)
- **Test ID Format**: Include feature and sequence (e.g., `SIGNUP-E2E-001`)
- **Priority Levels**: Use `critical`, `high`, `medium`, `low` for test prioritization
- **Tag Organization**: Use Playwright tag syntax: `{ tag: ['@priority', '@type', '@feature', '@test-id'] }`
- **Flow Steps**: Number steps clearly and describe user actions
- **Verification Points**: List specific assertions and expected outcomes
- **Preconditions**: Document any required setup or data dependencies
- **Test Data Notes**: Include information about data generation and uniqueness strategies

**Tag Categories:**
- **Priority**: `@critical`, `@high`, `@medium`, `@low`
- **Type**: `@e2e`
- **Feature**: `@signup`, `@signin`, `@dashboard`
- **Test ID**: `@SIGNUP-E2E-001`, `@LOGIN-E2E-002`

**IMPORTANT - Keep Documentation Concise:**
- ❌ **DO NOT** include general test running instructions
- ❌ **DO NOT** include file structure explanations
- ❌ **DO NOT** include code examples or tutorials
- ❌ **DO NOT** include extensive troubleshooting sections
- ❌ **DO NOT** include command references or configuration details
- ✅ **DO** focus only on the specific test case: flow, preconditions, expected results, and verification points
- ✅ **DO** keep the documentation under 60 lines when possible
- ✅ **DO** follow the exact format template provided above


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
