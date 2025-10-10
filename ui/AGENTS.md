# Prowler UI Agent Guide

**Comprehensive guide for AI agents and developers working on the Prowler UI Next.js application.**

## Mission & Scope
- Ship small, high-impact UI changes with minimal risk
- Align to current patterns: App Router, Server Components first, consistent styling, strict types
- Avoid broad refactors, library swaps, or reorganization unless requested
- Focus on safe, incremental frontend changes aligned with existing architecture

## Overview
The Prowler UI is a Next.js 15 application providing a modern web interface for the Prowler security platform. It features a comprehensive dashboard for managing cloud security scans, compliance frameworks, and findings across multiple cloud providers.

## Tech Stack (Updated January 2025)
- **Framework**: Next.js 15.5.3 with App Router
- **Runtime**: React 19.1.1
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
npm install           # Install dependencies
npm run dev           # Start development server (localhost:3000)
npm run build         # Build for production
npm start             # Start production server
npm run start:standalone  # Start standalone server
```

### Code Quality
```bash
npm run typecheck     # TypeScript type checking
npm run lint:check    # ESLint checking
npm run lint:fix      # Fix ESLint issues
npm run format:check  # Prettier format checking
npm run format:write  # Format code with Prettier
npm run healthcheck   # Run typecheck + lint together
```

### Testing
```bash
npm run test:e2e         # Run Playwright tests
npm run test:e2e:ui      # Run tests with UI
npm run test:e2e:debug   # Debug tests
npm run test:e2e:headed  # Run tests in headed mode
npm run test:e2e:report  # Show test report
npm run test:e2e:install # Install Playwright browsers
```

## Project Structure

```
ui/
├── app/                    # Next.js App Router
│   ├── (auth)/            # Authentication pages (sign-in, sign-up)
│   ├── (prowler)/         # Main application pages
│   │   ├── compliance/    # Compliance frameworks & reports
│   │   ├── findings/      # Security findings & vulnerabilities
│   │   ├── integrations/  # S3, Security Hub integrations
│   │   ├── lighthouse/    # AI-powered security assistant
│   │   ├── providers/     # Cloud provider management
│   │   ├── scans/         # Security scan management
│   │   └── services/      # Cloud services overview
│   └── api/               # API routes & server actions
├── components/            # Reusable UI components
│   ├── ui/               # Base UI components (buttons, forms, etc.)
│   ├── compliance/       # Compliance-specific components
│   ├── findings/         # Findings table & filters
│   ├── providers/        # Provider management UI
│   ├── scans/           # Scan management UI
│   └── integrations/    # Integration configuration
├── actions/              # Server actions (data fetching/mutations)
├── lib/                  # Utility functions & configurations
├── types/               # TypeScript type definitions
├── hooks/               # Custom React hooks
├── store/               # Zustand state management
├── tests/               # Playwright E2E tests
└── styles/              # Global CSS & Tailwind config
```

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

### Architecture Principles
- **Server First**: Prefer Server Components for data fetching and page assembly; use Client Components only for interactivity/state
- **Server Actions**: Put mutation logic in `actions/`. Validate with Zod. Revalidate caches as needed
- **Types**: Keep strict types; avoid `any`. Narrow and localize unavoidable exceptions
- **Forms**: React Hook Form + Zod resolvers
- **State**: Centralize cross-component client state in `store/` (Zustand). Keep local UI state local
- **Styling**: **New UI features/pages should use shadcn/ui with the new Tailwind theme**. Existing features/pages should continue using HeroUI for consistency; Tailwind utility classes for layout and customizations
- **Accessibility**: Ensure labels, focus management, and keyboard interactions. Prefer Radix primitives where needed
- **Data Fetching**: Use `fetch` with Next.js caching/revalidation semantics; avoid client fetching when server boundary is possible
- **Error/Loading**: Explicit, resilient states. Avoid silent failures

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

### Color System
```css
/* Prowler Brand Colors */
--prowler-green: #9FD655;
--prowler-midnight: #030921;
--prowler-pale: #f3fcff;

/* Severity Colors */
--critical: #AC1954;
--high: #F31260;
--medium: #FA7315;
--low: #fcd34d;
```

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
    { name: "my-store" }
  )
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
  parts: [
    { type: "text", text: "Hello world" }
  ]
};

// Extract text from parts
const text = message.parts
  .filter(p => p.type === "text")
  .map(p => "text" in p ? p.text : "")
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
- Memoize expensive client computations; avoid unnecessary re-renders
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

## Quality Gates (before submitting changes)

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
4. Add proper TypeScript types

### Creating Components
1. **Use shadcn/ui for new UI components that belong to new features/pages**
2. Existing features/pages should continue using HeroUI for consistency
3. Follow established patterns in `components/ui/`
4. Implement proper TypeScript interfaces
5. Add to component index files

### Integrating with Backend
1. Create server actions in `actions/`
2. Define TypeScript types in `types/`
3. Handle loading and error states
4. Implement proper caching strategy

### When Implementing New UI
- **Use shadcn/ui components with the new Tailwind theme for new UI features/pages**
- **For existing features/pages, continue using HeroUI components for consistency**
- Start from existing patterns in the closest domain folder
- Reuse primitives from `components/ui` (shadcn/ui for new features, HeroUI for existing) and existing composables
- Add types to `types/` if they're shared; otherwise colocate types near usage
- Update feature docs and `ui/CHANGELOG.md` when behavior changes

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
npm run build          # Build optimized bundle
npm run start          # Start production server
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

- ✅ React 18 → 19.1.1 (async components, useActionState)
- ✅ Next.js 14 → 15.5.3 (enhanced App Router)
- ✅ NextUI → HeroUI 2.8.4
- ✅ Zod 3.25.73 → 4.1.11 (breaking: deprecated methods)
- ✅ Zustand 4.5.7 → 5.0.8 (compatible)
- ✅ AI SDK 4.3.16 → 5.0.59 (breaking: new message structure)
- ✅ LangChain updates with new adapter patterns

## References

- **High-level project guide**: `../CLAUDE.md` (root Prowler project)
- **UI Changelog**: `./CHANGELOG.md`
- **Pull Request**: [#8801](https://github.com/prowler-cloud/prowler/pull/8801) - Latest dependency upgrades
