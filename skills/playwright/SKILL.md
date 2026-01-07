---
name: playwright
description: >
  Playwright E2E testing patterns.
  Trigger: When writing E2E tests - Page Objects, selectors, MCP workflow.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## MCP Workflow (If Available)

**BEFORE writing tests, use Playwright MCP tools:**

1. **Navigate** to target page
2. **Take snapshot** to see page structure
3. **Interact** with forms/elements to verify flow
4. **Document actual selectors** from snapshots
5. **Only then** write test code

## File Structure

```
tests/
├── base-page.ts              # Parent class for all pages
├── helpers.ts                # Shared utilities
└── {page-name}/
    ├── {page-name}-page.ts   # Page Object Model
    ├── {page-name}.spec.ts   # ALL tests here (no separate files!)
    └── {page-name}.md        # Documentation
```

## Selector Priority (REQUIRED)

```typescript
// 1. BEST - getByRole for interactive elements
this.submitButton = page.getByRole("button", { name: "Submit" });
this.navLink = page.getByRole("link", { name: "Dashboard" });

// 2. BEST - getByLabel for form controls
this.emailInput = page.getByLabel("Email");
this.passwordInput = page.getByLabel("Password");

// 3. SPARINGLY - getByText for static content
this.errorMessage = page.getByText("Invalid credentials");

// ❌ AVOID - CSS selectors
this.button = page.locator(".btn-primary");  // NO
this.input = page.locator("#email");         // NO
```

## Page Object Pattern

```typescript
import { Page, Locator, expect } from "@playwright/test";

export class BasePage {
  constructor(protected page: Page) {}

  async goto(path: string): Promise<void> {
    await this.page.goto(path);
    await this.page.waitForLoadState("networkidle");
  }
}

export interface LoginData {
  email: string;
  password: string;
}

export class LoginPage extends BasePage {
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly submitButton: Locator;

  constructor(page: Page) {
    super(page);
    this.emailInput = page.getByLabel("Email");
    this.passwordInput = page.getByLabel("Password");
    this.submitButton = page.getByRole("button", { name: "Sign in" });
  }

  async goto(): Promise<void> {
    await super.goto("/login");
  }

  async login(data: LoginData): Promise<void> {
    await this.emailInput.fill(data.email);
    await this.passwordInput.fill(data.password);
    await this.submitButton.click();
  }
}
```

## Test Pattern with Tags

```typescript
import { test, expect } from "@playwright/test";
import { LoginPage } from "./login-page";

test.describe("Login", () => {
  test("User can login successfully",
    { tag: ["@critical", "@e2e", "@login", "@LOGIN-E2E-001"] },
    async ({ page }) => {
      const loginPage = new LoginPage(page);

      await loginPage.goto();
      await loginPage.login({ email: "user@test.com", password: "pass123" });

      await expect(page).toHaveURL("/dashboard");
    }
  );
});
```

## Scope Detection

| User Says | Action |
|-----------|--------|
| "a test", "one test", "add test" | Create ONE test() |
| "comprehensive tests", "test suite" | Create full suite |

## Page Object Reuse

```typescript
// ✅ GOOD: Reuse existing page objects
import { LoginPage } from "../login/login-page";
import { HomePage } from "../home/home-page";

test("Full flow", async ({ page }) => {
  const loginPage = new LoginPage(page);
  const homePage = new HomePage(page);

  await loginPage.login(credentials);
  await homePage.verifyLoaded();
});
```

## helpers.ts

```typescript
export function generateUniqueEmail(): string {
  return `test.${Date.now()}@example.com`;
}

export function generateTestUser() {
  return {
    email: generateUniqueEmail(),
    password: "TestPass123!",
  };
}
```

## Commands

```bash
npx playwright test                    # Run all
npx playwright test --grep "login"     # Filter
npx playwright test --ui               # With UI
npx playwright test --debug            # Debug mode
```

## Keywords
playwright, e2e, testing, page object model, selectors, end-to-end
