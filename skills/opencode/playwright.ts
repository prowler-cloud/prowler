
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: playwright
description: Playwright E2E testing patterns. Page Object Model, selectors, MCP workflow, tags.
license: MIT
---

## When to use this skill

Use this skill for Playwright E2E testing in any project.

## MCP Workflow (If Available)

**BEFORE writing tests, use Playwright MCP tools:**

1. **Navigate** to target page
2. **Take snapshot** to see page structure
3. **Interact** with forms/elements to verify flow
4. **Document actual selectors** from snapshots
5. **Only then** write test code

## File Structure

\`\`\`
tests/
├── base-page.ts              # Parent class for all pages
├── helpers.ts                # Shared utilities
└── {page-name}/
    ├── {page-name}-page.ts   # Page Object Model
    ├── {page-name}.spec.ts   # ALL tests here (no separate files!)
    └── {page-name}.md        # Documentation
\`\`\`

## Selector Priority (REQUIRED)

\`\`\`typescript
// 1. BEST - getByRole for interactive elements
this.submitButton = page.getByRole("button", { name: "Submit" });
this.navLink = page.getByRole("link", { name: "Dashboard" });

// 2. BEST - getByLabel for form controls
this.emailInput = page.getByLabel("Email");
this.passwordInput = page.getByLabel("Password");

// 3. SPARINGLY - getByText for static content
this.errorMessage = page.getByText("Invalid credentials");

// ❌ AVOID - CSS selectors
this.button = page.locator(".btn-primary");
this.input = page.locator("#email");
\`\`\`

## Page Object Pattern

\`\`\`typescript
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
\`\`\`

## Test Pattern with Tags

\`\`\`typescript
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
\`\`\`

## Scope Detection

| User Says | Action |
|-----------|--------|
| "a test", "one test", "add test" | Create ONE test() |
| "comprehensive tests", "test suite" | Create full suite |

## helpers.ts

\`\`\`typescript
export function generateUniqueEmail(): string {
  return \\\`test.\\\${Date.now()}@example.com\\\`;
}

export function generateTestUser() {
  return {
    email: generateUniqueEmail(),
    password: "TestPass123!",
  };
}
\`\`\`

## Commands

\`\`\`bash
npx playwright test                    # Run all
npx playwright test --grep "login"     # Filter
npx playwright test --ui               # With UI
npx playwright test --debug            # Debug mode
\`\`\`

## Keywords
playwright, e2e, testing, page object model, selectors, end-to-end
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: page-object, selectors, tags, mcp-workflow"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("selector")) {
      return \`
## Playwright Selector Priority

\\\`\\\`\\\`typescript
// 1. BEST - getByRole (interactive elements)
page.getByRole("button", { name: "Submit" })
page.getByRole("link", { name: "Home" })
page.getByRole("textbox", { name: "Email" })

// 2. BEST - getByLabel (form controls)
page.getByLabel("Email")
page.getByLabel("Password")

// 3. SPARINGLY - getByText (static content)
page.getByText("Welcome")

// 4. AVOID - CSS selectors
page.locator(".btn")  // NO
page.locator("#email")  // NO
\\\`\\\`\\\`
      \`.trim();
    }

    if (topic.includes("page") || topic.includes("object")) {
      return \`
## Page Object Pattern

\\\`\\\`\\\`typescript
export class LoginPage extends BasePage {
  readonly emailInput = this.page.getByLabel("Email");
  readonly passwordInput = this.page.getByLabel("Password");
  readonly submitButton = this.page.getByRole("button", { name: "Sign in" });

  async goto() {
    await super.goto("/login");
  }

  async login(email: string, password: string) {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.submitButton.click();
  }
}
\\\`\\\`\\\`
      \`.trim();
    }

    return \`
## Playwright Quick Reference

1. **MCP Workflow**: Navigate → Snapshot → Interact → Document → Write tests
2. **Selectors**: getByRole > getByLabel > getByText > avoid CSS
3. **File Structure**: base-page.ts, helpers.ts, {page}/{page}-page.ts + .spec.ts
4. **Tags**: { tag: ["@critical", "@e2e", "@feature", "@TEST-ID"] }
5. **Reuse**: Check existing page objects before creating new ones

Topics: page-object, selectors, tags, mcp-workflow
    \`.trim();
  },
})
