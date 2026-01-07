import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-test-ui
description: E2E testing patterns for Prowler UI (Playwright).
license: Apache 2.0
---

> **Generic Patterns**: For base Playwright patterns (Page Object Model, selectors, helpers), see the \`playwright\` skill.
> This skill covers **Prowler-specific** conventions only.

## Prowler UI Test Structure

\`\`\`
ui/tests/
├── base-page.ts              # Prowler-specific base page
├── helpers.ts                # Prowler test utilities
└── {page-name}/
    ├── {page-name}-page.ts   # Page Object Model
    ├── {page-name}.spec.ts   # ALL tests (single file per feature)
    └── {page-name}.md        # Test documentation
\`\`\`

## MCP Workflow - CRITICAL

**⚠️ MANDATORY: If Playwright MCP tools are available, ALWAYS use them BEFORE creating tests.**

1. **Navigate** to target page
2. **Take snapshot** to see actual DOM structure
3. **Interact** with forms/elements to verify real flow
4. **Document actual selectors** from snapshots
5. **Only then** write test code

## Prowler Base Page

\`\`\`typescript
import { Page, Locator, expect } from "@playwright/test";

export class BasePage {
  constructor(protected page: Page) {}

  async goto(path: string): Promise<void> {
    await this.page.goto(path);
    await this.page.waitForLoadState("networkidle");
  }

  // Prowler-specific: notification handling
  async waitForNotification(): Promise<Locator> {
    const notification = this.page.locator('[role="status"]');
    await notification.waitFor({ state: "visible" });
    return notification;
  }

  async verifyNotificationMessage(message: string): Promise<void> {
    const notification = await this.waitForNotification();
    await expect(notification).toContainText(message);
  }
}
\`\`\`

## Prowler-Specific Pages

### Providers Page

\`\`\`typescript
export class ProvidersPage extends BasePage {
  readonly addButton = this.page.getByRole("button", { name: "Add Provider" });

  async goto(): Promise<void> {
    await super.goto("/providers");
  }

  async addProvider(type: string, alias: string): Promise<void> {
    await this.addButton.click();
    await this.page.getByLabel("Provider Type").selectOption(type);
    await this.page.getByLabel("Alias").fill(alias);
    await this.page.getByRole("button", { name: "Create" }).click();
  }
}
\`\`\`

## Test Tags for Prowler

| Category | Tags |
|----------|------|
| Priority | @critical, @high, @medium, @low |
| Type | @e2e, @smoke, @regression |
| Feature | @providers, @scans, @findings, @compliance |
| Test ID | @PROV-E2E-001, @SCAN-E2E-002 |

## Commands

\`\`\`bash
cd ui && pnpm run test:e2e                    # All tests
cd ui && pnpm run test:e2e tests/providers/   # Specific folder
cd ui && pnpm run test:e2e --grep "provider"  # By pattern
cd ui && pnpm run test:e2e:ui                 # With UI
cd ui && pnpm run test:e2e:debug              # Debug mode
\`\`\`

## Keywords
prowler ui test, playwright, e2e, page object model, providers, scans, findings
`;

export default tool({
  description: SKILL,
  args: {
    page: tool.schema.string().describe("Page name: sign-up, sign-in, providers, scans, findings"),
    scope: tool.schema.string().optional().describe("Scope: single (one test) or suite (full test suite)"),
  },
  async execute(args) {
    const pageName = args.page.toLowerCase().replace(/\s+/g, "-");
    const pageClass = pageName.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join("");
    const scope = args.scope?.toLowerCase() || "single";
    const isSuite = scope.includes("suite") || scope.includes("full") || scope.includes("comprehensive");

    if (isSuite) {
      return `
E2E Test Suite for "${pageName}" page

## CRITICAL: If Playwright MCP available, explore the app FIRST!
1. Navigate to /${pageName}
2. Take snapshots to see actual elements
3. Interact with forms to verify flow
4. Document real selectors from snapshots
5. THEN write tests

## Files to Create

### 1. ui/tests/${pageName}/${pageName}-page.ts
\`\`\`typescript
import { Page, Locator } from "@playwright/test";
import { BasePage } from "../base-page";

export class ${pageClass}Page extends BasePage {
  readonly submitButton: Locator;

  constructor(page: Page) {
    super(page);
    this.submitButton = page.getByRole("button", { name: "Submit" });
  }

  async goto(): Promise<void> {
    await super.goto("/${pageName}");
  }
}
\`\`\`

### 2. ui/tests/${pageName}/${pageName}.spec.ts
\`\`\`typescript
import { test, expect } from "@playwright/test";
import { ${pageClass}Page } from "./${pageName}-page";

test.describe("${pageClass}", () => {
  test("Happy path",
    { tag: ["@critical", "@e2e", "@${pageName}"] },
    async ({ page }) => {
      const featurePage = new ${pageClass}Page(page);
      await featurePage.goto();
      // Test implementation
    }
  );
});
\`\`\`

## Run Command
cd ui && pnpm run test:e2e tests/${pageName}/${pageName}.spec.ts
      `.trim();
    }

    return `
E2E Single Test for "${pageName}" page

## CRITICAL: If Playwright MCP available, explore the app FIRST!
1. Navigate to /${pageName}
2. Take snapshots, interact with elements
3. Document real selectors
4. THEN write the test

## Add to: ui/tests/${pageName}/${pageName}.spec.ts

\`\`\`typescript
test("Specific test description",
  { tag: ["@critical", "@e2e", "@${pageName}"] },
  async ({ page }) => {
    const featurePage = new ${pageClass}Page(page);
    await featurePage.goto();
    // Implement test
    await expect(page).toHaveURL("/expected");
  }
);
\`\`\`

## Run Command
cd ui && pnpm run test:e2e --grep "Specific test description"
    `.trim();
  },
})
