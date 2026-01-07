---
name: prowler-test-ui
description: >
  E2E testing patterns for Prowler UI (Playwright).
  Trigger: When writing E2E tests for the Next.js frontend.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

> **Generic Patterns**: For base Playwright patterns (Page Object Model, selectors, helpers), see the `playwright` skill.
> This skill covers **Prowler-specific** conventions only.

## Prowler UI Test Structure

```
ui/tests/
├── base-page.ts              # Prowler-specific base page
├── helpers.ts                # Prowler test utilities
└── {page-name}/
    ├── {page-name}-page.ts   # Page Object Model
    ├── {page-name}.spec.ts   # ALL tests (single file per feature)
    └── {page-name}.md        # Test documentation
```

---

## MCP Workflow - CRITICAL

**⚠️ MANDATORY: If Playwright MCP tools are available, ALWAYS use them BEFORE creating tests.**

1. **Navigate** to target page
2. **Take snapshot** to see actual DOM structure
3. **Interact** with forms/elements to verify real flow
4. **Document actual selectors** from snapshots
5. **Only then** write test code

**Why**: Prevents tests based on assumptions. Real exploration = stable tests.

---

## Prowler Base Page

```typescript
import { Page, Locator, expect } from "@playwright/test";

export class BasePage {
  constructor(protected page: Page) {}

  async goto(path: string): Promise<void> {
    await this.page.goto(path);
    await this.page.waitForLoadState("networkidle");
  }

  async waitForPageLoad(): Promise<void> {
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
```

---

## Prowler-Specific Pages

### Providers Page

```typescript
import { BasePage } from "../base-page";

export class ProvidersPage extends BasePage {
  readonly addButton = this.page.getByRole("button", { name: "Add Provider" });
  readonly providerTable = this.page.getByRole("table");

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
```

### Scans Page

```typescript
export class ScansPage extends BasePage {
  readonly newScanButton = this.page.getByRole("button", { name: "New Scan" });
  readonly scanTable = this.page.getByRole("table");

  async goto(): Promise<void> {
    await super.goto("/scans");
  }

  async startScan(providerAlias: string): Promise<void> {
    await this.newScanButton.click();
    await this.page.getByRole("combobox", { name: "Provider" }).click();
    await this.page.getByRole("option", { name: providerAlias }).click();
    await this.page.getByRole("button", { name: "Start Scan" }).click();
  }
}
```

---

## Test Tags for Prowler

```typescript
test("Provider CRUD operations",
  { tag: ["@critical", "@e2e", "@providers", "@PROV-E2E-001"] },
  async ({ page }) => {
    // ...
  }
);
```

| Category | Tags |
|----------|------|
| Priority | `@critical`, `@high`, `@medium`, `@low` |
| Type | `@e2e`, `@smoke`, `@regression` |
| Feature | `@providers`, `@scans`, `@findings`, `@compliance`, `@signin`, `@signup` |
| Test ID | `@PROV-E2E-001`, `@SCAN-E2E-002` |

---

## Prowler Test Documentation Template

**Keep under 60 lines. Focus on flow, preconditions, expected results only.**

```markdown
### E2E Tests: {Feature Name}

**Suite ID:** `{SUITE-ID}`
**Feature:** {Feature description}

---

## Test Case: `{TEST-ID}` - {Test case title}

**Priority:** `{critical|high|medium|low}`
**Tags:** @e2e, @{feature-name}

**Preconditions:**
- {Prerequisites}

### Flow Steps:
1. {Step}
2. {Step}

### Expected Result:
- {Outcome}

### Key Verification Points:
- {Assertion}
```

---

## Commands

```bash
cd ui && pnpm run test:e2e                              # All tests
cd ui && pnpm run test:e2e tests/providers/             # Specific folder
cd ui && pnpm run test:e2e --grep "provider"            # By pattern
cd ui && pnpm run test:e2e:ui                           # With UI
cd ui && pnpm run test:e2e:debug                        # Debug mode
cd ui && pnpm run test:e2e:headed                       # See browser
cd ui && pnpm run test:e2e:report                       # Generate report
```

## Keywords
prowler ui test, playwright, e2e, page object model, providers, scans, findings
