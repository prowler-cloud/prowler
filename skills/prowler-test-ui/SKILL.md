---
name: prowler-test-ui
description: >
  E2E testing patterns for Prowler UI (Playwright).
  Trigger: When writing Playwright E2E tests under ui/tests in the Prowler UI (Prowler-specific base page/helpers, tags, flows).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Writing Prowler UI E2E tests"
    - "Working with Prowler UI test helpers/pages"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
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
    └── {page-name}.md        # Test documentation (MANDATORY - sync with spec.ts)
```

---

## MANDATORY Checklist (Create or Modify Tests)

**⚠️ ALWAYS verify BEFORE completing any E2E task:**

### When CREATING new tests:
- [ ] `{page-name}-page.ts` - Page Object created/updated
- [ ] `{page-name}.spec.ts` - Tests added with correct tags (@TEST-ID)
- [ ] `{page-name}.md` - Documentation created with ALL test cases
- [ ] Test IDs in `.md` match tags in `.spec.ts`

### When MODIFYING existing tests:
- [ ] `{page-name}.md` MUST be updated if:
  - Test cases were added/removed
  - Test flow changed (steps)
  - Preconditions or expected results changed
  - Tags or priorities changed
- [ ] Test IDs synchronized between `.md` and `.spec.ts`

### Quick validation:
```bash
# Verify .md exists for each test folder
ls ui/tests/{feature}/{feature}.md

# Verify test IDs match
grep -o "@[A-Z]*-E2E-[0-9]*" ui/tests/{feature}/{feature}.spec.ts | sort -u
grep -o "\`[A-Z]*-E2E-[0-9]*\`" ui/tests/{feature}/{feature}.md | sort -u
```

**❌ An E2E change is NOT considered complete without updating the corresponding .md file**

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

## Wait Strategies (CRITICAL)

**⚠️ NEVER use `networkidle` - it causes flaky tests!**

| Strategy | Use Case |
|----------|----------|
| ❌ `networkidle` | NEVER - flaky with polling/WebSockets |
| ⚠️ `load` | Only when absolutely necessary |
| ✅ `expect(element).toBeVisible()` | PREFERRED - wait for specific UI state |
| ✅ `page.waitForURL()` | Wait for navigation |
| ✅ `pageObject.verifyPageLoaded()` | BEST - encapsulated verification |

**GOOD:**
```typescript
await homePage.verifyPageLoaded();
await expect(page).toHaveURL("/dashboard");
await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
```

**BAD:**
```typescript
await page.waitForLoadState("networkidle"); // ❌ FLAKY
await page.waitForTimeout(2000);            // ❌ ARBITRARY WAIT
```

---

## Prowler Base Page

```typescript
import { Page, Locator, expect } from "@playwright/test";

export class BasePage {
  constructor(protected page: Page) {}

  async goto(path: string): Promise<void> {
    await this.page.goto(path);
    // Child classes should override verifyPageLoaded() to wait for specific elements
  }

  // Override in child classes to wait for page-specific elements
  async verifyPageLoaded(): Promise<void> {
    await expect(this.page.locator("main")).toBeVisible();
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

## Page Navigation Verification Pattern

**⚠️ URL assertions belong in Page Objects, NOT in tests!**

When verifying redirects or page navigation, create dedicated methods in the target Page Object:

```typescript
// ✅ GOOD - In SignInPage
async verifyOnSignInPage(): Promise<void> {
  await expect(this.page).toHaveURL(/\/sign-in/);
  await expect(this.pageTitle).toBeVisible();
}

// ✅ GOOD - In test
await homePage.goto();  // Try to access protected route
await signInPage.verifyOnSignInPage();  // Verify redirect

// ❌ BAD - Direct assertions in test
await homePage.goto();
await expect(page).toHaveURL(/\/sign-in/);  // Should be in Page Object
await expect(page.getByText("Sign in")).toBeVisible();
```

**Naming convention:** `verifyOn{PageName}Page()` for redirect verification methods.

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

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
