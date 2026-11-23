---
name: prowler-test-ui
description: >
  E2E testing patterns for Prowler UI (Playwright).
  Trigger: When writing Playwright E2E tests under ui/tests in the Prowler UI (Prowler-specific base page/helpers, tags, flows).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, ui]
  auto_invoke:
    - "Writing Prowler UI E2E tests"
    - "Working with Prowler UI test helpers/pages"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

> **Generic Patterns**: For base Playwright patterns (Page Object Model, selectors, helpers), see the `playwright` skill.
> This skill covers **Prowler-specific** conventions only.

## Prowler UI Test Structure

```text
ui/
├── playwright.base.ts            # Shared config (testDir ./tests, expect timeout 20s, CI retries 2)
├── playwright.config.ts          # Main projects + webServer (pnpm dev / pnpm start in CI)
├── playwright.registry.config.ts # Registry suite: own fixture API (:4300) and UI servers
└── tests/
    ├── base-page.ts              # abstract BasePage (shared locators/verifications)
    ├── helpers.ts                # makeSuffix, getSession, addAWSProvider, deleteProviderIfExists, TEST_CREDENTIALS...
    ├── setups/*.auth.setup.ts    # Auth setup projects -> playwright/.auth/*.json storage states
    └── {page-name}/
        ├── {page-name}-page.ts   # Page Object Model
        ├── {page-name}.spec.ts   # Tests (one spec per feature by default)
        └── {page-name}.md        # Test documentation (MANDATORY - sync with spec.ts)
```

## Playwright Projects (`ui/playwright.config.ts`)

| Project | Specs | Depends on |
|---------|-------|-----------|
| `admin.auth.setup` (+ `manage-scans`, `manage-integrations`, `manage-account`, `manage-cloud-providers`, `unlimited-visibility`, `invite-and-manage-users`) | `tests/setups/*.auth.setup.ts` | - |
| `sign-in-base`, `auth`, `invitation-accept`, `runtime-config` | `tests/{name}/*.spec.ts` | - (unauthenticated) |
| `sign-up` | `sign-up.spec.ts` | - |
| `scans`, `providers`, `invitations` | `{name}.spec.ts` | `admin.auth.setup` |
| `navigation` | `tests/navigation/*.spec.ts` (Pixel 5, 390x844) | `admin.auth.setup` |

A new test folder needs a new project entry here (and in the `test:e2e*` scripts in `ui/package.json` if it should run by default).
`pnpm run test:e2e` runs only `auth, sign-up, providers, invitations, scans, runtime-config, navigation`; `sign-in-base` and `invitation-accept` must be run with `--project`.

Authenticated suites reuse storage state instead of logging in:

```typescript
test.use({ storageState: "playwright/.auth/admin_user.json" });
```

Data-dependent flows use `test.describe.serial(...)` and the `@serial` tag; clean up first (e.g. `deleteProviderIfExists`) and `test.skip(!process.env.E2E_..., "...")` when required env vars are missing.
Credentials and provider identifiers come only from `E2E_*` env vars (see `docs/developer-guide/end2end-testing.mdx`).

---

## MANDATORY Checklist (Create or Modify Tests)

**⚠️ ALWAYS verify BEFORE completing any E2E task:**

### When CREATING new tests
- [ ] `{page-name}-page.ts` - Page Object created/updated
- [ ] `{page-name}.spec.ts` - Tests added with correct tags (@TEST-ID)
- [ ] `{page-name}.md` - Documentation created with ALL test cases
- [ ] Test IDs in `.md` match tags in `.spec.ts`

### When MODIFYING existing tests
- [ ] `{page-name}.md` MUST be updated if:
  - Test cases were added/removed
  - Test flow changed (steps)
  - Preconditions or expected results changed
  - Tags or priorities changed
- [ ] Test IDs synchronized between `.md` and `.spec.ts`

### Quick validation
```bash
# Verify .md exists for each test folder
ls ui/tests/{feature}/{feature}.md

# Verify test IDs match
grep -oE "@[A-Z-]+-E2E-[0-9]+" ui/tests/{feature}/*.spec.ts | sed 's/.*@//' | sort -u
grep -oE "\`[A-Z-]+-E2E-[0-9]+\`" ui/tests/{feature}/{feature}.md | tr -d '\`' | sort -u
```

> [!IMPORTANT]
> ❌ An E2E change is NOT considered complete without updating the corresponding `.md` file.

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

## Prowler Base Page (`ui/tests/base-page.ts`)

`BasePage` is `abstract`; extend it and reuse its helpers instead of re-implementing them:

| Member | Purpose |
|--------|---------|
| `title`, `loadingIndicator`, `themeToggle` | Shared locators |
| `goto(url)`, `gotoFresh(url)` (`waitUntil: "commit"`, after clearing cookies), `refresh()`, `goBack()` | Navigation |
| `skipFirstRunRedirect()` | Prevents the empty-tenant redirect to the add-provider wizard |
| `verifyElementVisible/NotVisible/Text/ContainsText`, `verifyPageTitle`, `verifyNoErrors`, `verifyKeyboardNavigation`, `verifyAriaLabels` | Verifications |
| `waitForElement`, `waitForElementToDisappear`, `waitForUrl` | Waits (5s default) |

```typescript
import { Page, expect } from "@playwright/test";
import { BasePage } from "../base-page";

export class FeaturePage extends BasePage {
  readonly heading = this.page.getByRole("heading", { name: "Feature" });

  constructor(page: Page) {
    super(page);
  }

  async goto(): Promise<void> {
    await super.goto("/feature");
  }

  async verifyPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
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

## Existing Page Objects (reuse before creating)

| Page object | File |
|-------------|------|
| `SignInPage` | `tests/sign-in-base/sign-in-base-page.ts` (also `authenticateAndSaveState` used by setups) |
| `SignUpPage` | `tests/sign-up/sign-up-page.ts` |
| `HomePage` | `tests/home/home-page.ts` (`signOut`, `verifyPageLoaded`) |
| `ProvidersPage` | `tests/providers/providers-page.ts` (provider wizard: `clickAddProvider`, `selectAWSProvider`, ...) |
| `ScansPage` | `tests/scans/scans-page.ts` (`selectProviderByUID`, `clickStartNowButton`, `verifyScanLaunched`) |
| `InvitationsPage`, `InvitationAcceptPage`, `NavigationPage`, `UserProfilePage` (`profile/`), `RegistryPage`, `RuntimeConfigPage` | `tests/{folder}/{folder}-page.ts` |

---

## Test Tags for Prowler

```typescript
test("Provider CRUD operations",
  { tag: ["@critical", "@e2e", "@providers", "@aws", "@serial", "@PROVIDER-E2E-001"] },
  async ({ page }) => {
    // ...
  }
);
```

| Category | Tags |
|----------|------|
| Priority | `@critical`, `@high` (also `@medium`, `@low`) |
| Type | `@e2e`, `@serial` (must not run in parallel) |
| Feature | `@providers`, `@scans`, `@invitations`, `@signup`, `@sign-in-base`, `@registry`, ... |
| Provider | `@aws`, `@azure`, `@gcp`, `@kubernetes`, `@github`, `@m365`, `@oci`, `@alibabacloud`, ... |
| Test ID | `@{SUITE}-E2E-{NNN}`: existing suites `PROVIDER`, `SCAN`, `SIGNUP`, `SIGN-IN-BASE`, `INVITATION`, `INVITE-ACCEPT`, `AUTH-MW`, `AUTH-SESSION`, `AUTH-TOKEN`, `NAV`, `REGISTRY`, `RUNTIME-CONFIG` |

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
**Tags:**
- type → @e2e
- feature → @{feature-name}

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
cd ui && pnpm run test:e2e:install                                  # Install Playwright browsers (once)
cd ui && pnpm run test:e2e                                          # Default projects (needs API at UI_API_BASE_URL, default http://localhost:8080/api/v1)
cd ui && pnpm exec playwright test --project=providers              # One project (+ its auth setup dependency)
cd ui && pnpm exec playwright test --project=sign-in-base           # Projects not in the default script
cd ui && pnpm exec playwright test --project=providers --grep "@PROVIDER-E2E-001"
cd ui && pnpm run test:e2e:ui                                       # UI mode
cd ui && pnpm run test:e2e:debug                                    # Debug mode
cd ui && pnpm run test:e2e:headed                                   # See browser
cd ui && pnpm run test:e2e:report                                   # Open last HTML report
cd ui && pnpm run test:e2e:registry                                 # Registry suite (playwright.registry.config.ts, fixture mode)
```

Local env overrides are read from `ui/.env.local` (loaded by `playwright.config.ts`).

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
