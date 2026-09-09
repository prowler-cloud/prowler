### E2E Tests: Registry

**Suite ID:** `REGISTRY-E2E`
**Feature:** Cloud Registry access, onboarding, and tenant artifact management.

**Fixture boundary:** `pnpm run test:e2e:registry` uses `playwright.registry.config.ts` to start a test-only local API fixture and three real Next.js servers. It uses only synthetic fixture identities, token shapes, and Registry key data. It exercises the browser, NextAuth, proxy, server actions, and Registry UI; it does not prove a proprietary Registry deployment. Live controlled-backend acceptance remains a rollout prerequisite.

---

## Test Case: `REGISTRY-E2E-001` - Fail-Closed Runtime Profiles

**Priority:** `critical`
**Tags:** @e2e, @registry

**Preconditions:** Local and Cloud-with-Registry-flag-off fixture servers.

**Expected Result:** Registry navigation is absent and the direct route redirects safely in both profiles.

## Test Case: `REGISTRY-E2E-002` - Enabled Manager Discovery

**Priority:** `critical`
**Tags:** @e2e, @registry

**Preconditions:** Enabled Cloud fixture server and synthetic manager session.

**Expected Result:** Registry navigation is visible with the established New badge.

## Test Case: `REGISTRY-E2E-003` - Current-Authority Revocation

**Priority:** `critical`
**Tags:** @e2e, @registry

**Preconditions:** The fixture revokes current authority after the browser receives a manager session.

**Expected Result:** The next page request refreshes navigation from current authority; stale browser state cannot open `/registry` or mutate artifacts.

## Test Case: `REGISTRY-E2E-004` - Write-Only Credential Validation

**Priority:** `critical`
**Tags:** @e2e, @registry

**Expected Result:** Synthetic key submission returns a `202` task that the client-side task watcher polls to settlement while the dialog form shows a disabled Connecting… control; the flow settles through an authoritative status read into the connected marketplace with a "Registry connected" toast, and does not disclose the key in the DOM, URL, or browser storage.

## Test Case: `REGISTRY-E2E-005` - Complete Catalog, Recovery, and Lifecycle

**Priority:** `critical`
**Tags:** @e2e, @registry

**Expected Result:** The complete paginated catalog supports search, combined provider and capability filters, URL state, and owner logos with fallback. Built-ins display Built in without Add. Checks/compliance-only artifacts remain visible without Add. An external provider artifact installs through a 202 task and an authoritative membership read before Added appears. Removal preserves provider accounts. Reconnect, unavailable, and generic failures have actionable empty states.

## Test Case: `REGISTRY-E2E-006` - Pixel 5 Reduced-Motion Browsing

**Priority:** `high`
**Tags:** @e2e, @registry

**Expected Result:** Pixel 5 browsing with the reduced-motion preference enabled remains usable, and the card Add action stays fully keyboard-operable with an authoritative confirmation toast.

## Test Case: `REGISTRY-E2E-007` - Registry Provider Onboarding and First Scan

**Priority:** `critical`
**Tags:** @e2e, @registry

**Preconditions:** Private Cloud fixture profile with billing disabled, `manage_registry`, `manage_providers`, and `manage_scans`.

**Expected Result:** Installing the external provider makes Fixture Cloud available with a Registry badge in the existing Add Provider selector. The wizard accepts UID/alias, renders the backend credential schema, saves the synthetic secret, requires explicit connection success, and launches a scan visible in Scans. No credential values are stored in localStorage or sessionStorage. This synthetic acceptance covers the UI/HTTP contract; real Registry and provider credentials are still required for live validation.

After the scan, removing the artifact preserves the account in Providers and removes the dynamic type from the next Add Provider selector.

## Test Case: `REGISTRY-E2E-008` - Installation Across Reload

**Priority:** `critical`
**Tags:** @e2e, @registry

**Expected Result:** A pending installation survives a hard reload. After the controlled task is released, an authoritative membership read updates My artifacts and emits one success notification. The browser submits the installation only once.
