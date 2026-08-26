### E2E Tests: Registry

**Suite ID:** `REGISTRY-E2E`
**Feature:** Cloud Registry access, onboarding, and tenant artifact management.

**Fixture boundary:** `pnpm run test:e2e:registry` starts a test-only local API fixture and three real Next.js servers. It uses only synthetic fixture identities, token shapes, and Registry key data. It exercises the browser, NextAuth, proxy, server actions, and Registry UI; it does not prove a proprietary Registry deployment. Live controlled-backend acceptance remains a rollout prerequisite.

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

**Expected Result:** Focus and visibility refresh remove navigation; stale browser state cannot open `/registry`.

## Test Case: `REGISTRY-E2E-004` - Write-Only Credential Validation

**Priority:** `critical`
**Tags:** @e2e, @registry

**Expected Result:** Synthetic key validation remains pending for a `202` task, settles through an authoritative status read, and does not disclose the key in the DOM, URL, or browser storage.

## Test Case: `REGISTRY-E2E-005` - Complete Catalog, Recovery, and Lifecycle

**Priority:** `critical`
**Tags:** @e2e, @registry

**Expected Result:** Multi-page fixture catalog search/filter/Multi-provider behavior, card owner rows (logo and initial fallback), documented reconnect/unavailable/generic recovery states, direct card Add of the latest version, and confirmed Remove all use real UI and server-action paths.

## Test Case: `REGISTRY-E2E-006` - Pixel 5 Reduced-Motion Browsing

**Priority:** `high`
**Tags:** @e2e, @registry

**Expected Result:** Pixel 5 browsing honors reduced motion, and the card Add action stays fully keyboard-operable with an authoritative confirmation toast.
