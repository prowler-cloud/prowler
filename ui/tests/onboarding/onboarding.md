### E2E Tests: Onboarding System

**Suite ID:** `OB-E2E`
**Feature:** Extensible UI onboarding system with the guided add-provider tour.

> Behavioral assertions only: Welcome modal visibility, navigation to the flow
> route, and presence of the `data-tour-id` anchors in the DOM. Driver.js overlay
> animation is never asserted. Waits use `expect(...).toBeVisible()` and
> `page.waitForURL()` — never `networkidle`.

---

## Test Case: `OB-E2E-001` - Mandatory new-user onboarding path

**Priority:** `critical`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** A zero-provider authenticated user is forced into the
Welcome modal on first load; accepting it navigates to the add-provider flow and
exposes the tour trigger anchor.

**Preconditions:**

- Admin user authentication required (`admin.auth.setup`, reused `storageState`)
- All `prowler.tour.*` localStorage keys cleared before the test
- The account has zero providers (existing providers removed via `deleteProviderIfExists`)

### Flow Steps

1. Navigate to a page inside `app/(prowler)/`
2. Assert the Welcome modal is visible
3. Click "Get started"
4. Assert navigation to `/providers` (the `?onboarding=add-provider` param is consumed)
5. Assert the `data-tour-id="add-provider-trigger"` anchor is present in the DOM

### Expected Result

- Welcome modal is displayed for the zero-provider user
- Accepting navigates to the providers route
- The add-provider trigger anchor is mounted on the providers page

### Key verification points

- Welcome modal visible on first authenticated load (gate forced it)
- After accept, the URL is `/providers`
- `[data-tour-id="add-provider-trigger"]` exists in the DOM

### Notes

- Maps to spec: "Zero-provider user on first authenticated load", "User accepts
  the Welcome modal", "Every tour step target has a matching data-tour-id anchor"
- Full execution requires the Prowler stack (API + DB + auth env). The trigger
  anchor proves the tour surface is reachable without asserting overlay animation

---

## Test Case: `OB-E2E-002` - Restart onboarding from the avatar menu

**Priority:** `high`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** A user who already completed the tour can restart it
from the avatar menu; the tour starts again despite the existing completion
record.

**Preconditions:**

- Admin user authentication required (`admin.auth.setup`, reused `storageState`)
- A `completed` record exists in localStorage for `add-provider`
  (`prowler.tour.add-provider.v1`)

### Flow Steps

1. Navigate to a page with the user nav visible
2. Open the avatar account menu
3. Click "Product tour"
4. Assert navigation to `/providers?onboarding=add-provider`
5. Assert the `data-tour-id="add-provider-trigger"` anchor is present in the DOM

### Expected Result

- The restart entry navigates to the add-provider flow route with the onboarding param
- The tour starts despite the existing completion record (no Welcome modal)
- The add-provider trigger anchor is mounted on the providers page

### Key verification points

- "Product tour" entry is present in the avatar menu
- After selecting it, the URL is `/providers?onboarding=add-provider`
- `[data-tour-id="add-provider-trigger"]` exists in the DOM (re-trigger bypassed the completion record)

### Notes

- Maps to spec: "User activates the restart entry point from the avatar menu",
  "Re-trigger works after a full page reload", "Re-trigger does not depend on
  prior browser state"
- Full execution requires the Prowler stack (API + DB + auth env)
