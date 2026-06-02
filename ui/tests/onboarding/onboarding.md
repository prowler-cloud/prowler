### E2E Tests: Onboarding System

**Suite ID:** `OB-E2E`
**Feature:** Extensible UI onboarding system: the guided add-provider tour, the
cross-route guided sequence after the first provider connects, and per-flow
manual replay from the avatar menu.

> Behavioral assertions only: Welcome modal visibility, checkpoint dialog
> visibility, navigation to each flow route, presence of the `data-tour-id`
> anchors in the DOM, and localStorage markers. Driver.js overlay animation is
> never asserted. Waits use `expect(...).toBeVisible()` and
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

---

## Test Case: `OB-E2E-003` - First-run guided sequence + checkpoint

**Priority:** `critical`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** After the first provider connects, the checkpoint
dialog offers a guided sequence; "Continue the tour" chains through scans,
findings, compliance, and attack paths, advancing only on tour completion.

**Preconditions:**

- Admin user authentication required (`admin.auth.setup`, reused `storageState`)
- All `prowler.tour.*` keys and the `prowler.onboarding.checkpoint` marker cleared
- A connected provider exists (a `false → true` `hasProviders` flip is reachable);
  guarded/skipped when `E2E_AWS_PROVIDER_ACCOUNT_ID` is unset

### Flow Steps

1. Start zero-provider; assert the Welcome modal is visible
2. Connect a provider (real flip via `addAWSProvider`)
3. Assert the checkpoint dialog "Provider connected — keep exploring?" is visible
4. Click "Continue the tour"
5. Assert `/scans` with `data-tour-id="view-first-scan-launch"` present
6. Complete the scans tour; assert `/findings` with `explore-findings-filters`
7. Complete; assert `/compliance` with `view-compliance-frameworks`
8. Complete; assert `/attack-paths` with `attack-paths-intro` present

### Expected Result

- The checkpoint fires once on the real provider-connected flip
- Continuing chains through each flow route in registry order
- Each route exposes its first anchor in the DOM

### Key verification points

- Checkpoint dialog visible after the provider connects
- Sequence visits `/scans → /findings → /compliance → /attack-paths`
- The route-specific anchor is present at each step
- `prowler.onboarding.checkpoint` marker is set after a choice

### Notes

- Maps to spec `onboarding-sequence`: "Checkpoint after first provider connects",
  "Continue starts the sequence", "Next flow starts after navigating to its route"
- Full execution requires the Prowler stack (API + DB + auth env)

---

## Test Case: `OB-E2E-004` - Stop the sequence at any time

**Priority:** `high`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** Closing any tour mid-sequence ends the sequence; no
further flow auto-fires and a reload does not resume it.

**Preconditions:**

- Admin user authentication required (reused `storageState`)
- A connected provider exists; guarded/skipped when `E2E_AWS_PROVIDER_ACCOUNT_ID` is unset
- Tour state and checkpoint marker cleared in `beforeEach`

### Flow Steps

1. Start the guided sequence (continue from the checkpoint)
2. On `/findings`, close the active tour (press Escape)
3. Wait briefly and assert the URL is still `/findings` (no advance to `/compliance`)
4. Reload the page
5. Assert no tour auto-fires (no `.driver-popover` in the DOM)

### Expected Result

- Closing the tour stops the sequence immediately
- No navigation to `/compliance` occurs
- A reload does not resume the sequence

### Key verification points

- URL remains `/findings` after Escape (no auto-advance)
- After reload, zero `.driver-popover` elements exist

### Notes

- Maps to spec `onboarding-sequence`: "Stopping any tour ends the sequence"
- Full execution requires the Prowler stack (API + DB + auth env)

---

## Test Case: `OB-E2E-005` - Manual single-flow replay from the avatar menu

**Priority:** `high`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** The avatar "Product tour" submenu lists every flow;
selecting one replays that single flow only and never chains into the sequence.

**Preconditions:**

- Admin user authentication required (reused `storageState`)
- `completed` records seeded for the flows so the list represents replay state

### Flow Steps

1. Open the avatar account menu
2. Open the "Product tour" submenu
3. Assert all five flow titles are listed (registry order)
4. Select "Explore your findings"
5. Assert navigation to `/findings?onboarding=explore-findings`
6. Assert `data-tour-id="explore-findings-filters"` present
7. Close the tour and assert no navigation to `/compliance` (no sequence chaining)

### Expected Result

- The submenu lists all five flows by title
- Selecting a flow replays it standalone with the `?onboarding=<id>` param
- Closing the replayed tour does not advance to the next flow

### Key verification points

- Submenu contains `Add your first provider`, `Run your first scan`,
  `Explore your findings`, `Check compliance`, `Visualize attack paths`
- URL is `/findings?onboarding=explore-findings`
- No advance to `/compliance` after closing

### Notes

- Maps to spec `onboarding` (MODIFIED): "Avatar entry opens an ordered list of
  flows", "Selecting a flow replays that single flow only"
- Full execution requires the Prowler stack (API + DB + auth env)

---

## Test Case: `OB-E2E-006` - Attack-paths single-fire

**Priority:** `high`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** On `/attack-paths` only one driver popover exists at a
time — the page owns the driver and onboarding never mounts a second runner.

**Preconditions:**

- Admin user authentication required (reused `storageState`)
- A connected provider with at least one ready scan exists; guarded/skipped when
  `E2E_AWS_PROVIDER_ACCOUNT_ID` is unset

### Flow Steps

1. Navigate to `/attack-paths?onboarding=attack-paths`
2. Wait for the attack-paths tour popover to appear
3. Count `.driver-popover` elements in the DOM

### Expected Result

- Exactly one driver popover exists (no double-fire)

### Key verification points

- `.driver-popover` count is exactly `1`

### Notes

- Maps to spec `onboarding-sequence`: "Attack-Paths Single-Fire Integration"
- Full execution requires the Prowler stack (API + DB + auth env)

---

## Test Case: `OB-E2E-007` - Refresh mid-sequence does not re-fire

**Priority:** `high`

**Tags:**

- type → @e2e
- feature → @onboarding

**Description/Objective:** The sequence slice is ephemeral; a hard reload mid-tour
resets it so no tour auto-fires, and no Welcome modal appears (provider connected).

**Preconditions:**

- Admin user authentication required (reused `storageState`)
- A connected provider exists; guarded/skipped when `E2E_AWS_PROVIDER_ACCOUNT_ID` is unset
- Tour state and checkpoint marker cleared in `beforeEach`

### Flow Steps

1. Start the guided sequence and land on `/scans`
2. Hard-reload the page
3. Assert no `.driver-popover` auto-fires
4. Assert the Welcome modal is not visible

### Expected Result

- No tour auto-fires after the reload (ephemeral slice reset)
- No Welcome modal (the provider is connected, so the gate stays closed)

### Key verification points

- Zero `.driver-popover` elements after reload
- Welcome modal is not visible

### Notes

- Maps to spec `onboarding-sequence`: "Refresh mid-sequence does not re-fire
  infinitely"
- Full execution requires the Prowler stack (API + DB + auth env)
