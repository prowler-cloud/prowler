### E2E Tests: App Navigation

**Suite ID:** `NAV-E2E`
**Feature:** Responsive application sidebar.

---

## Test Case: `NAV-E2E-001` - Mobile sidebar fits viewport

**Priority:** `high`
**Tags:** @e2e, @navigation

**Preconditions:**

- Admin user authentication state exists
- Chromium mobile viewport is 390 x 844 CSS pixels

### Flow Steps

1. Navigate to Overview
2. Open mobile application menu
3. Wait for drawer animation to finish
4. Measure drawer, close control, viewport, and document width

### Expected Result

- Drawer stays inside viewport
- Close control stays visible inside viewport
- Open-menu control is hidden while drawer is open
- Page has no horizontal overflow

### Key Verification Points

- Drawer uses accessible name "App sidebar"
- Drawer and close control edges do not exceed viewport edges
- Body scroll width does not exceed client width

---

## Test Case: `NAV-E2E-002` - Authenticated navigation survives a PostHog outage

**Priority:** `high`
**Tags:** @e2e, @navigation

**Preconditions:**

- Admin user authentication state exists

### Flow Steps

1. Block PostHog network requests
2. Verify Overview loads
3. Open the application sidebar, select Providers, and verify the page still loads

### Expected Result

- A third-party (PostHog) network failure does not block authenticated navigation

### Scope Note

- This test asserts navigation resilience only — NOT the feedback widget. The
  widget is enabled by `NEXT_PUBLIC_POSTHOG_KEY`, which Next.js inlines at build
  time and cannot be injected via the start-time Playwright webServer env, so it
  never renders in E2E. The widget's render, submit, and capture behavior is
  covered by unit tests (`components/survey/feedback-survey.test.tsx`).

---

## Test Case: `NAV-E2E-003` - Public routes omit feedback

**Priority:** `high`
**Tags:** @e2e, @navigation

**Preconditions:**

- Empty browser storage state

### Flow Steps

1. Load Sign in
2. Check for the feedback trigger

### Expected Result

- The public route loads and exposes no feedback trigger

### Scope Note

- Meaningful independent of PostHog: `FeedbackSurvey` is mounted only in the
  authenticated (prowler) layout, so it must never appear on public routes
  regardless of survey/key state.
