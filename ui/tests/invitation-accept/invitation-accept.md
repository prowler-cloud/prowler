### E2E Tests: Invitation Accept Smart Router

**Suite ID:** `INVITE-ACCEPT-E2E`
**Feature:** `/invitation/accept` smart router that handles invitation links for both
authenticated and unauthenticated users.

---

## Test Case: `INVITE-ACCEPT-E2E-001` - Unauthenticated user sees choice screen and Sign in preserves token

**Priority:** `high`

**Tags:**

- type: @e2e
- feature: @invitation, @invitation-accept

**Description/Objective:** Verify the smart router renders the choice screen for
an unauthenticated user with a valid token, and that clicking "Sign in"
redirects to `/sign-in` with a `callbackUrl` that preserves the invitation token.

**Preconditions:**

- Application is running.
- No active session (cookies cleared).

### Flow Steps:

1. Clear all cookies.
2. Navigate to `/invitation/accept?invitation_token=test-token`.
3. Verify the choice screen is rendered.
4. Click the "I have an account — Sign in" button.
5. Verify the redirect target and `callbackUrl` query param.

### Expected Result:

- Heading "You've Been Invited" is visible.
- Description text "invited to join a tenant" is visible.
- Both "I have an account — Sign in" and "I'm new — Create an account" buttons are visible.
- After clicking "Sign in", URL is `/sign-in?callbackUrl=...`.
- Decoded `callbackUrl` equals `/invitation/accept?invitation_token=test-token`.
- Decoded `callbackUrl` contains `invitation_token=test-token`.

### Key verification points:

- `callbackUrl` preserves the original invitation path with token.

---

## Test Case: `INVITE-ACCEPT-E2E-002` - "Create an account" button redirects to sign-up with invitation token

**Priority:** `high`

**Tags:**

- type: @e2e
- feature: @invitation, @invitation-accept

**Description/Objective:** Verify the "Create an account" button redirects to
`/sign-up` preserving the `invitation_token` query param, and that the sign-up
form actually renders (no redirect loop back to `/invitation/accept`).

**Preconditions:**

- Application is running.
- No active session (cookies cleared).

### Flow Steps:

1. Clear all cookies.
2. Navigate to `/invitation/accept?invitation_token=test-token`.
3. Wait for the "I'm new — Create an account" button to be visible.
4. Click the button.
5. Verify the resulting URL and that the sign-up form is rendered.

### Expected Result:

- URL pathname is `/sign-up`.
- Query param `invitation_token` equals `test-token`.
- Sign-up form is rendered (email input and submit button visible).

### Key verification points:

- No redirect back to `/invitation/accept` (smart router does not loop).

### Notes:

- The legacy `action=signup` param is no longer emitted: the backward-compat
  redirect from `/sign-up?invitation_token=...` to `/invitation/accept` was
  removed, so no action bypass is needed. See also `AUTH-MW-E2E-003` in
  `ui/tests/auth/auth-middleware.spec.ts`, which covers that `/sign-up` with a
  token is no longer rewritten.

---

## Test Case: `INVITE-ACCEPT-E2E-004` - No token shows error screen

**Priority:** `medium`

**Tags:**

- type: @e2e
- feature: @invitation, @invitation-accept

**Description/Objective:** Verify that navigating to `/invitation/accept`
without an `invitation_token` query param shows the no-token error state and
that the "Go to Sign In" link redirects to `/sign-in`.

**Preconditions:**

- Application is running.
- No active session (cookies cleared).

### Flow Steps:

1. Clear all cookies.
2. Navigate to `/invitation/accept` (no query params).
3. Verify the no-token error screen is rendered.
4. Click the "Go to Sign In" link.
5. Verify redirect to `/sign-in`.

### Expected Result:

- Heading "Invalid Invitation Link" is visible.
- Description "No invitation token was provided" is visible.
- "Go to Sign In" link is visible and clickable.
- After click, URL matches `/sign-in`.

### Key verification points:

- Client-side render only: no API calls involved.
