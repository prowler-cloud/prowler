### E2E Tests: Authentication System

**Suite ID:** `AUTH-E2E`
**Feature:** Authentication middleware, session management, and token refresh.

---

## Test Case: `AUTH-MW-E2E-001` - Allow access to public routes without session

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @middleware

**Description/Objective:** Verify public routes are accessible without authentication.

**Preconditions:**
- Application is running.
- No active session (cookies cleared).

### Flow Steps:
1. Clear all cookies.
2. Navigate to /sign-in.
3. Verify page loads.
4. Navigate to /sign-up.
5. Verify page loads.

### Expected Result:
- Public routes are accessible without authentication.

---

## Test Case: `AUTH-MW-E2E-002` - Maintain protection after session error

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @middleware

**Description/Objective:** Verify protected routes remain protected after session invalidation.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Log in with valid credentials.
2. Navigate to a protected route.
3. Invalidate session (replace cookie with invalid token).
4. Navigate to another protected route.
5. Verify redirect to sign-in.

### Expected Result:
- Invalid session results in redirect to sign-in.

---

## Test Case: `AUTH-SESSION-E2E-001` - Show RefreshAccessTokenError message

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @session

**Description/Objective:** Verify that RefreshAccessTokenError displays appropriate toast message.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to /sign-in with error=RefreshAccessTokenError query parameter.
2. Check for toast notification.
3. Verify form elements are still visible.

### Expected Result:
- Toast shows "Session Expired" message with "Please sign in again".
- Sign-in form is displayed and functional.

---

## Test Case: `AUTH-SESSION-E2E-002` - Show MissingRefreshToken error message

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @session

**Description/Objective:** Verify that MissingRefreshToken error displays appropriate toast message.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to /sign-in with error=MissingRefreshToken query parameter.
2. Check for toast notification.
3. Verify email input is visible.

### Expected Result:
- Toast shows "Session Error" message.
- Sign-in form is displayed.

---

## Test Case: `AUTH-SESSION-E2E-003` - Show generic error for unknown error types

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @session

**Description/Objective:** Verify that unknown error types display a generic authentication error message.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to /sign-in with error=UnknownError query parameter.
2. Check for toast notification.

### Expected Result:
- Toast shows "Authentication Error" message with "Please sign in again".

---

## Test Case: `AUTH-SESSION-E2E-004` - Include callbackUrl in redirect

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @session

**Description/Objective:** Verify that callbackUrl is preserved when redirecting to sign-in after session expiry.

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Navigate to a protected route (/scans).
3. Clear cookies to simulate session expiry.
4. Navigate to another protected route (/providers).
5. Verify redirect to sign-in includes callbackUrl parameter.

### Expected Result:
- URL contains callbackUrl=/providers parameter.
- User can sign in and be redirected back to the original destination.

---

## Test Case: `AUTH-TOKEN-E2E-001` - Refresh access token when expired

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @token

**Description/Objective:** Verify that session is maintained after page reload (token refresh).

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Verify home page is loaded.
3. Capture initial session data.
4. Reload the page.
5. Verify session is still valid with same user data.

### Expected Result:
- Session persists after reload.
- User email, userId, and tenantId remain the same.

---

## Test Case: `AUTH-TOKEN-E2E-002` - Preserve user permissions after token refresh

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @token

**Description/Objective:** Verify that user permissions are preserved after token refresh.

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Capture initial session with permissions.
3. Reload the page.
4. Verify permissions match initial session.

### Expected Result:
- User permissions are identical before and after refresh.
- User profile data (email, name, companyName) is preserved.

---

## Test Case: `AUTH-TOKEN-E2E-003` - Clear session when cookies are removed

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @auth, @token

**Description/Objective:** Verify that session is cleared when cookies are removed.

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Verify session is valid.
3. Clear all cookies.
4. Check session status.

### Expected Result:
- Session returns null after cookies are cleared.
- User is effectively logged out.
