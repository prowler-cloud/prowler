### E2E Tests: User Sign-In

**Suite ID:** `SIGNIN-E2E`
**Feature:** User authentication and session management.

---

## Test Case: `SIGNIN-E2E-001` - Display login form elements

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify that all login form elements are displayed correctly.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Verify page is loaded.
3. Verify form elements (email, password, login button).
4. Verify social buttons (Google, GitHub).
5. Verify navigation links.

### Expected Result:
- All form elements are visible and properly labeled.

---

## Test Case: `SIGNIN-E2E-002` - Successful login with valid credentials

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @signin

**Description/Objective:** Verify that a user can successfully log in with valid credentials.

**Preconditions:**
- Application is running.
- Valid test user credentials are configured via `E2E_USER` and `E2E_PASSWORD` environment variables.

### Flow Steps:
1. Navigate to the Sign in page.
2. Enter valid email and password.
3. Click the login button.
4. Verify successful redirect to home page.

### Expected Result:
- User is authenticated and redirected to the home page.

---

## Test Case: `SIGNIN-E2E-003` - Show error with invalid credentials

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify that an error message is shown when invalid credentials are provided.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Enter invalid email and password.
3. Click the login button.
4. Verify error message is displayed.

### Expected Result:
- Error message "Invalid email or password" is displayed.
- User remains on the sign-in page.

---

## Test Case: `SIGNIN-E2E-004` - Handle empty form submission

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify form validation when submitting an empty form.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Click the login button without filling any fields.
3. Verify validation errors are displayed.

### Expected Result:
- Form validation errors are shown.
- User remains on the sign-in page.

---

## Test Case: `SIGNIN-E2E-005` - Validate email format

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify that invalid email formats are rejected.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Enter an invalid email format.
3. Submit the form.
4. Verify validation error is displayed.

### Expected Result:
- Email format validation error is shown.

---

## Test Case: `SIGNIN-E2E-006` - Require password when email is filled

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify that password is required when email is provided.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Fill only the email field.
3. Submit the form.
4. Verify password required error is displayed.

### Expected Result:
- "Password is required" error is shown.

---

## Test Case: `SIGNIN-E2E-007` - Toggle SAML SSO mode

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify SAML SSO mode can be toggled on and off.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Click "Continue with SAML SSO" button.
3. Verify SAML mode is active (password field hidden).
4. Click back button.
5. Verify normal mode is restored.

### Expected Result:
- SAML mode toggles correctly.
- Password field visibility changes accordingly.

---

## Test Case: `SIGNIN-E2E-008` - Show loading state during form submission

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify loading state is shown during form submission.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Fill valid credentials.
3. Submit the form.
4. Verify loading state on button.

### Expected Result:
- Login button shows loading state (disabled with aria-disabled).

---

## Test Case: `SIGNIN-E2E-009` - Handle SAML authentication flow

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify SAML authentication flow initiation.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Toggle SAML mode.
3. Enter SAML email.
4. Submit the form.

### Expected Result:
- SAML flow is initiated (would redirect to IdP in real scenario).

---

## Test Case: `SIGNIN-E2E-010` - Maintain session after browser refresh

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @signin

**Description/Objective:** Verify that user session persists after page refresh.

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Verify successful login.
3. Refresh the page.
4. Verify user is still logged in.

### Expected Result:
- Session persists after refresh.
- User remains on the authenticated page.

---

## Test Case: `SIGNIN-E2E-011` - Redirect to login for protected routes

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify unauthenticated users are redirected to login when accessing protected routes.

**Preconditions:**
- Application is running.
- No active session.

### Flow Steps:
1. Navigate directly to a protected route (e.g., /providers).
2. Verify redirect to sign-in page.

### Expected Result:
- User is redirected to /sign-in.

---

## Test Case: `SIGNIN-E2E-012` - Logout successfully

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @signin

**Description/Objective:** Verify user can log out successfully.

**Preconditions:**
- Application is running.
- User is logged in.

### Flow Steps:
1. Log in with valid credentials.
2. Click logout/sign out.
3. Verify redirect to sign-in page.
4. Attempt to access protected route.
5. Verify redirect to sign-in.

### Expected Result:
- User is logged out.
- Session is invalidated.
- Protected routes are no longer accessible.

---

## Test Case: `SIGNIN-E2E-013` - Handle session timeout gracefully

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify session isolation between browser contexts.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Create authenticated context and log in.
2. Verify session exists.
3. Create new unauthenticated context.
4. Verify new context has no session.
5. Verify new context is redirected to sign-in.

### Expected Result:
- Sessions are isolated between contexts.
- Unauthenticated context cannot access protected routes.

---

## Test Case: `SIGNIN-E2E-014` - Navigate to sign up page

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify navigation from sign-in to sign-up page.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Click the "Sign up" link.
3. Verify redirect to sign-up page.

### Expected Result:
- User is navigated to /sign-up.

---

## Test Case: `SIGNIN-E2E-015` - Navigate from sign up back to sign in

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify navigation from sign-up back to sign-in page.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign up page.
2. Click the login link.
3. Verify redirect to sign-in page.

### Expected Result:
- User is navigated to /sign-in.

---

## Test Case: `SIGNIN-E2E-016` - Handle browser back button correctly

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin

**Description/Objective:** Verify browser back button navigation works correctly.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Navigate to the Sign up page.
3. Click browser back button.
4. Verify return to sign-in page.

### Expected Result:
- Browser history navigation works correctly.

---

## Test Case: `SIGNIN-E2E-017` - Keyboard navigation

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @accessibility

**Description/Objective:** Verify form is navigable with keyboard.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Use Tab key to navigate through form elements.
3. Verify focus moves correctly through elements.

### Expected Result:
- All interactive elements are reachable via keyboard.
- Focus order is logical.

---

## Test Case: `SIGNIN-E2E-018` - Proper ARIA labels

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @accessibility

**Description/Objective:** Verify form elements have proper ARIA labels.

**Preconditions:**
- Application is running.

### Flow Steps:
1. Navigate to the Sign in page.
2. Verify ARIA labels on form elements.

### Expected Result:
- Email input has proper label.
- Password input has proper label.
- Login button has proper label.

---

## Test Case: `AUTH-MW-E2E-001` - Allow access to public routes without session

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @middleware

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
- feature: @signin, @middleware

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

## Test Case: `AUTH-MW-E2E-003` - Handle permission-based redirects

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @middleware

**Description/Objective:** Verify routes requiring specific permissions redirect appropriately.

**Preconditions:**
- Application is running.
- Test user may not have all permissions.

### Flow Steps:
1. Log in with valid credentials.
2. Check user permissions from session.
3. If user lacks billing permission, navigate to /billing.
4. Verify redirect to /profile.
5. If user lacks integrations permission, navigate to /integrations.
6. Verify redirect to /profile.

### Expected Result:
- Users without required permissions are redirected to /profile.

---

## Test Case: `AUTH-SESSION-E2E-001` - Show RefreshAccessTokenError message

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @session

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
- feature: @signin, @session

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
- feature: @signin, @session

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
- feature: @signin, @session

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
- feature: @signin, @token

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

## Test Case: `AUTH-TOKEN-E2E-002` - Handle concurrent requests with token refresh

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @token

**Description/Objective:** Verify that concurrent session requests are handled correctly.

**Preconditions:**
- Application is running.
- Valid test user credentials.

### Flow Steps:
1. Log in with valid credentials.
2. Fire 5 concurrent requests to /api/auth/session.
3. Verify all responses are successful.

### Expected Result:
- All concurrent requests return valid session data.
- No session errors occur.
- accessToken and refreshToken are present in all responses.

---

## Test Case: `AUTH-TOKEN-E2E-003` - Preserve user permissions after token refresh

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @token

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

## Test Case: `AUTH-TOKEN-E2E-004` - Clear session when cookies are removed

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @signin, @token

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
