### E2E Tests: User Sign-In

**Suite ID:** `SIGN-IN-BASE-E2E`
**Feature:** User sign-in form and navigation.

---

## Test Case: `SIGN-IN-BASE-E2E-001` - Display login form elements

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-002` - Successful login with valid credentials

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @sign-in-base

**Description/Objective:** Verify that a user can successfully log in with valid credentials.

**Preconditions:**
- Application is running.
- Valid test user credentials are configured via `ADMIN_USER` and `ADMIN_PASSWORD` environment variables.

### Flow Steps:
1. Navigate to the Sign in page.
2. Enter valid email and password.
3. Click the login button.
4. Verify successful redirect to home page.

### Expected Result:
- User is authenticated and redirected to the home page.

---

## Test Case: `SIGN-IN-BASE-E2E-003` - Show error with invalid credentials

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-004` - Handle empty form submission

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-005` - Validate email format

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-006` - Require password when email is filled

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-007` - Toggle SAML SSO mode

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-008` - Show loading state during form submission

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-009` - Handle SAML authentication flow

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-010` - Maintain session after browser refresh

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-011` - Redirect to login for protected routes

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-012` - Logout successfully

**Priority:** `critical`

**Tags:**
- type: @e2e, @critical
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-013` - Handle session timeout gracefully

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-014` - Navigate to sign up page

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-015` - Navigate from sign up back to sign in

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-016` - Handle browser back button correctly

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base

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

## Test Case: `SIGN-IN-BASE-E2E-017` - Keyboard navigation

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base, @accessibility

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

## Test Case: `SIGN-IN-BASE-E2E-018` - Proper ARIA labels

**Priority:** `normal`

**Tags:**
- type: @e2e
- feature: @sign-in-base, @accessibility

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
