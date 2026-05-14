---
name: vitest
description: >
  Vitest unit testing patterns with React Testing Library.
  Trigger: When writing unit tests for React components, hooks, or utilities.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Writing Vitest tests"
    - "Writing React component tests"
    - "Writing unit tests for UI"
    - "Testing hooks or utilities"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, Task
---

> **For E2E tests**: Use `prowler-test-ui` skill (Playwright).
> This skill covers **unit/integration tests** with Vitest + React Testing Library.

## Test Structure (REQUIRED)

Use **Given/When/Then** (AAA) pattern with comments:

```typescript
it("should update user name when form is submitted", async () => {
  // Given - Arrange
  const user = userEvent.setup();
  const onSubmit = vi.fn();
  render(<UserForm onSubmit={onSubmit} />);

  // When - Act
  await user.type(screen.getByLabelText(/name/i), "John");
  await user.click(screen.getByRole("button", { name: /submit/i }));

  // Then - Assert
  expect(onSubmit).toHaveBeenCalledWith({ name: "John" });
});
```

---

## Describe Block Organization

```typescript
describe("ComponentName", () => {
  describe("when [condition]", () => {
    it("should [expected behavior]", () => {});
  });
});
```

**Group by behavior, NOT by method.**

---

## Query Priority (REQUIRED)

| Priority | Query | Use Case |
|----------|-------|----------|
| 1 | `getByRole` | Buttons, inputs, headings |
| 2 | `getByLabelText` | Form fields |
| 3 | `getByPlaceholderText` | Inputs without label |
| 4 | `getByText` | Static text |
| 5 | `getByTestId` | Last resort only |

```typescript
// ✅ GOOD
screen.getByRole("button", { name: /submit/i });
screen.getByLabelText(/email/i);

// ❌ BAD
container.querySelector(".btn-primary");
```

---

## userEvent over fireEvent (REQUIRED)

```typescript
// ✅ ALWAYS use userEvent
const user = userEvent.setup();
await user.click(button);
await user.type(input, "hello");

// ❌ NEVER use fireEvent for interactions
fireEvent.click(button);
```

---

## Async Testing Patterns

```typescript
// ✅ findBy for elements that appear async
const element = await screen.findByText(/loaded/i);

// ✅ waitFor for assertions
await waitFor(() => {
  expect(screen.getByText(/success/i)).toBeInTheDocument();
});

// ✅ ONE assertion per waitFor
await waitFor(() => expect(mockFn).toHaveBeenCalled());
await waitFor(() => expect(screen.getByText(/done/i)).toBeVisible());

// ❌ NEVER multiple assertions in waitFor
await waitFor(() => {
  expect(mockFn).toHaveBeenCalled();
  expect(screen.getByText(/done/i)).toBeVisible(); // Slower failures
});
```

---

## Mocking

```typescript
// Basic mock
const handleClick = vi.fn();

// Mock with return value
const fetchUser = vi.fn().mockResolvedValue({ name: "John" });

// Always clean up
afterEach(() => {
  vi.restoreAllMocks();
});
```

### vi.spyOn vs vi.mock

| Method | When to Use |
|--------|-------------|
| `vi.spyOn` | Observe without replacing (PREFERRED) |
| `vi.mock` | Replace entire module (use sparingly) |

---

## Common Matchers

```typescript
// Presence
expect(element).toBeInTheDocument();
expect(element).toBeVisible();

// State
expect(button).toBeDisabled();
expect(input).toHaveValue("text");
expect(checkbox).toBeChecked();

// Content
expect(element).toHaveTextContent(/hello/i);
expect(element).toHaveAttribute("href", "/home");

// Functions
expect(fn).toHaveBeenCalledWith(arg1, arg2);
expect(fn).toHaveBeenCalledTimes(2);
```

---

## What NOT to Test

```typescript
// ❌ Internal state
expect(component.state.isLoading).toBe(true);

// ❌ Third-party libraries
expect(axios.get).toHaveBeenCalled();

// ❌ Static content (unless conditional)
expect(screen.getByText("Welcome")).toBeInTheDocument();

// ✅ User-visible behavior
expect(screen.getByRole("button")).toBeDisabled();
```

---

## File Organization

```
components/
├── Button/
│   ├── Button.tsx
│   ├── Button.test.tsx    # Co-located
│   └── index.ts
```

---

## Commands

```bash
pnpm test                    # Watch mode
pnpm test:run               # Single run
pnpm test:coverage          # With coverage
pnpm test Button            # Filter by name
```
