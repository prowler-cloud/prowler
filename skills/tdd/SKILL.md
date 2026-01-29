---
name: tdd
description: >
  Test-Driven Development workflow for UI development.
  Trigger: ALWAYS when working on UI tasks - new features, bug fixes, refactoring.
  This is a MANDATORY workflow, not optional.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [ui]
  auto_invoke:
    - "Implementing UI feature"
    - "Fixing UI bug"
    - "Refactoring UI code"
    - "Working on UI task"
    - "Modifying UI component"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, Task
---

## TDD Cycle (MANDATORY)

```
┌─────────────────────────────────────────┐
│  🔴 RED → 🟢 GREEN → ♻️ REFACTOR        │
│     ↑                        ↓          │
│     └────────────────────────┘          │
└─────────────────────────────────────────┘
```

**The question is NOT "should I write tests?" but "what tests do I need?"**

---

## The Three Laws of TDD

1. **No production code** until you have a failing test
2. **No more test** than necessary to fail
3. **No more code** than necessary to pass

---

## Phase 0: Assessment (ALWAYS FIRST)

Before writing ANY code:

```bash
# 1. Find existing tests
fd "*.test.tsx" components/feature/

# 2. Check coverage
pnpm test:coverage -- components/feature/

# 3. Read existing tests
```

### Decision Tree

```
┌──────────────────────────────────────────┐
│     Does test file exist for this code?  │
└──────────┬───────────────────────┬───────┘
           │ NO                    │ YES
           ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│ CREATE test file │    │ Check coverage   │
│ → Phase 1: RED   │    │ for your change  │
└──────────────────┘    └────────┬─────────┘
                                 │
                        ┌────────┴────────┐
                        │ Missing cases?  │
                        └───┬─────────┬───┘
                            │ YES     │ NO
                            ▼         ▼
                    ┌───────────┐ ┌───────────┐
                    │ ADD tests │ │ Proceed   │
                    │ Phase 1   │ │ Phase 2   │
                    └───────────┘ └───────────┘
```

---

## Phase 1: 🔴 RED - Write Failing Tests

### For NEW Functionality

```typescript
describe("PriceCalculator", () => {
  it("should return 0 for quantities below threshold", () => {
    // Given
    const quantity = 3;

    // When
    const result = calculateDiscount(quantity);

    // Then
    expect(result).toBe(0);
  });
});
```

**Run → MUST fail:** `ReferenceError: calculateDiscount is not defined`

### For BUG FIXES

```typescript
it("should not crash when date is null", () => {
  // Given - The buggy scenario
  const nullDate = null;

  // When/Then - Should not throw
  expect(() => render(<DatePicker value={nullDate} />)).not.toThrow();
});
```

**Run → Should FAIL (reproducing the bug)**

### For REFACTORING

```typescript
// Capture ALL current behavior BEFORE refactoring
describe("UserCard (before refactor)", () => {
  it("should display user name", () => {});
  it("should show avatar when provided", () => {});
  it("should handle missing avatar", () => {});
});
```

**Run → All should PASS (baseline)**

---

## Phase 2: 🟢 GREEN - Minimum Code

### Fake It Pattern (First Test)

```typescript
// 🔴 Test
it("should calculate 10% discount", () => {
  expect(calculateDiscount(100, 10)).toBe(10);
});

// 🟢 FAKE IT - Hardcoded is VALID
function calculateDiscount() {
  return 10; // Intentionally hardcoded
}
```

**This passes. But we're not done...**

---

## Phase 3: Triangulation (CRITICAL)

**One test allows faking. Multiple tests FORCE real logic.**

```typescript
// Test 1: Already passes with fake
it("should calculate 10% discount", () => {
  expect(calculateDiscount(100, 10)).toBe(10);
});

// Test 2: ADD - Different input (breaks fake)
it("should calculate 15% on 200", () => {
  expect(calculateDiscount(200, 15)).toBe(30);
});

// Test 3: ADD - Edge case
it("should return 0 for 0% rate", () => {
  expect(calculateDiscount(100, 0)).toBe(0);
});
```

**Now fake BREAKS → Real implementation required:**

```typescript
function calculateDiscount(amount: number, percent: number): number {
  return amount * (percent / 100);
}
```

### Triangulation Checklist

| Scenario | Required? |
|----------|-----------|
| Happy path | ✅ Yes |
| Zero/empty values | ✅ Yes |
| Boundary values | ✅ Yes |
| Different valid inputs | ✅ Yes (breaks fake) |
| Error conditions | ✅ Yes |

---

## Phase 4: ♻️ REFACTOR

Tests GREEN → Improve code quality

```typescript
// Before
function calculateDiscount(amount, percent) {
  return amount * (percent / 100);
}

// After - Types, validation
function calculateDiscount({ amount, percentOff }: DiscountParams): number {
  if (amount < 0) throw new Error("Amount cannot be negative");
  return amount * (percentOff / 100);
}
```

**Run tests after EACH change → Must stay GREEN**

---

## Quick Reference

```
┌────────────────────────────────────────────────┐
│                 TDD WORKFLOW                   │
├────────────────────────────────────────────────┤
│ 0. ASSESS: What tests exist? What's missing?   │
│                                                │
│ 1. RED: Write ONE failing test                 │
│    └─ Run → Must fail with clear error         │
│                                                │
│ 2. GREEN: Write MINIMUM code to pass           │
│    └─ Fake It is valid for first test          │
│                                                │
│ 3. TRIANGULATE: Add tests that break the fake  │
│    └─ Different inputs, edge cases             │
│                                                │
│ 4. REFACTOR: Improve with confidence           │
│    └─ Tests stay green throughout              │
│                                                │
│ 5. REPEAT: Next behavior/requirement           │
└────────────────────────────────────────────────┘
```

---

## Anti-Patterns (NEVER DO)

```typescript
// ❌ Code first, tests after
function newFeature() { /* impl */ }
// Then writing tests = USELESS

// ❌ Skip triangulation
it("works", () => {}); // Single test allows faking

// ❌ Test implementation details
expect(component.state.isLoading).toBe(true);

// ❌ All tests at once before any code
describe("Feature", () => {
  it("case 1"); it("case 2"); it("case 3"); // All stubs
});
```

---

## Commands

```bash
pnpm test                           # Watch mode
pnpm test:run                       # Single run
pnpm test:coverage                  # Coverage report
pnpm test ComponentName             # Filter
```
