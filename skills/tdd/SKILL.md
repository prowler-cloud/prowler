---
name: tdd
description: >
  Test-Driven Development workflow for ALL Prowler components (UI, SDK, API).
  Trigger: ALWAYS when implementing features, fixing bugs, or refactoring - regardless of component.
  This is a MANDATORY workflow, not optional.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, ui, api, prowler]
  auto_invoke:
    - "Implementing feature"
    - "Fixing bug"
    - "Refactoring code"
    - "Working on task"
    - "Modifying component"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, Task
---

## TDD Cycle (MANDATORY)

```
+-----------------------------------------+
|  RED -> GREEN -> REFACTOR               |
|     ^                        |          |
|     +------------------------+          |
+-----------------------------------------+
```

**The question is NOT "should I write tests?" but "what tests do I need?"**

---

## The Three Laws of TDD

1. **No production code** until you have a failing test
2. **No more test** than necessary to fail
3. **No more code** than necessary to pass

---

## Detect Your Stack

Before starting, identify which component you're working on:

| Working in | Stack | Runner | Test pattern | Details |
|------------|-------|--------|-------------|---------|
| `ui/` | TypeScript / React | Vitest + RTL | `*.test.{ts,tsx}` (co-located) | See `vitest` skill |
| `prowler/` | Python | pytest + moto | `*_test.py` (suffix) in `tests/` | See `prowler-test-sdk` skill |
| `api/` | Python / Django | pytest + django | `test_*.py` (prefix) in `api/src/backend/**/tests/` | See `prowler-test-api` skill |

---

## Phase 0: Assessment (ALWAYS FIRST)

Before writing ANY code:

### UI (`ui/`)

```bash
# 1. Find existing tests
fd "*.test.tsx" ui/components/feature/

# 2. Check coverage
pnpm test:coverage -- components/feature/

# 3. Read existing tests
```

### SDK (`prowler/`)

```bash
# 1. Find existing tests
fd "*_test.py" tests/providers/aws/services/ec2/

# 2. Run specific test
poetry run pytest tests/providers/aws/services/ec2/ec2_ami_public/ -v

# 3. Read existing tests
```

### API (`api/`)

```bash
# 1. Find existing tests
fd "test_*.py" api/src/backend/api/tests/

# 2. Run specific test
poetry run pytest api/src/backend/api/tests/test_models.py -v

# 3. Read existing tests
```

### Decision Tree (All Stacks)

```
+------------------------------------------+
|     Does test file exist for this code?  |
+----------+-----------------------+-------+
           | NO                    | YES
           v                       v
+------------------+    +------------------+
| CREATE test file |    | Check coverage   |
| -> Phase 1: RED  |    | for your change  |
+------------------+    +--------+---------+
                                 |
                        +--------+--------+
                        | Missing cases?  |
                        +---+---------+---+
                            | YES     | NO
                            v         v
                    +-----------+ +-----------+
                    | ADD tests | | Proceed   |
                    | Phase 1   | | Phase 2   |
                    +-----------+ +-----------+
```

---

## Phase 1: RED - Write Failing Tests

### For NEW Functionality

**UI (Vitest)**

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

**SDK (pytest)**

```python
class Test_ec2_ami_public:
    @mock_aws
    def test_no_public_amis(self):
        # Given - No AMIs exist
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch("prowler...ec2_service", new=EC2(aws_provider)):
            from prowler...ec2_ami_public import ec2_ami_public

            # When
            check = ec2_ami_public()
            result = check.execute()

            # Then
            assert len(result) == 0
```

**API (pytest-django)**

```python
@pytest.mark.django_db
class TestResourceModel:
    def test_create_resource_with_tags(self, providers_fixture):
        # Given
        provider, *_ = providers_fixture
        tenant_id = provider.tenant_id

        # When
        resource = Resource.objects.create(
            tenant_id=tenant_id, provider=provider,
            uid="arn:aws:ec2:us-east-1:123456789:instance/i-1234",
            name="test", region="us-east-1", service="ec2", type="instance",
        )

        # Then
        assert resource.uid == "arn:aws:ec2:us-east-1:123456789:instance/i-1234"
```

**Run -> MUST fail:** Test references code that doesn't exist yet.

### For BUG FIXES

Write a test that **reproduces the bug** first:

**UI:** `expect(() => render(<DatePicker value={null} />)).not.toThrow();`

**SDK:** `assert result[0].status == "FAIL"  # Currently returns PASS incorrectly`

**API:** `assert response.status_code == 403  # Currently returns 200`

**Run -> Should FAIL (reproducing the bug)**

### For REFACTORING

Capture ALL current behavior BEFORE refactoring:

```
# Any stack: run ALL existing tests, they should PASS
# This is your safety net - if any fail after refactoring, you broke something
```

**Run -> All should PASS (baseline)**

---

## Phase 2: GREEN - Minimum Code

Write the MINIMUM code to make the test pass. Hardcoding is valid for the first test.

**UI:**

```typescript
// Test expects calculateDiscount(100, 10) === 10
function calculateDiscount() {
  return 10; // FAKE IT - hardcoded is valid for first test
}
```

**Python (SDK/API):**

```python
# Test expects check.execute() returns 0 results
def execute(self):
    return []  # FAKE IT - hardcoded is valid for first test
```

**This passes. But we're not done...**

---

## Phase 3: Triangulation (CRITICAL)

**One test allows faking. Multiple tests FORCE real logic.**

Add tests with different inputs that break the hardcoded value:

| Scenario | Required? |
|----------|-----------|
| Happy path | YES |
| Zero/empty values | YES |
| Boundary values | YES |
| Different valid inputs | YES (breaks fake) |
| Error conditions | YES |

**UI:**

```typescript
it("should calculate 10% discount", () => {
  expect(calculateDiscount(100, 10)).toBe(10);
});

// ADD - breaks the fake:
it("should calculate 15% on 200", () => {
  expect(calculateDiscount(200, 15)).toBe(30);
});

it("should return 0 for 0% rate", () => {
  expect(calculateDiscount(100, 0)).toBe(0);
});
```

**Python:**

```python
def test_single_public_ami(self):
    # Different input -> breaks hardcoded empty list
    assert len(result) == 1
    assert result[0].status == "FAIL"

def test_private_ami(self):
    assert result[0].status == "PASS"
```

**Now fake BREAKS -> Real implementation required.**

---

## Phase 4: REFACTOR

Tests GREEN -> Improve code quality WITHOUT changing behavior.

- Extract functions/methods
- Improve naming
- Add types/validation
- Reduce duplication

**Run tests after EACH change -> Must stay GREEN**

---

## Quick Reference

```
+------------------------------------------------+
|                 TDD WORKFLOW                    |
+------------------------------------------------+
| 0. ASSESS: What tests exist? What's missing?   |
|                                                |
| 1. RED: Write ONE failing test                 |
|    +-- Run -> Must fail with clear error       |
|                                                |
| 2. GREEN: Write MINIMUM code to pass           |
|    +-- Fake It is valid for first test         |
|                                                |
| 3. TRIANGULATE: Add tests that break the fake  |
|    +-- Different inputs, edge cases            |
|                                                |
| 4. REFACTOR: Improve with confidence           |
|    +-- Tests stay green throughout             |
|                                                |
| 5. REPEAT: Next behavior/requirement           |
+------------------------------------------------+
```

---

## Anti-Patterns (NEVER DO)

```
# ANY language:

# 1. Code first, tests after
def new_feature(): ...  # Then writing tests = USELESS

# 2. Skip triangulation
# Single test allows faking forever

# 3. Test implementation details
assert component.state.is_loading == True   # BAD - test behavior, not internals
assert mock_service.call_count == 3         # BAD - brittle coupling

# 4. All tests at once before any code
# Write ONE test, make it pass, THEN write the next

# 5. Giant test methods
# Each test should verify ONE behavior
```

---

## Commands by Stack

### UI (`ui/`)

```bash
pnpm test                           # Watch mode
pnpm test:run                       # Single run (CI)
pnpm test:coverage                  # Coverage report
pnpm test ComponentName             # Filter by name
```

### SDK (`prowler/`)

```bash
poetry run pytest tests/path/ -v              # Run specific tests
poetry run pytest tests/path/ -v -k "test_name"  # Filter by name
poetry run pytest -n auto tests/              # Parallel run
poetry run pytest --cov=./prowler tests/      # Coverage
```

### API (`api/`)

```bash
poetry run pytest -x --tb=short                           # Run all (stop on first fail)
poetry run pytest api/src/backend/api/tests/test_file.py  # Specific file
poetry run pytest -k "test_name" -v                       # Filter by name
```
