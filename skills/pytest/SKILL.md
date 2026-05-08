---
name: pytest
description: "Trigger: When writing or refactoring pytest tests in Python, including fixtures, mocking, parametrization, async tests, and markers. Provides generic pytest structure before component-specific API or SDK rules."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, sdk, api]
  auto_invoke: "Writing Python tests with pytest"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill for generic pytest structure and patterns; if the test touches Prowler API or SDK specifics, pair it with `prowler-test-api` or `prowler-test-sdk`.

## Hard Rules

- Keep tests behavior-focused and name them after expected outcomes.
- Extract reusable setup into fixtures instead of repeating inline construction.
- Use `pytest.raises` for failure expectations and `@pytest.mark.parametrize` for matrix coverage.
- Mock external boundaries, not the logic under test.
- Register and use markers intentionally; do not invent silent marker names.
- Prefer local references only; do not rely on external documentation links inside the skill.

## Decision Gates

| Question | Action |
|---|---|
| Shared setup across tests? | Move it into a fixture or `conftest.py`. |
| Same assertion logic over many inputs? | Use `@pytest.mark.parametrize`. |
| Need to verify an exception? | Use `pytest.raises(..., match=...)`. |
| Testing async behavior? | Use `@pytest.mark.asyncio` or the repo's async test pattern. |
| Working in `api/` or `prowler/`? | Load the component-specific testing skill too. |

## Execution Steps

1. Identify whether the test is generic pytest, API-specific, or SDK-specific.
2. Read neighboring tests and `conftest.py` before adding new fixtures.
3. Write focused test functions or test classes with clear outcome-based names.
4. Promote repeated setup into fixtures and shared helpers only when duplication appears twice or more.
5. Use parametrization, markers, and mocks deliberately to keep coverage broad but readable.
6. Run the narrowest relevant pytest target and inspect failures before widening scope.
7. Report the exact command used and any fixture or marker introduced.

## Output Contract

- State whether the change relied on fixtures, parametrization, mocking, markers, or async support.
- Mention any component-specific skill paired with pytest.
- Report the exact pytest command used for validation.
- Call out any test isolation or fixture-scope decision that affects future contributors.

## References

- [TDD skill](../tdd/SKILL.md)
- [Prowler API testing skill](../prowler-test-api/SKILL.md)
- [Prowler SDK testing skill](../prowler-test-sdk/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
