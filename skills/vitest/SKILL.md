---
name: vitest
description: "Trigger: When writing or refactoring Vitest tests for React components, hooks, or UI utilities. Defines unit and integration testing patterns with React Testing Library."
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

## Activation Contract

Use this skill for UI unit and integration tests built with Vitest and React Testing Library; for browser E2E flows, switch to `prowler-test-ui` instead.

## Hard Rules

- Structure tests with Given/When/Then intent.
- Prefer behavior-oriented `describe` blocks grouped by condition, not by implementation method.
- Query the screen by accessibility priority first: role, label, placeholder, text, then test id.
- Use `userEvent` for interactions unless a lower-level event is explicitly required.
- Keep async assertions focused: one expectation per `waitFor` block.
- Restore mocks between tests.

## Decision Gates

| Question | Action |
|---|---|
| Testing a browser flow across pages? | Use `prowler-test-ui`, not Vitest. |
| Need to interact like a user? | Use `userEvent.setup()` and await the interaction. |
| Element appears later? | Use `findBy*` or `waitFor` appropriately. |
| Need a selector? | Prefer accessible queries before `getByTestId`. |
| Thinking about testing internals? | Stop and assert user-visible behavior instead. |

## Execution Steps

1. Confirm the test belongs in unit/integration scope, not Playwright.
2. Read nearby tests to match file placement and helper patterns.
3. Write or update the spec using AAA comments when clarity helps.
4. Render through public component APIs and interact through accessible queries.
5. Use `userEvent` for user actions and async queries for delayed UI.
6. Isolate mocks and restore them after each test.
7. Run only the relevant Vitest target and verify the expected behavior.

## Output Contract

- State whether the test covers a component, hook, or utility.
- Report the main query and interaction patterns used.
- Mention the exact Vitest command or filter used for validation.
- Call out if E2E coverage was intentionally out of scope.

## References

- [TDD skill](../tdd/SKILL.md)
- [Prowler UI E2E skill](../prowler-test-ui/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
