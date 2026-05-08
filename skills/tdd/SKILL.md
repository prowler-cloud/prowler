---
name: tdd
description: "Trigger: ALWAYS when implementing features, fixing bugs, refactoring, or modifying behavior in Prowler. Enforces the RED -> GREEN -> REFACTOR workflow across UI, API, and SDK work."
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

## Activation Contract

Use this skill before changing production code whenever the task adds behavior, fixes a bug, or refactors existing logic.

## Hard Rules

- Start with a failing test; no production change before RED is proven.
- Run the smallest relevant test scope, not the whole suite, unless the refactor safety net requires broader coverage.
- Add only enough code to pass the current failing test.
- After GREEN, refactor with tests still passing.
- Load the stack-specific testing skill when applicable: `vitest`, `prowler-test-ui`, `pytest`, `prowler-test-api`, or `prowler-test-sdk`.

## Decision Gates

| Question | Action |
|---|---|
| Working in `ui/`? | Use Vitest conventions and co-located `*.test.{ts,tsx}` files. |
| Working in `api/`? | Use pytest + Django patterns and the API testing skill. |
| Working in `prowler/`? | Use pytest + provider-specific SDK testing patterns. |
| Refactoring without new behavior? | Capture current behavior first by running the closest existing tests before editing. |
| No relevant test exists? | Create the narrowest new test that demonstrates the target behavior or bug. |

## Execution Steps

1. Identify the component and matching test runner.
2. Read nearby tests first to match naming, fixtures, and assertion style.
3. Write or extend one test that fails for the intended behavior.
4. Run that focused test and confirm RED.
5. Implement the minimum change to reach GREEN.
6. Add triangulation cases when one test could be satisfied by a fake or hardcoded implementation.
7. Refactor only after the behavior is protected by passing tests.
8. Re-run the focused suite and report the exact validation command used.

## Output Contract

- State the RED evidence: which test failed and why.
- State the GREEN evidence: which command passed after the change.
- Name the stack and test skill used.
- Call out any blocker if RED or GREEN could not be executed exactly as intended.

## References

- [Vitest skill](../vitest/SKILL.md)
- [Pytest skill](../pytest/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
