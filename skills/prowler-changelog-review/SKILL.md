---
name: prowler-changelog-review
description: >
  Reviews changelog completeness between two versions for all Prowler components (API, UI, SDK, MCP Server).
  Trigger: When reviewing changelogs before a release, checking if all PRs are documented, or auditing changelog completeness.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Review changelog completeness"
    - "Check if all PRs are in the changelog"
    - "Audit changelog between versions"
allowed-tools: Read, Glob, Grep, Bash, WebFetch
---

## When to Use

- Before a release, to verify all merged PRs are documented in changelogs
- When auditing changelog completeness between any two versions
- When preparing release notes

## Components to Review

| Component | Directory | Changelog | GitHub Label |
|-----------|-----------|-----------|--------------|
| API | `api/` | `api/CHANGELOG.md` | `component/api` |
| UI | `ui/` | `ui/CHANGELOG.md` | `component/ui` |
| SDK | `prowler/` | `prowler/CHANGELOG.md` | `component/sdk` |
| MCP Server | `mcp_server/` | `mcp_server/CHANGELOG.md` | `component/mcp-server` |

## Input

The user provides a **base version tag** (e.g., `5.17.1`). All commits from that tag to `HEAD` are analyzed.

If no version is provided, ask the user for one. List available tags with:

```bash
git tag --sort=-v:refname | head -10
```

## Review Process

For **each component**, follow these steps in order:

### Step 1: Get commits affecting the component

```bash
git log --oneline <tag>..HEAD -- <directory>/
```

### Step 2: Extract PR numbers from commit messages

PR numbers follow the pattern `(#NNNN)` in commit messages. Extract all unique PR numbers.

### Step 3: Read the component's CHANGELOG.md

Read the changelog and extract all PR numbers referenced in sections **after** the version that corresponds to the base tag.

### Step 4: Detect revert pairs

Before classifying, scan commit messages for revert patterns. A **revert pair** exists when:

- A commit message contains `revert` (case-insensitive) and references the same feature/check as another PR in the range
- Two PRs cancel each other out (one adds, the other reverts the same change)

Example: `feat(aws): Adding check X (#9928)` + `feat(aws): revert Adding check X (#9956)` = revert pair.

Classify both PRs in a revert pair as **Skipped (revert pair)** since the net effect is zero. Do NOT report them as missing.

### Step 5: Classify each commit

For each PR from Step 2 (excluding revert pairs from Step 4), classify it into one of:

| Classification | Criteria |
|---------------|----------|
| **Documented** | PR number appears in the changelog |
| **Meta/Chore** | Commit message starts with `chore:`, `chore(`, `build(deps)`, or is a version bump, lockfile update, changelog preparation, or skill update |
| **Missing** | PR has functional impact (feat, fix, refactor, security) and is NOT in the changelog |

For each PR classified as **Missing**, check if it has the `no-changelog` label:

```
WebFetch: https://api.github.com/repos/prowler-cloud/prowler/issues/<PR_NUMBER>/labels
```

If the PR has `no-changelog` label, reclassify it as **Skipped (no-changelog)**.

### Step 7: Report

Present results **per component** in this format:

```
## <Component Name> (<directory>/)

Commits since <tag>: <count>
Changelog: <path>

### Documented in changelog
| PR | Description |
|----|-------------|
| #XXXX | ... |

### Skipped (meta/chore)
| PR | Description |
|----|-------------|
| #XXXX | ... |

### Skipped (no-changelog label)
| PR | Description |
|----|-------------|
| #XXXX | ... |

### Skipped (revert pair)
| PR | Paired With | Description |
|----|-------------|-------------|
| #XXXX | #YYYY | Added then reverted: ... |

### MISSING from changelog
| PR | Type | Description |
|----|------|-------------|
| #XXXX | fix | ... |
```

### Step 8: Summary

After all components, provide a final summary:

```
## Summary

| Component | Commits | Documented | Skipped | Revert Pairs | Missing |
|-----------|---------|------------|---------|--------------|---------|
| API | X | X | X | X | X |
| UI | X | X | X | X | X |
| SDK | X | X | X | X | X |
| MCP Server | X | X | X | X | X |
```

If any PRs are **MISSING**, clearly state:
> **Action required:** X PRs are missing from changelogs and need to be added or labeled `no-changelog`.

If all PRs are accounted for:
> **All changelogs are complete.** Every PR is either documented, labeled `no-changelog`, or is a meta/chore commit.

## Important Notes

- Always check labels via the GitHub API before reporting a PR as missing
- PRs that appear in a **previous release section** of the changelog (e.g., documented under v5.17.1 but committed after the tag) should be classified as **Documented**
- **Revert pairs:** When a PR and its revert are both in the commit range, classify both as **Skipped (revert pair)** since the net effect is zero. Look for commit messages containing `revert` that reference the same feature/check as another PR. Never report revert pairs as missing.
- Run all 4 components in parallel when possible to minimize review time
- Use `WebFetch` for label checks, not `gh` CLI (it may not be installed)
