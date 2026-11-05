---
name: prowler-pr
description: >
  Creates Pull Requests for Prowler following the project template and conventions.
  Trigger: When working on pull request requirements or creation (PR template sections, PR title Conventional Commits check, changelog gate/no-changelog label, backport labels), or when inspecting PR-related GitHub workflows like conventional-commit.yml, pr-check-changelog.yml, pr-conflict-checker.yml, labeler.yml, or CODEOWNERS.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke:
    - "Create a PR with gh pr create"
    - "Review PR requirements: template, title conventions, changelog gate"
    - "Fill .github/pull_request_template.md (Context/Description/Steps to review/Checklist)"
    - "Inspect PR CI workflows (.github/workflows/*): conventional-commit, pr-check-changelog, pr-conflict-checker, labeler"
    - "Understand review ownership with CODEOWNERS"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- The default branch is **`master`** (not `main`). Patch fixes target `master` and are backported to `v5.X`.
- ALWAYS build the body from the CURRENT `.github/pull_request_template.md` (read it; do not reuse a cached copy). Keep every heading and the License line; fill or delete component sections that do not apply.
- PR title MUST pass `^(feat|fix|docs|style|refactor|perf|test|chore|build|ci|revert)(\([^)]+\))?!?: .+` (it becomes the squash commit, see `prowler-commit`).
- Changes in `prowler/`, `api/`, `ui/`, `mcp_server/` (or root `uv.lock`/`pyproject.toml`) need a fragment in `<component>/changelog.d/` (see `prowler-changelog`), or the `no-changelog` label when no entry is warranted.
- Link issues in **Context** with `Fix #XXXX` (or `Fixes #XXXX`), never in changelog fragments.

## PR Creation Process

1. **Analyze ALL commits**: `git log master..HEAD --oneline` and `git diff master...HEAD`
2. **Determine affected components** from paths: SDK (`prowler/`), API (`api/`), UI (`ui/`), MCP (`mcp_server/`), Docs (`docs/`)
3. **Read and fill the template** (`cat .github/pull_request_template.md`)
4. **Create the PR** with `gh pr create --base master`

## Template Sections (current file)

| Section | What to write |
|---------|---------------|
| `### Context` | Why the change is needed; `Fix #XXXX` |
| `### Description` | Summary of the change and new dependencies |
| `### Steps to review` | How to verify: commands, scan flags, UI path, test commands |
| `### Checklist` | Community checklist (collapsed `<details>`: issue listed/assigned, no duplicate open PR) + general items (tests, docstrings per Google style, backport, README, SDK changelog fragment) |
| `#### SDK/CLI` | New checks? Yes/No; if yes, do provider permissions need updating? |
| `#### UI` | Requirements work; npm dependency package-health evidence (maintenance, popularity, vulnerabilities, license, release age); screenshots for Mobile (<640px), Tablet (640-1024px), Desktop (>1024px); `ui/changelog.d/` fragment |
| `#### API` | Requirements work; endpoint output; `EXPLAIN ANALYZE` for new/modified queries or indexes; performance results; API spec regeneration; version updates; `api/changelog.d/` fragment |
| `#### MCP Server` | Requirements work; `mcp_server/changelog.d/` fragment |
| `### License` | Keep: "By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license." |

## Labels That Change PR Behavior

| Label | Effect |
|-------|--------|
| `no-changelog` | Skips the changelog gate (`pr-check-changelog.yml`) |
| `backport-to-v5.X` | After merge, `backport.yml` opens the backport PR to `v5.X` (labels it `backport`, source gets `was-backported`) |
| `no-compliance-check` | Skips the new-check compliance mapping review (`pr-check-compliance-mapping.yml`, which otherwise adds `needs-compliance-review` for unmapped new checks) |
| `has-conflicts` | Added/removed automatically by `pr-conflict-checker.yml` |
| `provider/*`, `component/*`, `documentation`, `compliance`, ... | Applied automatically from paths by `labeler.yml` + `.github/labeler.yml`; `community` is added for external authors |

Review ownership: `.github/CODEOWNERS` assigns every path to `@prowler-cloud/engineering`.

## Commands

```bash
git status
git log master..HEAD --oneline
git diff master...HEAD --stat

# Create PR (body from the template, filled)
gh pr create --base master --title "feat(aws): add <check_id> check" --body "$(cat <<'EOF'
### Context
...
EOF
)"

# Draft PR / add labels
gh pr create --draft --base master --title "fix(ui): description"
gh pr edit <number> --add-label no-changelog

# Check CI after pushing
gh pr checks <number>
```

## Before Creating PR

1. Tests pass locally for the touched component (`uv run pytest ...`, `pnpm test:unit`, etc.)
2. Hooks pass: `uv run prek run --files $(git diff --name-only master...HEAD)`
3. Changelog fragment added (or `no-changelog` justified)
4. Branch is up to date with `master`
5. Commits are clean and descriptive

## Before Re-Requesting Review (REQUIRED)

Resolve or respond to **every** open inline review thread before re-requesting review:

1. **Agreed + fixed**: Commit the change. Reply with the commit hash so the reviewer can verify quickly:
   > Fixed in `abc1234`.
2. **Agreed but deferred**: Explain why it's out of scope for this PR and where it's tracked.
3. **Disagreed**: Reply with clear technical reasoning. Do not leave threads silently open.
4. **Re-request review** only after all threads are in a clean state, either resolved or explicitly responded to.

> **Rule of thumb**: A reviewer should never have to wonder "did they see my comment?" when they re-open the PR.

## Resources

- **Template**: `.github/pull_request_template.md`
- **CI gates in depth**: `prowler-ci` skill
- **Documentation**: See [references/](references/) for links to the local developer guide
