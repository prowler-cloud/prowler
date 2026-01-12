---
name: prowler-pr
description: >
  Creates Pull Requests for Prowler following the project template and conventions.
  Trigger: When working on pull request requirements or creation (PR template sections, PR title Conventional Commits check, changelog gate/no-changelog label), or when inspecting PR-related GitHub workflows like conventional-commit.yml, pr-check-changelog.yml, pr-conflict-checker.yml, labeler.yml, or CODEOWNERS.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Create a PR with gh pr create"
    - "Review PR requirements: template, title conventions, changelog gate"
    - "Fill .github/pull_request_template.md (Context/Description/Steps to review/Checklist)"
    - "Inspect PR CI workflows (.github/workflows/*): conventional-commit, pr-check-changelog, pr-conflict-checker, labeler"
    - "Understand review ownership with CODEOWNERS"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## PR Creation Process

1. **Analyze changes**: `git diff main...HEAD` to understand ALL commits
2. **Determine affected components**: SDK, API, UI, MCP, Docs
3. **Fill template sections** based on changes
4. **Create PR** with `gh pr create`

## PR Template Structure

```markdown
### Context

{Why this change? Link issues with `Fix #XXXX`}

### Description

{Summary of changes and dependencies}

### Steps to review

{How to test/verify the changes}

### Checklist

<details>

<summary><b>Community Checklist</b></summary>

- [ ] This feature/issue is listed in [here](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or roadmap.prowler.com
- [ ] Is it assigned to me, if not, request it via the issue/feature in [here](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or [Prowler Community Slack](goto.prowler.com/slack)

</details>

- Are there new checks included in this PR? Yes / No
    - If so, do we need to update permissions for the provider?
- [ ] Review if the code is being covered by tests.
- [ ] Review if code is being documented following https://github.com/google/styleguide/blob/gh-pages/pyguide.md#38-comments-and-docstrings
- [ ] Review if backport is needed.
- [ ] Review if is needed to change the Readme.md
- [ ] Ensure new entries are added to CHANGELOG.md, if applicable.

#### SDK/CLI
- Are there new checks included in this PR? Yes / No
    - If so, do we need to update permissions for the provider? Please review this carefully.

#### UI (if applicable)
- [ ] All issue/task requirements work as expected on the UI
- [ ] Screenshots/Video - Mobile (X < 640px)
- [ ] Screenshots/Video - Tablet (640px > X < 1024px)
- [ ] Screenshots/Video - Desktop (X > 1024px)
- [ ] Ensure new entries are added to ui/CHANGELOG.md

#### API (if applicable)
- [ ] All issue/task requirements work as expected on the API
- [ ] Endpoint response output (if applicable)
- [ ] EXPLAIN ANALYZE output for new/modified queries or indexes (if applicable)
- [ ] Performance test results (if applicable)
- [ ] Any other relevant evidence of the implementation (if applicable)
- [ ] Verify if API specs need to be regenerated.
- [ ] Check if version updates are required.
- [ ] Ensure new entries are added to api/CHANGELOG.md

### License

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.
```

## Component-Specific Rules

| Component | CHANGELOG | Extra Checks |
|-----------|-----------|--------------|
| SDK | `prowler/CHANGELOG.md` | New checks → permissions update? |
| API | `api/CHANGELOG.md` | API specs, version bump, endpoint output, EXPLAIN ANALYZE, performance |
| UI | `ui/CHANGELOG.md` | Screenshots for Mobile/Tablet/Desktop |
| MCP | `mcp_server/CHANGELOG.md` | N/A |

## Commands

```bash
# Check current branch status
git status
git log main..HEAD --oneline

# View full diff
git diff main...HEAD

# Create PR with heredoc for body
gh pr create --title "feat: description" --body "$(cat <<'EOF'
### Context
...
EOF
)"

# Create draft PR
gh pr create --draft --title "feat: description"
```

## Title Conventions

Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `chore:` Maintenance
- `refactor:` Code restructure
- `test:` Tests

## Before Creating PR

1. ✅ All tests pass locally
2. ✅ Linting passes (`make lint` or component-specific)
3. ✅ CHANGELOG updated (if applicable)
4. ✅ Branch is up to date with main
5. ✅ Commits are clean and descriptive

## Resources

- **Documentation**: See [references/](references/) for links to local developer guide
