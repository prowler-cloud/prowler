---
name: prowler-ci
description: >
  Helps with Prowler repository CI and PR gates (GitHub Actions workflows).
  Trigger: When investigating CI checks failing on a PR, PR title validation, changelog gate/no-changelog label,
  conflict marker checks, secret scanning, CODEOWNERS/labeler automation, or anything under .github/workflows.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Inspect PR CI checks and gates (.github/workflows/*)"
    - "Debug why a GitHub Actions job is failing"
    - "Understand changelog gate and no-changelog label behavior"
    - "Understand PR title conventional-commit validation"
    - "Understand CODEOWNERS/labeler-based automation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## What this skill covers

Use this skill whenever you are:

- Reading or changing GitHub Actions workflows under `.github/workflows/`
- Explaining why a PR fails checks (title, changelog, conflict markers, secret scanning)
- Figuring out which workflows run for UI/API/SDK changes and why
- Diagnosing path-filtering behavior (why a workflow did/didn't run)

## Quick map (where to look)

- PR template: `.github/pull_request_template.md`
- PR title validation: `.github/workflows/conventional-commit.yml`
- Changelog gate: `.github/workflows/pr-check-changelog.yml`
- Conflict markers check: `.github/workflows/pr-conflict-checker.yml`
- Secret scanning: `.github/workflows/find-secrets.yml`
- Auto labels: `.github/workflows/labeler.yml` and `.github/labeler.yml`
- Review ownership: `.github/CODEOWNERS`

## Debug checklist (PR failing checks)

1. Identify which workflow/job is failing (name + file under `.github/workflows/`).
2. Check path filters: is the workflow supposed to run for your changed files?
3. If it's a title check: verify PR title matches Conventional Commits.
4. If it's changelog: verify the right `CHANGELOG.md` is updated OR apply `no-changelog` label.
5. If it's conflict checker: remove `<<<<<<<`, `=======`, `>>>>>>>` markers.
6. If it's secrets: remove credentials and rotate anything leaked.

## Notes

- Keep `prowler-pr` focused on *creating* PRs and filling the template.
- Use `prowler-ci` for *CI policies and gates* that apply to PRs.
