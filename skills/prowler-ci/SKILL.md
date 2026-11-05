---
name: prowler-ci
description: >
  Helps with Prowler repository CI and PR gates (GitHub Actions workflows).
  Trigger: When investigating CI checks failing on a PR, PR title validation, changelog gate/no-changelog label,
  conflict marker checks, secret scanning, release freeze, CODEOWNERS/labeler automation, or anything under .github/workflows.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
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

- Explaining why a PR check fails and how to reproduce it locally
- Which workflows run for SDK/API/UI/MCP/docs changes and why (path filters)
- Reading or changing GitHub Actions workflows under `.github/workflows/`

Use `prowler-pr` for *creating* PRs and filling the template; `gh-aw` for the agentic `issue-triage` workflow.

## Workflow Naming

Workflow files are prefixed by area and the `name:` matches: `sdk-*` (`SDK: ...`), `api-*` (`API: ...`), `ui-*` (`UI: ...`), `mcp-*` (`MCP: ...`), `helm-*`, `ci-*` (`CI: ...`), `docs-*`/`markdown-lint` (`Docs: ...`), and repo tooling (`Tools: ...`: changelog, conventional commit, conflicts, labeler, backport, TruffleHog, release freeze). Component workflows use `tj-actions/changed-files` (or `paths:`) so they only do real work when their folder changes.

## PR Gates: what fails and how to fix it

| Check (workflow) | Fails when | Fix / reproduce locally |
|------------------|-----------|-------------------------|
| PR title (`conventional-commit.yml`) | Title does not match `^(feat\|fix\|docs\|style\|refactor\|perf\|test\|chore\|build\|ci\|revert)(\([^)]+\))?!?: .+` | Edit the PR title |
| Changelog (`pr-check-changelog.yml`) | Missing/invalid fragment, PR link in a fragment, or direct `CHANGELOG.md` edit | Add `<component>/changelog.d/<slug>.<type>.md` (see `prowler-changelog`) or the `no-changelog` label |
| Conflicts (`pr-conflict-checker.yml`) | Conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) in changed files; also labels `has-conflicts` | Remove markers / rebase on `master` |
| Secrets (`find-secrets.yml`, TruffleHog) | Verified or unknown secret in the PR diff | See TruffleHog below |
| Release freeze (`release-freeze-gate.yml`) | Repo variable `RELEASE_FREEZE` is `true` (PRs to `master`) | Wait for the release; not a code problem |
| Test `__init__.py` (`check-test-init-files.yml`) | `__init__.py` inside `tests/` | Delete it; `python3 scripts/check_test_init_files.py .` |
| Duplicate test names (`sdk-check-duplicate-test-names.yml`) | Same `*_test.py` filename in two providers under `tests/providers/` | Rename the test file with a provider prefix |
| Provider cards (`docs-check-provider-cards.yml`) | `docs/snippets/provider-cards.mdx` out of sync | `python3 docs/scripts/generate_provider_cards.py` and commit |
| Compliance mapping (`pr-check-compliance-mapping.yml`) | Never fails: comments and adds `needs-compliance-review` for new checks not mapped in a compliance JSON | Map the check or add `no-compliance-check` |

## Component Checks (reproduce locally)

| Workflow | Runs |
|----------|------|
| `sdk-code-quality.yml` | `uv lock --check`; `uv run flake8 . --ignore=E266,W503,E203,E501,W605,E128 --exclude .venv,contrib,ui,api,skills,mcp_server`; `uv run black --exclude "\.venv\|api\|ui\|skills\|mcp_server" --check .`; `uv run pylint --disable=W,C,R,E -j 0 -rn -sn prowler/` |
| `sdk-tests.yml` | `uv run pytest -n auto --cov=./prowler/providers/<provider> tests/providers/<provider>` per changed provider (AWS narrows to changed services) |
| `sdk-security.yml` | `uv run bandit -q -lll -x '*_test.py,./.venv/,./contrib/,./api/,./ui' -r .`; `uv run vulture --exclude ".venv,contrib,api,ui" --min-confidence 100 .` |
| `api-code-quality.yml` (in `api/`) | `uv lock --check`; `uv run ruff check . --exclude contrib`; `uv run ruff format --check . --exclude contrib`; `uv run pylint --disable=W,C,R,E -j 0 -rn -sn src/` |
| `api-security.yml` (in `api/`) | bandit + vulture (same flags style as SDK) |
| `api-tests.yml` | API pytest suite (needs PostgreSQL/Valkey services) |
| `ui-tests.yml` (in `ui/`) | `pnpm install --frozen-lockfile`; `pnpm run healthcheck` (typecheck + lint + format check); `pnpm run audit`; unit tests (`vitest related` for changed files or full `pnpm run test:unit`); `pnpm run test:integration`; `pnpm run build` |
| `ui-e2e-tests-v2.yml` | Playwright E2E, scoped by `test-impact-analysis.yml` (`.github/test-impact.yml`) |
| `mcp-tests.yml` (in `mcp_server/`) | `uv run pytest --cov=./prowler_mcp_server --cov-report=xml tests` |
| `ci-actionlint.yml`, `ci-zizmor.yml` | actionlint and zizmor on workflows |
| `markdown-lint.yml` | markdownlint-cli 0.45.0 on tracked `*.md` |
| `*-container-checks.yml`, `*-codeql.yml` | Container build/scan, CodeQL |

Most of these also run as prek hooks: `uv run prek run --files <changed files>` is the fastest local check.

## Debug Checklist (PR failing checks)

1. `gh pr checks <number>` to find the failing workflow/job, then open its file in `.github/workflows/`.
2. Check path filters: is the workflow supposed to run for your changed files?
3. Map it to the tables above and run the same command locally.
4. For workflows triggered by labels (`labeled`/`unlabeled`), re-apply or remove the label to re-run.

## TruffleHog Secret Scanning

CI runs TruffleHog 3.99.2 on the PR diff with `--results=verified,unknown`, so fake values that match a detector format can fail too.

- Test data: use obviously fake values that do not match real key formats, e.g. `api_key = "sk-fake-test-key-for-unit-testing-only"`, not `sk-...T3BlbkFJ...` or `AKIA` + 16 chars.
- Known false positive on a line: append the inline comment `# trufflehog:ignore` (used in `tests/lib/utils/utils_test.py`).
- Real secret: remove it, rotate it (it is in git history), and tell the maintainers.
- Local: `uv run prek install --hook-type pre-push` enables the TruffleHog hook before push.

## Changing Workflows

- Pin every action by full commit SHA with a version comment (`uses: actions/checkout@<sha> # v6.0.2`); start jobs with `step-security/harden-runner`; declare `permissions: {}` at the top and grant per job.
- Run `uv run prek run actionlint --files <workflow>` and `uv run prek run zizmor --files <workflow>` before pushing. Workflows with `pull_request_target` carry `# zizmor: ignore[...]` justifications; keep them accurate.
- Never edit `issue-triage.lock.yml` by hand (generated by gh-aw, see `gh-aw`).

## Resources

- PR template: `.github/pull_request_template.md`
- Labels: `.github/labeler.yml`; review ownership: `.github/CODEOWNERS`
- Composite actions: `.github/actions/` (`setup-python-uv`, `trivy-scan`, `grype-scan`, `osv-scanner`, `slack-notification`)
