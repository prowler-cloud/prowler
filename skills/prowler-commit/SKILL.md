---
name: prowler-commit
description: >
  Creates professional git commits for Prowler following conventional-commits format, with prek pre-commit hooks.
  Trigger: When creating commits, after completing code changes, when user asks to commit.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
  scope: [root, api, ui, sdk, mcp_server]
  auto_invoke:
    - "Creating a git commit"
    - "Committing changes"
---

## Critical Rules

- ALWAYS use conventional-commits format: `type(scope): description`
- ALWAYS keep the first line under 72 characters
- ALWAYS ask for user confirmation before committing
- NEVER commit on `master` (or `main`): the prek `no-commit-to-branch` hook rejects it. Create a branch first
- NEVER be overly specific (avoid counts like "6 subsections", "3 files")
- NEVER include implementation details in the title
- NEVER use `-n` / `--no-verify` unless the user explicitly requests it
- NEVER use `git push --force` or `git push -f` (destructive, rewrites history)
- NEVER proactively offer to commit - wait for user to explicitly request it

---

## Commit Format

```text
type(scope): concise description

- Key change 1
- Key change 2
- Key change 3
```

PRs are squash-merged and the **PR title** becomes the commit on `master` (`feat(ui): ... (#13245)`), so the same format is enforced on PR titles by `.github/workflows/conventional-commit.yml`:

```text
^(feat|fix|docs|style|refactor|perf|test|chore|build|ci|revert)(\([^)]+\))?!?: .+
```

### Types

| Type | Use When |
|------|----------|
| `feat` | New feature or functionality (new check, endpoint, UI flow) |
| `fix` | Bug fix (including CVE/dependency patches shipped to users) |
| `docs` | Documentation only |
| `chore` | Maintenance, configs, releases, changelog compiles |
| `refactor` | Code change without feature/fix |
| `test` | Adding or updating tests |
| `perf` | Performance improvement |
| `style` | Formatting, no code change |
| `build` | Build system or packaging |
| `ci` | GitHub Actions / CI configuration |
| `revert` | Reverting a previous commit |

Append `!` before the colon for breaking changes: `feat(api)!: remove legacy endpoint`.

### Scopes (as used in the history)

| Scope | When |
|-------|------|
| `ui`, `api`, `mcp` | Changes in `ui/`, `api/`, `mcp_server/` |
| `aws`, `azure`, `gcp`, `cloudflare`, ... | SDK change for one provider (`prowler/providers/<provider>/`) |
| `ec2`, `iam`, ... | SDK change confined to one service |
| `compliance`, `outputs` | SDK compliance frameworks, output formats |
| `container` | Dockerfiles / base image / container CVE patches |
| `skills` | Changes in `skills/` |
| `guides`, `changelog`, `release` | Docs area, changelog, release bumps |
| *omit* | Multiple scopes or root-level |

---

## Good vs Bad Examples

```text
# GOOD
feat(azure): add Application Gateway WAF and HTTP/2 checks
fix(cloudflare): handle missing challenge passage TTL
fix(container): patch pyasn1 and joserfc CVEs
ci(ui): pin Playwright jobs to ubuntu-24.04
docs: update installation guide

# BAD
feat(api): add provider connection retry logic with exponential backoff and jitter (3 retries max)
chore(skills): add comprehensive Celery documentation covering 8 topics
fix(ui): fix the bug in dashboard component on line 45
Fixed stuff                                   # not conventional, fails the PR title check
```

Body bullets: high-level changes ("Add retry mechanism for failed connections"), not parameters or line numbers.

---

## Workflow

1. **Analyze changes**
   ```bash
   git status
   git branch --show-current     # must not be master
   git diff --stat HEAD
   git log -5 --oneline          # recent style
   ```

2. **Check the changelog**: changes under `prowler/`, `api/`, `ui/`, `mcp_server/` (or root `uv.lock`/`pyproject.toml`) need a fragment in `<component>/changelog.d/` (see `prowler-changelog`).

3. **Draft the message**: type, scope, title under 72 chars, 2-5 bullets for significant changes.

4. **Present to user**: files to be committed + proposed message. Wait for explicit confirmation.

5. **Commit** (prek hooks run automatically once installed with `uv run prek install`):
   ```bash
   git add <files>
   git commit -m "$(cat <<'EOF'
   type(scope): description

   - Change 1
   - Change 2
   EOF
   )"
   ```

6. **If a hook fails**, the commit did NOT happen. Fixer hooks (end-of-file-fixer, trailing-whitespace, black, isort, autoflake, ruff, pretty-format-json, UI Prettier/ESLint) may have rewritten files: review them, `git add` them, and run the same `git commit` again (not `--amend`: there is no commit yet). For linters (flake8, pylint, actionlint, zizmor, shellcheck, markdownlint, hadolint, bandit, vulture, UI typecheck/tests), fix the code first.

---

## Hooks Reference (prek)

| Config | Applies to | Notable hooks |
|--------|------------|---------------|
| `.pre-commit-config.yaml` | Repo | `no-commit-to-branch`, `check-yaml`/`check-json`, black/isort/flake8/autoflake/pylint (SDK paths), ruff via `uv run --project ./api` and `./mcp_server`, `uv-lock --check`, actionlint, zizmor, shellcheck, markdownlint, hadolint, TruffleHog, bandit, vulture, provider-cards snippet regeneration |
| `ui/.pre-commit-config.yaml` (`orphan: true`) | `ui/` only | Prettier, ESLint (`--max-warnings 40`), `pnpm run typecheck`, `vitest related --run` |

```bash
uv sync && uv run prek install           # install hooks (pre-commit stage only)
uv run prek install --hook-type pre-push # optional: TruffleHog on push
uv run prek run --all-files              # run everything manually
uv run prek run --files <path>...        # run on specific files
```

---

## Decision Tree

```text
On master?                  -> git switch -c <branch-name> first
Single file changed?        -> title only is fine
Multiple scopes affected?   -> omit scope: `feat: description`
Breaking change?            -> add `!`: `feat(api)!: description`
Standalone docs?            -> docs: / docs(scope):
```

---

## Commands

```bash
git status
git diff --stat HEAD
git add <files>
git commit -m "type(scope): description"

# Amend the last LOCAL, unpushed commit only
git commit --amend --no-edit
git commit --amend -m "new message"
```
