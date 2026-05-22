---
name: prowler-npm-security-audit
description: >
  Audits npm/pnpm package manager configuration and dependency changes against
  npm security best practices, Prowler UI conventions, and supply-chain
  hardening requirements. Trigger: PRs or repo audits that touch package.json,
  lockfiles, pnpm-workspace.yaml, npmrc, CI install steps, Docker installs,
  security dependency updates, or package supply-chain policy.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Auditing npm/pnpm package security"
    - "Reviewing npm supply-chain policy"
    - "Working on npm package, lockfile, or pnpm configuration"
---

## When to Use

Use this skill when reviewing or changing:

- `ui/package.json`, `ui/pnpm-lock.yaml`, `ui/pnpm-workspace.yaml`, or `ui/.npmrc`
- UI package-manager migrations, dependency bumps, or lockfile-only changes
- CI, Docker, worktree, or local setup paths that run package installs
- Security-only dependency remediation workflows for npm packages
- npm package-health evidence, trust policy, lifecycle scripts, or supply-chain controls

Do **not** recommend enabling general UI dependency-update automation in Dependabot or Renovate. Prowler intentionally avoids bot-driven UI version bumps; only security remediation should be considered.

## Critical Patterns

Base the audit on [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices) and Prowler's UI rules.

| Area | What to verify | Red flags |
| --- | --- | --- |
| Lifecycle scripts | `allowBuilds` is explicit and `strictDepBuilds: true` is enabled | Broad or undocumented build allowances; root lifecycle scripts mutating git state |
| Exotic dependencies | `blockExoticSubdeps: true` or equivalent is enabled | Git, tarball, HTTP, file, link, or workspace specs in committed lockfiles without rationale |
| Cooldown | `minimumReleaseAge` exists and security remediation respects the repository policy | Bot-driven general UI version bumps in Dependabot/Renovate; emergency security updates without review evidence |
| Trust policy | `trustPolicy: no-downgrade` is enabled | Open-ended `trustPolicyExclude` entries; exceptions without evidence |
| Determinism | Lockfile committed; CI/Docker use frozen installs; package manager pinned | Floating package managers; future major ranges not exercised in CI |
| CI coverage | Existing gates remain intact | Package-manager migration removes format, lint, tests, audit, or build gates |
| Overrides | Overrides are scoped and documented | Global overrides that force unrelated consumers or incompatible majors |
| Package health | New direct dependencies have rationale and package-health evidence | New packages without maintenance/license/vulnerability/provenance review |
| Local safety | Installs do not unexpectedly mutate shared git state | `postinstall` installs hooks or rewrites files without opt-in |
| Dependency confusion | Private scopes have registry mapping; no plaintext tokens | Unscoped private package names, committed tokens, or ambiguous registries |

## Prowler Audit Scope

Primary files:

```text
ui/package.json
ui/pnpm-lock.yaml
ui/pnpm-workspace.yaml
ui/.npmrc
ui/Dockerfile
.github/workflows/ui-*.yml
.github/dependabot.yml
.github/renovate.json
.config/wt.toml
ui/dependency-log.json
```

Also inspect package install scripts under `ui/scripts/` when lifecycle behavior changes.

## Review Output Format

Use this structure for review findings:

```markdown
Verdict: pass | pass-with-issues | fail

## Findings

### Blocker

### High

### Medium

### Low

### Questions

## Positive controls observed

## Checks run

## Not checked
```

Each finding must include:

- file path and line reference when possible;
- evidence;
- risk;
- smallest suggested fix.

## Commands

```bash
# Inspect package/security config
cd ui
pnpm audit --audit-level high
pnpm install --frozen-lockfile --prefer-offline
pnpm run healthcheck

# Search for exotic lockfile sources
rg -n "git\+|github:|bitbucket:|gitlab:|http://|https://|tarball:|file:|link:|workspace:" ui/pnpm-lock.yaml

# Confirm UI workflows keep expected gates
rg -n "pnpm run (healthcheck|format:check|audit|build|test)" .github/workflows/ui-*.yml
```

## Constraints

- Default to read-only review unless explicitly asked to fix.
- Do not treat frontend package hiding as a security boundary; backend authorization still matters.
- Do not invent package-health claims. Fetch primary evidence when needed.
- Prefer concrete, actionable findings over generic best-practice prose.
