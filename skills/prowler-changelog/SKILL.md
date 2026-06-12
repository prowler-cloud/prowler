---
name: prowler-changelog
description: >
  Manages changelog entries for Prowler components following keepachangelog.com format.
  Trigger: When creating PRs, adding changelog entries, or working with any CHANGELOG.md file in ui/, api/, mcp_server/, or prowler/.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, ui, api, sdk, mcp_server]
  auto_invoke:
    - "Add changelog entry for a PR or feature"
    - "Update CHANGELOG.md in any component"
    - "Create PR that requires changelog entry"
    - "Review changelog format and conventions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## How changelog entries work: fragments

A PR never edits `CHANGELOG.md` directly. Instead it adds one small **fragment file** per entry under the component's `changelog.d/` directory. Fragments are compiled into the component's `CHANGELOG.md` at release time (deleting the consumed fragments), so concurrent PRs never conflict on the changelog.

| Component | Fragments directory | Compiled file |
|-----------|---------------------|---------------|
| UI | `ui/changelog.d/` | `ui/CHANGELOG.md` |
| API | `api/changelog.d/` | `api/CHANGELOG.md` |
| MCP Server | `mcp_server/changelog.d/` | `mcp_server/CHANGELOG.md` |
| SDK | `prowler/changelog.d/` | `prowler/CHANGELOG.md` |

"What's unreleased" = "what's in `changelog.d/`". The compiled `CHANGELOG.md` files contain only released versions.

## Fragment filename

```text
<slug>.<type>.md
```

- `<slug>` is free-form (`[A-Za-z0-9][A-Za-z0-9._-]*`), chosen by the author, ideally descriptive of the change (e.g. `securityhub-delegated-admin`). The PR number is also a valid slug (e.g. `11259`) when it is already known; it is never required.
- `<type>` maps 1:1 to the keepachangelog sections:

| `<type>` | Section | Usage |
|----------|---------|-------|
| `added` | `### 🚀 Added` | New features, checks, endpoints |
| `changed` | `### 🔄 Changed` | Modifications to existing functionality |
| `deprecated` | `### ⚠️ Deprecated` | Features marked for removal |
| `removed` | `### ❌ Removed` | Deleted features |
| `fixed` | `### 🐞 Fixed` | Bug fixes |
| `security` | `### 🔐 Security` | Security patches, CVE fixes |

- A PR adds as many fragment files as entries it needs, freely mixing types: one file per entry. E.g. a PR touching Added, Changed and Fixed ships `kms-rotation-check.added.md` + `kms-metadata-cache.changed.md` + `kms-disabled-keys.fixed.md`, and all compile with the same PR link into their own sections.
- Several entries of the SAME type: a different slug per entry (`kms-rotation-check.added.md`, `kms-rotation-docs.added.md`).
- At least one fragment per touched component, same as the old one-entry-per-changelog rule.

## Fragment content

The file contains ONLY the entry text, exactly as it should appear in the changelog, on a single line ending with a trailing newline:

```bash
echo '`securityhub_delegated_admin_enabled_all_regions` check for AWS provider, verifying that Security Hub has a delegated administrator, is active in all opted-in regions, and has organization auto-enable on' > prowler/changelog.d/securityhub-delegated-admin.added.md
```

**Rules (same prose conventions as always):**

- **NEVER write the PR link in the text.** It is attached automatically at compile time (the compile workflow resolves the PR that added the fragment from git history). Writing `[(#NNNN)](...)` in a fragment produces a duplicated link.
- No period at the end
- Do NOT start with redundant verbs (the section header already provides the action)
- Be specific: what changed, not why (that's in the PR)
- Keep entries readable: use spaces around inline code and product names, and wrap endpoints, commands, errors, task names, and file paths in backticks
- Avoid long run-on sentences; split complex changes into one concise result plus one concise context clause

### Good fragments

```text
# ui/changelog.d/provider-search-bar.added.md
Search bar when adding a provider

# api/changelog.d/scan-dispatch-race.fixed.md
`POST /api/v1/scans` no longer intermittently fails with `Scan matching query does not exist`; scan dispatch now publishes the `scan-perform` Celery task after the transaction commits

# ui/changelog.d/node-24-bump.security.md
Node.js from 20.x to 24.13.0 LTS, patching 8 CVEs
```

### Bad fragments

```text
Fixed bug.                              # Too vague, has period, redundant verb
Add search bar                          # Redundant verb (the section already says "Added")
Search bar [(#9634)](https://github.com/prowler-cloud/prowler/pull/9634)   # NEVER include the PR link; it is added at compile time
```

## Semantic Versioning Rules

Prowler follows [semver.org](https://semver.org/):

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Bug fixes, patches | PATCH (x.y.**Z**) | 1.16.1 → 1.16.2 |
| New features (backwards compatible) | MINOR (x.**Y**.0) | 1.16.2 → 1.17.0 |
| Breaking changes, removals | MAJOR (**X**.0.0) | 1.17.0 → 2.0.0 |

**CRITICAL:** `removed` fragments MUST only ship in MAJOR version releases. Removing features is a breaking change.

## Mandatory Human Confirmation Gate

Before creating or editing any changelog fragment or `CHANGELOG.md` file, the agent MUST stop and get explicit user confirmation. This applies even when the changelog gate is failing, the required file seems obvious, or the user asked to "fix the changelog".

Present the proposed action before writing:

1. Target fragment path (component, slug, type) or CHANGELOG.md edit.
2. Exact entry text.
3. Reason the changelog entry is needed.

Only proceed after an explicit approval such as "confirm", "approved", "sí", or equivalent. If the user rejects or does not answer, do not create or edit anything. Offer alternatives such as adding `no-changelog` when appropriate.

## Adding a Changelog Entry

### Step 1: Determine Affected Component(s)

```bash
git diff master...HEAD --name-only | grep -E '^(ui|api|mcp_server|prowler)/' | cut -d/ -f1 | sort -u
```

| Path Pattern | Component |
|--------------|-----------|
| `ui/**` | UI |
| `api/**` | API |
| `mcp_server/**` | MCP Server |
| `prowler/**` | SDK |
| Root `uv.lock` / `pyproject.toml` | SDK (the gate requires a `prowler/changelog.d/` fragment) |
| Multiple | One fragment per affected component |

### Step 2: Create the fragment(s)

```bash
echo 'Entry text describing the change' > <component>/changelog.d/<slug>.<type>.md
```

### Step 3: Check pending fragments

```bash
ls prowler/changelog.d/ api/changelog.d/ ui/changelog.d/ mcp_server/changelog.d/
```

## PR Changelog Gate

The `pr-check-changelog.yml` workflow enforces fragments:

1. **REQUIRED**: PRs touching `ui/`, `api/`, `mcp_server/`, or `prowler/` MUST add (or fix) a fragment under the corresponding `changelog.d/`
2. **VALIDATED**: added fragment filenames must match `<slug>.<type>.md` with a valid type
3. **LINTED**: fragment content must NOT contain a hand-written PR link (`[(#N)](...)`); the gate fails if one is found because the link is attached automatically at compile time
4. **SKIP**: Add `no-changelog` label to bypass (use sparingly for docs-only, CI-only changes)

## Release flow (compile)

- At release time, the `compile-changelogs` workflow (manual dispatch: `prowler_version` + `target_branch`; per-component versions are auto-derived from each changelog's latest stamped heading plus the pending fragment types, with optional explicit overrides or `skip`) resolves each fragment's PR from git history, runs the compiler per component, and opens a `chore(changelog): vX.Y.Z` PR (labeled `no-changelog`) that inserts the stamped `## [X.Y.Z] (Prowler vX.Y.Z)` block into each `CHANGELOG.md` and deletes the consumed fragments. A human reviews and squash-merges it. `prepare-release.yml` then extracts the stamped sections exactly as before.
- **Minor release (X.Y.0):** compile on `master` and merge the compile PR BEFORE cutting the `v5.X` branch.
- **Patch release (X.Y.Z):** fixes are backported to `v5.X` with their fragment files (conflict-free); compile on `v5.X` and merge its PR there. The same workflow run automatically opens a second forward-sync PR against master (labeled `no-changelog`) that inserts the same stamped block under master's marker and deletes the consumed fragments, so the next minor cannot re-release them; merge it right after. Fragments that only existed on `v5.X` are skipped with a notice. No manual git is involved.
- Entries within a section are ordered by PR number ascending (approximately chronological). Do not fight this ordering.

## Fixing an already-released entry

Released version blocks in `CHANGELOG.md` are otherwise immutable, but typo/correction fixes to already-released entries are the one case where a PR edits `CHANGELOG.md` directly: make the edit and add the `no-changelog` label.

If a PR's entry shipped in the wrong released block (e.g. the PR merged after its release was cut), move the entry back to a fragment: delete it from the released block and recreate it as `<component>/changelog.d/<PR>.<type>.md` (label the PR `no-changelog` since it edits `CHANGELOG.md`).

## Compiled CHANGELOG.md format (for reference)

The compiler renders, per release, into each `CHANGELOG.md` right under the `<!-- changelog: release notes start -->` marker (never remove that marker):

```markdown
## [X.Y.Z] (Prowler vA.B.C)

### 🚀 Added

- Entry text [(#NNNN)](https://github.com/prowler-cloud/prowler/pull/NNNN)

### 🐞 Fixed

- Fix entry [(#NNNN)](https://github.com/prowler-cloud/prowler/pull/NNNN)

---
```

Section order is always: Added → Changed → Deprecated → Removed → Fixed → Security. `X.Y.Z` is the COMPONENT version; `A.B.C` is the Prowler release version. Every entry ends with its PR link; linking to `/issues/N` is forbidden (the issue↔PR mapping belongs in the PR body via `Fixes #N`).

## Resources

- **Templates**: See [assets/](assets/) for entry templates
- **keepachangelog.com**: https://keepachangelog.com/en/1.1.0/
