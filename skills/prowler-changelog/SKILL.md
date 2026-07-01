---
name: prowler-changelog
description: >
  Manages changelog entries for Prowler components following keepachangelog.com format.
  Trigger: When creating PRs, adding changelog entries, or working with any CHANGELOG.md file in ui/, api/, mcp_server/, or prowler/.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui, api, sdk, mcp_server]
  auto_invoke:
    - "Add changelog entry for a PR or feature"
    - "Update CHANGELOG.md in any component"
    - "Create PR that requires changelog entry"
    - "Review changelog format and conventions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Changelog Locations

| Component | File | Version Prefix | Current Version |
|-----------|------|----------------|-----------------|
| UI | `ui/CHANGELOG.md` | None | 1.x.x |
| API | `api/CHANGELOG.md` | None | 1.x.x |
| MCP Server | `mcp_server/CHANGELOG.md` | None | 0.x.x |
| SDK | `prowler/CHANGELOG.md` | None | 5.x.x |

## Format Rules (keepachangelog.com)

### Section Order (ALWAYS this order)

```markdown
## [X.Y.Z] (Prowler vA.B.C) OR (Prowler UNRELEASED)

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
```

### Emoji Prefixes (REQUIRED for ALL components)

| Section | Emoji | Usage |
|---------|-------|-------|
| Added | `### 🚀 Added` | New features, checks, endpoints |
| Changed | `### 🔄 Changed` | Modifications to existing functionality |
| Deprecated | `### ⚠️ Deprecated` | Features marked for removal |
| Removed | `### ❌ Removed` | Deleted features |
| Fixed | `### 🐞 Fixed` | Bug fixes |
| Security | `### 🔐 Security` | Security patches, CVE fixes |

### Entry Format

```markdown
### Added

- Existing entry one [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- Existing entry two [(#YYYY)](https://github.com/prowler-cloud/prowler/pull/YYYY)
- NEW ENTRY GOES HERE at the BOTTOM [(#ZZZZ)](https://github.com/prowler-cloud/prowler/pull/ZZZZ)

### Changed

- Existing change [(#AAAA)](https://github.com/prowler-cloud/prowler/pull/AAAA)
- NEW CHANGE ENTRY at BOTTOM [(#BBBB)](https://github.com/prowler-cloud/prowler/pull/BBBB)
```

**Rules:**
- **ADD NEW ENTRIES AT THE BOTTOM of each section** (before next section header or `---`)
- **Blank line after section header** before first entry
- **Blank line between sections**
- Be specific: what changed, not why (that's in the PR)
- Keep entries readable: use spaces around inline code and product names, and wrap endpoints, commands, errors, task names, and file paths in backticks
- Avoid long run-on sentences; split complex changes into one concise result plus one concise context clause
- One entry per PR (can link multiple PRs for related changes)
- No period at the end
- Do NOT start with redundant verbs (section header already provides the action)
- **CRITICAL: Preserve section order** — when adding a new section to the UNRELEASED block, insert it in the correct position relative to existing sections (Added → Changed → Deprecated → Removed → Fixed → Security). Never append a new section at the top or bottom without checking order
- **CRITICAL: ALWAYS link to the PR, NEVER to the issue.** Every entry MUST use `https://github.com/prowler-cloud/prowler/pull/N`. Linking to `/issues/N` is FORBIDDEN, even when the PR fixes an issue. The issue↔PR relationship belongs in the PR body (`Fixes #N`), not in the changelog. If a fix has no PR yet, do not add the entry until the PR exists.

### Semantic Versioning Rules

Prowler follows [semver.org](https://semver.org/):

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Bug fixes, patches | PATCH (x.y.**Z**) | 1.16.1 → 1.16.2 |
| New features (backwards compatible) | MINOR (x.**Y**.0) | 1.16.2 → 1.17.0 |
| Breaking changes, removals | MAJOR (**X**.0.0) | 1.17.0 → 2.0.0 |

**CRITICAL:** `### ❌ Removed` entries MUST only appear in MAJOR version releases. Removing features is a breaking change.

### Released Versions Are Immutable

**NEVER modify already released versions.** Once a version is released (has a Prowler version tag like `v5.16.0`), its changelog section is frozen.

**Common issue:** A PR is created during release cycle X, includes a changelog entry, but merges after release. The entry is now in the wrong section.

```markdown
## [1.16.0] (Prowler v5.16.0)    ← RELEASED, DO NOT MODIFY

### Added
- Feature from merged PR [(#9999)]   ← WRONG! PR merged after release

## [1.17.0] (Prowler UNRELEASED)  ← Move entry HERE
```

**Fix:** Move the entry from the released version to the UNRELEASED section.

### Version Header Format

```markdown
## [1.17.0] (Prowler UNRELEASED)    # For unreleased changes
## [1.16.0] (Prowler v5.16.0)       # For released versions

---                                  # Horizontal rule between versions
```

## Mandatory Changelog Preflight

Before editing any `CHANGELOG.md`, always inspect the active release boundary:

1. Read the UNRELEASED block plus the latest three released version blocks:
   ```bash
   awk '/^## \[/{n++} n<=4 {print}' ui/CHANGELOG.md
   ```
2. Identify the **only writable block**: the block whose header contains `(Prowler UNRELEASED)`.
3. Treat every block whose header contains `(Prowler vX.Y.Z)` as immutable. Do not add, move, reword, reorder, or deduplicate entries there.
4. If your PR's entry appears in any of the latest three released blocks, remove it from the released block and add it to the correct section in the UNRELEASED block.
5. If there is no UNRELEASED block at the top, stop and ask before editing.

**Do not trust the current topmost matching section name.** A released block can contain the same section heading (`### 🚀 Added`, `### 🔄 Changed`, etc.). Always anchor edits to the `Prowler UNRELEASED` version block first.

## Mandatory Human Confirmation Gate

Before creating or editing any changelog file (`CHANGELOG.md`), the agent MUST stop and get explicit user confirmation. This applies even when the changelog gate is failing, the required edit seems obvious, or the user asked to "fix the changelog".

Present the proposed changelog action before writing:

1. Target file path.
2. Target version block and section.
3. Exact entry to add, move, remove, or rewrite.
4. Reason the changelog is needed.

Only proceed after an explicit approval such as "confirm", "approved", "sí", or equivalent. If the user rejects or does not answer, do not edit or create the changelog. Offer alternatives such as adding `no-changelog` when appropriate.

## Adding a Changelog Entry

### Step 1: Determine Affected Component(s)

```bash
# Check which files changed
git diff main...HEAD --name-only
```

| Path Pattern | Component |
|--------------|-----------|
| `ui/**` | UI |
| `api/**` | API |
| `mcp_server/**` | MCP Server |
| `prowler/**` | SDK |
| Multiple | Update ALL affected changelogs |

### Step 2: Determine Change Type

| Change | Section |
|--------|---------|
| New feature, check, endpoint | 🚀 Added |
| Behavior change, refactor | 🔄 Changed |
| Bug fix | 🐞 Fixed |
| CVE patch, security improvement | 🔐 Security |
| Feature removal | ❌ Removed |
| Deprecation notice | ⚠️ Deprecated |

### Step 3: Add Entry at BOTTOM of Appropriate Section

**CRITICAL:** Add new entries at the BOTTOM of each section, NOT at the top.

**CRITICAL:** The link MUST point to the PR (`/pull/N`). Linking to `/issues/N` is FORBIDDEN. If the PR closes an issue, that mapping goes in the PR body via `Fixes #N` — never in the changelog entry.

```markdown
## [1.17.0] (Prowler UNRELEASED)

### 🐞 Fixed

- Existing fix one [(#9997)](https://github.com/prowler-cloud/prowler/pull/9997)
- Existing fix two [(#9998)](https://github.com/prowler-cloud/prowler/pull/9998)
- Button alignment in dashboard header [(#9999)](https://github.com/prowler-cloud/prowler/pull/9999)  ← NEW ENTRY AT BOTTOM

### 🔐 Security
```

This maintains chronological order within each section (oldest at top, newest at bottom).

## Examples

### Good Entries

```markdown
### 🚀 Added
- Search bar when adding a provider [(#9634)](https://github.com/prowler-cloud/prowler/pull/9634)

### 🐞 Fixed
- OCI update credentials form failing silently due to missing provider UID [(#9746)](https://github.com/prowler-cloud/prowler/pull/9746)

### 🔐 Security
- Node.js from 20.x to 24.13.0 LTS, patching 8 CVEs [(#9797)](https://github.com/prowler-cloud/prowler/pull/9797)
```

### Readable Technical Entries

```markdown
# GOOD - Technical but readable
### 🐞 Fixed
- `POST /api/v1/scans` no longer intermittently fails with `Scan matching query does not exist`; scan dispatch now publishes the `scan-perform` Celery task after the transaction commits [(#11122)](https://github.com/prowler-cloud/prowler/pull/11122)
- `entra_users_mfa_capable` no longer flags disabled guest users; Microsoft Graph is now the source of truth for `account_enabled` because EXO `Get-User` omits guest users [(#11002)](https://github.com/prowler-cloud/prowler/pull/11002)
```

### Bad Entries

```markdown
# BAD - Wrong section order (Fixed before Added)
### 🐞 Fixed
- Some bug fix [(#123)](...)

### 🚀 Added
- Some new feature [(#456)](...)

- Fixed bug.                              # Too vague, has period
- Added new feature for users             # Missing PR link, redundant verb
- Add search bar [(#123)]                 # Redundant verb (section already says "Added")
- This PR adds a cool new thing (#123)    # Wrong link format, conversational
- Some bug fix [(#123)](https://github.com/prowler-cloud/prowler/issues/123)   # FORBIDDEN: must link to /pull/N, never /issues/N
- POST /api/v1/scanswas intermittently failing withScan matching query does not existin thescan-performworker (#11122)  # Missing spaces/backticks, unreadable
- entra_users_mfa_capable no longer flags disabled guest users by requesting accountEnabled and userType from Microsoft Graph via $select and using Graph as the source of truth for account_enabled (EXO Get-User does not return guest users) (#11002)  # Run-on sentence, identifiers not formatted
```

## PR Changelog Gate

The `pr-check-changelog.yml` workflow enforces changelog entries:

1. **REQUIRED**: PRs touching `ui/`, `api/`, `mcp_server/`, or `prowler/` MUST update the corresponding changelog
2. **SKIP**: Add `no-changelog` label to bypass (use sparingly for docs-only, CI-only changes)

## Commands

```bash
# Check which changelogs need updates based on changed files
git diff main...HEAD --name-only | grep -E '^(ui|api|mcp_server|prowler)/' | cut -d/ -f1 | sort -u

# View current UNRELEASED section
head -50 ui/CHANGELOG.md
head -50 api/CHANGELOG.md
head -50 mcp_server/CHANGELOG.md
head -50 prowler/CHANGELOG.md
```

## Migration Note

**API, MCP Server, and SDK changelogs currently lack emojis.** When editing these files, add emoji prefixes to section headers as you update them:

```markdown
# Before (legacy)
### Added

# After (standardized)
### 🚀 Added
```

## Resources

- **Templates**: See [assets/](assets/) for entry templates
- **keepachangelog.com**: https://keepachangelog.com/en/1.1.0/
