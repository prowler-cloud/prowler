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
- One entry per PR (can link multiple PRs for related changes)
- No period at the end
- Do NOT start with redundant verbs (section header already provides the action)

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

### Bad Entries

```markdown
- Fixed bug.                              # Too vague, has period
- Added new feature for users             # Missing PR link, redundant verb
- Add search bar [(#123)]                 # Redundant verb (section already says "Added")
- This PR adds a cool new thing (#123)    # Wrong link format, conversational
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
