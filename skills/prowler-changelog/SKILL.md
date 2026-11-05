---
name: prowler-changelog
description: >
  Manages Prowler changelog entries as towncrier fragments (`<component>/changelog.d/<slug>.<type>.md`) compiled into keepachangelog-style CHANGELOG.md files at release time.
  Trigger: When creating PRs, adding changelog entries or fragments, fixing a failing changelog gate, or working with changelog.d/ or CHANGELOG.md in ui/, api/, mcp_server/, or prowler/.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.1"
  scope: [root, ui, api, sdk, mcp_server]
  auto_invoke:
    - "Add changelog entry for a PR or feature"
    - "Add or edit changelog fragments in <component>/changelog.d/"
    - "Create PR that requires changelog entry"
    - "Review changelog format and conventions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## How changelog entries work: fragments

A PR never edits `CHANGELOG.md` directly: the PR gate fails on any change to a component `CHANGELOG.md` (only exception: released-block corrections with the `no-changelog` label, see below). Instead, add one small **fragment file** per entry under the component's `changelog.d/`. At release time [towncrier](https://towncrier.readthedocs.io/) compiles the fragments into `CHANGELOG.md` and deletes them, so concurrent PRs never conflict.

| Component | Fragments directory | Compiled file | towncrier config |
|-----------|---------------------|---------------|------------------|
| SDK | `prowler/changelog.d/` | `prowler/CHANGELOG.md` | `prowler/towncrier.toml` |
| API | `api/changelog.d/` | `api/CHANGELOG.md` | `api/towncrier.toml` |
| UI | `ui/changelog.d/` | `ui/CHANGELOG.md` | `ui/towncrier.toml` |
| MCP Server | `mcp_server/changelog.d/` | `mcp_server/CHANGELOG.md` | `mcp_server/towncrier.toml` |

All four configs share the template `.github/towncrier/template.md.jinja`. "What's unreleased" = "what's in `changelog.d/`". The compiled `CHANGELOG.md` files contain only released versions.

## Fragment filename

```text
<slug>.<type>.md
```

- `<slug>`: free-form, `[A-Za-z0-9][A-Za-z0-9._-]*`, descriptive of the change (e.g. `securityhub-delegated-admin`). Prefer a descriptive slug.
- An all-digit slug is taken literally as the PR number (`.github/scripts/changelog_attribution.py` skips PR lookup for it), so use `13245.fixed.md` only when you know the real PR number.
- `<type>` maps 1:1 to the sections (from `towncrier.toml`):

| `<type>` | Section | Usage |
|----------|---------|-------|
| `added` | `### 🚀 Added` | New features, checks, endpoints |
| `changed` | `### 🔄 Changed` | Modifications to existing functionality |
| `deprecated` | `### ⚠️ Deprecated` | Features marked for removal |
| `removed` | `### ❌ Removed` | Deleted features (major releases only) |
| `fixed` | `### 🐞 Fixed` | Bug fixes |
| `security` | `### 🔐 Security` | Security patches, CVE fixes, vulnerable dependency bumps |

- The gate regex also accepts an optional numeric counter (`<slug>.<type>.<N>.md`); you never need it, the compile step adds it on collisions.
- One file per entry. A PR touching Added, Changed and Fixed ships `kms-rotation-check.added.md` + `kms-metadata-cache.changed.md` + `kms-disabled-keys.fixed.md`; all compile with the same PR link into their own sections.
- Several entries of the SAME type: a different slug per entry (`kms-rotation-check.added.md`, `kms-rotation-docs.added.md`).
- At least one fragment per touched component.

## Fragment content

The file contains ONLY the entry text, exactly as it should appear in the changelog, on a single line ending with a newline:

```bash
echo '`securityhub_delegated_admin_enabled_all_regions` check for AWS provider, verifying that Security Hub has a delegated administrator, is active in all opted-in regions, and has organization auto-enable on' > prowler/changelog.d/securityhub-delegated-admin.added.md
```

**Rules:**

- **NEVER write a PR or issue link.** The compile workflow resolves the PR that added the fragment from git history and appends `[(#NNNN)](...)`. The gate fails on `[(#N)]`, `[#N](`, `(#N)` and any `github.com/<owner>/<repo>/pull|issues/N` URL.
- No period at the end
- Do NOT start with redundant verbs (the section header already provides the action)
- Be specific: what changed, not why (that's in the PR)
- Use spaces around inline code and product names; wrap check IDs, endpoints, commands, errors, task names and file paths in backticks
- Avoid run-on sentences: one concise result plus at most one context clause

### Good fragments

```text
# ui/changelog.d/provider-search-bar.added.md
Search bar when adding a provider

# api/changelog.d/scan-dispatch-race.fixed.md
`POST /api/v1/scans` no longer intermittently fails with `Scan matching query does not exist`; scan dispatch now publishes the `scan-perform` Celery task after the transaction commits

# prowler/changelog.d/pyasn1-joserfc-cves.security.md
pyasn1 to 0.6.5 and joserfc to 1.7.5 in the SDK, patching the ASN.1 decoding and JWE decryption denial of service advisories
```

### Bad fragments

```text
Fixed bug.                              # Too vague, has period, redundant verb
Add search bar                          # Redundant verb (the section already says "Added")
Search bar [(#9634)](https://github.com/prowler-cloud/prowler/pull/9634)   # NEVER include the PR link; the gate fails
```

## Mandatory Human Confirmation Gate

Before creating or editing any changelog fragment or `CHANGELOG.md` file, the agent MUST stop and get explicit user confirmation. This applies even when the changelog gate is failing, the required file seems obvious, or the user asked to "fix the changelog".

Present the proposed action before writing:

1. Target fragment path (component, slug, type) or CHANGELOG.md edit.
2. Exact entry text.
3. Reason the changelog entry is needed.

Only proceed after an explicit approval such as "confirm", "approved", "sí", or equivalent. If the user rejects or does not answer, do not create or edit anything. Offer alternatives such as adding `no-changelog` when appropriate.

## Adding a Changelog Entry

### Step 1: Determine affected component(s)

```bash
git diff master...HEAD --name-only | grep -E '^(ui|api|mcp_server|prowler)/' | cut -d/ -f1 | sort -u
git diff master...HEAD --name-only | grep -E '^(uv\.lock|pyproject\.toml)$'   # root deps -> SDK fragment
```

| Path pattern | Fragment goes in |
|--------------|------------------|
| `prowler/**` | `prowler/changelog.d/` |
| `api/**` | `api/changelog.d/` |
| `ui/**` | `ui/changelog.d/` |
| `mcp_server/**` | `mcp_server/changelog.d/` |
| Root `uv.lock` / `pyproject.toml` | `prowler/changelog.d/` (the gate maps root deps to the SDK) |
| `tests/`, `docs/`, `.github/`, `skills/`, `dashboard/`, `util/` only | No fragment required (not monitored) |
| Multiple components | One fragment per component |

### Step 2: Create the fragment(s) (after confirmation)

```bash
echo 'Entry text describing the change' > <component>/changelog.d/<slug>.<type>.md
```

### Step 3: Preview the compiled result (writes nothing)

```bash
uvx towncrier==25.8.0 build --draft --config prowler/towncrier.toml --version 0.0.0 --name "Prowler vX.Y.Z"
```

In the draft, links show the slug (`#my-slug`) because PR attribution only runs in the compile workflow; that is expected.

## PR Changelog Gate (`.github/workflows/pr-check-changelog.yml`)

Runs on PRs to `master` and `v5.*`. It fails when:

1. **Missing**: a change under `api/`, `ui/`, `prowler/`, `mcp_server/` (or root `uv.lock`/`pyproject.toml` for the SDK) has no fragment added, modified, or renamed in the matching `changelog.d/`
2. **Invalid name**: an added fragment does not match `^[A-Za-z0-9][A-Za-z0-9._-]*\.(added|changed|deprecated|removed|fixed|security)(\.[0-9]+)?\.md$`
3. **Hand-written link**: a touched fragment contains a PR/issue link
4. **Direct edit**: the PR changes any `<component>/CHANGELOG.md`

The `no-changelog` label skips the whole job. Use it for PRs that genuinely need no entry (CI-only, test-only refactors, compile PRs, released-block corrections), not to dodge a required one.

## Release Flow (compile)

- `compile-changelogs.yml` (manual dispatch: `prowler_version` + `target_branch`) renames each fragment to its PR number with `.github/scripts/changelog_attribution.py`, runs `towncrier build` per component, and opens a `chore(changelog): vX.Y.Z` PR labeled `no-changelog` and `skip-sync`. A human reviews and squash-merges it; `prepare-release.yml` then extracts the stamped sections.
- Component versions are auto-derived: SDK mirrors the Prowler version, UI is `1.<minor>.<patch>`, API is `1.<minor + 1>.<patch>`, MCP Server bumps from its pending fragment types. Per-component inputs override a version or `skip` a component.
- The compile fails if: a component has pending `removed` fragments without an explicit major version input, `CHANGELOG.md` lost the `<!-- changelog: release notes start -->` marker, or it contains a hand-written `(Prowler UNRELEASED)` block.
- Fragments whose PR cannot be resolved are renamed `+<slug>.<type>.md` and render without a link.
- **Minor release (X.Y.0):** compile on `master` before cutting `v5.X`.
- **Patch release (X.Y.Z):** fixes are backported to `v5.X` with their fragments; compile on `v5.X`. The same run opens a forward-sync PR to `master` that inserts the stamped block and deletes the consumed fragments; merge it right after.

## Fixing an already-released entry

Released version blocks are immutable except for typo/correction fixes: edit `CHANGELOG.md` directly and add the `no-changelog` label.

If an entry shipped in the wrong released block (e.g. the PR merged after its release was cut), delete it from that block and recreate it as `<component>/changelog.d/<PR>.<type>.md` (all-digit slug = real PR number), with the `no-changelog` label.

## Compiled CHANGELOG.md format (reference only, never hand-write)

```markdown
<!-- changelog: release notes start -->

## [X.Y.Z] (Prowler vA.B.C)

### 🚀 Added

- Entry text [(#NNNN)](https://github.com/prowler-cloud/prowler/pull/NNNN)

### 🐞 Fixed

- Fix entry [(#NNNN)](https://github.com/prowler-cloud/prowler/pull/NNNN)

---
```

Section order is always Added, Changed, Deprecated, Removed, Fixed, Security. `X.Y.Z` is the COMPONENT version; `A.B.C` is the Prowler release. Entries link to the PR, never to `/issues/N` (put `Fixes #N` in the PR body instead).

## Commands

```bash
ls prowler/changelog.d/ api/changelog.d/ ui/changelog.d/ mcp_server/changelog.d/   # pending fragments
uvx towncrier==25.8.0 build --draft --config api/towncrier.toml --version 0.0.0 --name "Prowler vX.Y.Z"
```

## Resources

- **Templates**: See [assets/entry-templates.md](assets/entry-templates.md) for fragment content patterns
- **Per-directory rules**: `<component>/changelog.d/README.md`
- **Gate and compile**: `.github/workflows/pr-check-changelog.yml`, `.github/workflows/compile-changelogs.yml`, `.github/scripts/changelog_attribution.py`
