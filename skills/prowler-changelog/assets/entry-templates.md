# Changelog Fragment Templates

## Fragment basics

One fragment file per entry, under the component's `changelog.d/`:

```text
<component>/changelog.d/<slug>.<type>.md
```

- `<slug>`: free-form, descriptive (`[A-Za-z0-9][A-Za-z0-9._-]*`)
- `<type>`: `added`, `changed`, `deprecated`, `removed`, `fixed`, `security`
- Content: a single line with the entry text. **No PR link** (attached automatically at compile time) and no trailing period.

> **Note:** The section header already provides the verb. Entries describe WHAT, not the action.

## Content Patterns by Type

### Feature Addition (`.added.md`)

```text
Search bar when adding a provider
`{check_id}` check for {provider} provider
`/api/v1/{endpoint}` endpoint to {description}
```

### Behavior Change (`.changed.md`)

```text
Lighthouse AI MCP tool filtering from blacklist to whitelist approach
{package} from {old} to {new}
```

### Bug Fix (`.fixed.md`)

```text
OCI update credentials form failing silently due to missing provider UID
{What was broken} in {component}
```

### Security Patch (`.security.md`)

```text
Node.js from 20.x to 24.13.0 LTS, patching 8 CVEs
{package} to version {version} (CVE-XXXX-XXXXX)
```

### Removal (`.removed.md`)

```text
Deprecated {feature} from {location}
```

## Full Examples

```bash
echo 'Search bar when adding a provider' > ui/changelog.d/provider-search-bar.added.md

echo '`kms_key_rotation_max_90_days` check for GCP provider, verifying KMS customer-managed keys are rotated every 90 days or less' > prowler/changelog.d/kms-rotation-90d.added.md

echo 'OCI update credentials form failing silently due to missing provider UID' > ui/changelog.d/oci-credentials-form.fixed.md
```

Several entries in one PR → one file per entry, freely mixing types (different slugs when the type repeats):

```text
prowler/changelog.d/kms-rotation-check.added.md
prowler/changelog.d/kms-rotation-docs.added.md
prowler/changelog.d/kms-metadata-cache.changed.md
prowler/changelog.d/kms-disabled-keys.fixed.md
```

> **Remember:** never include the PR link in the fragment text; the compile step resolves and appends it automatically.
