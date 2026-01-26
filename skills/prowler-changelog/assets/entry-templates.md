# Changelog Entry Templates

## Section Headers

```markdown
### 🚀 Added
### 🔄 Changed
### ⚠️ Deprecated
### ❌ Removed
### 🐞 Fixed
### 🔐 Security
```

## Entry Patterns

> **Note:** Section headers already provide the verb. Entries describe WHAT, not the action.

### Feature Addition (🚀 Added)
```markdown
- Search bar when adding a provider [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- `{check_id}` check for {provider} provider [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- `/api/v1/{endpoint}` endpoint to {description} [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
```

### Behavior Change (🔄 Changed)
```markdown
- Lighthouse AI MCP tool filtering from blacklist to whitelist approach [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- {package} from {old} to {new} [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
```

### Bug Fix (🐞 Fixed)
```markdown
- OCI update credentials form failing silently due to missing provider UID [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- {What was broken} in {component} [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
```

### Security Patch (🔐 Security)
```markdown
- Node.js from 20.x to 24.13.0 LTS, patching 8 CVEs [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
- {package} to version {version} (CVE-XXXX-XXXXX) [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
```

### Removal (❌ Removed)
```markdown
- Deprecated {feature} from {location} [(#XXXX)](https://github.com/prowler-cloud/prowler/pull/XXXX)
```

## Version Header Templates

### Unreleased
```markdown
## [X.Y.Z] (Prowler UNRELEASED)
```

### Released
```markdown
## [X.Y.Z] (Prowler vA.B.C)

---
```

## Full Entry Example

```markdown
## [1.17.0] (Prowler UNRELEASED)

### 🚀 Added

- Search bar when adding a provider [(#9634)](https://github.com/prowler-cloud/prowler/pull/9634)
- New findings table UI with new design system components [(#9699)](https://github.com/prowler-cloud/prowler/pull/9699)

### 🔄 Changed

- Lighthouse AI MCP tool filtering from blacklist to whitelist approach [(#9802)](https://github.com/prowler-cloud/prowler/pull/9802)

### 🐞 Fixed

- OCI update credentials form failing silently due to missing provider UID [(#9746)](https://github.com/prowler-cloud/prowler/pull/9746)

### 🔐 Security

- Node.js from 20.x to 24.13.0 LTS, patching 8 CVEs [(#9797)](https://github.com/prowler-cloud/prowler/pull/9797)

---
```
