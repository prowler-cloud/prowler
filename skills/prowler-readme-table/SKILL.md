---
name: prowler-readme-table
description: >
  Updates the "Prowler at a Glance" table in README.md with accurate provider statistics.
  Trigger: When updating README.md provider stats, checks count, services count, compliance frameworks, or categories.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Updating README.md provider statistics table"
    - "Updating checks, services, compliance, or categories count in README.md"
allowed-tools: Read, Edit, Bash, Glob, Grep
---

## When to Use

Use this skill when updating the **Prowler at a Glance** table in the root `README.md`. This table tracks the number of checks, services, compliance frameworks, and categories for each supported provider.

## Procedure

### Step 1: Collect Stats via CLI

Run the following command for **each provider** and **each metric**:

```bash
python3 prowler-cli.py <provider> --list-<metric>
```

**Providers:** `aws`, `azure`, `gcp`, `kubernetes`, `github`, `m365`, `oraclecloud`, `alibabacloud`, `cloudflare`, `mongodbatlas`, `openstack`, `nhn`

**Metrics:** `checks`, `services`, `compliance`, `categories`

The CLI output ends with a summary line like:

```
There are 572 available checks.
There is 1 available Compliance Framework.
```

Extract the number from the summary line. Note that singular results use "There is" instead of "There are".

### Step 2: Batch Extraction

Use this one-liner to collect all stats at once (handles both singular and plural output):

```bash
for provider in aws azure gcp kubernetes github m365 oraclecloud alibabacloud cloudflare mongodbatlas openstack nhn; do
  for metric in checks services compliance categories; do
    result=$(python3 prowler-cli.py $provider --list-$metric 2>&1 | sed -n 's/.*There \(are\|is\) .*\x1b\[33m\([0-9]*\)\x1b\[0m.*/\2/p')
    echo "$provider $metric: $result"
  done
done
```

### Step 3: Update the Table

Edit the table in `README.md` (located in the `# Prowler at a Glance` section) with the collected numbers.

**Table format:**

```markdown
| Provider | Checks | Services | [Compliance Frameworks](...) | [Categories](...) | Support | Interface |
|---|---|---|---|---|---|---|
| AWS | 572 | 83 | 41 | 17 | Official | UI, API, CLI |
```

### Provider Name Mapping

| CLI Provider | Table Display Name |
|---|---|
| `aws` | AWS |
| `azure` | Azure |
| `gcp` | GCP |
| `kubernetes` | Kubernetes |
| `github` | GitHub |
| `m365` | M365 |
| `oraclecloud` | OCI |
| `alibabacloud` | Alibaba Cloud |
| `cloudflare` | Cloudflare |
| `mongodbatlas` | MongoDB Atlas |
| `openstack` | OpenStack |
| `nhn` | NHN |

### Special Rows (No CLI stats)

These providers delegate to external tools and do NOT use CLI stats:

| Provider | Checks Column | Services | Compliance | Categories |
|---|---|---|---|---|
| IaC | `[See trivy docs.](https://trivy.dev/latest/docs/coverage/iac/)` | N/A | N/A | N/A |
| LLM | `[See promptfoo docs.](https://www.promptfoo.dev/docs/red-team/plugins/)` | N/A | N/A | N/A |

### Support and Interface Columns

- **Support**: `Official` for all providers except `NHN` which is `Unofficial`
- **Interface**: Most providers use `UI, API, CLI`. Exceptions with `CLI` only: `Cloudflare`, `OpenStack`, `NHN`, `LLM`

## Rules

- **ALWAYS** use the CLI (`python3 prowler-cli.py`) to obtain numbers. Do NOT count files manually.
- **NEVER** commit changes unless explicitly asked.
- **NEVER** modify the IaC or LLM rows (they link to external docs).
- Verify the CLI is working by running one provider first before batch-processing all.

## Resources

- **CLI entry point**: `prowler-cli.py` in the repository root
- **Table location**: `README.md`, section `# Prowler at a Glance` (around line 100)
