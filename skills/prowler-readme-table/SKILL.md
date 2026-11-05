---
name: prowler-readme-table
description: >
  Updates the "Prowler at a Glance" table in README.md with accurate provider statistics.
  Trigger: When updating README.md provider stats, checks count, services count, compliance frameworks, or categories.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke:
    - "Updating README.md provider statistics table"
    - "Updating checks, services, compliance, or categories count in README.md"
allowed-tools: Read, Edit, Bash, Glob, Grep
---

## When to Use

Updating the **Prowler at a Glance** table in the root `README.md` (checks, services, compliance frameworks
and categories per provider).

## Rules

- **ALWAYS** take numbers from the CLI (`uv run python prowler-cli.py <provider> --list-<metric>`). Do not
  count files: `--list-compliance` includes universal top-level frameworks and entry-point plug-ins.
- Only change the four numeric columns. Keep row order, display names, `[Contact us]` links, and the
  Support / Interface columns as they are unless explicitly asked.
- **NEVER** touch the IaC, LLM and Image rows (no CLI stats: external-tool providers).
- Run one provider first to confirm the CLI works, then batch.
- **NEVER** commit unless asked.

## Step 1: Collect stats

The listing commands need no credentials. Each ends with a summary line such as
`There are 668 available checks.` (singular: `There is 1 available ...`), with the number wrapped in ANSI
color codes.

```bash
for provider in aws azure gcp kubernetes github m365 oraclecloud alibabacloud cloudflare mongodbatlas \
                googleworkspace openstack vercel okta linode huaweicloud e2enetworks scaleway stackit nhn; do
  for metric in checks services compliance categories; do
    n=$(uv run python prowler-cli.py "$provider" --list-$metric --no-banner 2>/dev/null \
        | sed -E 's/\x1b\[[0-9;]*m//g' | grep -Eo 'There (are|is) [0-9]+' | grep -Eo '[0-9]+')
    echo "$provider $metric: ${n:-ERROR}"
  done
done
```

The pipeline works with both GNU and BSD (macOS) `sed`. `ERROR` means the summary line was not found: rerun
that command without `2>/dev/null` and check the provider name.

## Step 2: Update the table

```markdown
| Provider | Checks | Services | [Compliance Frameworks](...) | [Categories](...) | Support | Interface |
|---|---|---|---|---|---|---|
| AWS | 668 | 89 | 50 | 19 | Official | UI, API, CLI |
```

| CLI provider | Row name in README |
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
| `googleworkspace` | Google Workspace |
| `openstack` | OpenStack |
| `vercel` | Vercel |
| `okta` | Okta |
| `linode` | Linode |
| `huaweicloud` | Huawei Cloud |
| `e2enetworks` | E2E Networks |
| `scaleway` | Scaleway |
| `stackit` | StackIT |
| `nhn` | NHN |

If a provider directory exists under `prowler/providers/` with no README row (or the reverse), report it
instead of inventing a row.

## Commands

```bash
ls prowler/providers/                                       # provider keys
uv run python prowler-cli.py aws --list-checks --no-banner | tail -2
grep -n "Prowler at a Glance" README.md                     # table location
```
