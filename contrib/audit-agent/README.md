# Prowler Audit Agent

Zero-touch **SOC 2** and **ISO 27001** compliance audits for **any GitHub repository**.

Scan a repo (and optionally its PRs) from the CLI; get findings mapped to controls. There is **no product UI** — reporting is local report files plus optional GitHub-native writes (PR comments, checks, issues).

The agent orchestrates **this monorepo’s Prowler providers and compliance modules** (`prowler-cli.py`, `prowler/providers/*`, `prowler/compliance/*`). It is not a separate scanner engine.

Target repositories do **not** need workflows, Actions, or config files committed into them.

---

## Features

| Aspect | How |
|--------|-----|
| IaC / config | `prowler iac` (Trivy misconfig) |
| Secrets in source | Trivy secret |
| Dependencies / CVEs | Trivy vuln |
| License compliance | Trivy license |
| Containers / Dockerfiles | Via IaC |
| GitHub hardening | `prowler github` (branch protection, secret scanning, Dependabot, org settings) |
| GitHub Actions / CI-CD | Workflow security + CIS GitHub |
| Cloud (aws / azure / gcp / …) | Optional — when credentials are in the environment |

Findings map to SOC 2 / ISO 27001 via:

1. Prowler OCSF compliance tags  
2. Check IDs from `prowler/compliance/**/*.json`  
3. Heuristic fallback (mainly for IaC / Trivy RuleIDs)

---

## Requirements

From the Prowler repository root:

* Python 3.10+ with project deps: `uv sync` (creates `.venv`)
* [Trivy](https://trivy.dev/) on `PATH` (`brew install trivy` on macOS)
* [GitHub CLI](https://cli.github.com/) (`gh`) authenticated with access to target repos  
  — or set `AUDIT_AGENT_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN`

---

## Quick start

```bash
# From the Prowler repo root
source "$HOME/.local/bin/env"   # if uv was installed via the official installer
uv sync
export PYTHONPATH=contrib/audit-agent

# Token: env var, or automatic fallback to `gh auth token`
export AUDIT_AGENT_TOKEN="$(gh auth token)"

# Dry-run: scan + print report (no writes to the target repo)
.venv/bin/python -m audit_agent --repo owner/name --dry-run

# Save markdown + JSON reports
.venv/bin/python -m audit_agent --repo owner/name --dry-run \
  --report-file ./audit-report.md \
  --output-dir ./audit-out

# Sticky PR comment + check run via API (still no commits to the target)
.venv/bin/python -m audit_agent --repo owner/name --pr 12

# Sync control-gap issues on the target
.venv/bin/python -m audit_agent --repo owner/name --sync-issues
```

Without `PYTHONPATH`:

```bash
.venv/bin/python contrib/audit-agent/run.py --repo owner/name --dry-run
```

---

## Outputs

Every run writes (under `--output-dir`, default temp dir):

| File | Contents |
|------|----------|
| `audit-report.md` | Compliance summary (same shape as the PR comment) |
| `audit-findings.json` | Structured findings + metadata |
| `*/**.ocsf.json` / `*.sarif` | Raw Prowler outputs (SARIF for IaC only) |

Use `--report-file PATH` to also write the markdown report to a chosen path.

---

## Configuration

Defaults apply when the target has no config. Optional remote file (fetched over the API if present): `.github/prowler-audit.yml`

See [`prowler-audit.yml.example`](prowler-audit.yml.example).

```yaml
version: 1
frameworks: [soc2, iso27001_2022]
providers: [iac, github]   # add aws/azure/gcp when credentials exist
scanners:
  iac: true
  secrets: true
  dependencies: true
  licenses: true
  github_actions: true
fail-pr-on:
  severity: high
  new-findings-only: true
```

---

## CLI reference

```text
--repo owner/name          Target repository (required)
--pr N                     Filter to PR files; post sticky comment + check
--sync-issues              Open/close control-gap issues on the target
--token TOKEN              GitHub token (else env / gh auth token)
--config PATH              Local config override
--output-dir PATH          Artifact directory (report + findings + raw outputs)
--report-file PATH         Extra path for the markdown report
--dry-run                  Print report; skip GitHub write APIs
--json-summary             Print a JSON summary to stdout
--image-tag TAG            Docker fallback image tag (only if image already local)
```

---

## Layout

```text
contrib/audit-agent/
├── README.md
├── run.py                      # Entry without PYTHONPATH
├── prowler-audit.yml.example
├── mappings/soc2_iso27001.json
└── audit_agent/                # Python package
    ├── __main__.py             # CLI
    ├── scan.py                 # Prowler provider runner
    ├── map_controls.py         # SOC2 / ISO mapping
    ├── prowler_compliance.py   # Compliance framework index
    ├── render.py               # PR / report markdown
    ├── report_files.py         # Persist md + json
    ├── github_api.py           # Optional GitHub API writes
    └── config.py
```

Developer docs: [docs/developer-guide/audit-agent.mdx](../../docs/developer-guide/audit-agent.mdx)
