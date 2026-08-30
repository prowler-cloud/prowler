# GitHub SOC 2 / ISO 27001 Compliance Report

Thin community helper: scan **any** GitHub repository with a personal access token (nothing is committed to the target) and write a single markdown report grouped by SOC 2 / ISO 27001 controls.

## What it does

1. Authenticates to the **remote** repo with `GITHUB_PERSONAL_ACCESS_TOKEN` (`prowler github --repository owner/name` uses the GitHub API — the target is not modified)
2. Clones a shallow copy only for the optional IaC/Trivy pass
3. Runs `prowler github --compliance soc2_github iso27001_2022_github`
4. Optionally runs `prowler iac` on the clone
5. Writes `audit-report.md` and `audit-report.csv` grouped by SOC 2 / ISO 27001 from the native compliance CSVs

IaC findings are listed separately. They are not mapped to SOC 2 / ISO 27001 (the IaC provider has no those frameworks).

## Requirements

- Prowler repo root with `uv sync`
- `GITHUB_PERSONAL_ACCESS_TOKEN` (or `GITHUB_TOKEN` / `GH_TOKEN`) with access to the target repo
- Optional: [GitHub CLI](https://cli.github.com/) (`gh`), [Trivy](https://trivy.dev/) for IaC

## Usage

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
chmod +x contrib/github-compliance-report/run.sh
./contrib/github-compliance-report/run.sh owner/repo ./audit-out
# → ./audit-out/audit-report.md
# → ./audit-out/audit-report.csv
# → ./audit-out/github/compliance/*.csv
# → ./audit-out/iac/  (optional)

SKIP_IAC=1 ./contrib/github-compliance-report/run.sh owner/repo ./audit-out
```

Equivalent without this script:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=...
gh repo clone owner/name /tmp/target -- --depth 1
uv run python prowler-cli.py github --repository owner/name \
  --compliance soc2_github iso27001_2022_github \
  --output-formats json-ocsf csv html
uv run python prowler-cli.py iac --scan-path /tmp/target \
  --scanners misconfig secret vuln license \
  --output-formats json-ocsf html
```
