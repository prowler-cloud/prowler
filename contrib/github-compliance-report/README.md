# GitHub SOC 2 / ISO 27001 report

Scan any GitHub repository with a token. Nothing is committed to the target.

Writes `audit-report.md` and `audit-report.csv` grouped by SOC 2 and ISO 27001 (from Prowler’s GitHub checks). Optional IaC/Trivy findings are listed separately, not mapped to those frameworks.

## Run

From the Prowler repo root (`uv sync` once):

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN="$(gh auth token)"
./contrib/github-compliance-report/run.sh owner/repo
```

Example:

```bash
./contrib/github-compliance-report/run.sh amardizdarevic45-wq/Lindle ./audit-out
open ./audit-out/audit-report.csv
```

If the token env vars are unset, the script uses `gh auth token`.

| Flag / arg | Meaning |
|---|---|
| `owner/repo` | Target repository (required) |
| second arg | Output directory (default `./audit-out`) |
| `SKIP_IAC=1` | GitHub API scan only — no clone, no Trivy |

```bash
SKIP_IAC=1 ./contrib/github-compliance-report/run.sh owner/repo ./audit-out
```

## Output

- `audit-report.md` — grouped markdown
- `audit-report.csv` — same rows (`;`-delimited, Excel-friendly in EU locales)
- `github/compliance/` — native Prowler SOC 2 / ISO CSVs
