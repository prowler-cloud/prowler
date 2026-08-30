#!/usr/bin/env bash
# Scan any GitHub repository (no commit to the target) with Prowler GitHub + IaC,
# using SOC 2 and ISO 27001 compliance frameworks when available.
#
# Usage:
#   export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
#   ./contrib/github-compliance-report/run.sh owner/repo [output-dir]
#
# Optional:
#   GITHUB_TOKEN / GH_TOKEN are also accepted if GITHUB_PERSONAL_ACCESS_TOKEN is unset.
#   SKIP_IAC=1 skips the IaC (Trivy) pass.
set -euo pipefail

REPO="${1:-}"
OUT_DIR="${2:-./output/github-compliance-report}"
TOKEN="${GITHUB_PERSONAL_ACCESS_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"

if [[ -z "${REPO}" ]]; then
  echo "Usage: $0 owner/repo [output-dir]" >&2
  exit 1
fi
if [[ -z "${TOKEN}" ]]; then
  echo "Set GITHUB_PERSONAL_ACCESS_TOKEN (or GITHUB_TOKEN / GH_TOKEN)." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

export GITHUB_PERSONAL_ACCESS_TOKEN="${TOKEN}"
export GITHUB_TOKEN="${TOKEN}"
export GH_TOKEN="${TOKEN}"

mkdir -p "${OUT_DIR}"
CLONE_DIR="${OUT_DIR}/repo"
rm -rf "${CLONE_DIR}"

echo "Cloning ${REPO} …" >&2
if command -v gh >/dev/null 2>&1; then
  gh repo clone "${REPO}" "${CLONE_DIR}" -- --depth 1
else
  git clone --depth 1 "https://x-access-token:${TOKEN}@github.com/${REPO}.git" "${CLONE_DIR}"
fi

PROWLER=(uv run python prowler-cli.py)
if [[ ! -f "${ROOT}/prowler-cli.py" ]]; then
  echo "Run this from a Prowler checkout with uv sync." >&2
  exit 1
fi

echo "Running prowler github …" >&2
"${PROWLER[@]}" github \
  --repository "${REPO}" \
  --compliance soc2_github iso27001_2022_github \
  --output-formats json-ocsf csv html \
  --output-directory "${OUT_DIR}/github" \
  || true

if [[ "${SKIP_IAC:-0}" != "1" ]]; then
  echo "Running prowler iac …" >&2
  "${PROWLER[@]}" iac \
    --scan-path "${CLONE_DIR}" \
    --scanners misconfig secret vuln license \
    --output-formats json-ocsf csv html \
    --output-directory "${OUT_DIR}/iac" \
    || true
fi

python3 "${ROOT}/contrib/github-compliance-report/report.py" \
  --repo "${REPO}" \
  --out-dir "${OUT_DIR}" \
  --report-file "${OUT_DIR}/audit-report.md" \
  --csv-file "${OUT_DIR}/audit-report.csv"

echo "Wrote ${OUT_DIR}/audit-report.md" >&2
echo "Wrote ${OUT_DIR}/audit-report.csv" >&2
echo "${OUT_DIR}"
