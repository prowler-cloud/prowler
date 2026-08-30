#!/usr/bin/env bash
# Scan an external GitHub repo (no writes to the target).
# Usage: ./contrib/github-compliance-report/run.sh owner/repo [output-dir]
#        SKIP_IAC=1 …   GitHub checks only (no clone / Trivy)
set -euo pipefail

REPO="${1:-}"
OUT_DIR="${2:-./audit-out}"
TOKEN="${GITHUB_PERSONAL_ACCESS_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"

if [[ -z "${TOKEN}" ]] && command -v gh >/dev/null 2>&1; then
  TOKEN="$(gh auth token 2>/dev/null || true)"
fi

if [[ -z "${REPO}" ]]; then
  echo "Usage: $0 owner/repo [output-dir]" >&2
  exit 1
fi
if [[ -z "${TOKEN}" ]]; then
  echo "Set GITHUB_PERSONAL_ACCESS_TOKEN or run: gh auth login" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

export GITHUB_PERSONAL_ACCESS_TOKEN="${TOKEN}"
export GITHUB_TOKEN="${TOKEN}"
export GH_TOKEN="${TOKEN}"

if [[ ! -f "${ROOT}/prowler-cli.py" ]]; then
  echo "Run this from a Prowler checkout with uv sync." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
PROWLER=(uv run python prowler-cli.py)

run_prowler() {
  set +e
  "${PROWLER[@]}" "$@"
  local rc=$?
  set -e
  # 0 = clean, 3 = findings present
  if [[ "${rc}" -ne 0 && "${rc}" -ne 3 ]]; then
    echo "prowler failed (exit ${rc})" >&2
    return "${rc}"
  fi
}

echo "Running prowler github on ${REPO} …" >&2
run_prowler github \
  --repository "${REPO}" \
  --compliance soc2_github iso27001_2022_github \
  --output-formats json-ocsf csv html \
  --output-directory "${OUT_DIR}/github"

if [[ "${SKIP_IAC:-0}" != "1" ]]; then
  CLONE_DIR="${OUT_DIR}/repo"
  rm -rf "${CLONE_DIR}"
  echo "Cloning ${REPO} for IaC …" >&2
  if command -v gh >/dev/null 2>&1; then
    gh repo clone "${REPO}" "${CLONE_DIR}" -- --depth 1
  else
    git clone --depth 1 "https://x-access-token:${TOKEN}@github.com/${REPO}.git" "${CLONE_DIR}"
  fi
  echo "Running prowler iac …" >&2
  run_prowler iac \
    --scan-path "${CLONE_DIR}" \
    --scanners misconfig secret vuln license \
    --output-formats json-ocsf csv html \
    --output-directory "${OUT_DIR}/iac"
fi

python3 "${ROOT}/contrib/github-compliance-report/report.py" \
  --repo "${REPO}" \
  --out-dir "${OUT_DIR}" \
  --report-file "${OUT_DIR}/audit-report.md" \
  --csv-file "${OUT_DIR}/audit-report.csv"

echo "Wrote ${OUT_DIR}/audit-report.md" >&2
echo "Wrote ${OUT_DIR}/audit-report.csv" >&2
