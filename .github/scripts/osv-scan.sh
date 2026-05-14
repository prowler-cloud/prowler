#!/usr/bin/env bash
# Run osv-scanner and fail when findings match the configured severity levels.
#
# Replaces `safety check --policy-file .safety-policy.yml`. Used by:
#   - .github/actions/osv-scanner/action.yml (composite action)
#   - .github/workflows/api-security.yml, sdk-security.yml, ui-security.yml
#
# Severity levels (comma-separated) are read from OSV_SEVERITY_LEVELS.
# Default: HIGH,CRITICAL,UNKNOWN — preserves prior .safety-policy.yml policy
#   (ignore-cvss-severity-below: 7 + ignore-cvss-unknown-severity: False).
# osv-scanner has no native CVSS threshold (google/osv-scanner#1400, closed
# not-planned). Severity is read from database_specific.severity, the GitHub
# Advisory categorical label present on GHSA-prefixed records.
#
# Per-vulnerability ignores (with reason + expiry) live in osv-scanner.toml at
# the repo root, if it exists. Without that file, osv-scanner uses defaults.
#
# Usage:
#   osv-scan.sh [osv-scanner pass-through args...]
# Examples:
#   osv-scan.sh --lockfile=poetry.lock
#   osv-scan.sh --recursive .
#   OSV_SEVERITY_LEVELS=CRITICAL osv-scan.sh --lockfile=poetry.lock

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CONFIG="${ROOT}/osv-scanner.toml"
SEVERITY_LEVELS="${OSV_SEVERITY_LEVELS:-HIGH,CRITICAL,UNKNOWN}"

for bin in osv-scanner jq; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    echo "error: ${bin} not found in PATH" >&2
    exit 2
  fi
done

SCAN_ARGS=()
if [ -f "${CONFIG}" ]; then
  SCAN_ARGS+=(--config="${CONFIG}")
fi

# Exit codes: 0=clean, 1=findings, 127=no supported files, 128=internal error.
STDERR="$(mktemp)"
trap 'rm -f "${STDERR}"' EXIT

set +e
OUTPUT="$(osv-scanner scan source "${SCAN_ARGS[@]}" --format=json "$@" 2>"${STDERR}")"
RC=$?
set -e

case "${RC}" in
  0|1) ;;
  127) echo "osv-scanner: no supported lockfiles in scan target"; exit 0 ;;
  *)
    echo "osv-scanner: exited with code ${RC}" >&2
    [ -s "${STDERR}" ] && cat "${STDERR}" >&2
    exit "${RC}"
    ;;
esac

# Build a JSON array of normalized severity levels for jq.
SEVERITY_JSON="$(printf '%s' "${SEVERITY_LEVELS}" | jq -Rc '
  split(",") | map(ascii_upcase | sub("^\\s+"; "") | sub("\\s+$"; ""))
')"

FINDINGS="$(printf '%s' "${OUTPUT}" | jq --argjson sevs "${SEVERITY_JSON}" '
  [ .results[]?.packages[]?
    | . as $pkg
    | .vulnerabilities[]?
    | { id,
        summary,
        severity: ((.database_specific.severity? // "UNKNOWN") | ascii_upcase),
        package: $pkg.package.name,
        version: $pkg.package.version,
        ecosystem: $pkg.package.ecosystem }
    | select($sevs | index(.severity))
  ]
')"

COUNT="$(printf '%s' "${FINDINGS}" | jq 'length')"

if [ "${COUNT}" -gt 0 ]; then
  echo "osv-scanner: ${COUNT} finding(s) at severity ${SEVERITY_LEVELS}"
  printf '%s' "${FINDINGS}" | jq -r '
    .[] | "  [\(.severity)] \(.id) \(.ecosystem)/\(.package)@\(.version) — \(.summary // "(no summary)")"
  '
  echo
  echo "To accept a finding, create osv-scanner.toml at the repo root with a reason and ignoreUntil."
  exit 1
fi

echo "osv-scanner: no findings at severity levels: ${SEVERITY_LEVELS}"
