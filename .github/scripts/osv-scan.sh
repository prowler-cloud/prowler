#!/usr/bin/env bash
# Run osv-scanner and fail when findings match the configured severity levels.
#
# Replaces `safety check --policy-file .safety-policy.yml`. Used by:
#   - .github/actions/osv-scanner/action.yml (composite action)
#   - .github/workflows/api-security.yml, sdk-security.yml, ui-security.yml
#
# Severity levels (comma-separated) are read from OSV_SEVERITY_LEVELS.
# Default: CRITICAL — only CVSS >= 9.0 findings fail the scan.
# osv-scanner has no native CVSS threshold (google/osv-scanner#1400, closed
# not-planned). Severity is derived from $group.max_severity (numeric CVSS
# score string) which osv-scanner emits per group.
#
# CVSS v3 score → categorical label:
#   CRITICAL  >= 9.0
#   HIGH      >= 7.0
#   MEDIUM    >= 4.0
#   LOW       >  0.0
#   UNKNOWN   no score available
#
# Per-vulnerability ignores (with reason + expiry) live in osv-scanner.toml at
# the repo root, if it exists. Without that file, osv-scanner uses defaults.
#
# Usage:
#   osv-scan.sh [osv-scanner pass-through args...]
# Examples:
#   osv-scan.sh --lockfile=uv.lock
#   osv-scan.sh --recursive .
#   OSV_SEVERITY_LEVELS=CRITICAL osv-scan.sh --lockfile=uv.lock

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CONFIG="${ROOT}/osv-scanner.toml"
SEVERITY_LEVELS="${OSV_SEVERITY_LEVELS:-CRITICAL}"

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

# Walk each vulnerability, look up its group's max_severity (numeric CVSS),
# map to a categorical label, then filter by OSV_SEVERITY_LEVELS.
FINDINGS="$(printf '%s' "${OUTPUT}" | jq --argjson sevs "${SEVERITY_JSON}" '
  [ .results[]?.packages[]?
    | . as $pkg
    | ($pkg.groups // []) as $groups
    | ($pkg.vulnerabilities // [])[]
    | . as $vuln
    | ([ $groups[] | select((.ids // []) | index($vuln.id)) ][0] // {}) as $group
    | (($group.max_severity // "") | tonumber? // null) as $score
    | (if   $score == null then "UNKNOWN"
       elif $score >= 9.0 then "CRITICAL"
       elif $score >= 7.0 then "HIGH"
       elif $score >= 4.0 then "MEDIUM"
       elif $score >  0   then "LOW"
       else                    "UNKNOWN"
       end) as $label
    | {
        id: $vuln.id,
        severity: $label,
        score: $score,
        summary: ($vuln.summary // null),
        package: $pkg.package.name,
        version: $pkg.package.version,
        ecosystem: $pkg.package.ecosystem
      }
    | select(.severity as $s | $sevs | any(. == $s))
  ]
')"

COUNT="$(printf '%s' "${FINDINGS}" | jq 'length')"

# Write the findings JSON to OSV_REPORT_FILE so callers (e.g. the composite
# action's PR-comment step) can consume the same data the gate decision uses.
if [ -n "${OSV_REPORT_FILE:-}" ]; then
  printf '%s' "${FINDINGS}" > "${OSV_REPORT_FILE}"
fi

if [ "${COUNT}" -gt 0 ]; then
  echo "osv-scanner: ${COUNT} finding(s) at severity ${SEVERITY_LEVELS}"
  printf '%s' "${FINDINGS}" | jq -r '
    .[] | "  [\(.severity)\(if .score then " \(.score)" else "" end)] \(.id) \(.ecosystem)/\(.package)@\(.version) — \(.summary // "(no summary)")"
  '
  echo
  echo "To accept a finding, create osv-scanner.toml at the repo root with a reason and ignoreUntil."
  exit 1
fi

echo "osv-scanner: no findings at severity levels: ${SEVERITY_LEVELS}"
