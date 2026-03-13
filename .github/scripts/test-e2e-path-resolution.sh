#!/usr/bin/env bash
#
# Test script for E2E test path resolution logic from ui-e2e-tests-v2.yml.
# Validates that the shell logic correctly transforms E2E_TEST_PATHS into
# Playwright-compatible paths.
#
# Usage: .github/scripts/test-e2e-path-resolution.sh

set -euo pipefail

# -- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

# -- Counters ----------------------------------------------------------------
TOTAL=0
PASSED=0
FAILED=0

# -- Temp directory setup & cleanup ------------------------------------------
TMPDIR_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

# ---------------------------------------------------------------------------
# create_test_tree DIR [SUBDIRS_WITH_TESTS...]
#
# Creates a fake ui/tests/ tree inside DIR.
# All standard subdirs are created (empty).
# For each name in SUBDIRS_WITH_TESTS, a fake .spec.ts file is placed inside.
# ---------------------------------------------------------------------------
create_test_tree() {
  local base="$1"; shift
  local all_subdirs=(
    auth home invitations profile providers scans
    setups sign-in-base sign-up attack-paths findings
    compliance browse manage-groups roles users overview
    integrations
  )

  for d in "${all_subdirs[@]}"; do
    mkdir -p "${base}/tests/${d}"
  done

  # Populate requested subdirs with a fake test file
  for d in "$@"; do
    mkdir -p "${base}/tests/${d}"
    touch "${base}/tests/${d}/example.spec.ts"
  done
}

# ---------------------------------------------------------------------------
# resolve_paths E2E_TEST_PATHS WORKING_DIR
#
# Extracted EXACT logic from .github/workflows/ui-e2e-tests-v2.yml lines 212-250.
# Outputs space-separated TEST_PATHS, or "SKIP" if no tests found.
# Must be run with WORKING_DIR as the cwd equivalent (we cd into it).
# ---------------------------------------------------------------------------
resolve_paths() {
  local E2E_TEST_PATHS="$1"
  local WORKING_DIR="$2"

  (
    cd "$WORKING_DIR"

    # --- Line 212-214: strip ui/ prefix, strip **, deduplicate ---------------
    TEST_PATHS="${E2E_TEST_PATHS}"
    TEST_PATHS=$(echo "$TEST_PATHS" | sed 's|ui/||g' | sed 's|\*\*||g' | tr ' ' '\n' | sort -u)

    # --- Line 216: drop setup helpers ----------------------------------------
    TEST_PATHS=$(echo "$TEST_PATHS" | grep -v '^tests/setups/' || true)

    # --- Lines 219-230: safety net for bare tests/ --------------------------
    if echo "$TEST_PATHS" | grep -qx 'tests/'; then
      SPECIFIC_DIRS=""
      for dir in tests/*/; do
        [[ "$dir" == "tests/setups/" ]] && continue
        SPECIFIC_DIRS="${SPECIFIC_DIRS}${dir}"$'\n'
      done
      TEST_PATHS=$(echo "$TEST_PATHS" | grep -vx 'tests/' || true)
      TEST_PATHS="${TEST_PATHS}"$'\n'"${SPECIFIC_DIRS}"
      TEST_PATHS=$(echo "$TEST_PATHS" | grep -v '^$' | sort -u)
    fi

    # --- Lines 231-234: bail if empty ----------------------------------------
    if [[ -z "$TEST_PATHS" ]]; then
      echo "SKIP"
      return
    fi

    # --- Lines 236-245: filter dirs with no test files -----------------------
    VALID_PATHS=""
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if find "$p" -name '*.spec.ts' -o -name '*.test.ts' 2>/dev/null | head -1 | grep -q .; then
        VALID_PATHS="${VALID_PATHS}${p}"$'\n'
      fi
    done <<< "$TEST_PATHS"
    VALID_PATHS=$(echo "$VALID_PATHS" | grep -v '^$')

    # --- Lines 246-249: bail if all empty ------------------------------------
    if [[ -z "$VALID_PATHS" ]]; then
      echo "SKIP"
      return
    fi

    # --- Line 250: final output (space-separated) ---------------------------
    echo "$VALID_PATHS" | tr '\n' ' ' | sed 's/ $//'
  )
}

# ---------------------------------------------------------------------------
# run_test NAME INPUT EXPECTED_TYPE [EXPECTED_VALUE]
#
# EXPECTED_TYPE is one of:
#   "contains <path>"  — output must contain this path
#   "equals <value>"   — output must exactly equal this value
#   "skip"             — expect SKIP (no runnable tests)
#   "not_contains <p>" — output must NOT contain this path
#
# Multiple expectations can be specified by calling assert_* after run_test.
# For convenience, run_test supports a single assertion inline.
# ---------------------------------------------------------------------------
CURRENT_RESULT=""
CURRENT_TEST_NAME=""

run_test() {
  local name="$1"
  local input="$2"
  local expect_type="$3"
  local expect_value="${4:-}"

  TOTAL=$((TOTAL + 1))
  CURRENT_TEST_NAME="$name"

  # Create a fresh temp tree per test
  local test_dir="${TMPDIR_ROOT}/test_${TOTAL}"
  mkdir -p "$test_dir"

  # Default populated dirs: scans, providers, auth, home, profile, sign-up, sign-in-base
  create_test_tree "$test_dir" scans providers auth home profile sign-up sign-in-base

  CURRENT_RESULT=$(resolve_paths "$input" "$test_dir")

  _check "$expect_type" "$expect_value"
}

# Like run_test but lets caller specify which subdirs have test files.
run_test_custom_tree() {
  local name="$1"
  local input="$2"
  local expect_type="$3"
  local expect_value="${4:-}"
  shift 4
  local populated_dirs=("$@")

  TOTAL=$((TOTAL + 1))
  CURRENT_TEST_NAME="$name"

  local test_dir="${TMPDIR_ROOT}/test_${TOTAL}"
  mkdir -p "$test_dir"

  create_test_tree "$test_dir" "${populated_dirs[@]}"

  CURRENT_RESULT=$(resolve_paths "$input" "$test_dir")

  _check "$expect_type" "$expect_value"
}

_check() {
  local expect_type="$1"
  local expect_value="$2"

  case "$expect_type" in
    skip)
      if [[ "$CURRENT_RESULT" == "SKIP" ]]; then
        _pass
      else
        _fail "expected SKIP, got: '$CURRENT_RESULT'"
      fi
      ;;
    contains)
      if [[ "$CURRENT_RESULT" == *"$expect_value"* ]]; then
        _pass
      else
        _fail "expected to contain '$expect_value', got: '$CURRENT_RESULT'"
      fi
      ;;
    not_contains)
      if [[ "$CURRENT_RESULT" != *"$expect_value"* ]]; then
        _pass
      else
        _fail "expected NOT to contain '$expect_value', got: '$CURRENT_RESULT'"
      fi
      ;;
    equals)
      if [[ "$CURRENT_RESULT" == "$expect_value" ]]; then
        _pass
      else
        _fail "expected exactly '$expect_value', got: '$CURRENT_RESULT'"
      fi
      ;;
    *)
      _fail "unknown expect_type: $expect_type"
      ;;
  esac
}

_pass() {
  PASSED=$((PASSED + 1))
  printf '%b  PASS%b %s\n' "$GREEN" "$RESET" "$CURRENT_TEST_NAME"
}

_fail() {
  FAILED=$((FAILED + 1))
  printf '%b  FAIL%b %s\n' "$RED" "$RESET" "$CURRENT_TEST_NAME"
  printf "        %s\n" "$1"
}

# ===========================================================================
# TEST CASES
# ===========================================================================

echo ""
printf '%bE2E Path Resolution Tests%b\n' "$BOLD" "$RESET"
echo "=========================================="

# 1. Normal single module
run_test \
  "1. Normal single module" \
  "ui/tests/scans/**" \
  "contains" "tests/scans/"

# 2. Multiple modules
run_test \
  "2. Multiple modules — scans present" \
  "ui/tests/scans/** ui/tests/providers/**" \
  "contains" "tests/scans/"

run_test \
  "2. Multiple modules — providers present" \
  "ui/tests/scans/** ui/tests/providers/**" \
  "contains" "tests/providers/"

# 3. Broad pattern (many modules)
run_test \
  "3. Broad pattern — no bare tests/" \
  "ui/tests/auth/** ui/tests/scans/** ui/tests/providers/** ui/tests/home/** ui/tests/profile/**" \
  "not_contains" "tests/ "

# 4. Empty directory
run_test \
  "4. Empty directory — skipped" \
  "ui/tests/attack-paths/**" \
  "skip"

# 5. Mix of populated and empty dirs
run_test \
  "5. Mix populated+empty — scans present" \
  "ui/tests/scans/** ui/tests/attack-paths/**" \
  "contains" "tests/scans/"

run_test \
  "5. Mix populated+empty — attack-paths absent" \
  "ui/tests/scans/** ui/tests/attack-paths/**" \
  "not_contains" "tests/attack-paths/"

# 6. All empty directories
run_test \
  "6. All empty directories" \
  "ui/tests/attack-paths/** ui/tests/findings/**" \
  "skip"

# 7. Setup paths filtered
run_test \
  "7. Setup paths filtered out" \
  "ui/tests/setups/**" \
  "skip"

# 8. Bare tests/ from broad pattern — safety net expands
run_test \
  "8. Bare tests/ expands — scans present" \
  "ui/tests/**" \
  "contains" "tests/scans/"

run_test \
  "8. Bare tests/ expands — setups excluded" \
  "ui/tests/**" \
  "not_contains" "tests/setups/"

# 9. Bare tests/ with all empty subdirs (only setups has files)
run_test_custom_tree \
  "9. Bare tests/ — only setups has files" \
  "ui/tests/**" \
  "skip" "" \
  setups

# 10. Duplicate paths
run_test \
  "10. Duplicate paths — deduplicated" \
  "ui/tests/scans/** ui/tests/scans/**" \
  "equals" "tests/scans/"

# 11. Empty input
TOTAL=$((TOTAL + 1))
CURRENT_TEST_NAME="11. Empty input"
test_dir="${TMPDIR_ROOT}/test_${TOTAL}"
mkdir -p "$test_dir"
create_test_tree "$test_dir" scans providers
CURRENT_RESULT=$(resolve_paths "" "$test_dir")
_check "skip" ""

# 12. Trailing/leading whitespace
run_test \
  "12. Whitespace handling" \
  "  ui/tests/scans/**  " \
  "contains" "tests/scans/"

# 13. Path without ui/ prefix
run_test \
  "13. Path without ui/ prefix" \
  "tests/scans/**" \
  "contains" "tests/scans/"

# 14. Setup mixed with valid paths — only valid pass through
run_test \
  "14. Setups + valid — setups filtered" \
  "ui/tests/setups/** ui/tests/scans/**" \
  "contains" "tests/scans/"

run_test \
  "14. Setups + valid — setups absent" \
  "ui/tests/setups/** ui/tests/scans/**" \
  "not_contains" "tests/setups/"

# ===========================================================================
# SUMMARY
# ===========================================================================

echo ""
echo "=========================================="
if [[ "$FAILED" -eq 0 ]]; then
  printf '%b%bAll tests passed: %d/%d%b\n' "$GREEN" "$BOLD" "$PASSED" "$TOTAL" "$RESET"
else
  printf '%b%b%d/%d passed, %d FAILED%b\n' "$RED" "$BOLD" "$PASSED" "$TOTAL" "$FAILED" "$RESET"
fi
echo ""

exit "$FAILED"
