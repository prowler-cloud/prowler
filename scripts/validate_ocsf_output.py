#!/usr/bin/env python3
"""
OCSF Output Validator

Validates OCSF JSON output files for Prowler Cloud integration requirements:
- finding_info.uid uniqueness across all findings
- resources[*].uid populated for every resource

Usage:
    python validate_ocsf_output.py <path_to_ocsf_json> [...]

Example:
    python validate_ocsf_output.py output/*.ocsf.json
"""

import glob
import json
import sys
from argparse import ArgumentParser
from pathlib import Path


def load_ocsf_file(path: str) -> list[dict]:
    """Load and parse an OCSF JSON file containing an array of findings."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not file_path.suffix == ".json" and not path.endswith(".ocsf.json"):
        raise ValueError(f"Expected .ocsf.json file, got: {path}")

    with open(file_path) as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array, got {type(data).__name__}")

    return data


def validate_unique_finding_uids(findings: list[dict]) -> list[str]:
    """Check that finding_info.uid is present and unique across all findings."""
    errors = []
    seen = {}

    for idx, finding in enumerate(findings):
        finding_info = finding.get("finding_info")
        if not finding_info or not isinstance(finding_info, dict):
            errors.append(f"Finding [{idx}]: missing 'finding_info' object")
            continue

        uid = finding_info.get("uid")
        if not uid:
            errors.append(f"Finding [{idx}]: missing 'finding_info.uid'")
            continue

        if uid in seen:
            errors.append(
                f"Finding [{idx}]: duplicate 'finding_info.uid' = '{uid}' "
                f"(first seen at index {seen[uid]})"
            )
        else:
            seen[uid] = idx

    return errors


def validate_resources_uid(findings: list[dict]) -> list[str]:
    """Check that every resource in every finding has a non-empty uid."""
    errors = []

    for idx, finding in enumerate(findings):
        resources = finding.get("resources")
        if not resources:
            errors.append(f"Finding [{idx}]: missing or empty 'resources' array")
            continue

        if not isinstance(resources, list):
            errors.append(f"Finding [{idx}]: 'resources' is not an array")
            continue

        for res_idx, resource in enumerate(resources):
            uid = resource.get("uid")
            if not uid or (isinstance(uid, str) and not uid.strip()):
                errors.append(
                    f"Finding [{idx}], resource [{res_idx}]: "
                    f"missing or empty 'resources[].uid'"
                )

    return errors


def validate_file(path: str) -> dict:
    """Run all validations on a single OCSF file."""
    result = {"file": path, "valid": True, "errors": [], "finding_count": 0}

    try:
        findings = load_ocsf_file(path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        result["valid"] = False
        result["errors"].append(str(e))
        return result

    result["finding_count"] = len(findings)

    if not findings:
        return result

    uid_errors = validate_unique_finding_uids(findings)
    resource_errors = validate_resources_uid(findings)

    all_errors = uid_errors + resource_errors
    if all_errors:
        result["valid"] = False
        result["errors"] = all_errors

    return result


def print_report(results: list[dict]):
    """Print a formatted validation report."""
    print("\n" + "=" * 60)
    print("OCSF OUTPUT VALIDATION REPORT")
    print("=" * 60)

    total_files = len(results)
    passed = sum(1 for r in results if r["valid"])
    failed = total_files - passed
    total_findings = sum(r["finding_count"] for r in results)

    for result in results:
        print(f"\nFile: {result['file']}")
        print(f"  Findings: {result['finding_count']}")

        if result["valid"]:
            print("  Status: PASS")
        else:
            print("  Status: FAIL")
            for error in result["errors"]:
                print(f"    [X] {error}")

    print("\n" + "-" * 60)
    print(f"Files: {total_files} | Findings: {total_findings}")
    print(f"Passed: {passed} | Failed: {failed}")
    print("-" * 60)

    if failed == 0:
        print("RESULT: PASS")
    else:
        print("RESULT: FAIL")
    print("=" * 60 + "\n")


def main():
    parser = ArgumentParser(
        description="Validate OCSF output files for Prowler Cloud integration"
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="OCSF JSON file path(s) or glob pattern(s)",
    )
    args = parser.parse_args()

    # Expand glob patterns
    file_paths = []
    for pattern in args.files:
        expanded = glob.glob(pattern)
        if expanded:
            file_paths.extend(expanded)
        else:
            file_paths.append(pattern)

    if not file_paths:
        print("Error: No files matched the provided pattern(s).")
        sys.exit(1)

    results = [validate_file(path) for path in file_paths]
    print_report(results)

    sys.exit(0 if all(r["valid"] for r in results) else 1)


if __name__ == "__main__":
    main()
