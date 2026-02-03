#!/usr/bin/env python3
"""
Prowler Compliance Framework Validator

Validates compliance framework JSON files for:
- JSON syntax validity
- Check existence in codebase
- Duplicate requirement IDs
- Required field completeness
- Assessment status consistency

Usage:
    python validate_compliance.py <path_to_compliance_json>

Example:
    python validate_compliance.py prowler/compliance/azure/cis_5.0_azure.json
"""

import json
import os
import sys
from pathlib import Path


def find_project_root():
    """Find the Prowler project root directory."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "prowler" / "providers").exists():
            return parent
    return None


def get_existing_checks(project_root: Path, provider: str) -> set:
    """Find all existing checks for a provider in the codebase."""
    checks = set()
    services_path = (
        project_root / "prowler" / "providers" / provider.lower() / "services"
    )

    if not services_path.exists():
        return checks

    for service_dir in services_path.iterdir():
        if service_dir.is_dir() and not service_dir.name.startswith("__"):
            for check_dir in service_dir.iterdir():
                if check_dir.is_dir() and not check_dir.name.startswith("__"):
                    check_file = check_dir / f"{check_dir.name}.py"
                    if check_file.exists():
                        checks.add(check_dir.name)

    return checks


def validate_compliance_framework(json_path: str) -> dict:
    """Validate a compliance framework JSON file."""
    results = {"valid": True, "errors": [], "warnings": [], "stats": {}}

    # 1. Check file exists
    if not os.path.exists(json_path):
        results["valid"] = False
        results["errors"].append(f"File not found: {json_path}")
        return results

    # 2. Validate JSON syntax
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        results["valid"] = False
        results["errors"].append(f"Invalid JSON syntax: {e}")
        return results

    # 3. Check required top-level fields
    required_fields = [
        "Framework",
        "Name",
        "Version",
        "Provider",
        "Description",
        "Requirements",
    ]
    for field in required_fields:
        if field not in data:
            results["valid"] = False
            results["errors"].append(f"Missing required field: {field}")

    if not results["valid"]:
        return results

    # 4. Extract provider
    provider = data.get("Provider", "").lower()

    # 5. Find project root and existing checks
    project_root = find_project_root()
    if project_root:
        existing_checks = get_existing_checks(project_root, provider)
    else:
        existing_checks = set()
        results["warnings"].append(
            "Could not find project root - skipping check existence validation"
        )

    # 6. Validate requirements
    requirements = data.get("Requirements", [])
    all_checks = set()
    requirement_ids = []
    automated_count = 0
    manual_count = 0
    empty_automated = []

    for req in requirements:
        req_id = req.get("Id", "UNKNOWN")
        requirement_ids.append(req_id)

        # Collect checks
        checks = req.get("Checks", [])
        all_checks.update(checks)

        # Check assessment status
        attributes = req.get("Attributes", [{}])
        if attributes:
            status = attributes[0].get("AssessmentStatus", "Unknown")
            if status == "Automated":
                automated_count += 1
                if not checks:
                    empty_automated.append(req_id)
            elif status == "Manual":
                manual_count += 1

    # 7. Check for duplicate IDs
    seen_ids = set()
    duplicates = []
    for req_id in requirement_ids:
        if req_id in seen_ids:
            duplicates.append(req_id)
        seen_ids.add(req_id)

    if duplicates:
        results["valid"] = False
        results["errors"].append(f"Duplicate requirement IDs: {duplicates}")

    # 8. Check for missing checks
    if existing_checks:
        missing_checks = all_checks - existing_checks
        if missing_checks:
            results["valid"] = False
            results["errors"].append(
                f"Missing checks in codebase ({len(missing_checks)}): {sorted(missing_checks)}"
            )

    # 9. Warn about empty automated
    if empty_automated:
        results["warnings"].append(
            f"Automated requirements with no checks: {empty_automated}"
        )

    # 10. Compile statistics
    results["stats"] = {
        "framework": data.get("Framework"),
        "name": data.get("Name"),
        "version": data.get("Version"),
        "provider": data.get("Provider"),
        "total_requirements": len(requirements),
        "automated_requirements": automated_count,
        "manual_requirements": manual_count,
        "unique_checks_referenced": len(all_checks),
        "checks_found_in_codebase": (
            len(all_checks - (all_checks - existing_checks))
            if existing_checks
            else "N/A"
        ),
        "missing_checks": (
            len(all_checks - existing_checks) if existing_checks else "N/A"
        ),
    }

    return results


def print_report(results: dict):
    """Print a formatted validation report."""
    print("\n" + "=" * 60)
    print("PROWLER COMPLIANCE FRAMEWORK VALIDATION REPORT")
    print("=" * 60)

    stats = results.get("stats", {})
    if stats:
        print(f"\nFramework: {stats.get('name', 'N/A')}")
        print(f"Provider:  {stats.get('provider', 'N/A')}")
        print(f"Version:   {stats.get('version', 'N/A')}")
        print("-" * 40)
        print(f"Total Requirements:    {stats.get('total_requirements', 0)}")
        print(f"  - Automated:         {stats.get('automated_requirements', 0)}")
        print(f"  - Manual:            {stats.get('manual_requirements', 0)}")
        print(f"Unique Checks:         {stats.get('unique_checks_referenced', 0)}")
        print(f"Checks in Codebase:    {stats.get('checks_found_in_codebase', 'N/A')}")
        print(f"Missing Checks:        {stats.get('missing_checks', 'N/A')}")

    print("\n" + "-" * 40)

    if results["errors"]:
        print("\nERRORS:")
        for error in results["errors"]:
            print(f"  [X] {error}")

    if results["warnings"]:
        print("\nWARNINGS:")
        for warning in results["warnings"]:
            print(f"  [!] {warning}")

    print("\n" + "-" * 40)
    if results["valid"]:
        print("RESULT: PASS - Framework is valid")
    else:
        print("RESULT: FAIL - Framework has errors")
    print("=" * 60 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_compliance.py <path_to_compliance_json>")
        print(
            "Example: python validate_compliance.py prowler/compliance/azure/cis_5.0_azure.json"
        )
        sys.exit(1)

    json_path = sys.argv[1]
    results = validate_compliance_framework(json_path)
    print_report(results)

    sys.exit(0 if results["valid"] else 1)


if __name__ == "__main__":
    main()
