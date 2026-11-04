#!/usr/bin/env python3
"""
Prowler Compliance Framework Validator

Validates a compliance framework JSON file (legacy per-provider OR universal
multi-provider schema) for:
- JSON syntax validity
- Required top-level fields (warns on empty version)
- Check existence in the codebase, per provider
- Duplicate requirement IDs and checks repeated inside one requirement
- Universal only: outputs.table_config present, group_by declared in
  attributes_metadata, Provider set on every config_requirements entry
- Legacy only: Automated requirements without checks (CIS-style AssessmentStatus)

It does NOT run the Pydantic models. Also load the file with
load_compliance_framework_universal() and run
tests/lib/check/compliance_catalog_integrity_test.py (see SKILL.md).

Usage:
    python validate_compliance.py <path_to_compliance_json>

Examples:
    python validate_compliance.py prowler/compliance/azure/cis_5.0_azure.json
    python validate_compliance.py prowler/compliance/dora_2022_2554.json
"""

import json
import os
import sys
from pathlib import Path


def find_project_root():
    """Find the Prowler project root directory (cwd first, then script parents)."""
    candidates = [Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents]
    for parent in candidates:
        if (parent / "prowler" / "providers").exists():
            return parent
    return None


def get_existing_checks(project_root: Path, provider: str) -> set:
    """Find all existing checks for a provider in the codebase."""
    checks = set()
    services_path = project_root / "prowler" / "providers" / provider.lower() / "services"
    if not services_path.exists():
        return checks
    for service_dir in services_path.iterdir():
        if service_dir.is_dir() and not service_dir.name.startswith("__"):
            for check_dir in service_dir.iterdir():
                if check_dir.is_dir() and not check_dir.name.startswith("__"):
                    if (check_dir / f"{check_dir.name}.py").exists():
                        checks.add(check_dir.name)
    return checks


def _duplicates(values: list) -> list:
    seen, dups = set(), []
    for value in values:
        if value in seen and value not in dups:
            dups.append(value)
        seen.add(value)
    return dups


def _validate_legacy(data: dict, project_root, results: dict) -> None:
    for field in ("Framework", "Name", "Version", "Provider", "Description", "Requirements"):
        if field not in data:
            results["errors"].append(f"Missing required field: {field}")
    if results["errors"]:
        return
    if not data.get("Version"):
        results["warnings"].append(
            "Empty Version: findings are keyed '{Framework}' instead of '{Framework}-{Version}' "
            "(acceptable only for unversioned frameworks)"
        )

    provider = data["Provider"].lower()
    requirements = data["Requirements"]
    refs = {provider: set()}
    automated = manual = 0
    empty_automated, repeated = [], []

    for req in requirements:
        checks = req.get("Checks", [])
        refs[provider].update(checks)
        if _duplicates(checks):
            repeated.append(req.get("Id"))
        attributes = req.get("Attributes") or [{}]
        status = attributes[0].get("AssessmentStatus")
        if status == "Automated":
            automated += 1
            if not checks:
                empty_automated.append(req.get("Id"))
        elif status == "Manual":
            manual += 1

    if empty_automated:
        results["warnings"].append(f"Automated requirements with no checks: {empty_automated}")

    results["stats"].update(
        schema="legacy",
        framework=data.get("Framework"),
        name=data.get("Name"),
        version=data.get("Version"),
        providers=[provider],
        automated_requirements=automated,
        manual_requirements=manual,
    )
    _common(requirements, [r.get("Id") for r in requirements], refs, repeated, project_root, results)


def _validate_universal(data: dict, project_root, results: dict) -> None:
    for field in ("framework", "name", "description", "requirements"):
        if field not in data:
            results["errors"].append(f"Missing required field: {field}")
    if results["errors"]:
        return
    if not data.get("version"):
        results["warnings"].append("Empty or missing version (output label is just the framework)")

    metadata = data.get("attributes_metadata") or []
    declared = {m.get("key") for m in metadata}
    if not metadata:
        results["warnings"].append("No attributes_metadata: attributes are not validated at load")

    table_config = (data.get("outputs") or {}).get("table_config")
    if not table_config:
        results["errors"].append(
            "Missing outputs.table_config: no compliance CSV/OCSF/table will be generated"
        )
    elif metadata and table_config.get("group_by") not in declared:
        results["errors"].append(
            f"table_config.group_by '{table_config.get('group_by')}' not declared in attributes_metadata"
        )

    requirements = data["requirements"]
    refs: dict[str, set] = {}
    repeated, no_provider, manual_any = [], [], 0
    for req in requirements:
        checks = req.get("checks") or {}
        if not any(checks.values()):
            manual_any += 1
        for prov, ids in checks.items():
            if prov != prov.lower():
                results["errors"].append(f"Requirement '{req.get('id')}': provider key '{prov}' must be lowercase")
            refs.setdefault(prov.lower(), set()).update(ids)
            if _duplicates(ids):
                repeated.append(f"{req.get('id')} ({prov})")
        for constraint in req.get("config_requirements") or []:
            if not constraint.get("Provider"):
                no_provider.append(req.get("id"))

    if no_provider:
        results["errors"].append(f"config_requirements without Provider: {sorted(set(no_provider))}")

    results["stats"].update(
        schema="universal",
        framework=data.get("framework"),
        name=data.get("name"),
        version=data.get("version"),
        providers=sorted(refs),
        requirements_without_any_check=manual_any,
    )
    _common(requirements, [r.get("id") for r in requirements], refs, repeated, project_root, results)


def _common(requirements, ids, refs, repeated, project_root, results) -> None:
    dups = _duplicates(ids)
    if dups:
        results["errors"].append(f"Duplicate requirement IDs: {dups}")
    if repeated:
        results["errors"].append(f"Checks listed twice in a requirement: {repeated}")

    missing_total = 0
    if project_root is None:
        results["warnings"].append("Project root not found - skipping check existence validation")
    else:
        for prov, referenced in sorted(refs.items()):
            existing = get_existing_checks(project_root, prov)
            if not existing:
                results["warnings"].append(f"No checks found on disk for provider '{prov}'")
                continue
            missing = sorted(referenced - existing)
            missing_total += len(missing)
            if missing:
                results["errors"].append(f"[{prov}] missing checks ({len(missing)}): {missing}")

    results["stats"].update(
        total_requirements=len(requirements),
        unique_checks_referenced=sum(len(v) for v in refs.values()),
        missing_checks=missing_total if project_root else "N/A",
    )


def validate_compliance_framework(json_path: str) -> dict:
    """Validate a compliance framework JSON file."""
    results = {"valid": True, "errors": [], "warnings": [], "stats": {}}
    if not os.path.exists(json_path):
        results["errors"].append(f"File not found: {json_path}")
    else:
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            results["errors"].append(f"Invalid JSON syntax: {e}")
        else:
            project_root = find_project_root()
            if "requirements" in data or "attributes_metadata" in data:
                _validate_universal(data, project_root, results)
            else:
                _validate_legacy(data, project_root, results)
    results["valid"] = not results["errors"]
    return results


def print_report(results: dict):
    """Print a formatted validation report."""
    print("\n" + "=" * 60)
    print("PROWLER COMPLIANCE FRAMEWORK VALIDATION REPORT")
    print("=" * 60)
    stats = results.get("stats", {})
    if stats:
        for key, value in stats.items():
            print(f"{key:32} {value}")
    if results["errors"]:
        print("\nERRORS:")
        for error in results["errors"]:
            print(f"  [X] {error}")
    if results["warnings"]:
        print("\nWARNINGS:")
        for warning in results["warnings"]:
            print(f"  [!] {warning}")
    print("\n" + "-" * 40)
    print("RESULT: PASS" if results["valid"] else "RESULT: FAIL")
    print("=" * 60 + "\n")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    results = validate_compliance_framework(sys.argv[1])
    print_report(results)
    sys.exit(0 if results["valid"] else 1)


if __name__ == "__main__":
    main()
