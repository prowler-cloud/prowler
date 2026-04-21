#!/usr/bin/env python3
"""
Dump every requirement of a compliance framework for a given id prefix across
providers, with their current Check mappings.

Useful for reviewing a whole control family in one pass before encoding audit
decisions in audit_framework_template.py.

Usage:
    # Dump all CCC.Core requirements across aws/azure/gcp
    python skills/prowler-compliance/assets/dump_section.py ccc "CCC.Core."

    # Dump all CIS 5.0 section 1 requirements for AWS only
    python skills/prowler-compliance/assets/dump_section.py cis_5.0_aws "1."

Arguments:
    framework_key: file prefix inside prowler/compliance/{provider}/ without
                   the provider suffix. Examples:
                     - "ccc"        → loads ccc_aws.json / ccc_azure.json / ccc_gcp.json
                     - "cis_5.0_aws" → loads only that one file
                     - "iso27001_2022" → loads all providers
    id_prefix:     Requirement id prefix to filter by (e.g. "CCC.Core.",
                   "1.1.", "A.5.").
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

PROWLER_COMPLIANCE_DIR = Path("prowler/compliance")


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    framework_key = sys.argv[1]
    id_prefix = sys.argv[2]

    # Find matching JSON files across all providers
    candidates: list[tuple[str, Path]] = []
    for prov_dir in sorted(PROWLER_COMPLIANCE_DIR.iterdir()):
        if not prov_dir.is_dir():
            continue
        for json_path in prov_dir.glob("*.json"):
            stem = json_path.stem
            if stem == framework_key or stem.startswith(f"{framework_key}_") \
                    or stem == f"{framework_key}_{prov_dir.name}":
                candidates.append((prov_dir.name, json_path))

    if not candidates:
        print(f"No files matching '{framework_key}'", file=sys.stderr)
        return 2

    discovered_providers = sorted({prov for prov, _ in candidates})

    by_id: dict[str, dict] = defaultdict(dict)
    for prov, path in candidates:
        with open(path) as f:
            data = json.load(f)
        for req in data["Requirements"]:
            if req["Id"].startswith(id_prefix):
                by_id[req["Id"]][prov] = {
                    "desc": req.get("Description", ""),
                    "sec": (req.get("Attributes") or [{}])[0].get("Section", ""),
                    "obj": (req.get("Attributes") or [{}])[0].get(
                        "SubSectionObjective", ""
                    ),
                    "checks": req.get("Checks") or [],
                }

    for ar_id in sorted(by_id):
        rows = by_id[ar_id]
        sample = next(iter(rows.values()))
        print(f"\n### {ar_id}")
        print(f"  desc: {sample['desc']}")
        if sample["sec"]:
            print(f"  sec : {sample['sec']}")
        if sample["obj"]:
            print(f"  obj : {sample['obj']}")
        for prov in discovered_providers:
            if prov in rows:
                checks = rows[prov]["checks"]
                print(f"  {prov}: ({len(checks)}) {checks}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
