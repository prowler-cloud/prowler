#!/usr/bin/env python3
"""
Build a per-provider check inventory by scanning Prowler's check metadata files.

Outputs one JSON per provider at /tmp/checks_{provider}.json with the shape:
    {
        "check_id": {
            "service": "...",
            "subservice": "...",
            "resource": "...",
            "severity": "...",
            "title": "...",
            "description": "...",
            "risk": "..."
        },
        ...
    }

This is the reference used by audit_framework_template.py for pre-validation
(every check id in the audit ledger must exist in the inventory) and by
query_checks.py for keyword/service lookup.

Usage:
    python skills/prowler-compliance/assets/build_inventory.py
    # Or for a specific provider:
    python skills/prowler-compliance/assets/build_inventory.py aws

Output:
    /tmp/checks_aws.json   (~586 checks)
    /tmp/checks_azure.json (~167 checks)
    /tmp/checks_gcp.json   (~102 checks)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_PROVIDERS = ["aws", "azure", "gcp", "kubernetes", "m365", "github",
                     "oraclecloud", "alibabacloud", "mongodbatlas", "nhn",
                     "iac", "llm", "googleworkspace", "cloudflare"]


def build_for_provider(provider: str) -> dict:
    inventory: dict[str, dict] = {}
    base = Path(f"prowler/providers/{provider}/services")
    if not base.exists():
        print(f"  skip {provider}: no services directory", file=sys.stderr)
        return inventory
    for meta_path in base.rglob("*.metadata.json"):
        try:
            with open(meta_path) as f:
                data = json.load(f)
        except Exception as exc:
            print(f"  warn: cannot parse {meta_path}: {exc}", file=sys.stderr)
            continue
        cid = data.get("CheckID") or meta_path.stem.replace(".metadata", "")
        inventory[cid] = {
            "service": data.get("ServiceName", ""),
            "subservice": data.get("SubServiceName", ""),
            "resource": data.get("ResourceType", ""),
            "severity": data.get("Severity", ""),
            "title": data.get("CheckTitle", ""),
            "description": data.get("Description", ""),
            "risk": data.get("Risk", ""),
        }
    return inventory


def main() -> int:
    providers = sys.argv[1:] or DEFAULT_PROVIDERS
    for provider in providers:
        inv = build_for_provider(provider)
        out_path = Path(f"/tmp/checks_{provider}.json")
        with open(out_path, "w") as f:
            json.dump(inv, f, indent=2)
        print(f"  {provider}: {len(inv)} checks → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
