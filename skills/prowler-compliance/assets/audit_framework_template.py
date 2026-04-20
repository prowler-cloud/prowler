#!/usr/bin/env python3
"""
Cloud-auditor pass template for any Prowler compliance framework.

Encode explicit REPLACE decisions per (requirement_id, provider) pair below.
Each decision FULLY overwrites the legacy Checks list for that requirement.

Workflow:
    1. Run build_inventory.py first to cache per-provider check metadata.
    2. Run dump_section.py to see current mappings for the catalog you're auditing.
    3. Fill in DECISIONS below with explicit check lists.
    4. Run this script — it pre-validates every check id against the inventory
       and aborts with stderr listing typos before writing.

Decision rules (apply as a hostile cloud auditor):
    - The Prowler check's title/risk MUST literally describe what the AR text says.
      "Related" is not enough.
    - If no check actually addresses the requirement, leave `[]` (= MANUAL).
      HONEST MANUAL is worth more than padded coverage.
    - Missing provider key = leave the legacy mapping untouched.
    - Empty list `[]` = explicitly MANUAL (overwrites legacy).

Usage:
    # 1. Copy this file to /tmp/audit_<framework>.py and fill in DECISIONS
    # 2. Edit FRAMEWORK_KEY below to match your framework file naming
    # 3. Run:
    python /tmp/audit_<framework>.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configure for your framework
# ---------------------------------------------------------------------------

# Framework file basename inside prowler/compliance/{provider}/.
# If your framework is called "cis_5.0_aws.json", FRAMEWORK_KEY is "cis_5.0".
# If the file is "ccc_aws.json", FRAMEWORK_KEY is "ccc".
FRAMEWORK_KEY = "ccc"

# Which providers to apply decisions to.
PROVIDERS = ["aws", "azure", "gcp"]

PROWLER_DIR = Path("prowler/compliance")
CHECK_INV = {prov: Path(f"/tmp/checks_{prov}.json") for prov in PROVIDERS}


# ---------------------------------------------------------------------------
# DECISIONS — encode one entry per requirement you want to audit
# ---------------------------------------------------------------------------

# DECISIONS[requirement_id][provider] = list[str] of check ids
# See SKILL.md → "Audit Reference Table: Requirement Text → Prowler Checks"
# for a comprehensive mapping cheat sheet built from a 172-AR CCC audit.

DECISIONS: dict[str, dict[str, list[str]]] = {}

# ---- Example entries (delete and replace with your own) ----

# Example 1: TLS in transit enforced (non-SSH traffic)
# DECISIONS["CCC.Core.CN01.AR01"] = {
#     "aws": [
#         "cloudfront_distributions_https_enabled",
#         "cloudfront_distributions_origin_traffic_encrypted",
#         "s3_bucket_secure_transport_policy",
#         "elbv2_ssl_listeners",
#         "rds_instance_transport_encrypted",
#         "kafka_cluster_in_transit_encryption_enabled",
#         "redshift_cluster_in_transit_encryption_enabled",
#         "opensearch_service_domains_https_communications_enforced",
#     ],
#     "azure": [
#         "storage_secure_transfer_required_is_enabled",
#         "app_minimum_tls_version_12",
#         "postgresql_flexible_server_enforce_ssl_enabled",
#         "sqlserver_recommended_minimal_tls_version",
#     ],
#     "gcp": [
#         "cloudsql_instance_ssl_connections",
#     ],
# }

# Example 2: MANUAL — no Prowler check exists
# DECISIONS["CCC.Core.CN01.AR07"] = {
#     "aws": [],    # no IANA port/protocol check exists in Prowler
#     "azure": [],
#     "gcp": [],
# }

# Example 3: Reuse a decision for multiple sibling ARs
# DECISIONS["CCC.ObjStor.CN05.AR02"] = DECISIONS["CCC.ObjStor.CN05.AR01"]


# ---------------------------------------------------------------------------
# Driver — do not edit below
# ---------------------------------------------------------------------------

def load_inventory(provider: str) -> dict:
    path = CHECK_INV[provider]
    if not path.exists():
        raise SystemExit(
            f"Check inventory missing: {path}\n"
            f"Run: python skills/prowler-compliance/assets/build_inventory.py {provider}"
        )
    with open(path) as f:
        return json.load(f)


def resolve_json_path(provider: str) -> Path:
    """Resolve the JSON file path for a given provider.

    Handles both shapes: {FRAMEWORK_KEY}_{provider}.json (ccc_aws.json) and
    cases where FRAMEWORK_KEY already contains the provider suffix.
    """
    candidates = [
        PROWLER_DIR / provider / f"{FRAMEWORK_KEY}_{provider}.json",
        PROWLER_DIR / provider / f"{FRAMEWORK_KEY}.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise SystemExit(
        f"Could not find framework JSON for provider={provider} "
        f"with FRAMEWORK_KEY={FRAMEWORK_KEY}. Tried: {candidates}"
    )


def plan_for_provider(
    provider: str,
) -> tuple[Path, dict, tuple[int, int, int], list[tuple[str, str]]]:
    """Build the updated JSON for one provider without writing it.

    Returns (path, mutated_data, (touched, added, removed), unknowns).
    Writing is deferred to a second pass so that a typo in any provider
    aborts the whole run before any file on disk changes.
    """
    path = resolve_json_path(provider)
    with open(path) as f:
        data = json.load(f)
    inv = load_inventory(provider)

    touched = 0
    add_count = 0
    rm_count = 0
    unknown: list[tuple[str, str]] = []

    for req in data["Requirements"]:
        rid = req["Id"]
        if rid not in DECISIONS or provider not in DECISIONS[rid]:
            continue
        new_checks = list(dict.fromkeys(DECISIONS[rid][provider]))
        for c in new_checks:
            if c not in inv:
                unknown.append((rid, c))
        before = set(req.get("Checks") or [])
        after = set(new_checks)
        rm_count += len(before - after)
        add_count += len(after - before)
        req["Checks"] = new_checks
        touched += 1

    return path, data, (touched, add_count, rm_count), unknown


def main() -> int:
    if not DECISIONS:
        print("No DECISIONS encoded. Fill in the DECISIONS dict and re-run.")
        return 1
    print(f"Applying {len(DECISIONS)} decisions to framework '{FRAMEWORK_KEY}'...")

    # Pass 1: validate every provider before touching disk. A typo in any
    # provider must abort the run before ANY file has been rewritten.
    plans: list[tuple[str, Path, dict, tuple[int, int, int]]] = []
    all_unknown: list[tuple[str, str, str]] = []
    for provider in PROVIDERS:
        path, data, counts, unknown = plan_for_provider(provider)
        for rid, c in unknown:
            all_unknown.append((provider, rid, c))
        plans.append((provider, path, data, counts))

    if all_unknown:
        print("\n!! UNKNOWN CHECK IDS (typos?):", file=sys.stderr)
        for provider, rid, c in all_unknown:
            print(f"   {provider} {rid} -> {c}", file=sys.stderr)
        print(
            "\nAborting: fix the check ids above and re-run. "
            "No files were modified.",
            file=sys.stderr,
        )
        return 2

    # Pass 2: all providers validated cleanly — write.
    for provider, path, data, (touched, added, removed) in plans:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(
            f"  {provider}: touched={touched} added={added} removed={removed}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
