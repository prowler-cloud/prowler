#!/usr/bin/env python3
"""
Keyword/service/id lookup over a Prowler check inventory produced by
build_inventory.py.

Usage:
    # Keyword AND-search across id + title + risk + description
    python skills/prowler-compliance/assets/query_checks.py aws encryption transit

    # Show all checks for a service
    python skills/prowler-compliance/assets/query_checks.py aws --service iam

    # Show full metadata for one check id
    python skills/prowler-compliance/assets/query_checks.py aws --id kms_cmk_rotation_enabled
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    provider = sys.argv[1]
    try:
        with open(f"/tmp/checks_{provider}.json") as f:
            inv = json.load(f)
    except FileNotFoundError:
        print(
            f"No inventory for {provider}. Run build_inventory.py first.",
            file=sys.stderr,
        )
        return 2

    if sys.argv[2] == "--service":
        if len(sys.argv) < 4:
            print("usage: --service <service_name>")
            return 1
        svc = sys.argv[3]
        hits = [cid for cid in sorted(inv) if inv[cid].get("service") == svc]
        for cid in hits:
            print(f"  {cid}")
            print(f"    {inv[cid].get('title', '')}")
        print(f"\n{len(hits)} checks in service '{svc}'")
    elif sys.argv[2] == "--id":
        if len(sys.argv) < 4:
            print("usage: --id <check_id>")
            return 1
        cid = sys.argv[3]
        if cid not in inv:
            print(f"NOT FOUND: {cid}")
            return 3
        m = inv[cid]
        print(f"== {cid} ==")
        print(f"service : {m.get('service')}")
        print(f"severity: {m.get('severity')}")
        print(f"resource: {m.get('resource')}")
        print(f"title   : {m.get('title')}")
        print(f"desc    : {m.get('description', '')[:500]}")
        print(f"risk    : {m.get('risk', '')[:500]}")
    else:
        keywords = [k.lower() for k in sys.argv[2:]]
        hits = 0
        for cid in sorted(inv):
            m = inv[cid]
            blob = " ".join(
                [
                    cid,
                    m.get("title", ""),
                    m.get("risk", ""),
                    m.get("description", ""),
                ]
            ).lower()
            if all(k in blob for k in keywords):
                hits += 1
                print(f"  {cid}  [{m.get('service', '')}]")
                print(f"    {m.get('title', '')[:120]}")
        print(f"\n{hits} matches for {' + '.join(keywords)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
