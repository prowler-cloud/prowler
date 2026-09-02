from datetime import date
from pathlib import Path

import yaml


def test_grpc_cve_suppression_is_narrow_and_temporary():
    ignore_file = Path(__file__).parents[1] / ".trivyignore.yaml"
    ignore_policy = yaml.safe_load(ignore_file.read_text())
    vulnerabilities = ignore_policy["vulnerabilities"]

    grpc_cve_entries = [
        entry for entry in vulnerabilities if entry["id"] == "CVE-2026-84304"
    ]

    assert grpc_cve_entries == [
        {
            "id": "CVE-2026-84304",
            "purls": ["pkg:golang/google.golang.org/grpc"],
            "expired_at": date(2026, 9, 15),
        }
    ]
