"""Unit tests for the Prowler Audit Agent (no live GitHub / Docker required)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_agent.config import (
    DEFAULT_CONFIG,
    load_local_config,
    meets_severity_threshold,
    scanners_for_trivy,
)
from audit_agent.map_controls import (
    filter_by_files,
    map_finding,
    map_findings,
    normalize_finding,
)
from audit_agent.render import COMMENT_MARKER, render_pr_comment


@pytest.fixture
def mapping():
    from audit_agent.map_controls import load_mapping

    return load_mapping()


def test_default_config_load():
    cfg = load_local_config(None)
    assert cfg["frameworks"] == DEFAULT_CONFIG["frameworks"]
    assert scanners_for_trivy(cfg) == ["misconfig", "secret", "vuln", "license"]


def test_load_json_config(tmp_path):
    path = tmp_path / "prowler-audit.json"
    path.write_text(
        json.dumps(
            {
                "scanners": {"dependencies": False},
                "fail-pr-on": {"severity": "critical"},
            }
        ),
        encoding="utf-8",
    )
    cfg = load_local_config(path)
    assert cfg["scanners"]["dependencies"] is False
    assert cfg["fail_pr_on"]["severity"] == "critical"
    assert scanners_for_trivy(cfg) == ["misconfig", "secret", "license"]


def test_meets_severity_threshold():
    assert meets_severity_threshold("high", "high")
    assert meets_severity_threshold("critical", "high")
    assert not meets_severity_threshold("medium", "high")


def test_map_secret_finding(mapping):
    finding = map_finding(
        {
            "status_code": "FAIL",
            "severity": "High",
            "finding_info": {"title": "AWS Access Key", "uid": "secret-1"},
            "resources": [{"name": "app.py"}],
            "unmapped": {"service_name": "secret", "check_id": "aws-access-key"},
        },
        mapping,
    )
    assert finding["status"] == "FAIL"
    assert "CC6.1" in finding["soc2"]
    assert "A.8.24" in finding["iso27001"]


def test_map_network_misconfig(mapping):
    finding = map_finding(
        {
            "status_code": "FAIL",
            "severity": "critical",
            "finding_info": {
                "title": "Security group allows SSH from 0.0.0.0/0",
                "uid": "AVD-AWS-0107",
            },
            "resources": [{"name": "infra/sg.tf"}],
            "unmapped": {"service_name": "misconfig", "check_id": "AVD-AWS-0107"},
        },
        mapping,
    )
    assert "CC6.6" in finding["soc2"]
    assert "A.8.20" in finding["iso27001"]


def test_map_findings_skips_pass(mapping):
    raw = [
        {
            "status_code": "PASS",
            "severity": "low",
            "finding_info": {"title": "ok", "uid": "1"},
            "resources": [],
            "unmapped": {"service_name": "misconfig"},
        },
        {
            "status_code": "FAIL",
            "severity": "high",
            "finding_info": {"title": "CVE-2024-1", "uid": "CVE-2024-1"},
            "resources": [{"name": "uv.lock"}],
            "unmapped": {"service_name": "vuln"},
        },
    ]
    mapped = map_findings(raw, mapping)
    assert len(mapped) == 1
    assert "CC7.1" in mapped[0]["soc2"]


def test_filter_by_files():
    findings = [
        {"file": "Terraform/API/main.tf", "title": "a"},
        {"file": "Frontend/Dockerfile", "title": "b"},
    ]
    filtered = filter_by_files(findings, {"Terraform/API/main.tf"})
    assert len(filtered) == 1
    assert filtered[0]["title"] == "a"


def test_render_pr_comment_contains_marker(mapping):
    from audit_agent.config import enabled_security_aspects

    findings = [
        map_finding(
            {
                "status_code": "FAIL",
                "severity": "high",
                "finding_info": {"title": "Public SSH", "uid": "x"},
                "resources": [{"name": "sg.tf"}],
                "unmapped": {"service_name": "misconfig", "check_id": "x"},
            },
            mapping,
        )
    ]
    body = render_pr_comment(
        findings,
        "acme/demo",
        enabled_aspects=enabled_security_aspects(DEFAULT_CONFIG),
    )
    assert COMMENT_MARKER in body
    assert "SOC 2" in body
    assert "ISO 27001" in body
    assert "Public SSH" in body
    assert "SOC 2 — All findings" in body
    assert "ISO 27001:2022 — All findings" in body
    assert "Security Aspects" in body
    assert "Secrets in source" in body
    assert "License compliance" in body
    assert "GitHub Actions" in body


def test_normalize_simplified():
    n = normalize_finding(
        {
            "check_id": "AVD-1",
            "severity": "medium",
            "status": "FAIL",
            "title": "t",
            "file": "a.tf",
        }
    )
    assert n["check_id"] == "AVD-1"
    assert n["file"] == "a.tf"


def test_prowler_compliance_index_loads():
    from audit_agent.prowler_compliance import (
        controls_for_check,
        frameworks_for_provider,
        load_check_control_index,
    )

    assert "soc2_aws" in frameworks_for_provider("aws")
    assert "iso27001_2022_aws" in frameworks_for_provider("aws")
    assert frameworks_for_provider("iac") == []

    index = load_check_control_index()
    assert index, "expected check→control index from prowler/compliance"
    sample = next(iter(index))
    assert controls_for_check(sample)["soc2"] or controls_for_check(sample)["iso27001"]


def test_map_github_branch_protection(mapping):
    finding = map_finding(
        {
            "check_id": "repository_default_branch_requires_multiple_approvals",
            "status": "FAIL",
            "severity": "high",
            "title": "Default branch requires multiple approvals",
            "file": "acme/demo",
            "service": "repository",
            "provider": "github",
        },
        mapping,
    )
    assert "CC8.1" in finding["soc2"]
    assert "A.8.9" in finding["iso27001"]


def test_filter_by_files_skips_empty_and_avoids_basename_false_positives():
    findings = [
        {"file": "main.tf", "title": "root", "provider": "iac"},
        {"file": "submodule/main.tf", "title": "nested", "provider": "iac"},
        {"file": "", "title": "empty", "provider": "iac"},
        {"file": "", "title": "github-pathless", "provider": "github"},
    ]
    filtered = filter_by_files(findings, {"submodule/main.tf"})
    titles = {f["title"] for f in filtered}
    assert titles == {"nested", "github-pathless"}


def test_minimal_yaml_lists():
    from audit_agent.config import _minimal_yaml

    data = _minimal_yaml(
        "\n".join(
            [
                "frameworks:",
                "  - soc2",
                "  - iso27001_2022",
                "providers:",
                "  - iac",
                "reporting:",
                "  issue_labels:",
                "    - compliance",
                "    - prowler-audit",
            ]
        )
    )
    assert data["frameworks"] == ["soc2", "iso27001_2022"]
    assert data["providers"] == ["iac"]
    assert data["reporting"]["issue_labels"] == ["compliance", "prowler-audit"]


def test_save_audit_report(tmp_path):
    from audit_agent.report_files import save_audit_report

    findings = [
        {
            "check_id": "x",
            "title": "t",
            "severity": "high",
            "status": "FAIL",
            "soc2": ["CC6.6"],
            "iso27001": ["A.8.20"],
            "raw": {"skip": True},
        }
    ]
    written = save_audit_report(
        out_dir=tmp_path,
        repo="acme/demo",
        comment_markdown="## report",
        findings=findings,
        report_file=tmp_path / "custom" / "out.md",
    )
    assert written["markdown"].read_text().startswith("## report")
    data = json.loads(written["json"].read_text())
    assert data["repo"] == "acme/demo"
    assert data["finding_count"] == 1
    assert "raw" not in data["findings"][0]


def test_frameworks_for_github_includes_cis():
    from audit_agent.prowler_compliance import frameworks_for_provider

    fws = frameworks_for_provider("github", ["soc2", "iso27001_2022"])
    assert "cis_1.2.0_github" in fws

