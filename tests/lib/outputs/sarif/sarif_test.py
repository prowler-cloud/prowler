import json
import os
import tempfile

import pytest

from prowler.lib.outputs.sarif.sarif import SARIF, SARIF_SCHEMA_URL, SARIF_VERSION
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class TestSARIF:
    def test_transform_fail_finding(self):
        finding = generate_finding_output(
            status="FAIL",
            status_extended="S3 bucket is not encrypted",
            severity="high",
            resource_name="main.tf",
            service_name="s3",
            check_id="s3_encryption_check",
            check_title="S3 Bucket Encryption",
        )
        sarif = SARIF(findings=[finding], file_path=None)

        assert sarif.data[0]["$schema"] == SARIF_SCHEMA_URL
        assert sarif.data[0]["version"] == SARIF_VERSION
        assert len(sarif.data[0]["runs"]) == 1

        run = sarif.data[0]["runs"][0]
        assert run["tool"]["driver"]["name"] == "Prowler"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "s3_encryption_check"
        assert rule["shortDescription"]["text"] == "S3 Bucket Encryption"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["security-severity"] == "7.0"

        result = run["results"][0]
        assert result["ruleId"] == "s3_encryption_check"
        assert result["ruleIndex"] == 0
        assert result["level"] == "error"
        assert result["message"]["text"] == "S3 bucket is not encrypted"

    def test_transform_pass_finding_excluded(self):
        finding = generate_finding_output(status="PASS", severity="high")
        sarif = SARIF(findings=[finding], file_path=None)

        run = sarif.data[0]["runs"][0]
        assert len(run["results"]) == 0
        assert len(run["tool"]["driver"]["rules"]) == 0

    def test_transform_muted_finding_excluded(self):
        finding = generate_finding_output(status="FAIL", severity="high", muted=True)
        sarif = SARIF(findings=[finding], file_path=None)
        run = sarif.data[0]["runs"][0]
        assert len(run["results"]) == 0
        assert len(run["tool"]["driver"]["rules"]) == 0

    @pytest.mark.parametrize(
        "severity,expected_level,expected_security_severity",
        [
            ("critical", "error", "9.0"),
            ("high", "error", "7.0"),
            ("medium", "warning", "4.0"),
            ("low", "note", "2.0"),
            ("informational", "note", "0.0"),
        ],
    )
    def test_transform_severity_mapping(
        self, severity, expected_level, expected_security_severity
    ):
        finding = generate_finding_output(
            status="FAIL",
            severity=severity,
        )
        sarif = SARIF(findings=[finding], file_path=None)

        run = sarif.data[0]["runs"][0]
        result = run["results"][0]
        rule = run["tool"]["driver"]["rules"][0]

        assert result["level"] == expected_level
        assert rule["defaultConfiguration"]["level"] == expected_level
        assert rule["properties"]["security-severity"] == expected_security_severity

    def test_transform_multiple_findings_dedup_rules(self):
        findings = [
            generate_finding_output(
                status="FAIL",
                resource_name="file1.tf",
                status_extended="Finding in file1",
            ),
            generate_finding_output(
                status="FAIL",
                resource_name="file2.tf",
                status_extended="Finding in file2",
            ),
        ]
        sarif = SARIF(findings=findings, file_path=None)

        run = sarif.data[0]["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 2
        assert run["results"][0]["ruleIndex"] == 0
        assert run["results"][1]["ruleIndex"] == 0

    def test_transform_multiple_different_rules(self):
        findings = [
            generate_finding_output(
                status="FAIL",
                service_name="alpha",
                check_id="alpha_check_one",
                status_extended="Finding A",
            ),
            generate_finding_output(
                status="FAIL",
                service_name="beta",
                check_id="beta_check_two",
                status_extended="Finding B",
            ),
        ]
        sarif = SARIF(findings=findings, file_path=None)

        run = sarif.data[0]["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert run["results"][0]["ruleIndex"] == 0
        assert run["results"][1]["ruleIndex"] == 1

    def test_transform_location_with_line_range(self):
        finding = generate_finding_output(
            status="FAIL",
            resource_name="modules/s3/main.tf",
        )
        finding.raw = {"resource_line_range": "10:25"}

        sarif = SARIF(findings=[finding], file_path=None)

        result = sarif.data[0]["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "modules/s3/main.tf"
        assert location["region"]["startLine"] == 10
        assert location["region"]["endLine"] == 25

    def test_transform_location_without_line_range(self):
        finding = generate_finding_output(
            status="FAIL",
            resource_name="main.tf",
        )
        sarif = SARIF(findings=[finding], file_path=None)

        result = sarif.data[0]["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "main.tf"
        assert "region" not in location

    def test_transform_no_resource_name(self):
        finding = generate_finding_output(
            status="FAIL",
            resource_name="",
        )
        sarif = SARIF(findings=[finding], file_path=None)

        result = sarif.data[0]["runs"][0]["results"][0]
        assert "locations" not in result

    def test_batch_write_data_to_file(self):
        finding = generate_finding_output(
            status="FAIL",
            status_extended="test finding",
            resource_name="main.tf",
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False
        ) as tmp:
            tmp_path = tmp.name

        sarif = SARIF(
            findings=[finding],
            file_path=tmp_path,
        )
        sarif.batch_write_data_to_file()

        with open(tmp_path) as f:
            content = json.load(f)

        assert content["$schema"] == SARIF_SCHEMA_URL
        assert content["version"] == SARIF_VERSION
        assert len(content["runs"][0]["results"]) == 1

        os.unlink(tmp_path)

    def test_sarif_schema_structure(self):
        finding = generate_finding_output(
            status="FAIL",
            severity="critical",
            resource_name="infra/main.tf",
            service_name="iac",
            check_id="iac_misconfig_check",
            check_title="IaC Misconfiguration",
            description="Checks for misconfigurations",
            remediation_recommendation_text="Fix the configuration",
        )
        finding.raw = {"resource_line_range": "5:15"}

        sarif = SARIF(findings=[finding], file_path=None)
        doc = sarif.data[0]

        assert "$schema" in doc
        assert "version" in doc
        assert "runs" in doc

        run = doc["runs"][0]

        assert "tool" in run
        assert "driver" in run["tool"]
        driver = run["tool"]["driver"]
        assert "name" in driver
        assert "version" in driver
        assert "informationUri" in driver
        assert "rules" in driver

        rule = driver["rules"][0]
        assert "id" in rule
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "help" in rule
        assert "defaultConfiguration" in rule
        assert "properties" in rule
        assert "tags" in rule["properties"]
        assert "security-severity" in rule["properties"]

        result = run["results"][0]
        assert "ruleId" in result
        assert "ruleIndex" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "uri" in loc["artifactLocation"]
        assert "region" in loc
        assert "startLine" in loc["region"]
        assert "endLine" in loc["region"]

    def test_transform_helpuri_present_when_related_url_set(self):
        finding = generate_finding_output(
            status="FAIL",
            provider="iac",
            related_url="https://docs.example.com/check",
        )
        sarif = SARIF(findings=[finding], file_path=None)
        rule = sarif.data[0]["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://docs.example.com/check"

    def test_transform_helpuri_absent_when_related_url_empty(self):
        finding = generate_finding_output(
            status="FAIL",
            related_url="",
        )
        sarif = SARIF(findings=[finding], file_path=None)
        rule = sarif.data[0]["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule

    def test_location_with_non_numeric_line_range(self):
        finding = generate_finding_output(
            status="FAIL",
            resource_name="main.tf",
        )
        finding.raw = {"resource_line_range": "abc:def"}
        sarif = SARIF(findings=[finding], file_path=None)
        location = sarif.data[0]["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]
        assert "region" not in location

    def test_location_with_single_value_line_range(self):
        finding = generate_finding_output(
            status="FAIL",
            resource_name="main.tf",
        )
        finding.raw = {"resource_line_range": "10"}
        sarif = SARIF(findings=[finding], file_path=None)
        location = sarif.data[0]["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]
        assert "region" not in location

    def test_only_pass_findings(self):
        findings = [
            generate_finding_output(status="PASS"),
            generate_finding_output(status="PASS"),
        ]
        sarif = SARIF(findings=findings, file_path=None)

        run = sarif.data[0]["runs"][0]
        assert len(run["results"]) == 0
        assert len(run["tool"]["driver"]["rules"]) == 0
