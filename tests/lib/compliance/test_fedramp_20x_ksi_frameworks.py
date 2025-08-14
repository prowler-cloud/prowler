import json
from pathlib import Path

import pytest


class TestFedRAMP20xKSIFrameworks:

    @pytest.fixture
    def compliance_path(self):
        return Path(__file__).parent.parent.parent.parent / "prowler" / "compliance"

    def test_fedramp_20x_ksi_aws_framework_exists(self, compliance_path):
        aws_ksi_path = compliance_path / "aws" / "fedramp_20x_ksi_aws.json"
        assert (
            aws_ksi_path.exists()
        ), f"FedRAMP 20x KSI AWS framework not found at {aws_ksi_path}"

    def test_fedramp_20x_ksi_azure_framework_exists(self, compliance_path):
        azure_ksi_path = compliance_path / "azure" / "fedramp_20x_ksi_azure.json"
        assert (
            azure_ksi_path.exists()
        ), f"FedRAMP 20x KSI Azure framework not found at {azure_ksi_path}"

    def test_fedramp_20x_ksi_gcp_framework_exists(self, compliance_path):
        gcp_ksi_path = compliance_path / "gcp" / "fedramp_20x_ksi_gcp.json"
        assert (
            gcp_ksi_path.exists()
        ), f"FedRAMP 20x KSI GCP framework not found at {gcp_ksi_path}"

    def test_fedramp_20x_ksi_aws_framework_valid_json(self, compliance_path):
        aws_ksi_path = compliance_path / "aws" / "fedramp_20x_ksi_aws.json"
        with open(aws_ksi_path) as f:
            data = json.load(f)
            assert data["Framework"] == "FedRAMP-20x-KSI"
            assert data["Provider"] == "AWS"
            assert "Requirements" in data
            assert len(data["Requirements"]) > 0

    def test_fedramp_20x_ksi_azure_framework_valid_json(self, compliance_path):
        azure_ksi_path = compliance_path / "azure" / "fedramp_20x_ksi_azure.json"
        with open(azure_ksi_path) as f:
            data = json.load(f)
            assert data["Framework"] == "FedRAMP-20x-KSI"
            assert data["Provider"] == "Azure"
            assert "Requirements" in data
            assert len(data["Requirements"]) > 0

    def test_fedramp_20x_ksi_gcp_framework_valid_json(self, compliance_path):
        gcp_ksi_path = compliance_path / "gcp" / "fedramp_20x_ksi_gcp.json"
        with open(gcp_ksi_path) as f:
            data = json.load(f)
            assert data["Framework"] == "FedRAMP-20x-KSI"
            assert data["Provider"] == "GCP"
            assert "Requirements" in data
            assert len(data["Requirements"]) > 0

    def test_fedramp_20x_ksi_aws_has_all_ksi_requirements(self, compliance_path):
        aws_ksi_path = compliance_path / "aws" / "fedramp_20x_ksi_aws.json"
        with open(aws_ksi_path) as f:
            data = json.load(f)
            requirement_ids = [req["Id"] for req in data["Requirements"]]

            # Check for all 10 KSI requirements
            expected_ksis = [
                "ksi-ced",
                "ksi-cmt",
                "ksi-cna",
                "ksi-iam",
                "ksi-inr",
                "ksi-mla",
                "ksi-piy",
                "ksi-rpl",
                "ksi-svc",
                "ksi-tpr",
            ]

            for ksi in expected_ksis:
                assert ksi in requirement_ids, f"Missing KSI requirement: {ksi}"

    def test_fedramp_20x_ksi_azure_has_all_ksi_requirements(self, compliance_path):
        azure_ksi_path = compliance_path / "azure" / "fedramp_20x_ksi_azure.json"
        with open(azure_ksi_path) as f:
            data = json.load(f)
            requirement_ids = [req["Id"] for req in data["Requirements"]]

            # Check for all 10 KSI requirements
            expected_ksis = [
                "ksi-ced",
                "ksi-cmt",
                "ksi-cna",
                "ksi-iam",
                "ksi-inr",
                "ksi-mla",
                "ksi-piy",
                "ksi-rpl",
                "ksi-svc",
                "ksi-tpr",
            ]

            for ksi in expected_ksis:
                assert ksi in requirement_ids, f"Missing KSI requirement: {ksi}"

    def test_fedramp_20x_ksi_gcp_has_all_ksi_requirements(self, compliance_path):
        gcp_ksi_path = compliance_path / "gcp" / "fedramp_20x_ksi_gcp.json"
        with open(gcp_ksi_path) as f:
            data = json.load(f)
            requirement_ids = [req["Id"] for req in data["Requirements"]]

            # Check for all 10 KSI requirements
            expected_ksis = [
                "ksi-ced",
                "ksi-cmt",
                "ksi-cna",
                "ksi-iam",
                "ksi-inr",
                "ksi-mla",
                "ksi-piy",
                "ksi-rpl",
                "ksi-svc",
                "ksi-tpr",
            ]

            for ksi in expected_ksis:
                assert ksi in requirement_ids, f"Missing KSI requirement: {ksi}"

    def test_fedramp_20x_ksi_aws_requirements_have_checks(self, compliance_path):
        aws_ksi_path = compliance_path / "aws" / "fedramp_20x_ksi_aws.json"
        with open(aws_ksi_path) as f:
            data = json.load(f)
            for req in data["Requirements"]:
                assert "Checks" in req, f"Requirement {req['Id']} missing Checks"
                assert (
                    len(req["Checks"]) > 0
                ), f"Requirement {req['Id']} has empty Checks"
                assert (
                    "Attributes" in req
                ), f"Requirement {req['Id']} missing Attributes"

    def test_fedramp_20x_ksi_azure_requirements_have_checks(self, compliance_path):
        azure_ksi_path = compliance_path / "azure" / "fedramp_20x_ksi_azure.json"
        with open(azure_ksi_path) as f:
            data = json.load(f)
            for req in data["Requirements"]:
                assert "Checks" in req, f"Requirement {req['Id']} missing Checks"
                assert (
                    len(req["Checks"]) > 0
                ), f"Requirement {req['Id']} has empty Checks"
                assert (
                    "Attributes" in req
                ), f"Requirement {req['Id']} missing Attributes"

    def test_fedramp_20x_ksi_gcp_requirements_have_checks(self, compliance_path):
        gcp_ksi_path = compliance_path / "gcp" / "fedramp_20x_ksi_gcp.json"
        with open(gcp_ksi_path) as f:
            data = json.load(f)
            for req in data["Requirements"]:
                assert "Checks" in req, f"Requirement {req['Id']} missing Checks"
                assert (
                    len(req["Checks"]) > 0
                ), f"Requirement {req['Id']} has empty Checks"
                assert (
                    "Attributes" in req
                ), f"Requirement {req['Id']} missing Attributes"

    def test_fedramp_20x_ksi_frameworks_version_consistency(self, compliance_path):
        aws_ksi_path = compliance_path / "aws" / "fedramp_20x_ksi_aws.json"
        azure_ksi_path = compliance_path / "azure" / "fedramp_20x_ksi_azure.json"
        gcp_ksi_path = compliance_path / "gcp" / "fedramp_20x_ksi_gcp.json"

        with open(aws_ksi_path) as f:
            aws_data = json.load(f)
        with open(azure_ksi_path) as f:
            azure_data = json.load(f)
        with open(gcp_ksi_path) as f:
            gcp_data = json.load(f)

        # All should have the same version
        assert (
            aws_data["Version"] == azure_data["Version"] == gcp_data["Version"]
        ), "FedRAMP 20x KSI framework versions are inconsistent across providers"

    def test_fedramp_20x_ksi_nist_controls_mapping(self, compliance_path):
        # Test that each KSI requirement has proper NIST control mappings
        for provider, path_suffix in [
            ("aws", "aws/fedramp_20x_ksi_aws.json"),
            ("azure", "azure/fedramp_20x_ksi_azure.json"),
            ("gcp", "gcp/fedramp_20x_ksi_gcp.json"),
        ]:
            framework_path = compliance_path / path_suffix
            with open(framework_path) as f:
                data = json.load(f)
                for req in data["Requirements"]:
                    assert (
                        len(req["Attributes"]) > 0
                    ), f"{provider}: Requirement {req['Id']} has no attributes"
                    for attr in req["Attributes"]:
                        assert (
                            "NistControls" in attr
                        ), f"{provider}: Requirement {req['Id']} attribute missing NistControls"
                        assert attr[
                            "NistControls"
                        ], f"{provider}: Requirement {req['Id']} has empty NistControls"
