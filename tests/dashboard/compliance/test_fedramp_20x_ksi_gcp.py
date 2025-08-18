import pandas as pd

from dashboard.compliance.fedramp_20x_ksi_gcp import get_table


class TestFedRAMP20xKSIGCP:
    def test_get_table_with_ksi_data(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-ced", "ksi-cmt", "ksi-iam"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service provider will continuously educate their employees on cybersecurity measures, testing them regularly",
                    "A secure cloud service provider will ensure that all system changes are properly documented and configuration baselines are updated accordingly",
                    "A secure cloud service offering will protect user data, control access, and apply zero trust principles",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Cybersecurity Education",
                    "Change Management",
                    "Identity and Access Management",
                ],
                "CHECKID": ["check1", "check2", "check3"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "REGION": ["us-central1", "europe-west1", "global"],
                "ACCOUNTID": ["project-123", "project-123", "project-123"],
                "RESOURCEID": ["resource1", "resource2", "resource3"],
            }
        )

        result = get_table(test_data)

        assert result is not None
        assert len(result) > 0

        # Verify that long descriptions are replaced with short names
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    # Check that descriptions have been shortened
                    assert not any(df["REQUIREMENTS_DESCRIPTION"].str.len() > 50)
                    assert (
                        "Cybersecurity Education"
                        in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    assert "Change Management" in df["REQUIREMENTS_DESCRIPTION"].values
                    assert (
                        "Identity and Access Management"
                        in df["REQUIREMENTS_DESCRIPTION"].values
                    )

    def test_get_table_empty_data(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": [],
                "REQUIREMENTS_DESCRIPTION": [],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [],
                "CHECKID": [],
                "STATUS": [],
                "REGION": [],
                "ACCOUNTID": [],
                "RESOURCEID": [],
            }
        )

        result = get_table(test_data)

        assert result is not None
        # The function returns an html.Div object from dash
        assert hasattr(result, "className")
        assert result.className == "compliance-data-layout"

    def test_get_table_gcp_specific_locations(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-svc", "ksi-tpr"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will follow FedRAMP encryption policies, continuously verify information resource integrity, and restrict access to third-party information resources",
                    "A secure cloud service offering will understand, monitor, and manage supply chain risks from third-party information resources",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Service Configuration",
                    "Third-Party Information Resources",
                ],
                "CHECKID": ["kms_check", "iam_policy_check"],
                "STATUS": ["PASS", "FAIL"],
                "REGION": ["asia-southeast1", "us-west1"],
                "ACCOUNTID": ["project-456", "project-456"],
                "RESOURCEID": ["kms-key-1", "policy-1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify GCP-specific fields and KSI mappings
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert (
                        "Service Configuration" in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    assert (
                        "Third-Party Information Resources"
                        in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    # Check GCP locations are preserved
                    assert (
                        "asia-southeast1" in df["REGION"].values
                        or "us-west1" in df["REGION"].values
                    )

    def test_get_table_monitoring_logging_auditing(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-mla", "ksi-mla", "ksi-mla"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will monitor, log, and audit all important events, activity, and changes",
                    "A secure cloud service offering will monitor, log, and audit all important events, activity, and changes",
                    "A secure cloud service offering will monitor, log, and audit all important events, activity, and changes",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Monitoring, Logging, and Auditing",
                    "Monitoring, Logging, and Auditing",
                    "Monitoring, Logging, and Auditing",
                ],
                "CHECKID": ["logging_check", "monitoring_check", "audit_check"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "REGION": ["us-east4", "us-east4", "us-east4"],
                "ACCOUNTID": ["project-789", "project-789", "project-789"],
                "RESOURCEID": ["log-sink-1", "alert-policy-1", "audit-config-1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify monitoring description is shortened
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert (
                        "Monitoring, Logging, and Auditing"
                        in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    # Check that statuses are preserved
                    assert "PASS" in df["STATUS"].values
                    assert "FAIL" in df["STATUS"].values

    def test_get_table_policy_and_inventory(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-piy", "ksi-piy"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will have intentional, organized, universal guidance for how every information resource, including personnel, is secured",
                    "A secure cloud service offering will have intentional, organized, universal guidance for how every information resource, including personnel, is secured",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Policy and Inventory",
                    "Policy and Inventory",
                ],
                "CHECKID": ["asset_inventory_check", "org_policy_check"],
                "STATUS": ["PASS", "PASS"],
                "REGION": ["global", "global"],
                "ACCOUNTID": ["org-project", "org-project"],
                "RESOURCEID": ["inventory-1", "org-policy-1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify policy and inventory mapping
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert (
                        "Policy and Inventory" in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    # Verify both checks are included
                    assert "asset_inventory_check" in df["CHECKID"].values
                    assert "org_policy_check" in df["CHECKID"].values

    def test_get_table_recovery_planning(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-rpl"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will define, maintain, and test incident response plan(s) and recovery capabilities to ensure minimal service disruption and data loss"
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Recovery Planning"],
                "CHECKID": ["backup_check"],
                "STATUS": ["PASS"],
                "REGION": ["us-central1"],
                "ACCOUNTID": ["dr-project"],
                "RESOURCEID": ["backup-policy-1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify recovery planning mapping
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert "Recovery Planning" in df["REQUIREMENTS_DESCRIPTION"].values
