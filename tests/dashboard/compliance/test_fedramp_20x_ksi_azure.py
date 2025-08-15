import pandas as pd

from dashboard.compliance.fedramp_20x_ksi_azure import get_table


class TestFedRAMP20xKSIAzure:
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
                "REGION": ["eastus", "westus", "global"],
                "ACCOUNTID": ["sub-12345", "sub-12345", "sub-12345"],
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

    def test_get_table_azure_specific_regions(self):
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
                "CHECKID": ["keyvault_check", "policy_check"],
                "STATUS": ["PASS", "FAIL"],
                "REGION": ["northeurope", "southeastasia"],
                "ACCOUNTID": ["sub-67890", "sub-67890"],
                "RESOURCEID": ["vault1", "policy1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify Azure-specific fields and KSI mappings
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
                    # Check Azure regions are preserved
                    assert (
                        "northeurope" in df["REGION"].values
                        or "southeastasia" in df["REGION"].values
                    )

    def test_get_table_cloud_native_architecture(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-cna", "ksi-cna", "ksi-cna"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will use cloud native architecture and design principles to enforce and enhance the Confidentiality, Integrity and Availability of the system",
                    "A secure cloud service offering will use cloud native architecture and design principles to enforce and enhance the Confidentiality, Integrity and Availability of the system",
                    "A secure cloud service offering will use cloud native architecture and design principles to enforce and enhance the Confidentiality, Integrity and Availability of the system",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Cloud Native Architecture",
                    "Cloud Native Architecture",
                    "Cloud Native Architecture",
                ],
                "CHECKID": ["network_check", "storage_check", "compute_check"],
                "STATUS": ["PASS", "PASS", "FAIL"],
                "REGION": ["centralus", "centralus", "centralus"],
                "ACCOUNTID": ["sub-99999", "sub-99999", "sub-99999"],
                "RESOURCEID": ["vnet1", "storage1", "vm1"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify cloud native architecture description is shortened
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert (
                        "Cloud Native Architecture"
                        in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    # Verify all checks are included
                    assert (
                        len(
                            df[
                                df["CHECKID"].isin(
                                    ["network_check", "storage_check", "compute_check"]
                                )
                            ]
                        )
                        >= 3
                    )

    def test_get_table_incident_reporting(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-inc"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will document, report, and analyze security incidents to ensure regulatory compliance and continuous security improvement"
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Incident Reporting"],
                "CHECKID": ["sentinel_check"],
                "STATUS": ["PASS"],
                "REGION": ["global"],
                "ACCOUNTID": ["sub-11111"],
                "RESOURCEID": ["sentinel_workspace"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify incident reporting mapping
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert "Incident Reporting" in df["REQUIREMENTS_DESCRIPTION"].values
