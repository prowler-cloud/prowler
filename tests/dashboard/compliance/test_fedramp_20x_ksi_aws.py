import pandas as pd

from dashboard.compliance.fedramp_20x_ksi_aws import get_table


class TestFedRAMP20xKSIAWS:
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
                "REGION": ["us-east-1", "us-west-2", "global"],
                "ACCOUNTID": ["123456789012", "123456789012", "123456789012"],
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

    def test_get_table_partial_ksi_descriptions(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-pol", "ksi-rec"],
                "REQUIREMENTS_DESCRIPTION": [
                    "A secure cloud service offering will have intentional, organized, universal guidance for how every information resource, including personnel, is secured",
                    "A secure cloud service offering will define, maintain, and test incident response plan(s) and recovery capabilities to ensure minimal service disruption and data loss",
                ],
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Policy and Inventory",
                    "Recovery Planning",
                ],
                "CHECKID": ["check4", "check5"],
                "STATUS": ["PASS", "FAIL"],
                "REGION": ["eu-west-1", "ap-south-1"],
                "ACCOUNTID": ["987654321098", "987654321098"],
                "RESOURCEID": ["resource4", "resource5"],
            }
        )

        result = get_table(test_data)

        assert result is not None

        # Verify specific KSI mappings
        for section in result:
            if "tables" in section:
                for table in section["tables"]:
                    df = table["data"]
                    assert (
                        "Policy and Inventory" in df["REQUIREMENTS_DESCRIPTION"].values
                    )
                    assert "Recovery Planning" in df["REQUIREMENTS_DESCRIPTION"].values

    def test_get_table_mixed_statuses(self):
        test_data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["ksi-mon", "ksi-mon", "ksi-mon"],
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
                "CHECKID": ["cloudtrail_check", "cloudwatch_check", "config_check"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "REGION": ["us-east-1", "us-east-1", "us-east-1"],
                "ACCOUNTID": ["111111111111", "111111111111", "111111111111"],
                "RESOURCEID": ["trail1", "alarm1", "config1"],
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
