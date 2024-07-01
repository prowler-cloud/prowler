from unittest.mock import MagicMock, patch

from prowler.lib.outputs.finding import Finding, Severity, Status


def mock_get_provider_data_mapping(_):
    return {
        "auth_method": "mock_auth",
        "timestamp": 1622520000,
        "account_uid": "mock_account_uid",
        "account_name": "mock_account_name",
        "account_email": "mock_account_email",
        "account_organization_uid": "mock_account_org_uid",
        "account_organization_name": "mock_account_org_name",
        "account_tags": ["tag1", "tag2"],
        "finding_uid": "mock_finding_uid",
        "provider": "aws",
        "check_id": "mock_check_id",
        "check_title": "mock_check_title",
        "check_type": "mock_check_type",
        "status": Status.PASS,
        "status_extended": "mock_status_extended",
        "muted": False,
        "service_name": "mock_service_name",
        "subservice_name": "mock_subservice_name",
        "severity": Severity.high,
        "resource_type": "mock_resource_type",
        "resource_uid": "mock_resource_uid",
        "resource_name": "mock_resource_name",
        "resource_details": "mock_resource_details",
        "resource_tags": "mock_resource_tags",
        "partition": None,
        "region": "mock_region",
        "description": "mock_description",
        "risk": "mock_risk",
        "related_url": "mock_related_url",
        "remediation_recommendation_text": "mock_remediation_text",
        "remediation_recommendation_url": "mock_remediation_url",
        "remediation_code_nativeiac": "mock_code_nativeiac",
        "remediation_code_terraform": "mock_code_terraform",
        "remediation_code_cli": "mock_code_cli",
        "remediation_code_other": "mock_code_other",
        "compliance": {"mock_compliance_key": "mock_compliance_value"},
        "categories": "mock_categories",
        "depends_on": "mock_depends_on",
        "related_to": "mock_related_to",
        "notes": "mock_notes",
        "prowler_version": "1.0.0",
    }


def mock_fill_common_finding_data(_, unix_timestamp):
    return {"common_key": "common_value", "unix_timestamp": unix_timestamp}


class TestFinding:
    @patch(
        "prowler.lib.outputs.finding.get_provider_data_mapping",
        new=mock_get_provider_data_mapping,
    )
    @patch(
        "prowler.lib.outputs.finding.fill_common_finding_data",
        new=mock_fill_common_finding_data,
    )
    def test_generate_output(self):
        # Mock provider and other arguments
        provider = MagicMock()
        provider.type = "aws"
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_arn = "test_resource_arn"
        check_output.region = "us-west-1"
        output_options = MagicMock()
        output_options.unix_timestamp = 1234567890

        # Call the method under test
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Assertions to verify expected behavior
        assert finding_output is not None
        assert finding_output.auth_method == "profile: mock_auth"
        assert finding_output.resource_name == "test_resource_id"
        assert finding_output.resource_uid == "test_resource_arn"
        assert finding_output.region == "us-west-1"
