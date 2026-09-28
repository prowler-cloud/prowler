from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mocked_response(operation_name, response):
    """Validate a mocked GuardDuty response against the real API model."""
    return mocked_api_response("guardduty", operation_name, response)


def mock_make_api_call_org_admin_and_config(self, operation_name, api_params):
    """Mock organization admin accounts and configuration APIs."""
    if operation_name == "ListOrganizationAdminAccounts":
        return mocked_response(
            operation_name,
            {
                "AdminAccounts": [
                    {"AdminAccountId": "123456789012", "AdminStatus": "ENABLED"}
                ]
            },
        )
    if operation_name == "DescribeOrganizationConfiguration":
        return mocked_response(
            operation_name,
            {
                "AutoEnableOrganizationMembers": "ALL",
                "MemberAccountLimitReached": False,
            },
        )
    return orig(self, operation_name, api_params)


def mock_make_api_call_org_admin_no_auto_enable(self, operation_name, api_params):
    """Mock organization admin configured but auto-enable disabled."""
    if operation_name == "ListOrganizationAdminAccounts":
        return mocked_response(
            operation_name,
            {
                "AdminAccounts": [
                    {"AdminAccountId": "123456789012", "AdminStatus": "ENABLED"}
                ]
            },
        )
    if operation_name == "DescribeOrganizationConfiguration":
        return mocked_response(
            operation_name,
            {
                "AutoEnableOrganizationMembers": "NONE",
                "MemberAccountLimitReached": False,
            },
        )
    return orig(self, operation_name, api_params)


def mock_make_api_call_no_org_admin(self, operation_name, api_params):
    """Mock no organization admin configured."""
    if operation_name == "ListOrganizationAdminAccounts":
        return mocked_response(operation_name, {"AdminAccounts": []})
    if operation_name == "DescribeOrganizationConfiguration":
        return mocked_response(
            operation_name,
            {
                "AutoEnableOrganizationMembers": "NONE",
                "MemberAccountLimitReached": False,
            },
        )
    return orig(self, operation_name, api_params)


def mock_make_api_call_admin_lookup_access_denied(self, operation_name, api_params):
    """ListOrganizationAdminAccounts is denied — lookup-failed path."""
    if operation_name == "ListOrganizationAdminAccounts":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform: guardduty:ListOrganizationAdminAccounts",
                }
            },
            operation_name,
        )
    if operation_name == "DescribeOrganizationConfiguration":
        return mocked_response(
            operation_name,
            {
                "AutoEnableOrganizationMembers": "ALL",
                "MemberAccountLimitReached": False,
            },
        )
    return orig(self, operation_name, api_params)


def mock_make_api_call_admin_account_missing_fields(self, operation_name, api_params):
    """AdminAccounts entry without the documented fields."""
    if operation_name == "ListOrganizationAdminAccounts":
        # Deliberately not validated against the API model: this simulates the
        # response drifting away from what botocore currently describes.
        return {"AdminAccounts": [{"SomethingElse": "unexpected"}]}
    if operation_name == "DescribeOrganizationConfiguration":
        return mocked_response(
            operation_name,
            {
                "AutoEnableOrganizationMembers": "ALL",
                "MemberAccountLimitReached": False,
            },
        )
    return orig(self, operation_name, api_params)


class Test_guardduty_delegated_admin_enabled_all_regions:
    @mock_aws
    def test_no_detectors(self):
        """Test when no GuardDuty detectors exist."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions.guardduty_client",
                new=GuardDuty(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions import (
                guardduty_delegated_admin_enabled_all_regions,
            )

            check = guardduty_delegated_admin_enabled_all_regions()
            result = check.execute()

            # Should have findings for each region (with unknown detectors)
            assert len(result) > 0
            # All should fail since no detectors are enabled
            for finding in result:
                assert finding.status == "FAIL"
                assert "detector not enabled" in finding.status_extended

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_org_admin,
    )
    @mock_aws
    def test_detector_enabled_no_delegated_admin(self):
        """Test when detector is enabled but no delegated admin is configured."""
        guardduty_client_boto = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        detector_id = guardduty_client_boto.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions.guardduty_client",
                new=GuardDuty(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions import (
                guardduty_delegated_admin_enabled_all_regions,
            )

            check = guardduty_delegated_admin_enabled_all_regions()
            result = check.execute()

            # Find the result for our region
            eu_west_1_result = None
            for finding in result:
                if finding.region == AWS_REGION_EU_WEST_1:
                    eu_west_1_result = finding
                    break

            assert eu_west_1_result is not None
            assert eu_west_1_result.status == "FAIL"
            assert (
                "no delegated administrator configured"
                in eu_west_1_result.status_extended
            )
            assert eu_west_1_result.resource_id == detector_id

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_org_admin_no_auto_enable,
    )
    @mock_aws
    def test_detector_enabled_with_admin_no_auto_enable(self):
        """Test when detector is enabled with delegated admin but auto-enable is off."""
        guardduty_client_boto = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        detector_id = guardduty_client_boto.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions.guardduty_client",
                new=GuardDuty(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions import (
                guardduty_delegated_admin_enabled_all_regions,
            )

            check = guardduty_delegated_admin_enabled_all_regions()
            result = check.execute()

            # Find the result for our region
            eu_west_1_result = None
            for finding in result:
                if finding.region == AWS_REGION_EU_WEST_1:
                    eu_west_1_result = finding
                    break

            assert eu_west_1_result is not None
            assert eu_west_1_result.status == "FAIL"
            assert (
                "organization auto-enable not configured"
                in eu_west_1_result.status_extended
            )
            assert eu_west_1_result.resource_id == detector_id

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_org_admin_and_config,
    )
    @mock_aws
    def test_detector_enabled_with_admin_and_auto_enable(self):
        """Test when detector is enabled with delegated admin and auto-enable is on (PASS)."""
        guardduty_client_boto = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        detector_id = guardduty_client_boto.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions.guardduty_client",
                new=GuardDuty(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions import (
                guardduty_delegated_admin_enabled_all_regions,
            )

            check = guardduty_delegated_admin_enabled_all_regions()
            result = check.execute()

            # Find the result for our region
            eu_west_1_result = None
            for finding in result:
                if finding.region == AWS_REGION_EU_WEST_1:
                    eu_west_1_result = finding
                    break

            assert eu_west_1_result is not None
            assert eu_west_1_result.status == "PASS"
            assert "delegated admin configured" in eu_west_1_result.status_extended
            assert "auto-enable active" in eu_west_1_result.status_extended
            assert eu_west_1_result.resource_id == detector_id
            assert (
                eu_west_1_result.resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_admin_lookup_access_denied,
    )
    @mock_aws
    def test_admin_lookup_access_denied(self):
        """A denied lookup is unknown, not absent: MANUAL instead of FAIL."""
        guardduty_client_boto = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        guardduty_client_boto.create_detector(Enable=True)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        service = GuardDuty(aws_provider)
        assert AWS_REGION_EU_WEST_1 in service.organization_admin_lookup_failed_regions

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions.guardduty_client",
                new=service,
            ),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_delegated_admin_enabled_all_regions.guardduty_delegated_admin_enabled_all_regions import (
                guardduty_delegated_admin_enabled_all_regions,
            )

            result = guardduty_delegated_admin_enabled_all_regions().execute()

            assert result and result[0].status == "MANUAL"
            assert "could not be determined" in result[0].status_extended
            assert (
                "management or delegated administrator account"
                in result[0].status_extended
            )
            assert (
                "no delegated administrator configured" not in result[0].status_extended
            )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_admin_account_missing_fields,
    )
    @mock_aws
    def test_admin_account_missing_fields(self):
        """An unparseable admin entry marks the region as unknown instead of raising."""
        guardduty_client_boto = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        guardduty_client_boto.create_detector(Enable=True)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        service = GuardDuty(aws_provider)

        assert service.organization_admin_accounts == []
        assert service.organization_admin_lookup_failed_regions == {
            AWS_REGION_EU_WEST_1
        }
