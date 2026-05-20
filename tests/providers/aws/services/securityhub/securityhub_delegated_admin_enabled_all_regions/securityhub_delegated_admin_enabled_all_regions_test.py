from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call

HUB_ARN = f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hub/default"


def _active_hub_responses(operation_name):
    """Return a moto-friendly response for hub-describing API calls.

    Returns None if the operation is not one of the hub APIs (so the caller
    can fall back to the default behavior).
    """
    if operation_name == "DescribeHub":
        return {
            "HubArn": HUB_ARN,
            "SubscribedAt": "2024-01-01T00:00:00.000Z",
            "AutoEnableControls": True,
        }
    if operation_name == "GetEnabledStandards":
        return {"StandardsSubscriptions": []}
    if operation_name == "ListEnabledProductsForImport":
        return {"ProductSubscriptions": []}
    if operation_name == "ListTagsForResource":
        return {"Tags": {}}
    return None


def mock_make_api_call_org_admin_and_config(self, operation_name, api_params):
    """Mock organization admin accounts and configuration APIs - PASS scenario."""
    hub_resp = _active_hub_responses(operation_name)
    if hub_resp is not None:
        return hub_resp
    if operation_name == "ListOrganizationAdminAccounts":
        return {
            "AdminAccounts": [
                {
                    "AdminAccountId": "123456789012",
                    "AdminStatus": "ENABLED",
                }
            ]
        }
    if operation_name == "DescribeOrganizationConfiguration":
        return {
            "AutoEnable": True,
            "AutoEnableStandards": "DEFAULT",
        }
    return orig(self, operation_name, api_params)


def mock_make_api_call_org_admin_no_auto_enable(self, operation_name, api_params):
    """Mock organization admin configured but auto-enable disabled."""
    hub_resp = _active_hub_responses(operation_name)
    if hub_resp is not None:
        return hub_resp
    if operation_name == "ListOrganizationAdminAccounts":
        return {
            "AdminAccounts": [
                {
                    "AdminAccountId": "123456789012",
                    "AdminStatus": "ENABLED",
                }
            ]
        }
    if operation_name == "DescribeOrganizationConfiguration":
        return {
            "AutoEnable": False,
            "AutoEnableStandards": "NONE",
        }
    return orig(self, operation_name, api_params)


def mock_make_api_call_no_org_admin(self, operation_name, api_params):
    """Mock no organization admin configured."""
    hub_resp = _active_hub_responses(operation_name)
    if hub_resp is not None:
        return hub_resp
    if operation_name == "ListOrganizationAdminAccounts":
        return {"AdminAccounts": []}
    if operation_name == "DescribeOrganizationConfiguration":
        return {
            "AutoEnable": False,
            "AutoEnableStandards": "NONE",
        }
    return orig(self, operation_name, api_params)


def mock_make_api_call_securityhub_not_subscribed(self, operation_name, api_params):
    """Simulate Security Hub not subscribed in the account (InvalidAccessException)."""
    if operation_name == "DescribeHub":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "InvalidAccessException",
                    "Message": "Account is not subscribed to AWS Security Hub",
                }
            },
            operation_name,
        )
    if operation_name == "ListOrganizationAdminAccounts":
        return {"AdminAccounts": []}
    return orig(self, operation_name, api_params)


class Test_securityhub_delegated_admin_enabled_all_regions:
    def teardown_method(self):
        """Evict cached securityhub modules so legacy mock.patch-based tests
        in the same session see a fresh import path."""
        import sys

        for mod in (
            "prowler.providers.aws.services.securityhub.securityhub_client",
            "prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions",
        ):
            sys.modules.pop(mod, None)

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_securityhub_not_subscribed,
    )
    @mock_aws
    def test_no_securityhub(self):
        """Test when Security Hub is not subscribed in any region."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.securityhub.securityhub_service import (
            SecurityHub,
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions.securityhub_client",
                new=SecurityHub(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions import (
                securityhub_delegated_admin_enabled_all_regions,
            )

            check = securityhub_delegated_admin_enabled_all_regions()
            result = check.execute()

            # Should have findings for each region (with NOT_AVAILABLE hubs)
            assert len(result) > 0
            # All should fail since hub is not enabled
            for finding in result:
                assert finding.status == "FAIL"
                assert "Security Hub not enabled" in finding.status_extended

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_org_admin,
    )
    @mock_aws
    def test_securityhub_enabled_no_delegated_admin(self):
        """Test when Security Hub is enabled but no delegated admin is configured."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.securityhub.securityhub_service import (
            SecurityHub,
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions.securityhub_client",
                new=SecurityHub(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions import (
                securityhub_delegated_admin_enabled_all_regions,
            )

            check = securityhub_delegated_admin_enabled_all_regions()
            result = check.execute()

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
            assert eu_west_1_result.resource_arn == HUB_ARN

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_org_admin_no_auto_enable,
    )
    @mock_aws
    def test_securityhub_enabled_with_admin_no_auto_enable(self):
        """Test when Security Hub is enabled with delegated admin but auto-enable is off."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.securityhub.securityhub_service import (
            SecurityHub,
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions.securityhub_client",
                new=SecurityHub(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions import (
                securityhub_delegated_admin_enabled_all_regions,
            )

            check = securityhub_delegated_admin_enabled_all_regions()
            result = check.execute()

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

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_org_admin_and_config,
    )
    @mock_aws
    def test_securityhub_enabled_with_admin_and_auto_enable(self):
        """Test when Security Hub is enabled with delegated admin and auto-enable on (PASS)."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.securityhub.securityhub_service import (
            SecurityHub,
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions.securityhub_client",
                new=SecurityHub(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.securityhub.securityhub_delegated_admin_enabled_all_regions.securityhub_delegated_admin_enabled_all_regions import (
                securityhub_delegated_admin_enabled_all_regions,
            )

            check = securityhub_delegated_admin_enabled_all_regions()
            result = check.execute()

            eu_west_1_result = None
            for finding in result:
                if finding.region == AWS_REGION_EU_WEST_1:
                    eu_west_1_result = finding
                    break

            assert eu_west_1_result is not None
            assert eu_west_1_result.status == "PASS"
            assert "delegated admin configured" in eu_west_1_result.status_extended
            assert "auto-enable" in eu_west_1_result.status_extended
            assert eu_west_1_result.resource_arn == HUB_ARN
