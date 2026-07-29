from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

WEB_ACL_ID = "test-web-acl-id"
WEB_ACL_NAME = "test-web-acl-name"
WEB_ACL_ARN = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
FIREHOSE_ARN = f"arn:aws:firehose:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:deliverystream/aws-waf-logs-regional"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


def _base_waf_regional_calls(operation_name, kwarg):
    """Return responses for WAFRegional API calls that are common across all test scenarios.

    Args:
        operation_name (str): The name of the botocore operation being called.
        kwarg (dict): The keyword arguments passed to the API call.

    Returns:
        dict or None: The mocked API response if the operation is handled, otherwise None.
    """
    unused_operations = [
        "ListRules",
        "GetRule",
        "ListRuleGroups",
        "ListActivatedRulesInRuleGroup",
        "ListResourcesForWebACL",
    ]
    if operation_name in unused_operations:
        return {}
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {"WebACLs": [{"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME}]}
    if operation_name == "GetWebACL":
        return {"WebACL": {"Rules": []}}
    return None


def mock_make_api_call_logging_enabled(self, operation_name, kwarg):
    """Mock botocore API calls with logging enabled on the Regional Web ACL.

    Args:
        self: The botocore client instance.
        operation_name (str): The name of the botocore operation being called.
        kwarg (dict): The keyword arguments passed to the API call.

    Returns:
        dict: The mocked API response.
    """
    base = _base_waf_regional_calls(operation_name, kwarg)
    if base is not None:
        return base
    if operation_name == "GetLoggingConfiguration":
        return {
            "LoggingConfiguration": {
                "ResourceArn": WEB_ACL_ARN,
                "LogDestinationConfigs": [FIREHOSE_ARN],
                "RedactedFields": [],
                "ManagedByFirewallManager": False,
            }
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_logging_disabled(self, operation_name, kwarg):
    """Mock botocore API calls with logging disabled on the Regional Web ACL.

    Args:
        self: The botocore client instance.
        operation_name (str): The name of the botocore operation being called.
        kwarg (dict): The keyword arguments passed to the API call.

    Returns:
        dict: The mocked API response.
    """
    base = _base_waf_regional_calls(operation_name, kwarg)
    if base is not None:
        return base
    if operation_name == "GetLoggingConfiguration":
        return {
            "LoggingConfiguration": {
                "ResourceArn": WEB_ACL_ARN,
                "LogDestinationConfigs": [],
                "RedactedFields": [],
                "ManagedByFirewallManager": False,
            }
        }
    return orig(self, operation_name, kwarg)


class Test_waf_regional_webacl_logging_enabled:
    """Tests for the waf_regional_webacl_logging_enabled check."""

    @mock_aws
    def test_no_waf(self):
        """Test that no findings are returned when no Regional Web ACLs exist."""
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                from prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled import (
                    waf_regional_webacl_logging_enabled,
                )

                check = waf_regional_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_logging_disabled,
    )
    @mock_aws
    def test_waf_regional_webacl_logging_disabled(self):
        """Test that a FAIL finding is returned when logging is disabled on a Regional Web ACL."""
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                from prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled import (
                    waf_regional_webacl_logging_enabled,
                )

                check = waf_regional_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Regional Web ACL {WEB_ACL_NAME} does not have logging enabled."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert result[0].resource_arn == WEB_ACL_ARN
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_logging_enabled,
    )
    @mock_aws
    def test_waf_regional_webacl_logging_enabled(self):
        """Test that a PASS finding is returned when logging is enabled on a Regional Web ACL."""
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                from prowler.providers.aws.services.waf.waf_regional_webacl_logging_enabled.waf_regional_webacl_logging_enabled import (
                    waf_regional_webacl_logging_enabled,
                )

                check = waf_regional_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Regional Web ACL {WEB_ACL_NAME} does have logging enabled."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert result[0].resource_arn == WEB_ACL_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
