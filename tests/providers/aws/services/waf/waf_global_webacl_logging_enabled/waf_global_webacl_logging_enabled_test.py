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

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call_logging_enabled(self, operation_name, kwarg):
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [],
            }
        }
    if operation_name == "GetLoggingConfiguration":
        return {
            "LoggingConfiguration": {
                "ResourceArn": f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}",
                "LogDestinationConfigs": [
                    "arn:aws:firehose:us-east-1:123456789012:deliverystream/my-firehose"
                ],
                "RedactedFields": [],
                "ManagedByFirewallManager": False,
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_logging_disabled(self, operation_name, kwarg):
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [],
            }
        }
    if operation_name == "GetLoggingConfiguration":
        return {
            "LoggingConfiguration": {
                "ResourceArn": f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}",
                "LogDestinationConfigs": [],
                "RedactedFields": [],
                "ManagedByFirewallManager": False,
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_waf_global_webacl_logging_enabled:
    @mock_aws
    def test_no_waf(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled import (
                    waf_global_webacl_logging_enabled,
                )

                check = waf_global_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_logging_disabled,
    )
    @mock_aws
    def test_waf_webacl_logging_disabled(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled import (
                    waf_global_webacl_logging_enabled,
                )

                check = waf_global_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} does not have logging enabled."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_logging_enabled,
    )
    @mock_aws
    def test_waf_webacl_logging_enabled(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled import (
                    waf_global_webacl_logging_enabled,
                )

                check = waf_global_webacl_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} does have logging enabled."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
