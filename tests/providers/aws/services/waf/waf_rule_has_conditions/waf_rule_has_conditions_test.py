from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

WEB_ACL_ID = "test-web-acl-id"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_waf_webacl_has_rules_or_rule_groups:
    @mock_aws
    def test_no_rules(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_webacl_has_rules_or_rule_groups.waf_webacl_has_rules_or_rule_groups.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_webacl_has_rules_or_rule_groups.waf_webacl_has_rules_or_rule_groups import (
                    waf_webacl_has_rules_or_rule_groups,
                )

                check = waf_webacl_has_rules_or_rule_groups()
                result = check.execute()

                assert len(result) == 0
