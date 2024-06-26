from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    TrustedAdvisor,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeTrustedAdvisorCheckResult":
        return {}
    if operation_name == "DescribeServices":
        return {
            "services": [
                {
                    "code": "amazon-marketplace",
                    "name": "Marketplace",
                    "categories": [
                        {
                            "code": "general-marketplace-seller-inquiry",
                            "name": "General Marketplace Seller Inquiry",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_TrustedAdvisor_Service:

    # Test TrustedAdvisor Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        trustedadvisor = TrustedAdvisor(aws_provider)
        assert trustedadvisor.service == "support"

    # Test TrustedAdvisor client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        trustedadvisor = TrustedAdvisor(aws_provider)
        assert trustedadvisor.client.__class__.__name__ == "Support"

    # Test TrustedAdvisor session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        trustedadvisor = TrustedAdvisor(aws_provider)
        assert trustedadvisor.session.__class__.__name__ == "Session"

    @mock_aws
    # Test TrustedAdvisor session
    def test__describe_trusted_advisor_checks__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        trustedadvisor = TrustedAdvisor(aws_provider)
        assert trustedadvisor.premium_support.enabled
        assert len(trustedadvisor.checks) == 104  # Default checks
        assert trustedadvisor.checks[0].region == AWS_REGION_US_EAST_1
