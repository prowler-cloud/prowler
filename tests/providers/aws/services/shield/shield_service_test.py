import botocore
from mock import patch

from prowler.providers.aws.services.shield.shield_service import Shield
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListProtections":
        return {
            "Protections": [
                {
                    "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                    "Name": "Protection for CloudFront distribution",
                    "ResourceArn": f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/E198WC25FXOWY8",
                }
            ]
        }
    if operation_name == "GetSubscriptionState":
        return {"SubscriptionState": "ACTIVE"}

    return make_api_call(self, operation_name, kwarg)


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Shield_Service:
    # Test Shield Service
    def test_service(self):
        # Shield client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        shield = Shield(aws_provider)
        assert shield.service == "shield"

    # Test Shield Client
    def test_client(self):
        # Shield client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        shield = Shield(aws_provider)
        assert shield.client.__class__.__name__ == "Shield"

    # Test Shield Session
    def test__get_session__(self):
        # Shield client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        shield = Shield(aws_provider)
        assert shield.session.__class__.__name__ == "Session"

    def test__get_subscription_state__(self):
        # Shield client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        shield = Shield(aws_provider)
        assert shield.enabled

    def test__list_protections__(self):
        # Shield client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        shield = Shield(aws_provider)
        protection_id = "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
        protection_name = "Protection for CloudFront distribution"
        cloudfront_distribution_id = "E198WC25FXOWY8"
        resource_arn = (
            f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{cloudfront_distribution_id}",
        )

        assert shield.protections
        assert len(shield.protections) == 1
        assert shield.protections[protection_id]
        assert shield.protections[protection_id].id == protection_id
        assert shield.protections[protection_id].name == protection_name
        assert not shield.protections[protection_id].protection_arn
        assert not shield.protections[protection_id].resource_arn == resource_arn
