from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.ses.ses_service import SES
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "EMAIL_ADDRESS",
                    "IdentityName": "test-email-identity",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {
                "policy1": '{"policy1": "value1"}',
            },
            "Tags": {"tag1": "value1", "tag2": "value2"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SES_Service:
    # Test SES Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ses = SES(aws_provider)
        assert ses.service == "sesv2"

    # Test SES client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ses = SES(aws_provider)
        for reg_client in ses.regional_clients.values():
            assert reg_client.__class__.__name__ == "SESV2"

    # Test SES session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ses = SES(aws_provider)
        assert ses.session.__class__.__name__ == "Session"

    @mock_aws
    # Test SES list queues
    def test_list_identities(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ses = SES(aws_provider)
        arn = f"arn:aws:ses:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:identity/test-email-identity"
        assert ses.email_identities[arn].name == "test-email-identity"
        assert ses.email_identities[arn].type == "EMAIL_ADDRESS"
        assert ses.email_identities[arn].arn == arn
        assert ses.email_identities[arn].region == AWS_REGION_EU_WEST_1
        assert ses.email_identities[arn].policy == {"policy1": "value1"}
        assert ses.email_identities[arn].tags == {"tag1": "value1", "tag2": "value2"}
