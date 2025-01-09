from unittest import mock

import botocore
from boto3 import client
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
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-email-identity-not-public",
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


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "EMAIL_ADDRESS",
                    "IdentityName": "test-email-identity-public",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {
                "policy1": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ses:SendEmail","Resource":"*"}]}',
            },
            "Tags": {"tag1": "value1", "tag2": "value2"},
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ses_identities_not_publicly_accessible:
    @mock_aws
    def test_no_identities(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
            new=SES(aws_provider),
        ):
            from prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import (
                ses_identity_not_publicly_accessible,
            )

            check = ses_identity_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_email_identity_not_public(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
            new=SES(aws_provider),
        ):
            from prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import (
                ses_identity_not_publicly_accessible,
            )

            check = ses_identity_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SES identity test-email-identity-not-public is not publicly accessible."
            )
            assert result[0].resource_id == "test-email-identity-not-public"
            assert (
                result[0].resource_arn
                == f"arn:aws:ses:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:identity/test-email-identity-not-public"
            )
            assert result[0].resource_tags == {"tag1": "value1", "tag2": "value2"}
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_email_identity_public(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
            new=SES(aws_provider),
        ):
            from prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import (
                ses_identity_not_publicly_accessible,
            )

            check = ses_identity_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SES identity test-email-identity-public is publicly accessible due to its resource policy."
            )
            assert result[0].resource_id == "test-email-identity-public"
            assert (
                result[0].resource_arn
                == f"arn:aws:ses:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:identity/test-email-identity-public"
            )
            assert result[0].resource_tags == {"tag1": "value1", "tag2": "value2"}
            assert result[0].region == AWS_REGION_EU_WEST_1
