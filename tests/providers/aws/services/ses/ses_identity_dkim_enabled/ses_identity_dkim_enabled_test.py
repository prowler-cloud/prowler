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


def mock_make_api_call_dkim_pass(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-domain-dkim-pass",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {},
            "Tags": [],
            "DkimAttributes": {
                "Status": "SUCCESS",
                "SigningEnabled": True,
                "SigningAttributesOrigin": "AWS_SES",
            },
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_dkim_fail_not_started(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-domain-dkim-not-started",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {},
            "Tags": [],
            "DkimAttributes": {
                "Status": "NOT_STARTED",
                "SigningEnabled": False,
                "SigningAttributesOrigin": "AWS_SES",
            },
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_dkim_fail_failed(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-domain-dkim-failed",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {},
            "Tags": [],
            "DkimAttributes": {
                "Status": "FAILED",
                "SigningEnabled": False,
                "SigningAttributesOrigin": "AWS_SES",
            },
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_dkim_pending(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-domain-dkim-pending",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {},
            "Tags": [],
            "DkimAttributes": {
                "Status": "PENDING",
                "SigningEnabled": False,
                "SigningAttributesOrigin": "AWS_SES",
            },
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_dkim_success_not_enabled(self, operation_name, kwarg):
    if operation_name == "ListEmailIdentities":
        return {
            "EmailIdentities": [
                {
                    "IdentityType": "DOMAIN",
                    "IdentityName": "test-domain-dkim-verified-not-signed",
                }
            ],
        }
    elif operation_name == "GetEmailIdentity":
        return {
            "Policies": {},
            "Tags": [],
            "DkimAttributes": {
                "Status": "SUCCESS",
                "SigningEnabled": False,
                "SigningAttributesOrigin": "AWS_SES",
            },
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ses_identity_dkim_enabled:
    @mock_aws
    def test_no_identities(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_dkim_pass,
    )
    def test_identity_dkim_enabled_and_verified(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SES identity test-domain-dkim-pass has DKIM signing enabled and verified."
            )
            assert result[0].resource_id == "test-domain-dkim-pass"
            assert (
                result[0].resource_arn
                == f"arn:aws:ses:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:identity/test-domain-dkim-pass"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_dkim_fail_not_started,
    )
    def test_identity_dkim_not_started(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SES identity test-domain-dkim-not-started has DKIM signing not verified (status: NOT_STARTED)."
            )
            assert result[0].resource_id == "test-domain-dkim-not-started"
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_dkim_fail_failed,
    )
    def test_identity_dkim_failed(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SES identity test-domain-dkim-failed has DKIM signing failed verification."
            )
            assert result[0].resource_id == "test-domain-dkim-failed"
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_dkim_pending,
    )
    def test_identity_dkim_pending(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SES identity test-domain-dkim-pending has DKIM signing not verified (status: PENDING)."
            )
            assert result[0].resource_id == "test-domain-dkim-pending"
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_dkim_success_not_enabled,
    )
    def test_identity_dkim_verified_but_not_enabled(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_dkim_enabled.ses_identity_dkim_enabled import (
                ses_identity_dkim_enabled,
            )

            check = ses_identity_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SES identity test-domain-dkim-verified-not-signed does not have DKIM signing configured."
            )
            assert result[0].resource_id == "test-domain-dkim-verified-not-signed"
            assert result[0].region == AWS_REGION_EU_WEST_1
