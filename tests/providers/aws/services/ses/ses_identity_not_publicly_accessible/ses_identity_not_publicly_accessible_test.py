from copy import deepcopy
from unittest import mock

import botocore
import pytest
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


PUBLIC_ALLOW_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ses:SendEmail","Resource":"*"}]}'
PRIVATE_ALLOW_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ses:SendEmail","Resource":"*"}]}'
MATCHING_DENY_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"ses:SendEmail","Resource":"*"}]}'
UNRELATED_DENY_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"ses:SendRawEmail","Resource":"*"}]}'
PUBLIC_ALLOW_AND_DENY_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ses:SendEmail","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"ses:SendEmail","Resource":"*"}]}'
PUBLIC_ALLOW_SINGLE_STATEMENT_POLICY = '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"ses:SendEmail","Resource":"*"}}'
PRIVATE_ALLOW_SINGLE_STATEMENT_POLICY = '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ses:SendEmail","Resource":"*"}}'
MATCHING_DENY_SINGLE_STATEMENT_POLICY = '{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"ses:SendEmail","Resource":"*"}}'
CONDITIONAL_ALLOW_SINGLE_STATEMENT_POLICY = '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"ses:SendEmail","Resource":"*","Condition":{"StringEquals":{"AWS:SourceAccount":"123456789012"}}}}'


def make_multiple_policies_api_mock(policies):
    def mock_api_call(self, operation_name, kwarg):
        if operation_name == "ListEmailIdentities":
            return {
                "EmailIdentities": [
                    {
                        "IdentityType": "DOMAIN",
                        "IdentityName": "test-email-identity-multiple-policies",
                    }
                ],
            }
        elif operation_name == "GetEmailIdentity":
            return {"Policies": policies, "Tags": {}}
        return make_api_call(self, operation_name, kwarg)

    return mock_api_call


mock_make_api_call_multiple_policies = make_multiple_policies_api_mock(
    {
        "public-policy": PUBLIC_ALLOW_POLICY,
        "private-policy": PRIVATE_ALLOW_POLICY,
    }
)
mock_make_api_call_multiple_policies_reversed = make_multiple_policies_api_mock(
    {
        "private-policy": PRIVATE_ALLOW_POLICY,
        "public-policy": PUBLIC_ALLOW_POLICY,
    }
)
mock_make_api_call_public_allow_and_matching_deny = make_multiple_policies_api_mock(
    {
        "public-policy": PUBLIC_ALLOW_POLICY,
        "deny-policy": MATCHING_DENY_POLICY,
    }
)
mock_make_api_call_matching_deny_and_public_allow = make_multiple_policies_api_mock(
    {
        "deny-policy": MATCHING_DENY_POLICY,
        "public-policy": PUBLIC_ALLOW_POLICY,
    }
)
mock_make_api_call_public_allow_and_unrelated_deny = make_multiple_policies_api_mock(
    {
        "public-policy": PUBLIC_ALLOW_POLICY,
        "deny-policy": UNRELATED_DENY_POLICY,
    }
)
mock_make_api_call_same_policy_allow_and_deny = make_multiple_policies_api_mock(
    {"combined-policy": PUBLIC_ALLOW_AND_DENY_POLICY}
)
mock_make_api_call_multiple_private_policies = make_multiple_policies_api_mock(
    {
        "private-policy-1": PRIVATE_ALLOW_POLICY,
        "private-policy-2": PRIVATE_ALLOW_POLICY,
    }
)
mock_make_api_call_public_single_statement = make_multiple_policies_api_mock(
    {"public-policy": PUBLIC_ALLOW_SINGLE_STATEMENT_POLICY}
)
mock_make_api_call_private_single_statement = make_multiple_policies_api_mock(
    {"private-policy": PRIVATE_ALLOW_SINGLE_STATEMENT_POLICY}
)
mock_make_api_call_public_and_deny_single_statements = make_multiple_policies_api_mock(
    {
        "public-policy": PUBLIC_ALLOW_SINGLE_STATEMENT_POLICY,
        "deny-policy": MATCHING_DENY_SINGLE_STATEMENT_POLICY,
    }
)
mock_make_api_call_conditional_single_statement = make_multiple_policies_api_mock(
    {"conditional-policy": CONDITIONAL_ALLOW_SINGLE_STATEMENT_POLICY}
)


def execute_check_with_api_mock(api_call_mock):
    with mock.patch("botocore.client.BaseClient._make_api_call", new=api_call_mock):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
                new=SES(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import (
                ses_identity_not_publicly_accessible,
            )

            return ses_identity_not_publicly_accessible().execute()


class Test_ses_identities_not_publicly_accessible:
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
                "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
                new=SES(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
                new=SES(aws_provider),
            ),
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
    @pytest.mark.parametrize(
        "api_call_mock",
        [
            mock_make_api_call_multiple_policies,
            mock_make_api_call_multiple_policies_reversed,
        ],
        ids=["public-policy-first", "public-policy-last"],
    )
    def test_email_identity_public_when_any_policy_is_public(self, api_call_mock):
        result = execute_check_with_api_mock(api_call_mock)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "SES identity test-email-identity-multiple-policies is publicly accessible due to its resource policies."
        )

    @mock_aws
    @pytest.mark.parametrize(
        "api_call_mock",
        [
            mock_make_api_call_public_allow_and_matching_deny,
            mock_make_api_call_matching_deny_and_public_allow,
            mock_make_api_call_public_allow_and_unrelated_deny,
            mock_make_api_call_same_policy_allow_and_deny,
        ],
        ids=[
            "matching-deny-last",
            "matching-deny-first",
            "unrelated-deny",
            "same-policy-deny",
        ],
    )
    def test_email_identity_public_allow_with_explicit_deny_is_manual(
        self, api_call_mock
    ):
        result = execute_check_with_api_mock(api_call_mock)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "SES identity test-email-identity-multiple-policies has public Allow and explicit Deny statements in its resource policies. Effective public access requires manual review."
        )

    @mock_aws
    def test_email_identity_multiple_private_policies(self):
        result = execute_check_with_api_mock(
            mock_make_api_call_multiple_private_policies
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "SES identity test-email-identity-multiple-policies is not publicly accessible."
        )

    @mock_aws
    @pytest.mark.parametrize(
        ("api_call_mock", "expected_status"),
        [
            (mock_make_api_call_public_single_statement, "FAIL"),
            (mock_make_api_call_private_single_statement, "PASS"),
            (mock_make_api_call_public_and_deny_single_statements, "MANUAL"),
        ],
        ids=["public", "private", "public-with-deny"],
    )
    def test_email_identity_single_statement_policy(
        self, api_call_mock, expected_status
    ):
        result = execute_check_with_api_mock(api_call_mock)

        assert len(result) == 1
        assert result[0].status == expected_status

    @mock_aws
    def test_check_preserves_nested_policy_condition_keys(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_conditional_single_statement,
        ):
            client("sesv2", region_name=AWS_REGION_EU_WEST_1)
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            ses_client = SES(aws_provider)
            identity = next(iter(ses_client.email_identities.values()))
            policies_before_check = deepcopy(identity.policies)

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
                    new=ses_client,
                ),
            ):
                from prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import (
                    ses_identity_not_publicly_accessible,
                )

                ses_identity_not_publicly_accessible().execute()

            assert identity.policies == policies_before_check

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_email_identity_public(self):
        client("sesv2", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ses.ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible.ses_client",
                new=SES(aws_provider),
            ),
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
                == "SES identity test-email-identity-public is publicly accessible due to its resource policies."
            )
            assert result[0].resource_id == "test-email-identity-public"
            assert (
                result[0].resource_arn
                == f"arn:aws:ses:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:identity/test-email-identity-public"
            )
            assert result[0].resource_tags == {"tag1": "value1", "tag2": "value2"}
            assert result[0].region == AWS_REGION_EU_WEST_1
