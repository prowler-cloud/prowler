from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

USER_POOL_NAME = "user_pool_name"

CHECK_PATH = "prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred.cognito_idp_client"
PROVIDER_PATH = "prowler.providers.common.provider.Provider.get_global_provider"


class Test_cognito_user_pool_account_recovery_sms_not_preferred:
    @mock_aws
    def test_no_user_pools(self):
        from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=CognitoIDP(aws_provider)):
                from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                    cognito_user_pool_account_recovery_sms_not_preferred,
                )

                check = cognito_user_pool_account_recovery_sms_not_preferred()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_user_pool_without_account_recovery_setting(self):
        from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

        client("cognito-idp", region_name=AWS_REGION_US_EAST_1).create_user_pool(
            PoolName=USER_POOL_NAME
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        cognito_client = CognitoIDP(aws_provider)
        # moto injects a verified_email-first AccountRecoverySetting into every pool,
        # so a pool that never had one cannot be produced through the API. Real
        # user pools predating the feature return no setting at all, which is the
        # case this check has to flag, so clear it here.
        for pool in cognito_client.user_pools.values():
            pool.account_recovery_settings = {}

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=cognito_client):
                from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                    cognito_user_pool_account_recovery_sms_not_preferred,
                )

                check = cognito_user_pool_account_recovery_sms_not_preferred()
                result = check.execute()

                pool = list(cognito_client.user_pools.values())[0]
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User pool {USER_POOL_NAME} does not define an account recovery setting, so SMS is preferred over email."
                )
                assert result[0].resource_id == pool.id
                assert result[0].resource_arn == pool.arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_pool_prefers_sms(self):
        from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

        client("cognito-idp", region_name=AWS_REGION_US_EAST_1).create_user_pool(
            PoolName=USER_POOL_NAME,
            AccountRecoverySetting={
                "RecoveryMechanisms": [
                    {"Priority": 2, "Name": "verified_email"},
                    {"Priority": 1, "Name": "verified_phone_number"},
                ]
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        cognito_client = CognitoIDP(aws_provider)

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=cognito_client):
                from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                    cognito_user_pool_account_recovery_sms_not_preferred,
                )

                check = cognito_user_pool_account_recovery_sms_not_preferred()
                result = check.execute()

                pool = list(cognito_client.user_pools.values())[0]
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User pool {USER_POOL_NAME} prefers SMS for account recovery."
                )
                assert result[0].resource_id == pool.id
                assert result[0].resource_arn == pool.arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_pool_prefers_email_over_sms(self):
        from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

        client("cognito-idp", region_name=AWS_REGION_US_EAST_1).create_user_pool(
            PoolName=USER_POOL_NAME,
            AccountRecoverySetting={
                "RecoveryMechanisms": [
                    {"Priority": 2, "Name": "verified_phone_number"},
                    {"Priority": 1, "Name": "verified_email"},
                ]
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        cognito_client = CognitoIDP(aws_provider)

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=cognito_client):
                from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                    cognito_user_pool_account_recovery_sms_not_preferred,
                )

                check = cognito_user_pool_account_recovery_sms_not_preferred()
                result = check.execute()

                pool = list(cognito_client.user_pools.values())[0]
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User pool {USER_POOL_NAME} prefers verified_email over SMS for account recovery."
                )
                assert result[0].resource_id == pool.id
                assert result[0].resource_arn == pool.arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_pool_admin_only_recovery(self):
        from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

        client("cognito-idp", region_name=AWS_REGION_US_EAST_1).create_user_pool(
            PoolName=USER_POOL_NAME,
            AccountRecoverySetting={
                "RecoveryMechanisms": [{"Priority": 1, "Name": "admin_only"}]
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        cognito_client = CognitoIDP(aws_provider)

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=cognito_client):
                from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                    cognito_user_pool_account_recovery_sms_not_preferred,
                )

                check = cognito_user_pool_account_recovery_sms_not_preferred()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User pool {USER_POOL_NAME} prefers admin_only over SMS for account recovery."
                )
