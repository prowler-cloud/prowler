from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

USER_POOL_ID = "us-east-1_123456789"
USER_POOL_NAME = "user_pool_name"
USER_POOL_ARN = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/{USER_POOL_ID}"

CHECK_PATH = "prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred.cognito_idp_client"


def set_mocked_user_pool(account_recovery_settings):
    return {
        USER_POOL_ARN: UserPool(
            id=USER_POOL_ID,
            arn=USER_POOL_ARN,
            name=USER_POOL_NAME,
            region=AWS_REGION_US_EAST_1,
            last_modified=datetime.now(),
            creation_date=datetime.now(),
            status="ACTIVE",
            account_recovery_settings=account_recovery_settings,
        )
    }


class Test_cognito_user_pool_account_recovery_sms_not_preferred:
    def test_no_user_pools(self):
        cognito_client = mock.MagicMock()
        cognito_client.user_pools = {}
        with (
            mock.patch(
                "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
                new=cognito_client,
            ),
            mock.patch(CHECK_PATH, new=cognito_client),
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                cognito_user_pool_account_recovery_sms_not_preferred,
            )

            check = cognito_user_pool_account_recovery_sms_not_preferred()
            result = check.execute()

            assert len(result) == 0

    def test_user_pool_without_account_recovery_setting(self):
        cognito_client = mock.MagicMock()
        cognito_client.user_pools = set_mocked_user_pool({})
        with (
            mock.patch(
                "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
                new=cognito_client,
            ),
            mock.patch(CHECK_PATH, new=cognito_client),
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                cognito_user_pool_account_recovery_sms_not_preferred,
            )

            check = cognito_user_pool_account_recovery_sms_not_preferred()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User pool {USER_POOL_NAME} does not define an account recovery setting, so SMS is preferred over email."
            )
            assert result[0].resource_id == USER_POOL_ID
            assert result[0].resource_arn == USER_POOL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_user_pool_prefers_sms(self):
        cognito_client = mock.MagicMock()
        cognito_client.user_pools = set_mocked_user_pool(
            {
                "RecoveryMechanisms": [
                    {"Priority": 2, "Name": "verified_email"},
                    {"Priority": 1, "Name": "verified_phone_number"},
                ]
            }
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
                new=cognito_client,
            ),
            mock.patch(CHECK_PATH, new=cognito_client),
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                cognito_user_pool_account_recovery_sms_not_preferred,
            )

            check = cognito_user_pool_account_recovery_sms_not_preferred()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User pool {USER_POOL_NAME} prefers SMS for account recovery."
            )
            assert result[0].resource_id == USER_POOL_ID
            assert result[0].resource_arn == USER_POOL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_user_pool_prefers_email_over_sms(self):
        cognito_client = mock.MagicMock()
        cognito_client.user_pools = set_mocked_user_pool(
            {
                "RecoveryMechanisms": [
                    {"Priority": 2, "Name": "verified_phone_number"},
                    {"Priority": 1, "Name": "verified_email"},
                ]
            }
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
                new=cognito_client,
            ),
            mock.patch(CHECK_PATH, new=cognito_client),
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_account_recovery_sms_not_preferred.cognito_user_pool_account_recovery_sms_not_preferred import (
                cognito_user_pool_account_recovery_sms_not_preferred,
            )

            check = cognito_user_pool_account_recovery_sms_not_preferred()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User pool {USER_POOL_NAME} prefers verified_email over SMS for account recovery."
            )
            assert result[0].resource_id == USER_POOL_ID
            assert result[0].resource_arn == USER_POOL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_user_pool_admin_only_recovery(self):
        cognito_client = mock.MagicMock()
        cognito_client.user_pools = set_mocked_user_pool(
            {"RecoveryMechanisms": [{"Priority": 1, "Name": "admin_only"}]}
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
                new=cognito_client,
            ),
            mock.patch(CHECK_PATH, new=cognito_client),
        ):
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
