from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_mfa_enabled:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_mfa_enabled.cognito_user_pool_mfa_enabled import (
                cognito_user_pool_mfa_enabled,
            )

            check = cognito_user_pool_mfa_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_mfa_config_none(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                mfa_config=None,
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_mfa_enabled.cognito_user_pool_mfa_enabled import (
                cognito_user_pool_mfa_enabled,
            )

            check = cognito_user_pool_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has MFA disabled."
            )

    def test_cognito_user_pools_mfa_config_disabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                mfa_config={"status": "OFF"},
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_mfa_enabled.cognito_user_pool_mfa_enabled import (
                cognito_user_pool_mfa_enabled,
            )

            check = cognito_user_pool_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has MFA disabled."
            )

    def test_cognito_user_pools_mfa_config_enabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                mfa_config={"status": "ON"},
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_mfa_enabled.cognito_user_pool_mfa_enabled import (
                cognito_user_pool_mfa_enabled,
            )

            check = cognito_user_pool_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has MFA enabled."
            )
