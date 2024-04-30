from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_temporary_password_expiration:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_temporary_password_expiration.cognito_user_pool_temporary_password_expiration import (
                cognito_user_pool_temporary_password_expiration,
            )

            check = cognito_user_pool_temporary_password_expiration()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_password_expiration_8(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                password_policy={"TemporaryPasswordValidityDays": 8},
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_temporary_password_expiration.cognito_user_pool_temporary_password_expiration import (
                cognito_user_pool_temporary_password_expiration,
            )

            check = cognito_user_pool_temporary_password_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has temporary password expiration set to 8 days."
            )

    def test_cognito_user_pools_password_expiration_7(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                password_policy={"TemporaryPasswordValidityDays": 7},
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_temporary_password_expiration.cognito_user_pool_temporary_password_expiration import (
                cognito_user_pool_temporary_password_expiration,
            )

            check = cognito_user_pool_temporary_password_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has temporary password expiration set to 7 days."
            )
