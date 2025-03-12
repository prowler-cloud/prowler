from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import (
    PasswordPolicy,
    UserPool,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_password_policy_number:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_password_policy_number.cognito_user_pool_password_policy_number import (
                cognito_user_pool_password_policy_number,
            )

            check = cognito_user_pool_password_policy_number()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_bad_password_policy(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                password_policy={
                    "RequireNumbers": False,
                },
                region=AWS_REGION_US_EAST_1,
                id=user_pool_id,
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_password_policy_number.cognito_user_pool_password_policy_number import (
                cognito_user_pool_password_policy_number,
            )

            check = cognito_user_pool_password_policy_number()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} does not have a password policy with a number requirement."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_user_pools_good_password_policy(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                password_policy=PasswordPolicy(
                    require_numbers=True,
                ),
                region=AWS_REGION_US_EAST_1,
                id=user_pool_id,
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_password_policy_number.cognito_user_pool_password_policy_number import (
                cognito_user_pool_password_policy_number,
            )

            check = cognito_user_pool_password_policy_number()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} has a password policy with a number requirement."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_user_pools_no_password_policy(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                password_policy=None,
                region=AWS_REGION_US_EAST_1,
                id=user_pool_id,
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_password_policy_number.cognito_user_pool_password_policy_number import (
                cognito_user_pool_password_policy_number,
            )

            check = cognito_user_pool_password_policy_number()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} has not a password policy set."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
