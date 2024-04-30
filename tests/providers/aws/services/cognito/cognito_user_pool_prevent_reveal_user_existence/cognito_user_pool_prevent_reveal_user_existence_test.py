from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_prevent_reveal_user_existence:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_prevent_reveal_user_existence.cognito_user_pool_prevent_reveal_user_existence import (
                cognito_user_pool_prevent_reveal_user_existence,
            )

            check = cognito_user_pool_prevent_reveal_user_existence()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_prevent_user_existence_errors_disabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                user_pool_client={"PreventUserExistenceErrors": "DISABLED"},
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
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_prevent_reveal_user_existence.cognito_user_pool_prevent_reveal_user_existence import (
                cognito_user_pool_prevent_reveal_user_existence,
            )

            check = cognito_user_pool_prevent_reveal_user_existence()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_id} has PreventUserExistenceErrors disabled."
            )

    def test_cognito_user_pools_prevent_user_existence_errors_enabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                user_pool_client={"PreventUserExistenceErrors": "ENABLED"},
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
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_prevent_reveal_user_existence.cognito_user_pool_prevent_reveal_user_existence import (
                cognito_user_pool_prevent_reveal_user_existence,
            )

            check = cognito_user_pool_prevent_reveal_user_existence()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"User pool {user_pool_id} has PreventUserExistenceErrors enabled."
            )
            assert result[0].resource_name == user_pool_name
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
