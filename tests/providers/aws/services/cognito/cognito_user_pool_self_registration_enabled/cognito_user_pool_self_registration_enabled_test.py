from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import (
    IdentityPool,
    UserPool,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_self_registration_enabled:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_enabled.cognito_user_pool_self_registration_enabled import (
                cognito_user_pool_self_registration_enabled,
            )

            check = cognito_user_pool_self_registration_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_no_identity_pools(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config={"AllowAdminCreateUserOnly": False},
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_identity_client = mock.MagicMock
        cognito_identity_client.identity_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_enabled.cognito_user_pool_self_registration_enabled import (
                cognito_user_pool_self_registration_enabled,
            )

            check = cognito_user_pool_self_registration_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has self registration enabled."
            )

    def test_cognito_identity_pools_allow_admin_create_user_enabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config={"AllowAdminCreateUserOnly": True},
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_identity_client = mock.MagicMock
        cognito_identity_client.identity_pools = {
            "eu-west-1_123456789": IdentityPool(
                id="eu-west-1_123456789",
                arn=f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789",
                region=AWS_REGION_US_EAST_1,
                name="eu-west-1_123456789",
                associated_pools={
                    "ProviderName": f"cognito-idp.{AWS_REGION_US_EAST_1}.amazonaws.com/eu-west-1_123456789"
                },
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_enabled.cognito_user_pool_self_registration_enabled import (
                cognito_user_pool_self_registration_enabled,
            )

            check = cognito_user_pool_self_registration_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has self registration disabled."
            )

    def test_cognito_identity_pools_allow_admin_create_user_disabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config={"AllowAdminCreateUserOnly": False},
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_identity_client = mock.MagicMock
        identity_pool_name = "eu-west-1_123456789"
        cognito_identity_client.identity_pools = {
            "eu-west-1_123456789": IdentityPool(
                id="eu-west-1_123456789",
                arn=f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789",
                region=AWS_REGION_US_EAST_1,
                name=identity_pool_name,
                associated_pools={
                    "ProviderName": f"cognito-idp.{AWS_REGION_US_EAST_1}.amazonaws.com/eu-west-1_123456789"
                },
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_enabled.cognito_user_pool_self_registration_enabled import (
                cognito_user_pool_self_registration_enabled,
            )

            check = cognito_user_pool_self_registration_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool {user_pool_name} has self registration enabled and is associated with the following identity pools: {identity_pool_name}"
            )
