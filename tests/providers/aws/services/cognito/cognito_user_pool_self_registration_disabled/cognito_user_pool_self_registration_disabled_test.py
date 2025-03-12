from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import (
    AdminCreateUserConfig,
    IdentityPool,
    IdentityPoolRoles,
    UserPool,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_self_registration_disabled:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        cognito_identity_client = mock.MagicMock
        cognito_identity_client.identity_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_disabled.cognito_user_pool_self_registration_disabled import (
                cognito_user_pool_self_registration_disabled,
            )

            check = cognito_user_pool_self_registration_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_no_identity_pools(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config=AdminCreateUserConfig(
                    allow_admin_create_user_only=False
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
        cognito_identity_client = mock.MagicMock
        cognito_identity_client.identity_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_disabled.cognito_user_pool_self_registration_disabled import (
                cognito_user_pool_self_registration_disabled,
            )

            check = cognito_user_pool_self_registration_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} has self registration enabled."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_identity_pools_allow_admin_create_user_enabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config=AdminCreateUserConfig(
                    allow_admin_create_user_only=True
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
        cognito_identity_client = mock.MagicMock
        identity_pool_name = "identity_pool_name"
        identity_pool_id = "eu-west-1_123456789"
        identity_pool_arn = f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789"
        authenticated_role = "authenticated_role"
        cognito_identity_client.identity_pools = {
            identity_pool_arn: IdentityPool(
                id=identity_pool_id,
                arn=identity_pool_arn,
                region=AWS_REGION_US_EAST_1,
                name=identity_pool_name,
                associated_pools=[
                    {
                        "ProviderName": f"cognito-idp.{AWS_REGION_US_EAST_1}.amazonaws.com/eu-west-1_123456789"
                    }
                ],
                roles=IdentityPoolRoles(
                    authenticated=authenticated_role,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_disabled.cognito_user_pool_self_registration_disabled import (
                cognito_user_pool_self_registration_disabled,
            )

            check = cognito_user_pool_self_registration_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} has self registration disabled."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_identity_pools_allow_admin_create_user_disabled(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                admin_create_user_config=AdminCreateUserConfig(
                    allow_admin_create_user_only=False
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
        cognito_identity_client = mock.MagicMock
        identity_pool_name = "eu-west-1_123456789"
        identity_pool_id = "eu-west-1_123456789"
        identity_pool_arn = f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789"
        authenticated_role = "authenticated_role"
        cognito_identity_client.identity_pools = {
            identity_pool_arn: IdentityPool(
                id=identity_pool_id,
                arn=identity_pool_arn,
                region=AWS_REGION_US_EAST_1,
                name=identity_pool_name,
                associated_pools=[
                    {
                        "ProviderName": f"cognito-idp.{AWS_REGION_US_EAST_1}.amazonaws.com/eu-west-1_123456789"
                    }
                ],
                roles=IdentityPoolRoles(
                    authenticated=authenticated_role,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_self_registration_disabled.cognito_user_pool_self_registration_disabled import (
                cognito_user_pool_self_registration_disabled,
            )

            check = cognito_user_pool_self_registration_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} has self registration enabled assuming the role(s): {identity_pool_name}({authenticated_role})."
            )

            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
