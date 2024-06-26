from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import (
    IdentityPool,
    IdentityPoolRoles,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_identity_pool_guest_access_disabled:
    def test_cognito_no_identity_pools(self):
        cognito_identity_client = mock.MagicMock
        cognito_identity_client.identity_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            new=cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_identity_pool_guest_access_disabled.cognito_identity_pool_guest_access_disabled import (
                cognito_identity_pool_guest_access_disabled,
            )

            check = cognito_identity_pool_guest_access_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_identity_pools_guest_access_disabled(self):
        cognito_identity_client = mock.MagicMock
        identity_pool_arn = f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789"
        identity_pool_name = "identity_pool_name"
        identity_pool_id = "eu-west-1_123456789"
        cognito_identity_client.identity_pools = {
            identity_pool_arn: IdentityPool(
                allow_unauthenticated_identities=False,
                region=AWS_REGION_US_EAST_1,
                id=identity_pool_id,
                arn=identity_pool_arn,
                name=identity_pool_name,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            new=cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_identity_pool_guest_access_disabled.cognito_identity_pool_guest_access_disabled import (
                cognito_identity_pool_guest_access_disabled,
            )

            check = cognito_identity_pool_guest_access_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Identity pool {identity_pool_id} has guest access disabled."
            )

            assert result[0].resource_id == identity_pool_id
            assert result[0].resource_arn == identity_pool_arn

    def test_cognito_identity_pools_guest_access_enabled(self):
        cognito_identity_client = mock.MagicMock
        identity_pool_arn = f"arn:aws:cognito-identity:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:identitypool/eu-west-1_123456789"
        identity_pool_name = "identity_pool_name"
        identity_pool_id = "eu-west-1_123456789"
        unauthenticated_role = "unauthenticated_role"
        cognito_identity_client.identity_pools = {
            identity_pool_arn: IdentityPool(
                allow_unauthenticated_identities=True,
                region=AWS_REGION_US_EAST_1,
                id=identity_pool_id,
                arn=identity_pool_arn,
                name=identity_pool_name,
                roles=IdentityPoolRoles(unauthenticated=unauthenticated_role),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIdentity",
            cognito_identity_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            new=cognito_identity_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_identity_pool_guest_access_disabled.cognito_identity_pool_guest_access_disabled import (
                cognito_identity_pool_guest_access_disabled,
            )

            check = cognito_identity_pool_guest_access_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Identity pool {identity_pool_name} has guest access enabled assuming the role {unauthenticated_role}."
            )

            assert result[0].resource_id == identity_pool_id
            assert result[0].resource_arn == identity_pool_arn
