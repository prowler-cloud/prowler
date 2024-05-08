from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import (
    CompromisedCredentialsRiskConfiguration,
    RiskConfiguration,
    UserPool,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_blocks_compromised_credentials_sign_in_attempts:
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts import (
                cognito_user_pool_blocks_compromised_credentials_sign_in_attempts,
            )

            check = cognito_user_pool_blocks_compromised_credentials_sign_in_attempts()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_advanced_security_off(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        user_pool_id = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="OFF",
                risk_configuration=RiskConfiguration(
                    compromised_credentials_risk_configuration=CompromisedCredentialsRiskConfiguration(
                        event_filter=["SIGN_IN"],
                        actions="BLOCK",
                    )
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts import (
                cognito_user_pool_blocks_compromised_credentials_sign_in_attempts,
            )

            check = cognito_user_pool_blocks_compromised_credentials_sign_in_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} does not block sign-in attempts with suspected compromised credentials."
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_user_pools_advanced_security_audit(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        user_pool_id = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="AUDIT",
                risk_configuration=RiskConfiguration(
                    compromised_credentials_risk_configuration=CompromisedCredentialsRiskConfiguration(
                        event_filter=["SIGN_IN"],
                        actions="BLOCK",
                    )
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts import (
                cognito_user_pool_blocks_compromised_credentials_sign_in_attempts,
            )

            check = cognito_user_pool_blocks_compromised_credentials_sign_in_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} does not block sign-in attempts with suspected compromised credentials."
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_user_pools_advanced_security_enforced(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        user_pool_id = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="ENFORCED",
                risk_configuration=RiskConfiguration(
                    compromised_credentials_risk_configuration=CompromisedCredentialsRiskConfiguration(
                        event_filter=["SIGN_IN"],
                        actions="BLOCK",
                    )
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts import (
                cognito_user_pool_blocks_compromised_credentials_sign_in_attempts,
            )

            check = cognito_user_pool_blocks_compromised_credentials_sign_in_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} blocks sign-in attempts with suspected compromised credentials."
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn

    def test_cognito_user_pools_advanced_security_enforced_no_sign_in(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        user_pool_id = "eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="ENFORCED",
                risk_configuration=RiskConfiguration(
                    compromised_credentials_risk_configuration=CompromisedCredentialsRiskConfiguration(
                        event_filter=[],
                        actions="BLOCK",
                    )
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts.cognito_user_pool_blocks_compromised_credentials_sign_in_attempts import (
                cognito_user_pool_blocks_compromised_credentials_sign_in_attempts,
            )

            check = cognito_user_pool_blocks_compromised_credentials_sign_in_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"User pool {user_pool_name} does not block sign-in attempts with suspected compromised credentials."
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
