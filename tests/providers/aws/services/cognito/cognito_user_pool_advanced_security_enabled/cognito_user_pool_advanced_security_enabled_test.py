from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_advanced_security_enabled:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_advanced_security_enabled.cognito_user_pool_advanced_security_enabled import (
                cognito_user_pool_advanced_security_enabled,
            )

            check = cognito_user_pool_advanced_security_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_user_pools_advanced_security_off(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="OFF",
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_advanced_security_enabled.cognito_user_pool_advanced_security_enabled import (
                cognito_user_pool_advanced_security_enabled,
            )

            check = cognito_user_pool_advanced_security_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has advanced security disabled."
            )

    def test_cognito_user_pools_advanced_security_audit(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="AUDIT",
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_advanced_security_enabled.cognito_user_pool_advanced_security_enabled import (
                cognito_user_pool_advanced_security_enabled,
            )

            check = cognito_user_pool_advanced_security_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has advanced security audit enabled."
            )

    def test_cognito_user_pools_advanced_security_enforced(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                advanced_security_mode="ENFORCED",
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
            from prowler.providers.aws.services.cognito.cognito_user_pool_advanced_security_enabled.cognito_user_pool_advanced_security_enabled import (
                cognito_user_pool_advanced_security_enabled,
            )

            check = cognito_user_pool_advanced_security_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "User pool eu-west-1_123456789 has advanced security enforced."
            )
