from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import Secret

# Mock Test Region
AWS_REGION = "eu-west-1"


class Test_secretsmanager_check_if_service_is_in_use:
    def test_no_secrets(self):
        secretsmanager_client = mock.MagicMock
        secretsmanager_client.secrets = {}
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_check_if_service_is_in_use.secretsmanager_check_if_service_is_in_use import (
                secretsmanager_check_if_service_is_in_use,
            )

            check = secretsmanager_check_if_service_is_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "SecretsManager service is not in use."

    def test_one_secret(self):
        secretsmanager_client = mock.MagicMock
        secret_name = "test-secret"
        secret_arn = f"arn:aws:secretsmanager:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:secret:{secret_name}"
        secretsmanager_client.secrets = {
            secret_name: Secret(
                arn=secret_arn,
                region=AWS_REGION,
                name=secret_name,
                rotation_enabled=False,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_check_if_service_is_in_use.secretsmanager_check_if_service_is_in_use import (
                secretsmanager_check_if_service_is_in_use,
            )

            check = secretsmanager_check_if_service_is_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "SecretsManager service is in use."
