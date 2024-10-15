from unittest import mock

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import Secret
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class Test_secretsmanager_secret_rotated_successfully:
    def test_no_secrets(self):
        secretsmanager_client = mock.MagicMock
        secretsmanager_client.secrets = {}
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_successfully.secretsmanager_secret_rotated_successfully import (
                secretsmanager_secret_rotated_successfully,
            )

            check = secretsmanager_secret_rotated_successfully()
            result = check.execute()

            assert len(result) == 0

    def test_secret_rotation_failed(self):
        secretsmanager_client = mock.MagicMock
        secret_name = "test-secret"
        secret_arn = f"arn:aws:secretsmanager:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:secret:{secret_name}"
        secretsmanager_client.secrets = {
            secret_name: Secret(
                arn=secret_arn,
                region=AWS_REGION_EU_WEST_1,
                name=secret_name,
                rotation_enabled=True,
                last_rotation_date="2023-01-01T00:00:00Z",
                last_rotation_error_message="Rotation failed",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_successfully.secretsmanager_secret_rotated_successfully import (
                secretsmanager_secret_rotated_successfully,
            )

            check = secretsmanager_secret_rotated_successfully()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret_name
            assert result[0].resource_arn == secret_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret_name} last rotation failed with error: Rotation failed."
            )

    def test_secret_rotation_success(self):
        secretsmanager_client = mock.MagicMock
        secret_name = "test-secret"
        secret_arn = f"arn:aws:secretsmanager:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:secret:{secret_name}"
        secretsmanager_client.secrets = {
            secret_name: Secret(
                arn=secret_arn,
                region=AWS_REGION_EU_WEST_1,
                name=secret_name,
                rotation_enabled=True,
                last_rotation_date="2023-01-01T00:00:00Z",
                last_rotation_error_message=None,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_successfully.secretsmanager_secret_rotated_successfully import (
                secretsmanager_secret_rotated_successfully,
            )

            check = secretsmanager_secret_rotated_successfully()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret_name
            assert result[0].resource_arn == secret_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret_name} last rotation was successful."
            )
