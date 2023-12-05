from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import Secret
from tests.providers.aws.audit_info_utils import AWS_REGION_EU_WEST_1


class Test_secretsmanager_automatic_rotation_enabled:
    def test_no_secrets(self):
        secretsmanager_client = mock.MagicMock
        secretsmanager_client.secrets = {}
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_automatic_rotation_enabled.secretsmanager_automatic_rotation_enabled import (
                secretsmanager_automatic_rotation_enabled,
            )

            check = secretsmanager_automatic_rotation_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_secret_rotation_disabled(self):
        secretsmanager_client = mock.MagicMock
        secret_name = "test-secret"
        secret_arn = f"arn:aws:secretsmanager:{AWS_REGION_EU_WEST_1}:{DEFAULT_ACCOUNT_ID}:secret:{secret_name}"
        secretsmanager_client.secrets = {
            secret_name: Secret(
                arn=secret_arn,
                region=AWS_REGION_EU_WEST_1,
                name=secret_name,
                rotation_enabled=False,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_automatic_rotation_enabled.secretsmanager_automatic_rotation_enabled import (
                secretsmanager_automatic_rotation_enabled,
            )

            check = secretsmanager_automatic_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret_name
            assert result[0].resource_arn == secret_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret_name} has rotation disabled."
            )

    def test_secret_rotation_enabled(self):
        secretsmanager_client = mock.MagicMock
        secret_name = "test-secret"
        secret_arn = f"arn:aws:secretsmanager:{AWS_REGION_EU_WEST_1}:{DEFAULT_ACCOUNT_ID}:secret:{secret_name}"
        secretsmanager_client.secrets = {
            secret_name: Secret(
                arn=secret_arn,
                region=AWS_REGION_EU_WEST_1,
                name=secret_name,
                rotation_enabled=True,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_service.SecretsManager",
            new=secretsmanager_client,
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_automatic_rotation_enabled.secretsmanager_automatic_rotation_enabled import (
                secretsmanager_automatic_rotation_enabled,
            )

            check = secretsmanager_automatic_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret_name
            assert result[0].resource_arn == secret_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret_name} has rotation enabled."
            )
