from datetime import datetime, timezone
from unittest.mock import patch

import botocore
from boto3 import client
from freezegun import freeze_time
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call_secret_rotated_recently(self, operation_name, kwarg):
    if operation_name == "ListSecrets":
        return {
            "SecretList": [
                {
                    "ARN": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test-secret",
                    "Name": "test-secret",
                    "LastAccessedDate": datetime(
                        2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc
                    ),
                    "LastRotatedDate": datetime(
                        2023, 4, 9, 0, 0, 0, tzinfo=timezone.utc
                    ),
                    "Tags": [{"Key": "Name", "Value": "test-secret"}],
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_secret_not_rotated_for_99_days(self, operation_name, kwarg):
    if operation_name == "ListSecrets":
        return {
            "SecretList": [
                {
                    "ARN": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test-secret",
                    "Name": "test-secret",
                    "LastAccessedDate": datetime(
                        2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc
                    ),
                    "LastRotatedDate": datetime(
                        2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc
                    ),
                    "Tags": [{"Key": "Name", "Value": "test-secret"}],
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_secretsmanager_secret_rotated_periodically:
    def test_no_secrets(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
            SecretsManager,
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically import (
                secretsmanager_secret_rotated_periodically,
            )

            check = secretsmanager_secret_rotated_periodically()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_secret_never_rotated(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )

        secret_arn = secretsmanager_client.create_secret(
            Name="test-secret",
            Tags=[
                {"Key": "Name", "Value": "test-secret"},
            ],
        )["ARN"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
            SecretsManager,
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically import (
                secretsmanager_secret_rotated_periodically,
            )

            check = secretsmanager_secret_rotated_periodically()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Secret test-secret has never been rotated."
            )
            assert result[0].resource_id == "test-secret"
            assert result[0].resource_arn == secret_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "test-secret"}]

    @freeze_time("2023-04-10")
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_secret_not_rotated_for_99_days,
    )
    @mock_aws
    def test_secret_not_rotated_for_99_days(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
            SecretsManager,
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically import (
                secretsmanager_secret_rotated_periodically,
            )

            check = secretsmanager_secret_rotated_periodically()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Secret test-secret has not been rotated in 99 days, which is more than the maximum allowed of 90 days."
            )
            assert result[0].resource_id == "test-secret"
            assert (
                result[0].resource_arn
                == "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test-secret"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "test-secret"}]

    @freeze_time("2023-04-10")
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_secret_rotated_recently,
    )
    @mock_aws
    def test_secret_rotated_recently(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
            SecretsManager,
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically import (
                secretsmanager_secret_rotated_periodically,
            )

            check = secretsmanager_secret_rotated_periodically()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Secret test-secret was last rotated on April 09, 2023."
            )
            assert result[0].resource_id == "test-secret"
            assert (
                result[0].resource_arn
                == "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test-secret"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "test-secret"}]
