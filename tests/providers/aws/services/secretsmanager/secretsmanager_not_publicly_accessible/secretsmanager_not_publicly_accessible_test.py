from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_secretsmanager_not_publicly_accessible:
    def test_no_secrets(self):
        client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible import (
                secretsmanager_not_publicly_accessible,
            )

            check = secretsmanager_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_secret_not_public_policy(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(
            Name="test-secret-no-public-policy",
        )
        secretsmanager_client.put_resource_policy(
            SecretId=secret["ARN"],
            ResourcePolicy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::123456789012:root","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}',
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible import (
                secretsmanager_not_publicly_accessible,
            )

            check = secretsmanager_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret["Name"]
            assert result[0].resource_arn == secret["ARN"]
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret['Name']} is not publicly accessible."
            )

    @mock_aws
    def test_secret_public_policy(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(
            Name="test-secret-public-policy",
        )
        secretsmanager_client.put_resource_policy(
            SecretId=secret["ARN"],
            ResourcePolicy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}',
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.secretsmanager.secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible import (
                secretsmanager_not_publicly_accessible,
            )

            check = secretsmanager_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == secret["Name"]
            assert result[0].resource_arn == secret["ARN"]
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SecretsManager secret {secret['Name']} is publicly accessible due to its resource policy."
            )
