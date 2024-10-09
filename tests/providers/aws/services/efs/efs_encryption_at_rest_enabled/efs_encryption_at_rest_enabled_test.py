from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


class Test_efs_encryption_at_rest_enabled:
    @mock_aws
    def test_efs_encryption_enabled(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        filesystem = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Encrypted=True
        )

        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{filesystem['FileSystemId']}"

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_encryption_at_rest_enabled.efs_encryption_at_rest_enabled.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_encryption_at_rest_enabled.efs_encryption_at_rest_enabled import (
                efs_encryption_at_rest_enabled,
            )

            check = efs_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"EFS {filesystem['FileSystemId']} has encryption at rest enabled."
            )
            assert result[0].resource_id == filesystem["FileSystemId"]
            assert result[0].resource_arn == efs_arn

    @mock_aws
    def test_efs_encryption_disabled(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        filesystem = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Encrypted=False
        )

        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{filesystem['FileSystemId']}"

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_encryption_at_rest_enabled.efs_encryption_at_rest_enabled.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_encryption_at_rest_enabled.efs_encryption_at_rest_enabled import (
                efs_encryption_at_rest_enabled,
            )

            check = efs_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"EFS {filesystem['FileSystemId']} does not have encryption at rest enabled."
            )
            assert result[0].resource_id == filesystem["FileSystemId"]
            assert result[0].resource_arn == efs_arn
