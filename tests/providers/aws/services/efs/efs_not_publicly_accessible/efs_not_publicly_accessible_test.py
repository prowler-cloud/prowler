import json
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


FILE_SYSTEM_POLICY = json.dumps(
    {
        "Id": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["elasticfilesystem:ClientMount"],
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            }
        ],
    }
)

FILE_SYSTEM_INVALID_POLICY = json.dumps(
    {
        "Id": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["elasticfilesystem:ClientMount"],
                "Principal": {"AWS": "*"},
            }
        ],
    }
)

# https://docs.aws.amazon.com/efs/latest/ug/access-control-block-public-access.html#what-is-a-public-policy
FILE_SYSTEM_POLICY_WITH_SOURCE_ARN_CONDITION = json.dumps(
    {
        "Version": "2012-10-17",
        "Id": "efs-policy-wizard-15ad9567-2546-4bbb-8168-5541b6fc0e55",
        "Statement": [
            {
                "Sid": "efs-statement-14a7191c-9401-40e7-a388-6af6cfb7dd9c",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "elasticfilesystem:ClientMount",
                    "elasticfilesystem:ClientWrite",
                    "elasticfilesystem:ClientRootAccess",
                ],
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
                    }
                },
            }
        ],
    }
)

# https://docs.aws.amazon.com/efs/latest/ug/access-control-block-public-access.html#what-is-a-public-policy
FILE_SYSTEM_POLICY_WITH_MOUNT_TARGET_CONDITION = json.dumps(
    {
        "Version": "2012-10-17",
        "Id": "efs-policy-wizard-15ad9567-2546-4bbb-8168-5541b6fc0e55",
        "Statement": [
            {
                "Sid": "efs-statement-14a7191c-9401-40e7-a388-6af6cfb7dd9c",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "elasticfilesystem:ClientMount",
                    "elasticfilesystem:ClientWrite",
                    "elasticfilesystem:ClientRootAccess",
                ],
                "Condition": {
                    "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}
                },
            }
        ],
    }
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeFileSystemPolicy":
        return {"Policy": FILE_SYSTEM_POLICY}

    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "DescribeFileSystemPolicy":
        return {"Policy": FILE_SYSTEM_POLICY_WITH_MOUNT_TARGET_CONDITION}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v3(self, operation_name, kwarg):
    if operation_name == "DescribeFileSystemPolicy":
        return {"Policy": FILE_SYSTEM_POLICY_WITH_SOURCE_ARN_CONDITION}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v4(self, operation_name, kwarg):
    if operation_name == "DescribeFileSystemPolicy":
        return {"Policy": FILE_SYSTEM_INVALID_POLICY}
    return make_api_call(self, operation_name, kwarg)


class Test_efs_not_publicly_accessible:
    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_efs_valid_policy(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_efs_valid_policy_with_mount_target_condition(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v3)
    def test_efs_valid_policy_with_source_arn_condition(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v4)
    def test_efs_invalid_policy(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has a policy which allows access to any client within the VPC."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_efs_no_policy(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} doesn't have any policy which means it grants full access to any client within the VPC."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
            assert result[0].resource_tags == []
