import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_key_not_publicly_accessible:
    @mock_aws
    def test_no_kms_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_key_not_publicly_accessible(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key without policy
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} is not exposed to Public."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_key_public_accessible(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with public policy
        key = kms_client.create_key(
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "key-default-1",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            )
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} may be publicly accessible."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_key_empty_principal(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with public policy
        key = kms_client.create_key(
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "key-default-1",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            )
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} is not exposed to Public."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
