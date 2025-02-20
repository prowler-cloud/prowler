import json
from typing import Any, List
from unittest import mock

import pytest
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_key_not_publicly_accessible:
    @mock_aws
    def test_no_kms_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
                new=KMS(aws_provider),
            ),
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
        key = kms_client.create_key(MultiRegion=False)["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
                new=KMS(aws_provider),
            ),
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
            MultiRegion=False,
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
            ),
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
                new=KMS(aws_provider),
            ),
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
            MultiRegion=False,
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
            ),
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
                new=KMS(aws_provider),
            ),
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

    @pytest.mark.parametrize(
        "no_of_keys_created,expected_no_of_passes",
        [
            (5, 3),
            (7, 5),
            (10, 8),
        ],
    )
    @mock_aws
    def test_kms_key_not_publicly_accessible_when_get_key_policy_fails_on_2_keys_out_of_x_keys(
        self, no_of_keys_created: int, expected_no_of_passes: int
    ) -> None:
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms_client.__dict__["region"] = AWS_REGION_US_EAST_1
        # Creaty KMS key with public policy
        for i in range(no_of_keys_created):
            kms_client.create_key(MultiRegion=False)

        orig_get_key_policy = kms_client.get_key_policy

        def mock_get_key_policy(
            KeyId: str, PolicyName: str, count: List[int] = [0]
        ) -> Any:
            if count[0] in [2, 4]:
                count[0] += 1
                raise Exception("FakeClientError")
            else:
                count[0] += 1
                return orig_get_key_policy(KeyId=KeyId, PolicyName=PolicyName)

        kms_client.get_key_policy = mock_get_key_policy

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
                return_value={AWS_REGION_US_EAST_1: kms_client},
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
                new=KMS(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == expected_no_of_passes
            statuses = [r.status for r in result]
            assert statuses.count("PASS") == expected_no_of_passes
