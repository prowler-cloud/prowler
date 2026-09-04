import json
from unittest import mock

import pytest
from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.kms.kms_service import KMS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_KMS_Service:
    # Test KMS Service
    @mock_aws
    def test_service(self):
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert kms.service == "kms"

    # Test KMS Client
    @mock_aws
    def test_client(self):
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        for regional_client in kms.regional_clients.values():
            assert regional_client.__class__.__name__ == "KMS"

    # Test KMS Session
    @mock_aws
    def test__get_session__(self):
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert kms.session.__class__.__name__ == "Session"

    # Test KMS Session
    @mock_aws
    def test_audited_account(self):
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert kms.audited_account == AWS_ACCOUNT_NUMBER

    # Test KMS List Keys
    @mock_aws
    def test_list_keys(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create KMS keys
        key1 = kms_client.create_key()["KeyMetadata"]
        key2 = kms_client.create_key()["KeyMetadata"]
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[1].arn == key2["Arn"]
        assert kms.keys_scan_errors == {}

    # Test KMS Describe Keys
    @mock_aws
    def test_describe_key(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create KMS keys
        key1 = kms_client.create_key(
            MultiRegion=False,
            Tags=[
                {"TagKey": "test", "TagValue": "test"},
            ],
        )["KeyMetadata"]
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert len(kms.keys) == 1
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].state == key1["KeyState"]
        assert kms.keys[0].origin == key1["Origin"]
        assert kms.keys[0].manager == key1["KeyManager"]
        assert kms.keys[0].multi_region == key1["MultiRegion"]
        assert kms.keys[0].tags == [
            {"TagKey": "test", "TagValue": "test"},
        ]
        assert kms.keys[0].detail_retrieved is True
        assert kms.keys[0].detail_fetch_error is None

    @pytest.mark.parametrize(
        "error_code", ["AccessDeniedException", "ThrottlingException"]
    )
    @mock_aws
    def test_list_keys_client_error_records_region_and_discards_partial_results(
        self, error_code
    ):
        regional_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        regional_client.__dict__["region"] = AWS_REGION_US_EAST_1

        class PartialPaginator:
            def paginate(self):
                yield {
                    "Keys": [
                        {
                            "KeyId": "partial-key",
                            "KeyArn": f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/partial-key",
                        }
                    ]
                }
                raise ClientError(
                    {
                        "Error": {
                            "Code": error_code,
                            "Message": "not authorized",
                        }
                    },
                    "ListKeys",
                )

        regional_client.get_paginator = lambda _: PartialPaginator()
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: regional_client},
        ):
            kms = KMS(aws_provider)

        assert kms.keys == []
        assert kms.keys_scan_errors == {AWS_REGION_US_EAST_1: error_code}

    @mock_aws
    def test_list_keys_error_preserves_successful_regions(self):
        east_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        east_client.__dict__["region"] = AWS_REGION_US_EAST_1
        east_key = east_client.create_key(MultiRegion=False)["KeyMetadata"]
        west_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        west_client.__dict__["region"] = AWS_REGION_EU_WEST_1
        original_get_paginator = west_client.get_paginator

        def get_west_paginator(operation_name):
            if operation_name == "list_keys":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "not authorized",
                        }
                    },
                    "ListKeys",
                )
            return original_get_paginator(operation_name)

        west_client.get_paginator = get_west_paginator
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={
                AWS_REGION_US_EAST_1: east_client,
                AWS_REGION_EU_WEST_1: west_client,
            },
        ):
            kms = KMS(aws_provider)

        assert [key.id for key in kms.keys] == [east_key["KeyId"]]
        assert kms.keys[0].detail_retrieved is True
        assert kms.keys_scan_errors == {AWS_REGION_EU_WEST_1: "AccessDeniedException"}

    @mock_aws
    def test_list_keys_generic_error_records_error_class(self):
        regional_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        regional_client.__dict__["region"] = AWS_REGION_US_EAST_1

        def raise_runtime_error(_):
            raise RuntimeError("temporary failure")

        regional_client.get_paginator = raise_runtime_error
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: regional_client},
        ):
            kms = KMS(aws_provider)

        assert kms.keys == []
        assert kms.keys_scan_errors == {AWS_REGION_US_EAST_1: "RuntimeError"}

    @mock_aws
    def test_describe_key_error_records_incomplete_detail(self):
        regional_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        regional_client.__dict__["region"] = AWS_REGION_US_EAST_1
        key = regional_client.create_key()["KeyMetadata"]

        def raise_access_denied(**_):
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "not authorized",
                    }
                },
                "DescribeKey",
            )

        regional_client.describe_key = raise_access_denied
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: regional_client},
        ):
            kms = KMS(aws_provider)

        assert len(kms.keys) == 1
        assert kms.keys[0].id == key["KeyId"]
        assert kms.keys[0].detail_retrieved is False
        assert kms.keys[0].detail_fetch_error == "AccessDeniedException"
        assert kms.keys[0].manager is None

    @mock_aws
    def test_describe_key_generic_error_records_error_class(self):
        regional_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        regional_client.__dict__["region"] = AWS_REGION_US_EAST_1
        key = regional_client.create_key()["KeyMetadata"]

        def raise_runtime_error(**_):
            raise RuntimeError("temporary failure")

        regional_client.describe_key = raise_runtime_error
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: regional_client},
        ):
            kms = KMS(aws_provider)

        assert len(kms.keys) == 1
        assert kms.keys[0].id == key["KeyId"]
        assert kms.keys[0].detail_retrieved is False
        assert kms.keys[0].detail_fetch_error == "RuntimeError"

    # Test KMS Get rotation status
    @mock_aws
    def test_get_key_rotation_status(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create KMS keys
        key1 = kms_client.create_key(MultiRegion=False)["KeyMetadata"]
        key2 = kms_client.create_key(MultiRegion=False)["KeyMetadata"]
        kms_client.enable_key_rotation(KeyId=key2["KeyId"])
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].rotation_enabled is False
        assert kms.keys[1].arn == key2["Arn"]
        assert kms.keys[1].rotation_enabled is True

    # Test KMS Key policy
    @mock_aws
    def test_get_key_policy(self):
        public_policy = json.dumps(
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
        default_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create KMS keys
        key1 = kms_client.create_key(MultiRegion=False, Policy=default_policy)[
            "KeyMetadata"
        ]
        key2 = kms_client.create_key(MultiRegion=False, Policy=public_policy)[
            "KeyMetadata"
        ]
        # KMS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].policy == json.loads(default_policy)
        assert kms.keys[1].arn == key2["Arn"]
        assert kms.keys[1].policy == json.loads(public_policy)

    # Test KMS List Aliases
    @mock_aws
    def test_list_aliases(self):
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key_with_alias = kms_client.create_key()["KeyMetadata"]
        key_without_alias = kms_client.create_key()["KeyMetadata"]
        kms_client.create_alias(
            AliasName="alias/enclave-signing-key",
            TargetKeyId=key_with_alias["KeyId"],
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        by_id = {k.id: k for k in kms.keys}
        assert by_id[key_with_alias["KeyId"]].aliases == ["alias/enclave-signing-key"]
        assert by_id[key_without_alias["KeyId"]].aliases == []

    # Test KMS Describe Key maps Description
    @mock_aws
    def test_describe_key_maps_description(self):
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key_with_desc = kms_client.create_key(
            MultiRegion=False,
            Description="production enclave key for the vault workload",
        )["KeyMetadata"]
        key_without_desc = kms_client.create_key(MultiRegion=False)["KeyMetadata"]
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        by_id = {k.id: k for k in kms.keys}
        assert (
            by_id[key_with_desc["KeyId"]].description
            == "production enclave key for the vault workload"
        )
        assert by_id[key_without_desc["KeyId"]].description == ""

    # Test KMS Get Key Policy failure surfaces policy_fetch_error
    @mock_aws
    def test_get_key_policy_failure_records_error(self):
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key(MultiRegion=False)["KeyMetadata"]
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)

        # Monkey-patch the regional client so GetKeyPolicy raises, reset the
        # (possibly-populated) policy field, and re-invoke _get_key_policy.
        def _boom(**_):
            raise RuntimeError("simulated GetKeyPolicy failure")

        kms.regional_clients[AWS_REGION_US_EAST_1].get_key_policy = _boom
        for k in kms.keys:
            k.policy = None
            k.policy_fetch_error = None
        kms._get_key_policy()

        target = next(k for k in kms.keys if k.id == key["KeyId"])
        assert target.policy is None
        assert target.policy_fetch_error == "RuntimeError"
