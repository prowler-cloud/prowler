from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

DMS_ENDPOINT_NAME = "dms-endpoint"
DMS_ENDPOINT_ARN = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:{DMS_ENDPOINT_NAME}"
DMS_INSTANCE_NAME = "rep-instance"
DMS_INSTANCE_ARN = (
    f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rep:{DMS_INSTANCE_NAME}"
)


def mock_make_api_call_enabled_not_redis(self, operation_name, kwarg):
    if operation_name == "DescribeEndpoints":
        return {
            "Endpoints": [
                {
                    "EndpointIdentifier": DMS_ENDPOINT_NAME,
                    "EndpointArn": DMS_ENDPOINT_ARN,
                    "SslMode": "require",
                    "RedisSettings": {
                        "SslSecurityProtocol": "ssl-encryption",
                    },
                    "EngineName": "oracle",
                }
            ]
        }
    elif operation_name == "ListTagsForResource":
        if kwarg["ResourceArn"] == DMS_INSTANCE_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "rep-instance"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
        elif kwarg["ResourceArn"] == DMS_ENDPOINT_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "dms-endpoint"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_enabled(self, operation_name, kwarg):
    if operation_name == "DescribeEndpoints":
        return {
            "Endpoints": [
                {
                    "EndpointIdentifier": DMS_ENDPOINT_NAME,
                    "EndpointArn": DMS_ENDPOINT_ARN,
                    "SslMode": "require",
                    "RedisSettings": {
                        "SslSecurityProtocol": "ssl-encryption",
                    },
                    "EngineName": "redis",
                }
            ]
        }
    elif operation_name == "ListTagsForResource":
        if kwarg["ResourceArn"] == DMS_INSTANCE_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "rep-instance"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
        elif kwarg["ResourceArn"] == DMS_ENDPOINT_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "dms-endpoint"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_not_enabled(self, operation_name, kwarg):
    if operation_name == "DescribeEndpoints":
        return {
            "Endpoints": [
                {
                    "EndpointIdentifier": DMS_ENDPOINT_NAME,
                    "EndpointArn": DMS_ENDPOINT_ARN,
                    "SslMode": "require",
                    "RedisSettings": {
                        "SslSecurityProtocol": "plaintext",
                    },
                    "EngineName": "redis",
                }
            ]
        }
    elif operation_name == "ListTagsForResource":
        if kwarg["ResourceArn"] == DMS_INSTANCE_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "rep-instance"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
        elif kwarg["ResourceArn"] == DMS_ENDPOINT_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "dms-endpoint"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
    return make_api_call(self, operation_name, kwarg)


class Test_dms_endpoint_redis_in_transit_encryption_enabled:
    @mock_aws
    def test_no_dms_endpoints(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)
        dms_client.endpoints = {}

        from prowler.providers.aws.services.dms.dms_service import DMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled.dms_client",
            new=DMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled import (
                dms_endpoint_redis_in_transit_encryption_enabled,
            )

            check = dms_endpoint_redis_in_transit_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_dms_not_mongodb_auth_mecanism_enabled(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_enabled_not_redis,
        ):

            from prowler.providers.aws.services.dms.dms_service import DMS

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled.dms_client",
                new=DMS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled import (
                    dms_endpoint_redis_in_transit_encryption_enabled,
                )

                check = dms_endpoint_redis_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_dms_mongodb_auth_mecanism_not_enabled(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_not_enabled,
        ):

            from prowler.providers.aws.services.dms.dms_service import DMS

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled.dms_client",
                new=DMS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled import (
                    dms_endpoint_redis_in_transit_encryption_enabled,
                )

                check = dms_endpoint_redis_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == (
                    "DMS Endpoint dms-endpoint for Redis OSS is not encrypted in transit."
                )
                assert result[0].resource_id == "dms-endpoint"
                assert (
                    result[0].resource_arn
                    == "arn:aws:dms:us-east-1:123456789012:endpoint:dms-endpoint"
                )
                assert result[0].resource_tags == [
                    {
                        "Key": "Name",
                        "Value": "dms-endpoint",
                    },
                    {
                        "Key": "Owner",
                        "Value": "admin",
                    },
                ]
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_dms_mongodb_auth_mecanism_enabled(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_enabled,
        ):

            from prowler.providers.aws.services.dms.dms_service import DMS

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled.dms_client",
                new=DMS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dms.dms_endpoint_redis_in_transit_encryption_enabled.dms_endpoint_redis_in_transit_encryption_enabled import (
                    dms_endpoint_redis_in_transit_encryption_enabled,
                )

                check = dms_endpoint_redis_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].status_extended == (
                    "DMS Endpoint dms-endpoint for Redis OSS is encrypted in transit."
                )
                assert result[0].resource_id == "dms-endpoint"
                assert (
                    result[0].resource_arn
                    == "arn:aws:dms:us-east-1:123456789012:endpoint:dms-endpoint"
                )
                assert result[0].resource_tags == [
                    {
                        "Key": "Name",
                        "Value": "dms-endpoint",
                    },
                    {
                        "Key": "Owner",
                        "Value": "admin",
                    },
                ]
                assert result[0].region == "us-east-1"
