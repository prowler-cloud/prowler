from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.glue.glue_service import Glue
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetDataCatalogEncryptionSettings":
        return {
            "DataCatalogEncryptionSettings": {
                "EncryptionAtRest": {
                    "CatalogEncryptionMode": "SSE-KMS",
                    "SseAwsKmsKeyId": "kms_key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    elif operation_name == "GetResourcePolicy":
        return {
            "PolicyInJson": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::123456789012:root","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}',
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "GetDataCatalogEncryptionSettings":
        return {
            "DataCatalogEncryptionSettings": {
                "EncryptionAtRest": {
                    "CatalogEncryptionMode": "SSE-KMS",
                    "SseAwsKmsKeyId": "kms_key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    elif operation_name == "GetResourcePolicy":
        return {
            "PolicyInJson": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"glue:*","Resource":"*"}]}',
        }
    return make_api_call(self, operation_name, kwarg)


class Test_glue_data_catalogs_not_publicly_accessible:
    @mock_aws
    def test_glue_no_data_catalogs(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible import (
                glue_data_catalogs_not_publicly_accessible,
            )

            check = glue_data_catalogs_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_glue_data_catalog_not_public_policy(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible import (
                glue_data_catalogs_not_publicly_accessible,
            )

            check = glue_data_catalogs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Glue Data Catalog is not publicly accessible."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-catalog"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_glue_data_catalog_public_policy(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_not_publicly_accessible.glue_data_catalogs_not_publicly_accessible import (
                glue_data_catalogs_not_publicly_accessible,
            )

            check = glue_data_catalogs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue Data Catalog is publicly accessible due to its resource policy."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-catalog"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
