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
                    "CatalogEncryptionMode": "DISABLED",
                    "SseAwsKmsKeyId": "kms-key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "GetDataCatalogEncryptionSettings":
        return {
            "DataCatalogEncryptionSettings": {
                "EncryptionAtRest": {
                    "CatalogEncryptionMode": "DISABLED",
                    "SseAwsKmsKeyId": "kms-key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    elif operation_name == "SearchTables":
        return {
            "TableList": [
                {
                    "Name": "test-table",
                    "DatabaseName": "test-database",
                    "CatalogId": AWS_ACCOUNT_NUMBER,
                }
            ],
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v3(self, operation_name, kwarg):
    if operation_name == "GetDataCatalogEncryptionSettings":
        return {
            "DataCatalogEncryptionSettings": {
                "EncryptionAtRest": {
                    "CatalogEncryptionMode": "SSE-KMS",
                    "SseAwsKmsKeyId": "kms-key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_glue_data_catalogs_metadata_encryption_enabled:
    @mock_aws
    def test_glue_no_data_catalogs(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_glue_catalog_unencrypted(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue data catalog settings have metadata encryption disabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-catalog"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_glue_catalog_unencrypted_ignoring(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._scan_unused_services = False
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_glue_catalog_unencrypted_ignoring_with_tables(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._scan_unused_services = False
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue data catalog settings have metadata encryption disabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-catalog"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v3)
    def test_glue_catalog_encrypted(self):
        client("glue", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled.glue_client",
            new=Glue(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Glue data catalog settings have metadata encryption enabled with KMS key kms-key."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:data-catalog"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
