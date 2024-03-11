from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import CatalogEncryptionSetting
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_glue_data_catalogs_metadata_encryption_enabled:
    def test_glue_no_settings(self):
        glue_client = mock.MagicMock
        glue_client.provider = set_mocked_aws_provider
        glue_client.catalog_encryption_settings = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_catalog_unencrypted(self):
        glue_client = mock.MagicMock
        glue_client.provider = set_mocked_aws_provider()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="disabled.",
                tables=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.audited_partition = "aws"
        glue_client.region = AWS_REGION_US_EAST_1
        glue_client.data_catalog_arn_template = f"arn:{glue_client.audited_partition}:glue:{glue_client.region}:{glue_client.audited_account}:data-catalog"
        glue_client.__get_data_catalog_arn_template__ = mock.MagicMock(
            return_value=glue_client.data_catalog_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
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
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_glue_catalog_unencrypted_ignoring(self):
        glue_client = mock.MagicMock
        glue_client.provider = set_mocked_aws_provider()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="disabled.",
                tables=False,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.provider._ignore_unused_services = True
        glue_client.audited_partition = "aws"
        glue_client.region = AWS_REGION_US_EAST_1
        glue_client.data_catalog_arn_template = f"arn:{glue_client.audited_partition}:glue:{glue_client.region}:{glue_client.audited_account}:data-catalog"
        glue_client.__get_data_catalog_arn_template__ = mock.MagicMock(
            return_value=glue_client.data_catalog_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_catalog_unencrypted_ignoring_with_tables(self):
        glue_client = mock.MagicMock
        glue_client.provider = set_mocked_aws_provider()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="disabled.",
                tables=True,
                kms_id=None,
                region=AWS_REGION_US_EAST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.provider._ignore_unused_services = True
        glue_client.audited_partition = "aws"
        glue_client.region = AWS_REGION_US_EAST_1
        glue_client.data_catalog_arn_template = f"arn:{glue_client.audited_partition}:glue:{glue_client.region}:{glue_client.audited_account}:data-catalog"
        glue_client.__get_data_catalog_arn_template__ = mock.MagicMock(
            return_value=glue_client.data_catalog_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_metadata_encryption_enabled.glue_data_catalogs_metadata_encryption_enabled import (
                glue_data_catalogs_metadata_encryption_enabled,
            )

            check = glue_data_catalogs_metadata_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Glue data catalog settings have metadata encryption disabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_glue_catalog_encrypted(self):
        glue_client = mock.MagicMock
        glue_client.provider = set_mocked_aws_provider()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="SSE-KMS",
                kms_id="kms-key",
                tables=False,
                region=AWS_REGION_US_EAST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.audited_partition = "aws"
        glue_client.region = AWS_REGION_US_EAST_1
        glue_client.data_catalog_arn_template = f"arn:{glue_client.audited_partition}:glue:{glue_client.region}:{glue_client.audited_account}:data-catalog"
        glue_client.__get_data_catalog_arn_template__ = mock.MagicMock(
            return_value=glue_client.data_catalog_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
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
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_US_EAST_1
