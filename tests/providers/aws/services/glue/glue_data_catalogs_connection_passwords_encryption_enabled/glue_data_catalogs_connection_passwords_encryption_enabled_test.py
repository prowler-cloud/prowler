from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import CatalogEncryptionSetting

AWS_REGION = "us-east-1"


class Test_glue_data_catalogs_connection_passwords_encryption_enabled:
    def test_glue_no_settings(self):
        glue_client = mock.MagicMock
        glue_client.catalog_encryption_settings = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_passwords_encryption_enabled.glue_data_catalogs_connection_passwords_encryption_enabled import (
                glue_data_catalogs_connection_passwords_encryption_enabled,
            )

            check = glue_data_catalogs_connection_passwords_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_catalog_password_unencrypted(self):
        glue_client = mock.MagicMock
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                kms_id=None,
                region=AWS_REGION,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_passwords_encryption_enabled.glue_data_catalogs_connection_passwords_encryption_enabled import (
                glue_data_catalogs_connection_passwords_encryption_enabled,
            )

            check = glue_data_catalogs_connection_passwords_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Glue data catalog connection password is not encrypted",
                result[0].status_extended,
            )
            assert result[0].resource_id == "12345678912"

    def test_glue_catalog_encrypted(self):
        glue_client = mock.MagicMock
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                region=AWS_REGION,
                password_encryption=True,
                password_kms_id="kms-key",
            )
        ]
        glue_client.audited_account = "12345678912"

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_passwords_encryption_enabled.glue_data_catalogs_connection_passwords_encryption_enabled import (
                glue_data_catalogs_connection_passwords_encryption_enabled,
            )

            check = glue_data_catalogs_connection_passwords_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Glue data catalog connection password is encrypted",
                result[0].status_extended,
            )
            assert result[0].resource_id == "12345678912"
