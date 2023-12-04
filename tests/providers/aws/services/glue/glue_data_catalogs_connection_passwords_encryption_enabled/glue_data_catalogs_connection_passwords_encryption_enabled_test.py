from unittest import mock

from prowler.providers.aws.services.glue.glue_service import CatalogEncryptionSetting
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_glue_data_catalogs_connection_passwords_encryption_enabled:
    def test_glue_no_settings(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
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
        glue_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
                kms_id=None,
                region=AWS_REGION_EU_WEST_1,
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
            assert (
                result[0].status_extended
                == "Glue data catalog connection password is not encrypted."
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_glue_catalog_password_unencrypted_ignoring(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
                kms_id=None,
                region=AWS_REGION_EU_WEST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.audit_info.ignore_unused_services = True
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

    def test_glue_catalog_password_unencrypted_ignoring_with_tables(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=True,
                kms_id=None,
                region=AWS_REGION_EU_WEST_1,
                password_encryption=False,
                password_kms_id=None,
            )
        ]
        glue_client.audited_account = "12345678912"
        glue_client.audit_info.ignore_unused_services = True
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
            assert (
                result[0].status_extended
                == "Glue data catalog connection password is not encrypted."
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_glue_catalog_encrypted(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
                region=AWS_REGION_EU_WEST_1,
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
            assert (
                result[0].status_extended
                == "Glue data catalog connection password is encrypted with KMS key kms-key."
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION_EU_WEST_1
