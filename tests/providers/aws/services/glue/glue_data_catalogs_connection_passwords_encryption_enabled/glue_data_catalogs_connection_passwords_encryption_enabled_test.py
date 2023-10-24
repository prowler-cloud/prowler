from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.glue.glue_service import CatalogEncryptionSetting
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_glue_data_catalogs_connection_passwords_encryption_enabled:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
            ignore_unused_services=False,
        )
        return audit_info

    def test_glue_no_settings(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = self.set_mocked_audit_info()
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
        glue_client.audit_info = self.set_mocked_audit_info()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
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
            assert (
                result[0].status_extended
                == "Glue data catalog connection password is not encrypted."
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION

    def test_glue_catalog_password_unencrypted_ignoring(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = self.set_mocked_audit_info()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
                kms_id=None,
                region=AWS_REGION,
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
        glue_client.audit_info = self.set_mocked_audit_info()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=True,
                kms_id=None,
                region=AWS_REGION,
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
            assert result[0].region == AWS_REGION

    def test_glue_catalog_encrypted(self):
        glue_client = mock.MagicMock
        glue_client.audit_info = self.set_mocked_audit_info()
        glue_client.catalog_encryption_settings = [
            CatalogEncryptionSetting(
                mode="DISABLED",
                tables=False,
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
            assert (
                result[0].status_extended
                == "Glue data catalog connection password is encrypted with KMS key kms-key."
            )
            assert result[0].resource_id == "12345678912"
            assert result[0].region == AWS_REGION
