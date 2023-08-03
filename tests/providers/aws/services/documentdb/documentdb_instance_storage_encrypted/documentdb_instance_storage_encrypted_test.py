from re import search
from unittest import mock

from prowler.providers.aws.services.documentdb.documentdb_service import DBInstance

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_documentdb_instance_storage_encrypted:
    def test_documentdb_no_instances(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = []

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_instance_storage_encrypted.documentdb_instance_storage_encrypted import (
                documentdb_instance_storage_encrypted,
            )

            check = documentdb_instance_storage_encrypted()
            result = check.execute()
            assert len(result) == 0

    def test_documentdb_instance_no_encryption(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = [
            DBInstance(
                id="test",
                engine="docdb",
                engine_version="test",
                status="test",
                public=True,
                encrypted=False,
                backup_retention_period=90,
                auto_minor_version_upgrade=False,
                enhanced_monitoring_arn="test",
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_instance_storage_encrypted.documentdb_instance_storage_encrypted import (
                documentdb_instance_storage_encrypted,
            )

            check = documentdb_instance_storage_encrypted()
            result = check.execute()
            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert search(
                "is not encrypted",
                result[0].status_extended,
            )

    def test_documentdb_instance_with_encryption(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = [
            DBInstance(
                id="test",
                engine="docdb",
                engine_version="test",
                status="test",
                public=True,
                encrypted=True,
                backup_retention_period=90,
                auto_minor_version_upgrade=False,
                enhanced_monitoring_arn="test",
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_instance_storage_encrypted.documentdb_instance_storage_encrypted import (
                documentdb_instance_storage_encrypted,
            )

            check = documentdb_instance_storage_encrypted()
            result = check.execute()
            assert len(result) == 1

            assert result[0].status == "PASS"
            assert search(
                "is encrypted",
                result[0].status_extended,
            )
