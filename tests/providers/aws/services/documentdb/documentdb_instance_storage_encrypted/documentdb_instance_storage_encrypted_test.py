from unittest import mock

from prowler.providers.aws.services.documentdb.documentdb_service import Instance

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

DOC_DB_INSTANCE_NAME = "test-db"
DOC_DB_INSTANCE_ARN = (
    f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:{DOC_DB_INSTANCE_NAME}"
)
DOC_DB_ENGINE_VERSION = "5.0.0"


class Test_documentdb_instance_storage_encrypted:
    def test_documentdb_no_instances(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = {}

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

    def test_documentdb_instance_not_encrypted(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = {
            DOC_DB_INSTANCE_ARN: Instance(
                id=DOC_DB_INSTANCE_NAME,
                arn=DOC_DB_INSTANCE_ARN,
                engine="docdb",
                engine_version=DOC_DB_ENGINE_VERSION,
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                region=AWS_REGION,
            )
        }

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
            assert (
                result[0].status_extended
                == f"DocumentDB Instance {DOC_DB_INSTANCE_NAME} is not encrypted."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_INSTANCE_NAME
            assert result[0].resource_arn == DOC_DB_INSTANCE_ARN

    def test_documentdb_instance_with_encryption(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_instances = {
            DOC_DB_INSTANCE_ARN: Instance(
                id=DOC_DB_INSTANCE_NAME,
                arn=DOC_DB_INSTANCE_ARN,
                engine="docdb",
                engine_version=DOC_DB_ENGINE_VERSION,
                status="available",
                public=False,
                encrypted=True,
                auto_minor_version_upgrade=False,
                region=AWS_REGION,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_instance_storage_encrypted.documentdb_instance_storage_encrypted import (
                documentdb_instance_storage_encrypted,
            )

            check = documentdb_instance_storage_encrypted()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DocumentDB Instance {DOC_DB_INSTANCE_NAME} is encrypted."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_INSTANCE_NAME
            assert result[0].resource_arn == DOC_DB_INSTANCE_ARN
