from unittest import mock

from prowler.providers.aws.services.documentdb.documentdb_service import DBCluster

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

DOC_DB_CLUSTER_NAME = "test-cluster"
DOC_DB_CLUSTER_ARN = (
    f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:cluster:{DOC_DB_CLUSTER_NAME}"
)
DOC_DB_ENGINE_VERSION = "5.0.0"


class Test_documentdb_cluster_backup_enabled:
    def test_documentdb_no_clusters(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {}

        documentdb_client.audit_config = {"minimum_backup_retention_period": 7}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_documentdb_cluster_not_backed_up(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=0,
                encrypted=False,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        documentdb_client.audit_config = {"minimum_backup_retention_period": 7}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} does not have backup enabled."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_with_backup_less_than_recommended(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=1,
                encrypted=True,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        documentdb_client.audit_config = {"minimum_backup_retention_period": 7}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} has backup enabled with retention period 1 days. Recommended to increase the backup retention period to a minimum of 7 days."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_with_backup_equal_to_recommended(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=7,
                encrypted=True,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        documentdb_client.audit_config = {"minimum_backup_retention_period": 7}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} has backup enabled with retention period 7 days."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_with_backup(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=9,
                encrypted=True,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        documentdb_client.audit_config = {"minimum_backup_retention_period": 7}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} has backup enabled with retention period 9 days."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_with_backup_modified_retention(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=2,
                encrypted=True,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }

        documentdb_client.audit_config = {"minimum_backup_retention_period": 1}
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import (
                documentdb_cluster_backup_enabled,
            )

            check = documentdb_cluster_backup_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} has backup enabled with retention period 2 days."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN
