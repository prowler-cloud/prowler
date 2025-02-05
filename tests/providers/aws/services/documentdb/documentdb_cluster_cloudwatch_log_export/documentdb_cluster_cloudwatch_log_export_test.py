from unittest import mock

from prowler.providers.aws.services.documentdb.documentdb_service import DBCluster

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

DOC_DB_CLUSTER_NAME = "test-cluster"
DOC_DB_CLUSTER_ARN = (
    f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:cluster:{DOC_DB_CLUSTER_NAME}"
)
DOC_DB_ENGINE_VERSION = "5.0.0"


class Test_documentdb_cluster_cloudwatch_log_export:
    def test_documentdb_no_clusters(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {}

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import (
                documentdb_cluster_cloudwatch_log_export,
            )

            check = documentdb_cluster_cloudwatch_log_export()
            result = check.execute()
            assert len(result) == 0

    def test_documentdb_cluster_cloudwatch_log_export_disabled(self):
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
                deletion_protection=False,
                region=AWS_REGION,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import (
                documentdb_cluster_cloudwatch_log_export,
            )

            check = documentdb_cluster_cloudwatch_log_export()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DocumentDB Cluster {DOC_DB_CLUSTER_NAME} does not have cloudwatch log export enabled."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_cloudwatch_log_export_audit_only_enabled(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=9,
                encrypted=True,
                cloudwatch_logs=["audit"],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import (
                documentdb_cluster_cloudwatch_log_export,
            )

            check = documentdb_cluster_cloudwatch_log_export()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DocumentDB Cluster test-cluster is only shipping audit to CloudWatch Logs. Recommended to ship both Audit and Profiler logs."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_cloudwatch_log_export_profiler_only_enabled(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=9,
                encrypted=True,
                cloudwatch_logs=["profiler"],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import (
                documentdb_cluster_cloudwatch_log_export,
            )

            check = documentdb_cluster_cloudwatch_log_export()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DocumentDB Cluster test-cluster is only shipping profiler to CloudWatch Logs. Recommended to ship both Audit and Profiler logs."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN

    def test_documentdb_cluster_cloudwatch_log_export_enabled(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=9,
                encrypted=True,
                cloudwatch_logs=["audit", "profiler"],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION,
                tags=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import (
                documentdb_cluster_cloudwatch_log_export,
            )

            check = documentdb_cluster_cloudwatch_log_export()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "DocumentDB Cluster test-cluster is shipping audit profiler to CloudWatch Logs."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == DOC_DB_CLUSTER_NAME
            assert result[0].resource_arn == DOC_DB_CLUSTER_ARN
