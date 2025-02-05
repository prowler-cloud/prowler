from unittest import mock

from prowler.providers.aws.services.documentdb.documentdb_service import (
    ClusterSnapshot,
    DBCluster,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION_US_EAST_1 = "us-east-1"

DOC_DB_CLUSTER_NAME = "test-cluster"
DOC_DB_CLUSTER_ARN = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{DOC_DB_CLUSTER_NAME}"
DOC_DB_ENGINE_VERSION = "5.0.0"


class Test_documentdb_cluster_public_snapshot:
    def test_documentdb_no_snapshot(self):
        documentdb_client = mock.MagicMock
        documentdb_client.db_clusters = {}
        documentdb_client.db_cluster_snapshots = []

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot import (
                documentdb_cluster_public_snapshot,
            )

            check = documentdb_cluster_public_snapshot()
            result = check.execute()
            assert len(result) == 0

    def test_documentdb_cluster_private_snapshot(self):
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
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }
        documentdb_client.db_cluster_snapshots = [
            ClusterSnapshot(
                id="snapshot-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1",
                cluster_id=DOC_DB_CLUSTER_NAME,
                encrypted=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot import (
                documentdb_cluster_public_snapshot,
            )

            check = documentdb_cluster_public_snapshot()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "DocumentDB Cluster Snapshot snapshot-1 is not shared publicly."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
            )
            assert result[0].resource_tags == []

    def test_documentdb_cluster_public_snapshot(self):
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
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }
        documentdb_client.db_cluster_snapshots = [
            ClusterSnapshot(
                id="snapshot-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1",
                cluster_id=DOC_DB_CLUSTER_NAME,
                encrypted=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_service.DocumentDB",
            new=documentdb_client,
        ), mock.patch(
            "prowler.providers.aws.services.documentdb.documentdb_client.documentdb_client",
            new=documentdb_client,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot import (
                documentdb_cluster_public_snapshot,
            )

            documentdb_client.db_cluster_snapshots[0].public = True
            check = documentdb_cluster_public_snapshot()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DocumentDB Cluster Snapshot snapshot-1 is public."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
            )
            assert result[0].resource_tags == []
