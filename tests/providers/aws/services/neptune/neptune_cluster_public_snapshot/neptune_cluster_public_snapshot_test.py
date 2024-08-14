from unittest import mock

from prowler.providers.aws.services.neptune.neptune_service import (
    Cluster,
    ClusterSnapshot,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION_US_EAST_1 = "us-east-1"

NEPTUNE_CLUSTER_NAME = "test-cluster"
NEPTUNE_CLUSTER_ARN = f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{NEPTUNE_CLUSTER_NAME}"


class Test_neptune_cluster_public_snapshot:
    def test_neptune_no_snapshot(self):
        neptune_client = mock.MagicMock
        neptune_client.clusters = {}
        neptune_client.db_cluster_snapshots = []

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot.neptune_client",
            new=neptune_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot import (
                neptune_cluster_public_snapshot,
            )

            check = neptune_cluster_public_snapshot()
            result = check.execute()
            assert len(result) == 0

    def test_neptune_cluster_private_snapshot(self):
        neptune_client = mock.MagicMock
        neptune_client.clusters = {
            NEPTUNE_CLUSTER_ARN: Cluster(
                name=NEPTUNE_CLUSTER_NAME,
                arn=NEPTUNE_CLUSTER_ARN,
                id="test-cluster-id",
                backup_retention_period=7,
                encrypted=True,
                kms_key="kms-key-id",
                multi_az=False,
                iam_auth=False,
                deletion_protection=False,
                db_subnet_group_id="subnet-group",
                region=AWS_REGION_US_EAST_1,
            )
        }
        neptune_client.db_cluster_snapshots = [
            ClusterSnapshot(
                id="snapshot-1",
                arn=f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1",
                cluster_id=NEPTUNE_CLUSTER_NAME,
                encrypted=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot.neptune_client",
            new=neptune_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot import (
                neptune_cluster_public_snapshot,
            )

            check = neptune_cluster_public_snapshot()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "NeptuneDB Cluster Snapshot snapshot-1 is not shared publicly."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
            )
            assert result[0].resource_tags == []

    def test_neptune_cluster_public_snapshot(self):
        neptune_client = mock.MagicMock
        neptune_client.clusters = {
            NEPTUNE_CLUSTER_ARN: Cluster(
                name=NEPTUNE_CLUSTER_NAME,
                arn=NEPTUNE_CLUSTER_ARN,
                id="test-cluster-id",
                backup_retention_period=7,
                encrypted=True,
                kms_key="kms-key-id",
                multi_az=False,
                iam_auth=False,
                deletion_protection=False,
                db_subnet_group_id="subnet-group",
                region=AWS_REGION_US_EAST_1,
            )
        }
        neptune_client.db_cluster_snapshots = [
            ClusterSnapshot(
                id="snapshot-1",
                arn=f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1",
                cluster_id=NEPTUNE_CLUSTER_NAME,
                encrypted=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot.neptune_client",
            new=neptune_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_public_snapshot.neptune_cluster_public_snapshot import (
                neptune_cluster_public_snapshot,
            )

            neptune_client.db_cluster_snapshots[0].public = True
            check = neptune_cluster_public_snapshot()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "NeptuneDB Cluster Snapshot snapshot-1 is public."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
            )
            assert result[0].resource_tags == []
