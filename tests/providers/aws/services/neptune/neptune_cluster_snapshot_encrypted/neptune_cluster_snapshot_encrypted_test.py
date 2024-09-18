from unittest import mock

from prowler.providers.aws.services.neptune.neptune_service import ClusterSnapshot
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_neptune_cluster_snapshot_encrypted:
    def test_neptune_no_snapshots(self):
        neptune_client = mock.MagicMock()
        neptune_client.db_cluster_snapshots = []

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted import (
                neptune_cluster_snapshot_encrypted,
            )

            check = neptune_cluster_snapshot_encrypted()
            result = check.execute()

            assert len(result) == 0

    def test_neptune_snapshot_not_encrypted(self):
        neptune_client = mock.MagicMock
        snapshot_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
        neptune_client.db_cluster_snapshots = [
            ClusterSnapshot(
                arn=snapshot_arn,
                id="snapshot-1",
                cluster_id="cluster-1",
                region=AWS_REGION_US_EAST_1,
                encrypted=False,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted import (
                neptune_cluster_snapshot_encrypted,
            )

            check = neptune_cluster_snapshot_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Neptune Cluster Snapshot snapshot-1 is not encrypted at rest."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == snapshot_arn
            assert result[0].resource_tags == []

    def test_neptune_snapshot_encrypted(self):
        neptune_client = mock.MagicMock
        snapshot_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
        neptune_client.db_cluster_snapshots = [
            ClusterSnapshot(
                arn=snapshot_arn,
                id="snapshot-1",
                cluster_id="cluster-1",
                region=AWS_REGION_US_EAST_1,
                encrypted=True,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_snapshot_encrypted.neptune_cluster_snapshot_encrypted import (
                neptune_cluster_snapshot_encrypted,
            )

            check = neptune_cluster_snapshot_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Neptune Cluster Snapshot snapshot-1 is encrypted at rest."
            )
            assert result[0].resource_id == "snapshot-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == snapshot_arn
            assert result[0].resource_tags == []
