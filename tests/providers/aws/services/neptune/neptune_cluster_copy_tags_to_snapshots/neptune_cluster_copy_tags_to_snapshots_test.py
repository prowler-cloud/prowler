from unittest import mock

from prowler.providers.aws.services.neptune.neptune_service import Cluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_neptune_cluster_copy_tags_to_snapshots:
    def test_neptune_no_clusters(self):
        neptune_client = mock.MagicMock
        neptune_client.clusters = {}

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots import (
                neptune_cluster_copy_tags_to_snapshots,
            )

            check = neptune_cluster_copy_tags_to_snapshots()
            result = check.execute()

            assert len(result) == 0

    def test_neptune_cluster_copy_tags_disabled(self):
        neptune_client = mock.MagicMock
        cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
        neptune_client.clusters = {
            cluster_arn: Cluster(
                arn=cluster_arn,
                name="db-cluster-1",
                id="db-cluster-1",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                copy_tags_to_snapshot=False,
                backup_retention_period=7,
                encrypted=True,
                kms_key="arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
                multi_az=False,
                iam_auth=False,
                deletion_protection=False,
                db_subnet_group_id="subnet-1234abcd",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots import (
                neptune_cluster_copy_tags_to_snapshots,
            )

            check = neptune_cluster_copy_tags_to_snapshots()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Neptune DB Cluster db-cluster-1 is not configured to copy tags to snapshots."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []

    def test_neptune_cluster_copy_tags_enabled(self):
        neptune_client = mock.MagicMock
        cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-2"
        neptune_client.clusters = {
            cluster_arn: Cluster(
                arn=cluster_arn,
                name="db-cluster-2",
                id="db-cluster-2",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                copy_tags_to_snapshot=True,
                backup_retention_period=7,
                encrypted=True,
                kms_key="arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
                multi_az=False,
                iam_auth=False,
                deletion_protection=False,
                db_subnet_group_id="subnet-1234abcd",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_copy_tags_to_snapshots.neptune_cluster_copy_tags_to_snapshots import (
                neptune_cluster_copy_tags_to_snapshots,
            )

            check = neptune_cluster_copy_tags_to_snapshots()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Neptune DB Cluster db-cluster-2 is configured to copy tags to snapshots."
            )
            assert result[0].resource_id == "db-cluster-2"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
