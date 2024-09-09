from unittest import mock

from prowler.providers.aws.services.rds.rds_service import DBCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_rds_cluster_minor_version_upgrade_enabled:
    def test_rds_no_clusters(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled import (
                rds_cluster_minor_version_upgrade_enabled,
            )

            check = rds_cluster_minor_version_upgrade_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_rds_cluster_no_multi(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {
            "db-cluster-1": DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
                endpoint="",
                engine="postgres",
                status="available",
                public=False,
                encrypted=True,
                auto_minor_version_upgrade=False,
                backup_retention_period=7,
                backtrack=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="default.postgres10",
                multi_az=False,
                username="admin",
                iam_auth=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled import (
                rds_cluster_minor_version_upgrade_enabled,
            )

            check = rds_cluster_minor_version_upgrade_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_rds_cluster_no_auto_upgrade(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {
            "db-cluster-1": DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
                endpoint="",
                engine="postgres",
                status="available",
                public=False,
                encrypted=True,
                auto_minor_version_upgrade=False,
                backup_retention_period=7,
                backtrack=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="default.postgres10",
                multi_az=True,
                username="admin",
                iam_auth=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled import (
                rds_cluster_minor_version_upgrade_enabled,
            )

            check = rds_cluster_minor_version_upgrade_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 does not have minor version upgrade enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []

    def test_rds_cluster_with_auto_upgrade(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {
            "db-cluster-1": DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
                endpoint="",
                engine="postgres",
                status="available",
                public=False,
                encrypted=True,
                auto_minor_version_upgrade=True,
                backup_retention_period=7,
                backtrack=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="default.postgres10",
                multi_az=True,
                username="admin",
                iam_auth=False,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_minor_version_upgrade_enabled.rds_cluster_minor_version_upgrade_enabled import (
                rds_cluster_minor_version_upgrade_enabled,
            )

            check = rds_cluster_minor_version_upgrade_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 has minor version upgrade enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []
