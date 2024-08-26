from unittest import mock

from prowler.providers.aws.services.rds.rds_service import DBCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_rds_cluster_multi_az:
    def test_rds_no_clusters(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az import (
                rds_cluster_multi_az,
            )

            check = rds_cluster_multi_az()
            result = check.execute()

            assert len(result) == 0

    def test_rds_cluster_no_multi_az(self):
        rds_client = mock.MagicMock
        cluster_arn = (
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
        )
        rds_client.db_clusters = {
            cluster_arn: DBCluster(
                id="db-cluster-1",
                arn=cluster_arn,
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="",
                multi_az=False,
                username="test",
                iam_auth=False,
                backtrack=0,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az import (
                rds_cluster_multi_az,
            )

            check = rds_cluster_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 does not have multi-AZ enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
            )
            assert result[0].resource_tags == []

    def test_rds_cluster_multi_az(self):
        rds_client = mock.MagicMock
        cluster_arn = (
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
        )
        rds_client.db_clusters = {
            cluster_arn: DBCluster(
                id="db-cluster-1",
                arn=cluster_arn,
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="",
                multi_az=True,
                username="test",
                iam_auth=False,
                backtrack=0,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az.rds_client",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_multi_az.rds_cluster_multi_az import (
                rds_cluster_multi_az,
            )

            check = rds_cluster_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 has multi-AZ enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
            )
            assert result[0].resource_tags == []
