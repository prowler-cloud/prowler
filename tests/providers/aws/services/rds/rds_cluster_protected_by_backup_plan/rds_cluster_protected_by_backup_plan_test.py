from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_cluster_protected_by_backup_plan:
    @mock_aws
    def test_rds_no_clusters(self):
        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_cluster_no_existing_backup_plans(self):
        cluster = mock.MagicMock()
        backup = mock.MagicMock()

        from prowler.providers.aws.services.rds.rds_service import DBCluster

        arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
        cluster.db_clusters = {
            arn: DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1",
                endpoint="db-cluster-1.c9akciq32.rds.amazonaws.com",
                backtrack=1,
                parameter_group="test",
                engine_version="13.3",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=False,
                auto_minor_version_upgrade=True,
                multi_az=False,
                username="admin",
                iam_auth=False,
                name="db-cluster-1",
                region="us-east-1",
                cluster_class="db.m1.small",
                engine="aurora-postgres",
                allocated_storage=10,
                tags=[],
            )
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_client.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=backup,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup,
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is not protected by a backup plan."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
                )
                assert result[0].resource_tags == []

    def test_rds_cluster_without_backup_plan(self):
        cluster = mock.MagicMock()
        backup = mock.MagicMock()

        from prowler.providers.aws.services.rds.rds_service import DBCluster

        arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
        cluster.db_clusters = {
            arn: DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1",
                endpoint="db-cluster-1.c9akciq32.rds.amazonaws.com",
                backtrack=1,
                parameter_group="test",
                engine_version="13.3",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=False,
                auto_minor_version_upgrade=True,
                multi_az=False,
                username="admin",
                iam_auth=False,
                name="db-cluster-1",
                region="us-east-1",
                cluster_class="db.m1.small",
                engine="aurora-postgres",
                allocated_storage=10,
                tags=[],
            )
        }

        backup.protected_resources = [
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-2"
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_client.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=backup,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup,
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is not protected by a backup plan."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
                )
                assert result[0].resource_tags == []

    def test_rds_cluster_with_backup_plan(self):
        cluster = mock.MagicMock()

        from prowler.providers.aws.services.rds.rds_service import DBCluster

        arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
        cluster.db_clusters = {
            arn: DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1",
                endpoint="db-cluster-1.c9akciq32.rds.amazonaws.com",
                backtrack=1,
                parameter_group="test",
                engine_version="13.3",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=False,
                auto_minor_version_upgrade=True,
                multi_az=False,
                username="admin",
                iam_auth=False,
                name="db-cluster-1",
                region="us-east-1",
                cluster_class="db.m1.small",
                engine="aurora-postgres",
                allocated_storage=10,
                tags=[],
            )
        }

        backup = mock.MagicMock()
        backup.protected_resources = [arn]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_client.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=backup,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup,
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is protected by a backup plan."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
                )
                assert result[0].resource_tags == []

    def test_rds_cluster_with_backup_plan_via_cluster_wildcard(self):
        cluster = mock.MagicMock()
        cluster.audited_partition = "aws"

        from prowler.providers.aws.services.rds.rds_service import DBCluster

        arn = "arn:aws:rds:*:*:cluster:*"
        cluster.db_clusters = {
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1": DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1",
                endpoint="db-cluster-1.c9akciq32.rds.amazonaws.com",
                backtrack=1,
                parameter_group="test",
                engine_version="13.3",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=False,
                auto_minor_version_upgrade=True,
                multi_az=False,
                username="admin",
                iam_auth=False,
                name="db-cluster-1",
                region="us-east-1",
                cluster_class="db.m1.small",
                engine="aurora-postgres",
                allocated_storage=10,
                tags=[],
            )
        }

        backup = mock.MagicMock()
        backup.protected_resources = [arn]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_client.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=backup,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup,
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is protected by a backup plan."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
                )
                assert result[0].resource_tags == []

    def test_rds_cluster_with_backup_plan_via_all_wildcard(self):
        cluster = mock.MagicMock()

        from prowler.providers.aws.services.rds.rds_service import DBCluster

        arn = "*"
        cluster.db_clusters = {
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1": DBCluster(
                id="db-cluster-1",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1",
                endpoint="db-cluster-1.c9akciq32.rds.amazonaws.com",
                backtrack=1,
                parameter_group="test",
                engine_version="13.3",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=False,
                auto_minor_version_upgrade=True,
                multi_az=False,
                username="admin",
                iam_auth=False,
                name="db-cluster-1",
                region="us-east-1",
                cluster_class="db.m1.small",
                engine="aurora-postgres",
                allocated_storage=10,
                tags=[],
            )
        }

        backup = mock.MagicMock()
        backup.protected_resources = [arn]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_client.rds_client",
                new=cluster,
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan.backup_client",
                new=backup,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup,
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_protected_by_backup_plan.rds_cluster_protected_by_backup_plan import (
                    rds_cluster_protected_by_backup_plan,
                )

                check = rds_cluster_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is protected by a backup plan."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-cluster-1"
                )
                assert result[0].resource_tags == []
