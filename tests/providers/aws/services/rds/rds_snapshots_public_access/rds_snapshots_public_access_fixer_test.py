from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_rds_snapshots_public_access_fixer:
    @mock_aws
    def test_rds_private_snapshot(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        conn.create_db_snapshot(
            DBInstanceIdentifier="db-primary-1", DBSnapshotIdentifier="snapshot-1"
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer import (
                    fixer,
                )

                assert fixer("snapshot-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_public_snapshot(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        conn.create_db_snapshot(
            DBInstanceIdentifier="db-primary-1", DBSnapshotIdentifier="snapshot-1"
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ) as service_client:

                service_client.db_snapshots[0].public = True

                # Test Fixer
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer import (
                    fixer,
                )

                assert fixer("snapshot-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_cluster_private_snapshot(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
        )

        conn.create_db_cluster_snapshot(
            DBClusterIdentifier="db-primary-1", DBClusterSnapshotIdentifier="snapshot-1"
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer import (
                    fixer,
                )

                assert fixer("snapshot-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_cluster_public_snapshot(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
        )

        conn.create_db_cluster_snapshot(
            DBClusterIdentifier="db-primary-1", DBClusterSnapshotIdentifier="snapshot-1"
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ) as service_client:

                service_client.db_cluster_snapshots[0].public = True

                # Test Fixer
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer import (
                    fixer,
                )

                assert fixer("snapshot-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_cluster_public_snapshot_error(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
        )

        conn.create_db_cluster_snapshot(
            DBClusterIdentifier="db-primary-1", DBClusterSnapshotIdentifier="snapshot-1"
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ) as service_client:

                service_client.db_cluster_snapshots[0].public = True

                # Test Fixer
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access_fixer import (
                    fixer,
                )

                assert not fixer("snapshot-2", AWS_REGION_US_EAST_1)
