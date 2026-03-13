from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "postgres",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_rds_snapshots_encrypted:
    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_rds_no_snapshots(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted import (
                    rds_snapshots_encrypted,
                )

                check = rds_snapshots_encrypted()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_rds_snapshot_not_encrypted(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=False,
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
                "prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted import (
                    rds_snapshots_encrypted,
                )

                check = rds_snapshots_encrypted()
                result = check.execute()

                # Moto creates additional automatic snapshots
                assert len(result) == 2
                # Find the manual snapshot result
                manual_snapshot_result = next(
                    (r for r in result if r.resource_id == "snapshot-1"), None
                )
                assert manual_snapshot_result is not None
                assert manual_snapshot_result.status == "FAIL"
                assert (
                    manual_snapshot_result.status_extended
                    == "RDS Instance Snapshot snapshot-1 is not encrypted."
                )

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_rds_snapshot_encrypted(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=False,
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
                "prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted import (
                    rds_snapshots_encrypted,
                )

                # Find the manual snapshot and set it to encrypted
                manual_snapshot = next(
                    (s for s in service_client.db_snapshots if s.id == "snapshot-1"),
                    None,
                )
                if manual_snapshot:
                    manual_snapshot.encrypted = True
                check = rds_snapshots_encrypted()
                result = check.execute()

                assert len(result) == 2
                # Find the manual snapshot result
                manual_snapshot_result = next(
                    (r for r in result if r.resource_id == "snapshot-1"), None
                )
                assert manual_snapshot_result is not None
                assert manual_snapshot_result.status == "PASS"
                assert (
                    manual_snapshot_result.status_extended
                    == "RDS Instance Snapshot snapshot-1 is encrypted."
                )
                assert manual_snapshot_result.resource_id == "snapshot-1"
                assert manual_snapshot_result.region == AWS_REGION_US_EAST_1
                assert (
                    manual_snapshot_result.resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:snapshot:snapshot-1"
                )
                assert manual_snapshot_result.resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_rds_cluster_snapshot_encrypted(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
            PubliclyAccessible=False,
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
                "prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted import (
                    rds_snapshots_encrypted,
                )

                # Find the manual cluster snapshot and set it to encrypted
                manual_snapshot = next(
                    (
                        s
                        for s in service_client.db_cluster_snapshots
                        if s.id == "snapshot-1"
                    ),
                    None,
                )
                if manual_snapshot:
                    manual_snapshot.encrypted = True
                check = rds_snapshots_encrypted()
                result = check.execute()

                assert len(result) == 2
                # Find the manual snapshot result
                manual_snapshot_result = next(
                    (r for r in result if r.resource_id == "snapshot-1"), None
                )
                assert manual_snapshot_result is not None
                assert manual_snapshot_result.status == "PASS"
                assert (
                    manual_snapshot_result.status_extended
                    == "RDS Cluster Snapshot snapshot-1 is encrypted."
                )
                assert manual_snapshot_result.resource_id == "snapshot-1"
                assert manual_snapshot_result.region == AWS_REGION_US_EAST_1
                assert (
                    manual_snapshot_result.resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
                )
                assert manual_snapshot_result.resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_rds_cluster_snapshot_not_encrypted(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
            PubliclyAccessible=False,
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
                "prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_encrypted.rds_snapshots_encrypted import (
                    rds_snapshots_encrypted,
                )

                check = rds_snapshots_encrypted()
                result = check.execute()

                assert len(result) == 2
                # Find the manual snapshot result
                manual_snapshot_result = next(
                    (r for r in result if r.resource_id == "snapshot-1"), None
                )
                assert manual_snapshot_result is not None
                assert manual_snapshot_result.status == "FAIL"
                assert (
                    manual_snapshot_result.status_extended
                    == "RDS Cluster Snapshot snapshot-1 is not encrypted."
                )
                assert manual_snapshot_result.resource_id == "snapshot-1"
                assert manual_snapshot_result.region == AWS_REGION_US_EAST_1
                assert (
                    manual_snapshot_result.resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
                )
                assert manual_snapshot_result.resource_tags == []
