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
    # if operation_name == "DescribeDBClusterSnapshotAttributes":
    #     return {
    #         "DBClusterSnapshotAttributesResult": {
    #             "DBClusterSnapshotIdentifier": "test-snapshot",
    #             "DBClusterSnapshotAttributes": [
    #                 {"AttributeName": "restore", "AttributeValues": ["all"]}
    #             ],
    #         }
    #     }
    return make_api_call(self, operation_name, kwarg)


class Test_rds_snapshots_public_access:
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
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                    rds_snapshots_public_access,
                )

                check = rds_snapshots_public_access()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
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
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                    rds_snapshots_public_access,
                )

                check = rds_snapshots_public_access()
                result = check.execute()

                # Moto creates additional automatic snapshots
                assert len(result) == 2
                # Find the manual snapshot result
                manual_snapshot_result = next(
                    (r for r in result if r.resource_id == "snapshot-1"), None
                )
                assert manual_snapshot_result is not None
                assert manual_snapshot_result.status == "PASS"
                assert (
                    manual_snapshot_result.status_extended
                    == "RDS Instance Snapshot snapshot-1 is not shared."
                )

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
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
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                    rds_snapshots_public_access,
                )

                # Find the manual snapshot and set it to public
                manual_snapshot = next(
                    (s for s in service_client.db_snapshots if s.id == "snapshot-1"),
                    None,
                )
                if manual_snapshot:
                    manual_snapshot.public = True
                check = rds_snapshots_public_access()
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
                    == "RDS Instance Snapshot snapshot-1 is public."
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
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                    rds_snapshots_public_access,
                )

                check = rds_snapshots_public_access()
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
                    == "RDS Cluster Snapshot snapshot-1 is not shared."
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
                "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                    rds_snapshots_public_access,
                )

                # Find the manual cluster snapshot and set it to public
                manual_snapshot = next(
                    (
                        s
                        for s in service_client.db_cluster_snapshots
                        if s.id == "snapshot-1"
                    ),
                    None,
                )
                if manual_snapshot:
                    manual_snapshot.public = True
                check = rds_snapshots_public_access()
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
                    == "RDS Cluster Snapshot snapshot-1 is public."
                )
                assert manual_snapshot_result.resource_id == "snapshot-1"
                assert manual_snapshot_result.region == AWS_REGION_US_EAST_1
                assert (
                    manual_snapshot_result.resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:snapshot-1"
                )
                assert manual_snapshot_result.resource_tags == []
