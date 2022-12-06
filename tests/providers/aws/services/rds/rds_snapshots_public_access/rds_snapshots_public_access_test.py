from re import search
from unittest import mock

from boto3 import client
from moto import mock_rds

AWS_REGION = "us-east-1"


class Test_rds_snapshots_public_access:
    @mock_rds
    def test_rds_no_snapshots(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                rds_snapshots_public_access,
            )

            check = rds_snapshots_public_access()
            result = check.execute()

            assert len(result) == 0

    @mock_rds
    def test_rds_private_snapshot(self):
        conn = client("rds", region_name=AWS_REGION)
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                rds_snapshots_public_access,
            )

            check = rds_snapshots_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "is not shared",
                result[0].status_extended,
            )
            assert result[0].resource_id == "snapshot-1"

    @mock_rds
    def test_rds_public_snapshot(self):
        conn = client("rds", region_name=AWS_REGION)
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
            new=RDS(current_audit_info),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                rds_snapshots_public_access,
            )

            service_client.db_snapshots[0].public = True
            check = rds_snapshots_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is public",
                result[0].status_extended,
            )
            assert result[0].resource_id == "snapshot-1"

    @mock_rds
    def test_rds_cluster_private_snapshot(self):
        conn = client("rds", region_name=AWS_REGION)
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                rds_snapshots_public_access,
            )

            check = rds_snapshots_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "is not shared",
                result[0].status_extended,
            )
            assert result[0].resource_id == "snapshot-1"

    @mock_rds
    def test_rds_cluster_public_snapshot(self):
        conn = client("rds", region_name=AWS_REGION)
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access.rds_client",
            new=RDS(current_audit_info),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.rds.rds_snapshots_public_access.rds_snapshots_public_access import (
                rds_snapshots_public_access,
            )

            service_client.db_cluster_snapshots[0].public = True
            check = rds_snapshots_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is public",
                result[0].status_extended,
            )
            assert result[0].resource_id == "snapshot-1"
