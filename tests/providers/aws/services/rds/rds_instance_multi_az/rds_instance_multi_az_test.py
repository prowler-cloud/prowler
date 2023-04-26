from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_rds

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.rds.rds_service import DBCluster, DBInstance

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_rds_instance_multi_az:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_rds
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 0

    @mock_rds
    def test_rds_instance_no_multi_az(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "does not have multi-AZ enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "db-master-1"

    @mock_rds
    def test_rds_instance_multi_az(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            MultiAZ=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has multi-AZ enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "db-master-1"

    def test_rds_instance_in_cluster_multi_az(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {
            "test-cluster": DBCluster(
                id="test-cluster",
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
                region=AWS_REGION,
                tags=[],
            )
        }
        rds_client.db_instances = [
            DBInstance(
                id="test-instance",
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group=[],
                multi_az=False,
                cluster_id="test-cluster",
                region=AWS_REGION,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has multi-AZ enabled at cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test-instance"

    def test_rds_instance_in_cluster_without_multi_az(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {
            "test-cluster": DBCluster(
                id="test-cluster",
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
                region=AWS_REGION,
                tags=[],
            )
        }
        rds_client.db_instances = [
            DBInstance(
                id="test-instance",
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group=[],
                multi_az=False,
                cluster_id="test-cluster",
                region=AWS_REGION,
                tags=[],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have multi-AZ enabled at cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test-instance"
