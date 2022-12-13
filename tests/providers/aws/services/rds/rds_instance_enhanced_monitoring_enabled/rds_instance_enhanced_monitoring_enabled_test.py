from re import search
from unittest import mock

from boto3 import client
from moto import mock_rds

AWS_REGION = "us-east-1"


class Test_rds_instance_enhanced_monitoring_enabled:
    @mock_rds
    def test_rds_no_instances(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                rds_instance_enhanced_monitoring_enabled,
            )

            check = rds_instance_enhanced_monitoring_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_rds
    def test_rds_instance_no_monitoring(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                rds_instance_enhanced_monitoring_enabled,
            )

            check = rds_instance_enhanced_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have enhanced monitoring enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == "db-master-1"

    @mock_rds
    def test_rds_instance_with_monitoring(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
            new=RDS(current_audit_info),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                rds_instance_enhanced_monitoring_enabled,
            )

            service_client.db_instances[0].enhanced_monitoring_arn = "log-stream"
            check = rds_instance_enhanced_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has enhanced monitoring enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == "db-master-1"
