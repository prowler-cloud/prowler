from re import search
from unittest import mock

from boto3 import client
from moto import mock_rds

AWS_REGION = "us-east-1"


class Test_rds_instance_transport_encrypted:
    @mock_rds
    def test_rds_no_instances(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                rds_instance_transport_encrypted,
            )

            check = rds_instance_transport_encrypted()
            result = check.execute()

            assert len(result) == 0

    @mock_rds
    def test_rds_instance_no_ssl(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "rds.force_ssl",
                    "ParameterValue": "0",
                    "ApplyMethod": "immediate",
                },
            ],
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                rds_instance_transport_encrypted,
            )

            check = rds_instance_transport_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "connections are not encrypted",
                result[0].status_extended,
            )
            assert result[0].resource_id == "db-master-1"

    @mock_rds
    def test_rds_instance_with_ssl(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "rds.force_ssl",
                    "ParameterValue": "1",
                    "ApplyMethod": "immediate",
                },
            ],
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.rds.rds_service import RDS

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
            new=RDS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                rds_instance_transport_encrypted,
            )

            check = rds_instance_transport_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "connections use SSL encryption",
                result[0].status_extended,
            )
            assert result[0].resource_id == "db-master-1"
