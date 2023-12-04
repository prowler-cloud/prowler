from re import search
from unittest import mock

import botocore
from boto3 import client
from moto import mock_rds

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_storage_encrypted:
    @mock_rds
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted import (
                    rds_instance_storage_encrypted,
                )

                check = rds_instance_storage_encrypted()
                result = check.execute()

                assert len(result) == 0

    @mock_rds
    def test_rds_instance_no_encryption(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted import (
                    rds_instance_storage_encrypted,
                )

                check = rds_instance_storage_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "is not encrypted",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_rds
    def test_rds_instance_with_encryption(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_storage_encrypted.rds_instance_storage_encrypted import (
                    rds_instance_storage_encrypted,
                )

                check = rds_instance_storage_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "is encrypted",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []
