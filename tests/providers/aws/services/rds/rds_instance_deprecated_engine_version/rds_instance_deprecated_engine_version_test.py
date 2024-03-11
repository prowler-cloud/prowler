from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

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


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_deprecated_engine_version:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_no_deprecated_engine_version(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mysql",
            EngineVersion="8.0.32",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS instance db-master-1 is not using a deprecated engine mysql with version 8.0.32."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_deprecated_engine_version(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-2",
            AllocatedStorage=10,
            Engine="mysql",
            EngineVersion="8.0.23",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance db-master-2 is using a deprecated engine mysql with version 8.0.23."
                )
                assert result[0].resource_id == "db-master-2"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-2"
                )
                assert result[0].resource_tags == []
