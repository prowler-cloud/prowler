from unittest import mock
from unittest.mock import patch

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
    """
    Moto's RDS implementation does not currently expose EngineLifecycleSupport on DescribeDBInstances.
    This patch injects it into the response so that Prowler's RDS service can map it onto the DBInstance model.

    The check under test fails when:
      EngineLifecycleSupport == "open-source-rds-extended-support"
    """
    response = make_api_call(self, operation_name, kwarg)

    if operation_name == "DescribeDBInstances":
        for instance in response.get("DBInstances", []):
            if instance.get("DBInstanceIdentifier") == "db-extended-1":
                instance["EngineLifecycleSupport"] = "open-source-rds-extended-support"
        return response

    return response


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_extended_support:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support import (
                    rds_instance_extended_support,
                )

                check = rds_instance_extended_support()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_not_enrolled_in_extended_support(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-standard-1",
            AllocatedStorage=10,
            Engine="postgres",
            EngineVersion="8.0.32",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=False,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support import (
                    rds_instance_extended_support,
                )

                check = rds_instance_extended_support()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS instance db-standard-1 (postgres 8.0.32) is not enrolled in RDS Extended Support."
                )
                assert result[0].resource_id == "db-standard-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-standard-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_enrolled_in_extended_support(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-extended-1",
            AllocatedStorage=10,
            Engine="postgres",
            EngineVersion="8.0.32",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=False,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_extended_support.rds_instance_extended_support import (
                    rds_instance_extended_support,
                )

                check = rds_instance_extended_support()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance db-extended-1 (postgres 8.0.32) is enrolled in RDS Extended Support "
                    "(EngineLifecycleSupport=open-source-rds-extended-support)."
                )
                assert result[0].resource_id == "db-extended-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-extended-1"
                )
                assert result[0].resource_tags == []
