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
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }

    return make_api_call(self, operation_name, kwarg)


@mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_iam_authentication_enabled:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_aurora_instance_without_iam_auth(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            EnableIAMDatabaseAuthentication=False,
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 which is not clustered does not have IAM authentication enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_postgres_instance_with_iam_auth(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
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
            EnableIAMDatabaseAuthentication=True,
            DBParameterGroupName="test",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 which is not clustered has IAM authentication enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_mysql_instance_with_iam_auth(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.mysql",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mysql",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
            EnableIAMDatabaseAuthentication=True,
            DBParameterGroupName="test",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 which is not clustered has IAM authentication enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_mariadb_instance_with_iam_auth(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.mariadb",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mariadb",
            DBName="staging-mariadb",
            DBInstanceClass="db.m1.small",
            EnableIAMDatabaseAuthentication=True,
            DBParameterGroupName="test",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 which is not clustered has IAM authentication enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_sqlserver_instance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.sqlserver18",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="sqlserver-ee",
            DBName="staging-sqlserver",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_iam_authentication_enabled.rds_instance_iam_authentication_enabled import (
                    rds_instance_iam_authentication_enabled,
                )

                check = rds_instance_iam_authentication_enabled()
                result = check.execute()

                assert len(result) == 0
