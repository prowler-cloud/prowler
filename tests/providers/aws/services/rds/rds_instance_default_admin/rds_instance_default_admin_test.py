from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_default_admin:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin import (
                    rds_instance_default_admin,
                )

                check = rds_instance_default_admin()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_with_default_username(self):
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
            MasterUsername="postgres",
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
                "prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin import (
                    rds_instance_default_admin,
                )

                check = rds_instance_default_admin()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using the default master username."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_without_default_username(self):
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
            MasterUsername="postgres2",
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
                "prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin import (
                    rds_instance_default_admin,
                )

                check = rds_instance_default_admin()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is not using the default master username."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_cluster_instance_with_default_username(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            MasterUsername="postgres",
            MasterUserPassword="defaultpassword",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            DBClusterIdentifier="db-cluster-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            MasterUsername="postgres",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin import (
                    rds_instance_default_admin,
                )

                check = rds_instance_default_admin()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using the default master username at cluster db-cluster-1 level."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_cluster_instance_without_default_username(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            MasterUsername="custom",
            MasterUserPassword="defaultpassword",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            DBClusterIdentifier="db-cluster-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            MasterUsername="postgres2",
            DBInstanceClass="db.m1.small",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_default_admin.rds_instance_default_admin import (
                    rds_instance_default_admin,
                )

                check = rds_instance_default_admin()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is not using the default master username at cluster db-cluster-1 level."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []
